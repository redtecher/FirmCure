#!/usr/bin/env python3
"""
ELF DYNAMIC Segment Patcher — 通用固件函数劫持工具

在 ELF 二进制文件的 DYNAMIC 段中注入 DT_NEEDED 条目，强制动态链接器加载指定的
共享库。适用于 LD_PRELOAD 被禁用且 section 信息被剥离的嵌入式固件。

支持:
  - ELF32 / ELF64
  - 大端 / 小端 (MIPS BE/LE, ARM, x86 等)
  - 被剥离 section 的二进制文件 (仅需 segment 信息)
  - p_filesz=0 的 DYNAMIC 段

原理:
  1. 在 .dynstr 字符串表之后的 padding 区域写入库名
  2. 在 DYNAMIC 数组中插入新的 DT_NEEDED 条目
  3. 动态链接器会在运行时自动加载该库

  默认插入到 DT_NEEDED 列表首位 (position=first)，确保 hook 库先于被 hook 库加载，
  使 hook 库的符号能够覆盖原始库的符号。

用法:
  python3 main.py <固件二进制> <库名> [-o 输出文件] [--position first|last]
  python3 main.py <固件二进制> --list
  python3 main.py --batch <目录> <库名> [--pattern "*.so"]

参考: https://blog.csdn.net/Karka_/article/details/132021841
"""

import struct
import sys
import argparse
import os
import glob as globmod

# ============================================================
# ELF 常量
# ============================================================
ELFMAG = b'\x7fELF'
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1  # 小端
ELFDATA2MSB = 2  # 大端

PT_LOAD = 1
PT_DYNAMIC = 2

DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29

# 引用字符串表偏移量的 DYNAMIC tag
STRING_REF_TAGS = {DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH}

# 引用虚拟地址的 DYNAMIC tag (用于定位文件中的相邻数据结构)
ADDR_REF_TAGS = {DT_STRTAB, DT_SYMTAB, DT_HASH, DT_PLTGOT, 0x6ffffef5}


class ELFPatcher:
    """解析并修补 ELF 二进制文件，注入 DT_NEEDED 条目。"""

    def __init__(self, data: bytes):
        self.data = bytearray(data)
        self._parse_ident()
        self._parse_ehdr()
        self._parse_phdrs()
        self._validate()

    # ----------------------------------------------------------
    # 基础解析
    # ----------------------------------------------------------

    def _parse_ident(self):
        if self.data[:4] != ELFMAG:
            raise ValueError("不是有效的 ELF 文件 (magic 不匹配)")

        self.ei_class = self.data[4]
        self.ei_data = self.data[5]

        if self.ei_class not in (ELFCLASS32, ELFCLASS64):
            raise ValueError(f"不支持的 ELF class: {self.ei_class}")

        if self.ei_data == ELFDATA2LSB:
            self.endian = '<'
            self.endian_name = 'Little-endian'
        elif self.ei_data == ELFDATA2MSB:
            self.endian = '>'
            self.endian_name = 'Big-endian'
        else:
            raise ValueError(f"未知的 ELF 数据编码: {self.ei_data}")

        self.is64 = (self.ei_class == ELFCLASS64)
        self.addr_fmt = 'Q' if self.is64 else 'I'
        self.addr_size = 8 if self.is64 else 4
        self.dyn_entry_size = 16 if self.is64 else 8

    def _u16(self, off):
        return struct.unpack_from(self.endian + 'H', self.data, off)[0]

    def _u32(self, off):
        return struct.unpack_from(self.endian + 'I', self.data, off)[0]

    def _addr(self, off):
        return struct.unpack_from(self.endian + self.addr_fmt, self.data, off)[0]

    def _set_addr(self, off, val):
        struct.pack_into(self.endian + self.addr_fmt, self.data, off, val)

    def _parse_ehdr(self):
        if self.is64:
            self.e_phoff = self._addr(0x20)
            self.e_phentsize = self._u16(0x36)
            self.e_phnum = self._u16(0x38)
        else:
            self.e_phoff = self._addr(0x1C)
            self.e_phentsize = self._u16(0x2A)
            self.e_phnum = self._u16(0x2C)

    def _parse_phdrs(self):
        self.phdrs = []
        self.dynamic_phdr = None
        self.load_segments = []

        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize

            if self.is64:
                phdr = {
                    'p_type':   self._u32(off),
                    'p_flags':  self._u32(off + 4),
                    'p_offset': self._addr(off + 8),
                    'p_vaddr':  self._addr(off + 16),
                    'p_paddr':  self._addr(off + 24),
                    'p_filesz': self._addr(off + 32),
                    'p_memsz':  self._addr(off + 40),
                    'p_align':  self._addr(off + 48),
                    '_phdr_off': off,
                }
            else:
                phdr = {
                    'p_type':   self._u32(off),
                    'p_offset': self._addr(off + 4),
                    'p_vaddr':  self._addr(off + 8),
                    'p_paddr':  self._addr(off + 12),
                    'p_filesz': self._addr(off + 16),
                    'p_memsz':  self._addr(off + 20),
                    'p_flags':  self._u32(off + 24),
                    'p_align':  self._addr(off + 28),
                    '_phdr_off': off,
                }

            self.phdrs.append(phdr)

            if phdr['p_type'] == PT_DYNAMIC:
                self.dynamic_phdr = phdr
            elif phdr['p_type'] == PT_LOAD:
                self.load_segments.append(phdr)

    def _validate(self):
        if self.dynamic_phdr is None:
            raise ValueError("未找到 PT_DYNAMIC 段 — 不是动态链接的二进制文件")
        if not self.load_segments:
            raise ValueError("未找到 PT_LOAD 段")

    # ----------------------------------------------------------
    # 地址转换
    # ----------------------------------------------------------

    def vaddr_to_offset(self, vaddr):
        """虚拟地址 → 文件偏移"""
        for seg in self.load_segments:
            if seg['p_vaddr'] <= vaddr < seg['p_vaddr'] + seg['p_filesz']:
                return vaddr - seg['p_vaddr'] + seg['p_offset']
        raise ValueError(f"虚拟地址 0x{vaddr:x} 未映射到任何 LOAD 段")

    def offset_to_vaddr(self, offset):
        """文件偏移 → 虚拟地址"""
        for seg in self.load_segments:
            if seg['p_offset'] <= offset < seg['p_offset'] + seg['p_filesz']:
                return offset - seg['p_offset'] + seg['p_vaddr']
        raise ValueError(f"文件偏移 0x{offset:x} 不在任何 LOAD 段中")

    # ----------------------------------------------------------
    # DYNAMIC 段操作
    # ----------------------------------------------------------

    def _dyn_base_offset(self):
        """获取 DYNAMIC 段在文件中的实际偏移 (处理 p_filesz=0 的情况)"""
        phdr = self.dynamic_phdr
        if phdr['p_filesz'] > 0:
            return phdr['p_offset']
        return self.vaddr_to_offset(phdr['p_vaddr'])

    def _dyn_scan_limit(self):
        """DYNAMIC 条目扫描的最大字节数"""
        phdr = self.dynamic_phdr
        if phdr['p_filesz'] > 0:
            return phdr['p_filesz']
        return phdr['p_memsz'] if phdr['p_memsz'] > 0 else 0x1000

    def read_dyn_entries(self):
        """读取 DYNAMIC 条目列表 (直到 DT_NULL)"""
        entries = []
        base = self._dyn_base_offset()
        limit = self._dyn_scan_limit()
        esz = self.dyn_entry_size

        for i in range(limit // esz):
            off = base + i * esz
            if off + esz > len(self.data):
                break
            tag = self._addr(off)
            val = self._addr(off + self.addr_size)
            entries.append({'idx': i, 'off': off, 'tag': tag, 'val': val})
            if tag == DT_NULL:
                break
        return entries

    def _write_dyn(self, off, tag, val):
        self._set_addr(off, tag)
        self._set_addr(off + self.addr_size, val)

    def _find_strtab(self):
        """返回 (strtab_vaddr, strtab_file_offset)"""
        for e in self.read_dyn_entries():
            if e['tag'] == DT_STRTAB:
                va = e['val']
                return va, self.vaddr_to_offset(va)
        raise ValueError("DYNAMIC 段中未找到 DT_STRTAB")

    def _read_cstring(self, file_offset):
        """从文件偏移处读取 C 字符串"""
        end = self.data.index(0, file_offset)
        return self.data[file_offset:end].decode('ascii', errors='replace')

    def get_needed_libs(self):
        """获取当前 DT_NEEDED 依赖库列表 (按加载顺序)"""
        _, strtab_off = self._find_strtab()
        libs = []
        for e in self.read_dyn_entries():
            if e['tag'] == DT_NEEDED:
                libs.append(self._read_cstring(strtab_off + e['val']))
        return libs

    # ----------------------------------------------------------
    # 空间分析
    # ----------------------------------------------------------

    def _find_next_data_offset(self, after_offset):
        """找到 after_offset 之后最近的数据结构起始位置"""
        candidates = []

        for phdr in self.phdrs:
            if phdr['p_offset'] > after_offset:
                candidates.append(phdr['p_offset'])

        for e in self.read_dyn_entries():
            if e['tag'] in ADDR_REF_TAGS:
                try:
                    ref_off = self.vaddr_to_offset(e['val'])
                    if ref_off > after_offset:
                        candidates.append(ref_off)
                except ValueError:
                    pass

        return min(candidates) if candidates else len(self.data)

    def _find_strtab_padding(self, name_bytes):
        """
        在字符串表之后寻找可写入库名的 padding 空间。
        返回 (写入偏移, strtab文件偏移)。
        """
        strtab_va, strtab_off = self._find_strtab()

        max_end = 0
        for e in self.read_dyn_entries():
            if e['tag'] in STRING_REF_TAGS:
                try:
                    s = self._read_cstring(strtab_off + e['val'])
                    end = e['val'] + len(s) + 1
                    if end > max_end:
                        max_end = end
                except (ValueError, IndexError):
                    pass

        for e in self.read_dyn_entries():
            if e['tag'] == DT_STRSZ and e['val'] > max_end:
                max_end = e['val']
                break

        write_start = strtab_off + max_end

        seg_end = len(self.data)
        for seg in self.load_segments:
            if seg['p_offset'] <= strtab_off < seg['p_offset'] + seg['p_filesz']:
                seg_end = seg['p_offset'] + seg['p_filesz']
                break

        available = seg_end - write_start
        if available < len(name_bytes):
            raise ValueError(
                f"字符串表后 padding 不足: 需要 {len(name_bytes)} 字节, "
                f"仅有 {available} 字节 (0x{write_start:x} ~ 0x{seg_end:x})"
            )

        return write_start, strtab_off

    def _check_shift_space(self):
        """检查是否有足够空间进行 shift (后移所有条目)"""
        entries = self.read_dyn_entries()
        base = self._dyn_base_offset()
        esz = self.dyn_entry_size

        null_idx = None
        for e in entries:
            if e['tag'] == DT_NULL:
                null_idx = e['idx']
                break

        if null_idx is None:
            return False, 0

        used_end = base + (null_idx + 1) * esz
        next_data = self._find_next_data_offset(used_end - 1)
        padding = next_data - used_end

        return padding >= esz, padding

    # ----------------------------------------------------------
    # 核心修补逻辑
    # ----------------------------------------------------------

    def patch(self, lib_name: str, position: str = 'first') -> bool:
        """
        注入 DT_NEEDED 条目。
        position='first': 插入到 DT_NEEDED 列表首位 (hook 必须用这个)
        position='last':  追加到 DT_NEEDED 列表末尾
        返回 True 表示成功修改。
        """
        existing = self.get_needed_libs()
        if lib_name in existing:
            print(f"[!] '{lib_name}' 已在依赖列表中, 无需重复注入")
            return False

        name_bytes = lib_name.encode('ascii') + b'\x00'

        # === 步骤 1: 将库名写入字符串表 padding ===
        name_off, strtab_off = self._find_strtab_padding(name_bytes)
        d_val = name_off - strtab_off

        print(f"[*] 字符串表偏移: 0x{strtab_off:x}")
        print(f"[*] 写入库名 '{lib_name}' 到文件偏移 0x{name_off:x} (strtab offset 0x{d_val:x})")
        self.data[name_off:name_off + len(name_bytes)] = name_bytes

        # 更新 DT_STRSZ (如有)
        new_strsz = d_val + len(name_bytes)
        for e in self.read_dyn_entries():
            if e['tag'] == DT_STRSZ:
                old_strsz = e['val']
                if new_strsz > old_strsz:
                    print(f"[*] 更新 DT_STRSZ: 0x{old_strsz:x} -> 0x{new_strsz:x}")
                    self._set_addr(e['off'] + self.addr_size, new_strsz)
                break

        # === 步骤 2: 插入 DT_NEEDED 条目 ===
        base = self._dyn_base_offset()
        esz = self.dyn_entry_size

        if position == 'first':
            self._insert_at_first(base, esz, d_val)
        else:
            self._insert_at_last(base, esz, d_val)

        return True

    def _insert_at_first(self, base, esz, d_val):
        """将所有 DYNAMIC 条目后移一位, 在首部插入 DT_NEEDED (确保 hook 优先加载)"""
        entries = self.read_dyn_entries()
        null_idx = None
        for e in entries:
            if e['tag'] == DT_NULL:
                null_idx = e['idx']
                break

        if null_idx is None:
            raise ValueError("DYNAMIC 段中没有 DT_NULL 终止符")

        move_len = (null_idx + 1) * esz
        can_shift, padding = self._check_shift_space()

        if can_shift:
            print(f"[*] [first] 后移 {null_idx + 1} 个 DYNAMIC 条目 (每个 {esz} 字节), "
                  f"padding={padding} 字节")
            print(f"[*] [first] 在文件偏移 0x{base:x} 插入 DT_NEEDED (列表首位)")

            src = bytes(self.data[base:base + move_len])
            self.data[base + esz:base + esz + move_len] = src
            self._write_dyn(base, DT_NEEDED, d_val)
            self._update_dynamic_phdr_size(esz)
        else:
            raise ValueError(
                f"DYNAMIC 段后 padding 不足, 无法 shift: 需要 {esz} 字节, "
                f"仅有 {padding} 字节。请尝试 --position last"
            )

    def _insert_at_last(self, base, esz, d_val):
        """在 DT_NULL 位置插入 DT_NEEDED (追加到列表末尾)"""
        entries = self.read_dyn_entries()
        scan_limit = self._dyn_scan_limit()

        null_idx = None
        for e in entries:
            if e['tag'] == DT_NULL:
                null_idx = e['idx']
                break

        if null_idx is None:
            raise ValueError("DYNAMIC 段中没有 DT_NULL 终止符")

        # 计算连续 DT_NULL 的数量
        null_count = 0
        for i in range(null_idx, scan_limit // esz):
            off = base + i * esz
            if off + esz > len(self.data):
                break
            if self._addr(off) == DT_NULL:
                null_count += 1
            else:
                break

        if null_count >= 2:
            off = base + null_idx * esz
            print(f"[*] [last] 替换多余的 DT_NULL (文件偏移 0x{off:x}, "
                  f"连续 DT_NULL 共 {null_count} 个)")
            self._write_dyn(off, DT_NEEDED, d_val)
        else:
            # 尝试 shift
            can_shift, padding = self._check_shift_space()
            if can_shift:
                move_len = (null_idx + 1) * esz
                print(f"[*] [last] 无多余 DT_NULL, 改用后移方式 (padding={padding} 字节)")
                src = bytes(self.data[base:base + move_len])
                self.data[base + esz:base + esz + move_len] = src
                self._write_dyn(base, DT_NEEDED, d_val)
                self._update_dynamic_phdr_size(esz)
            else:
                raise ValueError(
                    f"无多余 DT_NULL 且 padding 不足 ({padding} 字节), 无法插入"
                )

    def _update_dynamic_phdr_size(self, delta):
        """更新 PT_DYNAMIC 的 p_filesz / p_memsz"""
        phdr_off = self.dynamic_phdr['_phdr_off']
        old_filesz = self.dynamic_phdr['p_filesz']
        new_filesz = old_filesz + delta

        if self.is64:
            self._set_addr(phdr_off + 32, new_filesz)
            old_memsz = self._addr(phdr_off + 40)
            if new_filesz > old_memsz:
                self._set_addr(phdr_off + 40, new_filesz)
        else:
            self._set_addr(phdr_off + 16, new_filesz)
            old_memsz = self._addr(phdr_off + 20)
            if new_filesz > old_memsz:
                self._set_addr(phdr_off + 20, new_filesz)

        print(f"[*] PT_DYNAMIC filesz: 0x{old_filesz:x} -> 0x{new_filesz:x}")

    def get_data(self) -> bytes:
        return bytes(self.data)

    # ----------------------------------------------------------
    # 信息输出
    # ----------------------------------------------------------

    def print_info(self):
        print(f"[*] ELF 类: {'ELF64' if self.is64 else 'ELF32'}")
        print(f"[*] 字节序: {self.endian_name}")
        print(f"[*] Program Headers: {self.e_phnum} 个")
        print(f"[*] LOAD 段: {len(self.load_segments)} 个")

        dyn = self.dynamic_phdr
        print(f"[*] DYNAMIC 段: offset=0x{dyn['p_offset']:x}, "
              f"vaddr=0x{dyn['p_vaddr']:x}, filesz=0x{dyn['p_filesz']:x}")

        entries = self.read_dyn_entries()
        print(f"[*] DYNAMIC 条目: {len(entries)} 个 (含 DT_NULL)")

        try:
            strtab_va, strtab_off = self._find_strtab()
            print(f"[*] 字符串表: vaddr=0x{strtab_va:x}, file=0x{strtab_off:x}")
        except ValueError:
            print("[!] 字符串表未找到")

        libs = self.get_needed_libs()
        if libs:
            print(f"[*] 已有依赖库 ({len(libs)} 个, 按加载顺序):")
            for i, lib in enumerate(libs):
                marker = " <-- hook 目标" if "apmib" in lib else ""
                print(f"    [{i}] {lib}{marker}")
        else:
            print("[*] 未发现 DT_NEEDED 依赖")


# ============================================================
# 批量修补
# ============================================================

def patch_firmware_dir(fw_root: str, lib_name: str, position: str = 'first'):
    """
    扫描固件目录, 对所有依赖目标库的动态链接 ELF 文件注入 DT_NEEDED。
    自动将修补后的文件写回原位置 (先备份为 .bak)。
    """
    # 1. 找到固件中所有的动态链接库, 确定哪些库被 hook
    # 2. 扫描所有动态链接的 ELF 可执行文件
    # 3. 检查是否依赖了被 hook 的库
    # 4. 注入 DT_NEEDED

    print(f"[*] 扫描固件目录: {fw_root}")
    print(f"[*] 注入库: {lib_name}, 位置: {position}")
    print()

    patched_count = 0
    skipped_count = 0
    failed_list = []

    for root, dirs, files in os.walk(fw_root):
        # 跳过 lib 目录中的 .so 文件 (通常不需要 patch 库本身)
        for fname in files:
            fpath = os.path.join(root, fname)
            if not os.path.isfile(fpath):
                continue

            # 跳过备份和已修补文件
            if fname.endswith('.bak') or fname.endswith('.patched'):
                continue

            try:
                with open(fpath, 'rb') as f:
                    raw = f.read()
            except (PermissionError, OSError):
                continue

            # 快速判断是否是 ELF 且动态链接
            if len(raw) < 52 or raw[:4] != ELFMAG:
                continue

            # 检查是否是动态链接 (查找 PT_INTERP 或 PT_DYNAMIC)
            try:
                elf = ELFPatcher(raw)
            except ValueError:
                continue

            # 检查是否已有目标库
            try:
                libs = elf.get_needed_libs()
            except ValueError:
                continue

            if lib_name in libs:
                skipped_count += 1
                continue

            # 只修补可执行文件 (有 PT_INTERP 的), 不修补 .so
            has_interp = False
            for phdr in elf.phdrs:
                if phdr['p_type'] == 3:  # PT_INTERP
                    has_interp = True
                    break
            if not has_interp:
                continue

            print(f"{'='*50}")
            print(f"[*] 修补: {os.path.relpath(fpath, fw_root)}")
            print(f"    当前依赖: {libs}")

            try:
                elf_copy = ELFPatcher(raw)
                if elf_copy.patch(lib_name, position=position):
                    # 备份原文件
                    bak_path = fpath + '.bak'
                    if not os.path.exists(bak_path):
                        os.rename(fpath, bak_path)
                    else:
                        os.remove(fpath)

                    with open(fpath, 'wb') as f:
                        f.write(elf_copy.get_data())
                    st = os.stat(bak_path)
                    os.chmod(fpath, st.st_mode)

                    print(f"[+] 成功! (原文件备份: {fname}.bak)")
                    patched_count += 1
                else:
                    skipped_count += 1
            except Exception as e:
                print(f"[!] 失败: {e}")
                failed_list.append((fpath, str(e)))

    print(f"\n{'='*50}")
    print(f"[*] 批量修补完成:")
    print(f"    成功: {patched_count} 个")
    print(f"    跳过: {skipped_count} 个")
    if failed_list:
        print(f"    失败: {len(failed_list)} 个:")
        for fp, err in failed_list:
            print(f"      - {os.path.relpath(fp, fw_root)}: {err}")


# ============================================================
# 命令行入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='ELF DYNAMIC 段修补工具 — 注入 DT_NEEDED 实现固件函数劫持',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 查看依赖
  %(prog)s ./boa --list

  # 单个文件修补 (hook 库插入到列表首位, 确保符号优先)
  %(prog)s ./boa libhooknvram.so -o boa_patched

  # 批量修补整个固件目录 (自动备份为 .bak)
  %(prog)s --batch ./squashfs-root libhooknvram.so

  # 追加到末尾 (非 hook 场景)
  %(prog)s ./binary libextra.so --position last

关键说明:
  默认 --position first 将 hook 库插入到 DT_NEEDED 列表首位。
  这确保 hook 库在 libapmib.so 等被 hook 的库之前加载,
  使 hook 库的同名符号能覆盖原始库的符号, 实现 hook 效果。

  修补后, 将 hook .so 放入固件的 /lib/ 目录即可:
    cp libhooknvram.so squashfs-root/lib/
""")
    parser.add_argument('binary', nargs='?', help='输入 ELF 二进制文件')
    parser.add_argument('library', nargs='?', help='要注入的共享库名 (如 libhooknvram.so)')
    parser.add_argument('-o', '--output', help='输出文件 (默认: <输入>_patched)')
    parser.add_argument('-l', '--list', action='store_true',
                        help='仅列出当前依赖库')
    parser.add_argument('--position', choices=['first', 'last'], default='first',
                        help='插入位置: first=列表首位(hook推荐), last=末尾 (默认: first)')
    parser.add_argument('--batch', metavar='DIR',
                        help='批量修补: 扫描目录下所有动态链接 ELF 并注入')

    args = parser.parse_args()

    # 批量模式
    if args.batch:
        if not args.library:
            parser.error("批量模式需要指定 library 参数")
        if not os.path.isdir(args.batch):
            print(f"[!] 目录不存在: {args.batch}", file=sys.stderr)
            sys.exit(1)
        patch_firmware_dir(args.batch, args.library, position=args.position)
        sys.exit(0)

    # 单文件模式
    if not args.binary:
        parser.error("需要指定 binary 参数 (或使用 --batch)")

    if not args.list and not args.library:
        parser.error("除 --list 外需要指定 library 参数")

    if not os.path.isfile(args.binary):
        print(f"[!] 文件不存在: {args.binary}", file=sys.stderr)
        sys.exit(1)

    with open(args.binary, 'rb') as f:
        raw = f.read()

    try:
        elf = ELFPatcher(raw)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)

    elf.print_info()

    if args.list:
        sys.exit(0)

    output = args.output or f"{args.binary}_patched"

    print(f"\n{'='*50}")
    print(f"[*] 注入 DT_NEEDED: {args.library} (position={args.position})")
    print(f"{'='*50}")

    try:
        if elf.patch(args.library, position=args.position):
            with open(output, 'wb') as f:
                f.write(elf.get_data())
            st = os.stat(args.binary)
            os.chmod(output, st.st_mode)
            print(f"\n[+] 修补完成! 输出: {output}")
            if args.position == 'first':
                print(f"[*] hook 库已插入到 DT_NEEDED 首位, 符号将优先于原始库")
            print(f"[*] 使用: 将 {args.library} 放入固件 /lib/ 目录后运行")
        else:
            print("[*] 无需修改")
    except ValueError as e:
        print(f"\n[!] 修补失败: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
