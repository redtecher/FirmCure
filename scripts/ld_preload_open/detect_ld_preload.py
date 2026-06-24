#!/usr/bin/env python3
"""
固件 LD_PRELOAD 支持检测 — 纯静态分析
无需 QEMU，仅分析固件文件。

用法: python3 detect_ld_preload.py <squashfs-root 路径>
"""

import os
import sys
import struct
import glob as g

# ============================================================
# ELF 快速解析
# ============================================================
ELFMAG = b'\x7fELF'
ELFCLASS32, ELFCLASS64 = 1, 2
ELFDATA2LSB, ELFDATA2MSB = 1, 2
PT_DYNAMIC, PT_INTERP = 2, 3

MACHINE_NAMES = {8: 'MIPS', 40: 'ARM', 62: 'x86_64', 3: 'x86', 183: 'AArch64'}


class ElfInfo:
    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read(64)
        self.valid = self.data[:4] == ELFMAG
        if not self.valid:
            return
        self.is64 = self.data[4] == ELFCLASS64
        self.ei_data = self.data[5]
        self.endian = '<' if self.ei_data == ELFDATA2LSB else '>'
        self.e_machine = self._u16(0x12)
        if self.is64:
            self.e_phoff = self._u64(0x20)
            self.e_phentsize = self._u16(0x36)
            self.e_phnum = self._u16(0x38)
        else:
            self.e_phoff = self._u32(0x1C)
            self.e_phentsize = self._u16(0x2A)
            self.e_phnum = self._u16(0x2C)

    def _u16(self, off): return struct.unpack_from(self.endian + 'H', self.data, off)[0]
    def _u32(self, off): return struct.unpack_from(self.endian + 'I', self.data, off)[0]
    def _u64(self, off): return struct.unpack_from(self.endian + 'Q', self.data, off)[0]

    @property
    def arch_name(self):
        name = MACHINE_NAMES.get(self.e_machine, f'Unknown({self.e_machine})')
        bits = '64' if self.is64 else '32'
        endian = 'BE' if self.ei_data == ELFDATA2MSB else 'LE'
        return f'{name} {bits} {endian}'

    def _has_phdr_type(self, ptype):
        if not self.valid:
            return False
        with open(self.path, 'rb') as f:
            for i in range(self.e_phnum):
                f.seek(self.e_phoff + i * self.e_phentsize)
                phdr = f.read(self.e_phentsize)
                if len(phdr) >= 4 and struct.unpack_from(self.endian + 'I', phdr, 0)[0] == ptype:
                    return True
        return False

    @property
    def is_dynamic_exec(self): return self.valid and self._has_phdr_type(PT_INTERP)

    @property
    def has_dynamic(self): return self.valid and self._has_phdr_type(PT_DYNAMIC)

    @property
    def has_sections(self):
        if not self.valid:
            return False
        off = 0x3C if self.is64 else 0x30
        return self._u16(off) > 0


# ============================================================
# 输出
# ============================================================
G, R, Y, NC = '\033[0;32m', '\033[0;31m', '\033[1;33m', '\033[0m'
ok = lambda m: print(f"{G}[+]{NC} {m}")
no = lambda m: print(f"{R}[-]{NC} {m}")
wn = lambda m: print(f"{Y}[!]{NC} {m}")
ii = lambda m: print(f"    {m}")


def detect_ld_preload(fw_root, verbose=True):
    """
    检测固件 rootfs 是否支持 LD_PRELOAD。

    Args:
        fw_root: 固件 squashfs-root 路径
        verbose: 是否输出详细信息

    Returns:
        True  - LD_PRELOAD 可用
        False - LD_PRELOAD 不可用，需要 DT_NEEDED 注入
        None  - 不确定
    """
    fw_root = os.path.abspath(fw_root.rstrip('/'))
    if not os.path.isdir(fw_root):
        if verbose:
            print(f"目录不存在: {fw_root}")
        return None

    if verbose:
        print("=" * 52)
        print(" LD_PRELOAD 支持检测 (纯静态分析)")
        print(f" 固件路径: {fw_root}")
        print("=" * 52)
        print()

    score = 0  # 正分 = 支持, 负分 = 不支持

    # ========== 1. 定位 ld.so ==========
    if verbose:
        print("--- 1. 动态链接器 ---")
    ld_so = None
    for p in ['lib/ld-uClibc.so.0', 'lib/ld-uClibc.so', 'lib/ld-musl-*.so',
              'lib/ld-linux.so.1', 'lib/ld-linux.so.2', 'lib/ld-linux-*.so*',
              'lib/ld.so.1', 'lib/ld.so', 'lib64/ld-linux-*.so*']:
        matches = g.glob(os.path.join(fw_root, p))
        if matches:
            ld_so = matches[0]; break
    if not ld_so:
        if verbose:
            no("未找到 ld.so"); print("\n结论: 无法判断")
        return None
    if verbose:
        ok(f"{os.path.relpath(ld_so, fw_root)}")
    ld_info = ElfInfo(ld_so)
    if verbose:
        ii(f"架构: {ld_info.arch_name}")
        print()

    # 读取 ld.so 全部数据用于字符串分析
    with open(ld_so, 'rb') as f:
        ld_data = f.read()
    ld_strs = set(s.decode('ascii', errors='ignore')
                  for s in ld_data.split(b'\x00') if 2 < len(s) < 256)

    # ========== 2. libc 类型 ==========
    if verbose:
        print("--- 2. libc 类型 ---")
    libc_type = 'unknown'
    if g.glob(os.path.join(fw_root, 'lib/libuClibc-*.so')):
        ver = os.path.basename(g.glob(os.path.join(fw_root, 'lib/libuClibc-*.so'))[0])
        ver = ver.split('-')[1].rstrip('.so') if '-' in ver else '?'
        libc_type = 'uclibc'
        if verbose:
            ok(f"uClibc {ver}")
    elif g.glob(os.path.join(fw_root, 'lib/ld-musl-*.so')):
        libc_type = 'musl'
        if verbose:
            ok("musl libc")
    elif os.path.isfile(os.path.join(fw_root, 'lib/libc.so.6')):
        libc_type = 'glibc'
        if verbose:
            ok("glibc")
    else:
        if verbose:
            wn("未知")
    if verbose:
        print()

    # ========== 3. 编译配置文件 ==========
    if verbose:
        print("--- 3. 编译配置 (.config) ---")
    config_found = False
    for cfg in ['.config', 'etc/.config']:
        full = os.path.join(fw_root, cfg)
        if os.path.isfile(full):
            with open(full, 'rb') as f:
                cfg_data = f.read()
            if b'SUPPORT_LD_PRELOAD' in cfg_data:
                if b'SUPPORT_LD_PRELOAD=y' in cfg_data:
                    if verbose:
                        ok(f"{cfg}: SUPPORT_LD_PRELOAD=y")
                    score += 5
                else:
                    if verbose:
                        no(f"{cfg}: SUPPORT_LD_PRELOAD 未启用")
                    score -= 5
            else:
                if verbose:
                    wn(f"{cfg}: 无此选项 (非 uClibc 配置)")
            config_found = True; break
    if not config_found:
        if verbose:
            wn("未找到 .config 文件")
    if verbose:
        print()

    # ========== 4. ld.so 字符串深度分析 ==========
    if verbose:
        print("--- 4. ld.so 字符串深度分析 ---")

    has_ld_preload = 'LD_PRELOAD' in ld_strs
    has_ld_so_preload = any('ld.so.preload' in s for s in ld_strs)

    if has_ld_preload:
        if verbose:
            ok("包含 'LD_PRELOAD' 字符串")
        score += 1
    else:
        if verbose:
            no("不包含 'LD_PRELOAD' 字符串 -> 编译时已移除")
        score -= 3

    if has_ld_so_preload:
        if verbose:
            ok("包含 '/etc/ld.so.preload' 机制")
        score += 1

    runtime_indicators = [s for s in ld_strs if any(
        kw in s.lower() for kw in ['_dl_preload', 'npreloads',
                                     'preload_list', 'preload_file', 'loading preload']
    )]
    runtime_indicators = [s for s in runtime_indicators
                          if s not in ('LD_PRELOAD', 'PRELOAD')]
    if runtime_indicators:
        if verbose:
            ok(f"包含运行时加载符号: {runtime_indicators[:5]}")
        score += 2
    else:
        if verbose:
            no("缺少运行时加载符号 (npreloads/_dl_preload/preload_list)")
        score -= 2

    if libc_type == 'glibc':
        if verbose:
            ok("glibc 天然支持 LD_PRELOAD (编译时不可禁用)")
        score += 5
        glibc_indicators = ['LD_LIBRARY_PATH', 'LD_DEBUG', 'LD_PROFILE']
        found = [s for s in glibc_indicators if s in ld_strs]
        if len(found) >= 2:
            if verbose:
                ok(f"包含完整 LD_* 环境变量支持: {found}")
            score += 1
    elif libc_type == 'uclibc':
        has_open = any('dlopen' in s or '_dlopen' in s for s in ld_strs)
        has_sym = any('dlsym' in s or '_dlsym' in s for s in ld_strs)
        if has_open or has_sym:
            if verbose:
                ok(f"包含动态加载函数 (dlopen={'Y' if has_open else 'N'}/dlsym={'Y' if has_sym else 'N'})")
            score += 2
        else:
            if verbose:
                no("不包含 dlopen/dlsym -> preload 加载逻辑被编译排除")
            score -= 3
        if 'getenv' in ld_strs or '__getenv' in ld_strs:
            if verbose:
                ok("包含 getenv -> 有环境变量处理逻辑")
            score += 1
    elif libc_type == 'musl':
        if verbose:
            ok("musl libc (较新版本默认支持 LD_PRELOAD)")
        score += 2
    if verbose:
        print()

    # ========== 5. ELF 文件扫描 ==========
    if verbose:
        print("--- 5. ELF 文件概况 ---")
    execs, libs = [], []
    for dirpath, dirnames, filenames in os.walk(fw_root):
        dirnames[:] = [d for d in dirnames if d not in ('dev','proc','sys','tmp','run','lost+found')]
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            try:
                elf = ElfInfo(fp)
                if elf.is_dynamic_exec:
                    execs.append((fp, elf))
                elif elf.has_dynamic and not elf.is_dynamic_exec and elf.valid:
                    libs.append((fp, elf))
            except Exception:
                continue

    if verbose:
        if execs:
            ok(f"动态可执行文件: {len(execs)} 个")
            for fp, e in execs[:5]:
                ii(f"{os.path.relpath(fp, fw_root)} ({e.arch_name})")
        if libs:
            ii(f"动态库 (.so): {len(libs)} 个")
        if not execs and not libs:
            wn("未找到 ELF 文件")
        print()

    # ========== 6. section header & patchelf ==========
    if verbose:
        print("--- 6. section header ---")
        if execs:
            _, sample = execs[0]
            if sample.has_sections:
                ok("有 section header -> patchelf 可用")
            else:
                no("无 section header -> patchelf 不可用, 需要 DT_NEEDED 注入")
        print()

    # ========== 结论 ==========
    if verbose:
        print("=" * 52)
        print(" 结论")
        print("=" * 52)

    if libc_type == 'glibc':
        if verbose:
            ok("glibc 固件, LD_PRELOAD 天然可用")
            print("  不需要 DT_NEEDED 注入")
        return True

    if verbose:
        print(f"  静态分析评分: {score}")
        print()

    if score >= 3:
        if verbose:
            ok("LD_PRELOAD 很可能可用")
            print("  建议: 直接使用 LD_PRELOAD 环境变量")
        return True
    elif score <= -2:
        if verbose:
            no("LD_PRELOAD 不可用")
            print(f"  需要 DT_NEEDED 注入:")
            print(f"    python3 main.py --batch {fw_root} <hook库>.so")
        return False
    else:
        if verbose:
            wn("无法确定 (-2 ~ +2 之间)")
            print("  建议: 在 QEMU 中实际测试, 或直接使用 DT_NEEDED 注入 (更稳妥)")
        return None


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python3 detect_ld_preload.py <squashfs-root 路径>")
        sys.exit(1)
    result = detect_ld_preload(sys.argv[1])
    if result is True:
        sys.exit(0)
    elif result is False:
        sys.exit(1)
    else:
        sys.exit(2)
