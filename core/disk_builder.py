#!/usr/bin/env python3
"""
磁盘镜像构建器 - 打包 rootfs 到 QEMU 磁盘镜像
"""

import os
import re
import tempfile
import time
import subprocess
from pathlib import Path
from typing import Tuple, Optional

from .qemu_config import DiskImageSpec


class DiskBuilder:
    """rootfs → qcow2 磁盘镜像"""

    def __init__(self, sudo_password: str = ""):
        self.sudo_password = sudo_password
        self._verify_tools()

    def _verify_tools(self):
        required_tools = ["qemu-img", "parted", "kpartx"]
        for tool in required_tools:
            result = subprocess.run(["which", tool], capture_output=True)
            if result.returncode != 0:
                print(f"[!] 工具未找到: {tool}")

    def _run_sudo(self, cmd: str, check: bool = True) -> subprocess.CompletedProcess:
        if self.sudo_password:
            full_cmd = f"echo '{self.sudo_password}' | sudo -S {cmd}"
        else:
            full_cmd = f"sudo {cmd}"
        result = subprocess.run(
            full_cmd, shell=True, check=False,
            capture_output=True, text=True
        )
        if check and result.returncode != 0:
            stderr_msg = result.stderr.strip()
            raise subprocess.CalledProcessError(
                result.returncode, cmd,
                stderr=stderr_msg if stderr_msg else None
            )
        return result

    def build_qcow2(
        self,
        rootfs_path: Path,
        output_path: Path,
        spec: DiskImageSpec = None,
        root_device: Optional[str] = None,
        startup_script_content: Optional[str] = None,
        httpd_command: Optional[str] = None,
        nvram_needed: bool = False,
        nvram_arch: Optional[str] = None,
        nvram_libc: str = "glibc",
        vendor: Optional[str] = None,
        architecture: Optional[str] = None,
    ) -> Tuple[Path, str]:
        """
        打包 rootfs 到 qcow2 镜像

        Returns:
            (qcow2_path, root_device)
        """
        if spec is None:
            spec = DiskImageSpec()

        print(f"[*] 打包 rootfs: {rootfs_path}")
        print(f"[*] 输出镜像: {output_path}")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        # 修复 rootfs 中权限不足的文件/目录，确保可读
        self._run_sudo(f"chmod -R +rX {rootfs_path}", check=False)

        rootfs_size = self._get_directory_size(rootfs_path)
        rootfs_allocated_size = self._get_directory_allocated_size(rootfs_path)

        # rootfs 的逻辑大小经常低于实际落盘占用；再加上 ext4 元数据、分区偏移和后续脚本注入，
        # 只按文件字节数估算会导致镜像写满。
        effective_rootfs_size = max(rootfs_size, rootfs_allocated_size)
        headroom_bytes = max(64 * 1024 * 1024, effective_rootfs_size // 4)
        min_size_bytes = effective_rootfs_size + headroom_bytes

        # 默认镜像下限为 256MB。
        # 当 rootfs 更大时，按 2 的幂自动扩容，避免复制完成后没有空间注入脚本/NVRAM。
        image_size_bytes = 256 * 1024 * 1024
        while image_size_bytes <= min_size_bytes:
            image_size_bytes *= 2

        print(f"[*] Rootfs 大小(逻辑): {rootfs_size / (1024**3):.2f} GB")
        print(f"[*] Rootfs 占用(落盘): {rootfs_allocated_size / (1024**3):.2f} GB")
        print(f"[*] 镜像大小: {image_size_bytes / (1024**2):.0f} MB")

        with tempfile.TemporaryDirectory() as tmpdir:
            raw_file = Path(tmpdir) / "disk.raw"
            size_mb = int(image_size_bytes / (1024**2))

            subprocess.run(
                f"qemu-img create -f raw {raw_file} {size_mb}M",
                shell=True,
                check=True
            )

            if spec.partition_table != "none":
                print("[*] 创建分区表...")
                subprocess.run(
                    f"parted -s {raw_file} mklabel {spec.partition_table}",
                    shell=True,
                    check=True
                )

                use_p2 = root_device and "p2" in root_device

                if use_p2:
                    subprocess.run(
                        f"parted -s {raw_file} -- mkpart primary ext4 1MiB 2MiB",
                        shell=True,
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    subprocess.run(
                        f"parted -s {raw_file} -- mkpart primary ext4 2MiB 100%",
                        shell=True,
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                else:
                    subprocess.run(
                        f"parted -s {raw_file} -- mkpart primary ext4 1MiB 100%",
                        shell=True,
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )

                loop_dev = self._setup_loop_device(raw_file)
                print(f"[*] Loop 设备: {loop_dev}")

                try:
                    print("[*] 创建分区映射...")
                    self._run_sudo(f"kpartx -a -s -v {loop_dev}")
                    time.sleep(3)  # 等待分区设备创建完成

                    part_dev = self._find_partition_device(loop_dev, use_p2=use_p2)
                    print(f"[*] 分区设备: {part_dev}")

                    print(f"[*] 创建 {spec.filesystem} 文件系统...")
                    self._create_filesystem(part_dev, spec, architecture=architecture)

                    mount_point = Path(tmpdir) / "mount"
                    mount_point.mkdir()

                    try:
                        # 挂载时添加必要的选项以支持执行权限
                        self._run_sudo(f"mount -o rw,dev,exec,suid {part_dev} {mount_point}")

                        print("[*] 复制 rootfs 到镜像...")
                        # 使用兼容的rsync选项：
                        # -a 归档模式（-rlptgoD）
                        # -H 保留硬链接
                        # -x 限制在文件系统内（不跨越挂载点）
                        # 移除不兼容的选项：--numeric-owner（rsync 3.2.7不支持）
                        result = self._run_sudo(
                            f"rsync -aHx '{rootfs_path}/' '{mount_point}/' 2>&1",
                            check=False
                        )

                        # 验证复制是否成功
                        file_count = self._run_sudo(f"find {mount_point} -type f | wc -l", check=False)
                        print(f"    [复制] 已复制 {file_count.stdout.strip()} 个文件到镜像")
                        if int(file_count.stdout.strip()) == 0:
                            raise RuntimeError(f"rsync 复制失败，挂载点为空: {mount_point}")

                        print("[*] 修复文件权限...")
                        self._fix_permissions(mount_point)

                        # 验证关键二进制文件的权限
                        print("[*] 验证文件权限...")
                        test_files = ['/bin/sh', '/bin/busybox', '/sbin/init', '/lib/ld-linux*.so*']
                        for test_file in test_files:
                            test_path = f"{mount_point}{test_file}"
                            result = self._run_sudo(f"ls -la {test_path} 2>/dev/null || true", check=False)
                            if result.stdout.strip():
                                print(f"    {test_file}: {result.stdout.strip().split()[-3]}")

                        print("[*] 修复文件系统...")
                        self._fix_filesystem(mount_point, startup_script_content, httpd_command, nvram_needed, nvram_arch, nvram_libc, vendor, architecture)

                        # 强制同步，确保所有权限和元数据写入磁盘
                        print("[*] 同步文件系统...")
                        self._run_sudo(f"sync")
                    finally:
                        # 确保 umount，即使复制/修复过程中出错
                        print("[*] 卸载挂载点...")
                        self._run_sudo(f"umount {mount_point}", check=False)
                finally:
                    print("[*] 清理...")
                    self._cleanup(loop_dev)

            print("[*] 转换为 QCOW2...")
            subprocess.run(
                f"qemu-img convert -f raw -O qcow2 {raw_file} {output_path}",
                shell=True,
                check=True
            )

            final_root_device = root_device if root_device else "/dev/sda1"
            print(f"[✓] 镜像创建成功: {output_path}")
            print(f"[✓] Root 设备: {final_root_device}")

            return output_path, final_root_device

    def _setup_loop_device(self, raw_file: Path) -> str:
        result = self._run_sudo(f"losetup --show --find {raw_file}", check=False)

        if result.returncode != 0 or not result.stdout.strip():
            for i in range(10):
                result = self._run_sudo(f"losetup /dev/loop{i} {raw_file}", check=False)
                if result.returncode == 0:
                    return f"/dev/loop{i}"
            raise RuntimeError("无法设置 loop 设备")

        return result.stdout.strip()

    def _find_partition_device(self, loop_dev: str, use_p2: bool) -> str:
        part_suffix = "p2" if use_p2 else "p1"
        part_num = "2" if use_p2 else "1"

        mapper_part = f"/dev/mapper/{os.path.basename(loop_dev)}{part_suffix}"
        
        # 等待设备创建完成
        for _ in range(10):
            if os.path.exists(mapper_part):
                return mapper_part
            time.sleep(0.5)

        # 尝试其他路径
        for candidate in [f"{loop_dev}{part_suffix}", f"{loop_dev}{part_num}"]:
            if os.path.exists(candidate):
                return candidate

        raise RuntimeError(f"分区设备未找到: {mapper_part}")

    def _create_filesystem(self, part_dev: str, spec: DiskImageSpec, architecture: Optional[str] = None):
        if spec.filesystem == "ext4":
            disable_features = "^metadata_csum,^64bit,^orphan_file,^flex_bg,^extra_isize,^extent"
            # ARM 内核通常未编译 CONFIG_LBDAF，需禁用 huge_file 特性
            if architecture and architecture.startswith("arm"):
                disable_features += ",^huge_file"
            self._run_sudo(
                f"mkfs.ext4 -F -O {disable_features} "
                f"-L {spec.label} {part_dev}"
            )
        else:
            self._run_sudo(f"mkfs.{spec.filesystem} -F -L {spec.label} {part_dev}")

    def _fix_permissions(self, mount_point: Path):
        """修复rootfs中的文件权限，确保所有二进制文件和脚本可执行"""
        print(f"    [权限] 开始修复文件权限，挂载点: {mount_point}...")

        # 检查挂载点是否存在
        if not os.path.exists(mount_point):
            raise RuntimeError(f"挂载点不存在: {mount_point}")

        # 统计文件数量
        stat_result = self._run_sudo(f"find {mount_point} -type f | wc -l", check=False)
        file_count = int(stat_result.stdout.strip())
        print(f"    [权限] 挂载点中有 {file_count} 个文件")

        if file_count == 0:
            raise RuntimeError(f"挂载点为空，权限修复失败: {mount_point}")

        # 1. 设置基础权限 - 所有文件用户可读写，所有目录用户可执行
        self._run_sudo(f"chmod -R u+rw {mount_point}")
        self._run_sudo(f"find {mount_point} -type d -exec chmod u+x {{}} \\;")
        print("    [权限] 基础权限已设置")

        # 2. 批量设置关键目录的所有文件为可执行（使用简单粗暴的方法）
        print("    [权限] 正在设置关键目录权限...")
        critical_dirs = ['bin', 'sbin', 'usr/bin', 'usr/sbin', 'lib', 'usr/lib', 'lib64', 'usr/lib64']
        for dir_path in critical_dirs:
            full_path = f"{mount_point}/{dir_path}"
            result = self._run_sudo(f"test -d {full_path} && echo 'EXISTS' || echo 'NOTEXIST'", check=False)
            if 'EXISTS' in result.stdout:
                self._run_sudo(f"chmod -R a+x {full_path}/ 2>/dev/null || true")
                # 统计该目录的文件数
                count_result = self._run_sudo(f"find {full_path} -type f | wc -l", check=False)
                print(f"    [权限] {dir_path}: {count_result.stdout.strip()} 个文件已设置可执行")

        # 3. 识别并设置ELF文件权限（使用更高效的方法）
        print("    [权限] 正在识别并设置ELF二进制文件权限...")
        elf_count = 0
        for root_dir in ['bin', 'sbin', 'usr/bin', 'usr/sbin']:
            search_path = f"{mount_point}/{root_dir}"
            result = self._run_sudo(f"test -d {search_path} && echo 'EXISTS' || echo 'NOTEXIST'", check=False)
            if 'NOTEXIST' in result.stdout:
                continue

            # 使用更简单的方法：直接给该目录所有文件设置执行权限
            self._run_sudo(f"find {search_path} -type f -executable -exec chmod +x {{}} \\; 2>/dev/null || true", check=False)

            # 尝试用file命令识别ELF并设置权限
            find_result = self._run_sudo(
                f'find {search_path} -type f -exec file {{}} \\; 2>/dev/null | grep -i ELF | cut -d: -f1',
                check=False
            )
            if find_result.stdout.strip():
                elf_files = find_result.stdout.strip().split('\n')
                for elf_file in elf_files:
                    if elf_file.strip():
                        self._run_sudo(f"chmod +x '{elf_file}' 2>/dev/null", check=False)
                        elf_count += 1
        print(f"    [权限] 已处理 {elf_count} 个ELF文件")

        # 4. 设置脚本文件权限
        print("    [权限] 正在设置脚本文件权限...")
        script_count = 0
        for ext in ['.sh', '.cgi', '.lua', '.py']:
            find_result = self._run_sudo(
                f"find {mount_point} -type f -name '*{ext}' -exec chmod +x {{}} \\; 2>/dev/null; echo $?",
                check=False
            )
            # 尝试统计数量
            count_result = self._run_sudo(
                f"find {mount_point} -type f -name '*{ext}' | wc -l",
                check=False
            )
            count = int(count_result.stdout.strip())
            if count > 0:
                print(f"    [权限] {ext} 扩展名: {count} 个文件")
                script_count += count

        print(f"    [权限] 已处理约 {script_count} 个脚本文件")

        # 5. 最后确保关键二进制文件可执行
        critical_files = [
            '/bin/sh', '/bin/busybox', '/bin/bash', '/sbin/init', '/bin/init',
            '/lib/ld-', '/lib64/ld-', '/lib/ld-linux', '/lib64/ld-linux'
        ]
        for pattern in critical_files:
            self._run_sudo(f"chmod +x {mount_point}{pattern}* 2>/dev/null || true", check=False)

        print("    [权限] 权限修复完成")

    def _fix_broken_symlinks(self, mount_point: Path):
        """修复 rootfs 根目录下的异常符号链接 — 仅检查第一层

        判断条件：符号链接目标不存在，或目标不是目录（如 var -> /dev/null），
        则删除符号链接并重建为真实目录。
        """
        fixed = 0
        for item in mount_point.iterdir():
            if not item.is_symlink():
                continue
            try:
                target = os.readlink(str(item))
                resolved = item.resolve()
                # 指向 /dev/null 的符号链接 → 删除重建为目录
                if target == "/dev/null":
                    self._run_sudo(f"rm -f '{item}'")
                    self._run_sudo(f"mkdir -p '{item}'")
                    fixed += 1
                    print(f"    [symlink] {item.name} -> {target} (已重建为目录)")
            except Exception as e:
                print(f"    [symlink] {item.name}: 修复失败 {e}")
        if fixed:
            print(f"[*] 修复了 {fixed} 个根目录异常符号链接")
        else:
            print("[*] 根目录符号链接检查完毕，无异常")

    def _fix_filesystem(self, mount_point: Path, startup_script_content: Optional[str] = None, httpd_command: Optional[str] = None, nvram_needed: bool = False, nvram_arch: Optional[str] = None, nvram_libc: str = "glibc", vendor: Optional[str] = None, architecture: Optional[str] = None):
        # 先修复损坏的符号链接
        self._fix_broken_symlinks(mount_point)

        etc_dir = mount_point / "etc"

        passwd_file = etc_dir / "passwd"
        try:
            if not passwd_file.exists() or passwd_file.stat().st_size == 0:
                self._run_sudo(f"sh -c 'echo \"root::0:0:root:/root:/bin/sh\" > {passwd_file}'")
        except:
            pass

        hosts_file = etc_dir / "hosts"
        try:
            if not hosts_file.exists() or hosts_file.stat().st_size == 0:
                self._run_sudo(f"sh -c 'echo \"127.0.0.1 localhost\" > {hosts_file}'")
        except:
            pass

        self._ensure_device_nodes(mount_point)
        self._inject_network_script(mount_point, vendor, architecture)
        self._inject_startup_script(mount_point, startup_script_content, httpd_command, nvram_needed, nvram_arch, nvram_libc, vendor)

    def _ensure_device_nodes(self, mount_point: Path):
        """创建 /dev 下必要的设备节点，确保内核能打开 console 且 init 能获得 stdio"""
        dev_dir = mount_point / "dev"
        self._run_sudo(f"mkdir -p {dev_dir}")

        devices = [
            ("console", "c", "5", "1", "600"),
            ("null",    "c", "1", "3", "666"),
            ("zero",    "c", "1", "5", "666"),
            ("random",  "c", "1", "8", "666"),
            ("urandom", "c", "1", "9", "666"),
            ("ttyS0",   "c", "4", "64", "660"),
            ("tty",     "c", "5", "0", "666"),
        ]

        for name, dtype, major, minor, mode in devices:
            dev_path = dev_dir / name
            if not dev_path.exists():
                self._run_sudo(f"mknod -m {mode} {dev_path} {dtype} {major} {minor}", check=False)
                print(f"    [dev] 创建 {name}")

        # MTD/Flash 设备节点 (libapmib.so 等 vendor 库需要访问 flash)
        self._create_mtd_devices(dev_dir)

        print("[*] 设备节点检查完毕")

    def _create_mtd_devices(self, dev_dir: Path):
        """创建 MTD/Flash 设备节点，配合 nandsim 内核模块使用"""
        mtd_dir = dev_dir / "mtd"
        mtdblock_dir = dev_dir / "mtdblock"
        self._run_sudo(f"mkdir -p {mtd_dir} {mtdblock_dir}", check=False)

        for i in range(11):
            # /dev/mtdN (字符设备, major 90, minor = 2*i)
            mtd_path = dev_dir / f"mtd{i}"
            if not mtd_path.exists():
                self._run_sudo(f"mknod -m 644 {mtd_path} c 90 {2*i}", check=False)
            # /dev/mtd/N (字符设备)
            mtd_sub = mtd_dir / str(i)
            if not mtd_sub.exists():
                self._run_sudo(f"mknod -m 644 {mtd_sub} c 90 {2*i}", check=False)
            # /dev/mtdrN (只读字符设备, minor = 2*i+1)
            mtdr_path = dev_dir / f"mtdr{i}"
            if not mtdr_path.exists():
                self._run_sudo(f"mknod -m 644 {mtdr_path} c 90 {2*i+1}", check=False)
            # /dev/mtdblockN (块设备, major 31)
            mtdblock_path = dev_dir / f"mtdblock{i}"
            if not mtdblock_path.exists():
                self._run_sudo(f"mknod -m 644 {mtdblock_path} b 31 {i}", check=False)
            # /dev/mtdblock/N (块设备)
            mtdblock_sub = mtdblock_dir / str(i)
            if not mtdblock_sub.exists():
                self._run_sudo(f"mknod -m 644 {mtdblock_sub} b 31 {i}", check=False)

        print(f"    [dev] MTD 设备: mtd0~10, mtdr0~10, mtdblock0~10")

    def _inject_network_script(self, mount_point: Path, vendor: Optional[str] = None, architecture: Optional[str] = None):
        network_script = mount_point / "bin" / "setup_network.sh"
        try:
            # arm64 virt 机器网卡名称为 enp0s2，其他架构为 eth0
            iface = "enp0s2" if (architecture and architecture.startswith("arm64")) else "eth0"

            # Tenda 厂商需要额外的 br0 桥接接口
            tenda_br0_block = ""
            if vendor and vendor.lower() == "tenda":
                tenda_br0_block = f'''
# === Tenda: 配置 br0 bridge 接口 ===
echo "[Tenda] 配置 br0 接口..."
ip link add name br0 type bridge 2>/dev/null
ip link set br0 up
ip addr add 10.10.10.2/24 dev br0
route add default gw 10.10.10.1 2>/dev/null
echo "[Tenda] br0 配置完成"
'''

            # 非 Tenda: 主接口直接用 10.10.10.2; Tenda: 主接口用 10.10.10.3, br0 用 10.10.10.2
            iface_ip = "10.10.10.3" if (vendor and vendor.lower() == "tenda") else "10.10.10.2"

            network_script_content = f'''#!/bin/sh
export PATH=$PATH:/sbin

echo "========================================="
echo "  FirmCure Network Setup"
echo "========================================="
echo ""

ifconfig {iface} up 2>/dev/null
ifconfig {iface} {iface_ip} netmask 255.255.255.0 up
route add default gw 10.10.10.1 2>/dev/null
{tenda_br0_block}
if command -v ping >/dev/null 2>&1; then
    echo "[*] Testing connection..."
    ping -c 3 10.10.10.1
else
    echo "[*] ping not available, skipping connectivity test"
fi

echo ""
echo "VM IP: 10.10.10.2"
echo "Host IP: 10.10.10.1"
echo "========================================="
'''
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as tf:
                tf.write(network_script_content)
                temp_script = tf.name
            self._run_sudo(f"cp {temp_script} {network_script}")
            self._run_sudo(f"chmod +x {network_script}")
            os.unlink(temp_script)
            vendor_info = f" (vendor={vendor})" if vendor else ""
            print(f"[*] 已注入网络配置脚本: /bin/setup_network.sh{vendor_info}")
        except Exception as e:
            print(f"[!] 注入网络脚本失败: {e}")
    
    def _strip_comments(self, script_content: str) -> str:
        """删除脚本中除了 shebang 之外的所有注释"""
        lines = script_content.split('\n')
        cleaned_lines = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if i == 0 and stripped.startswith("#!"):
                cleaned_lines.append(line)
            elif stripped.startswith("#"):
                continue
            else:
                cleaned_lines.append(line)
        return '\n'.join(cleaned_lines)

    def _inject_startup_script(self, mount_point: Path, startup_script_content: Optional[str], httpd_command: Optional[str], nvram_needed: bool = False, nvram_arch: Optional[str] = None, nvram_libc: str = "glibc", vendor: Optional[str] = None):
        try:
            if startup_script_content:
                startup_script = mount_point / "startup.sh"
                with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as tf:
                    tf.write(self._strip_comments(startup_script_content))
                    temp_script = tf.name
                self._run_sudo(f"cp {temp_script} {startup_script}")
                self._run_sudo(f"chmod +x {startup_script}")
                os.unlink(temp_script)
                print(f"[*] 已注入启动脚本: /startup.sh")

            if httpd_command:
                # 注入 NVRAM faker 库 + 配置（如果需要）
                if nvram_needed and nvram_arch:
                    self._inject_nvram(mount_point, nvram_arch, nvram_libc, vendor)

                # 检测 LD_PRELOAD 是否可用
                use_ld_preload = True
                if nvram_needed:
                    use_ld_preload = self._detect_and_patch_ld_preload(
                        mount_point, httpd_command, nvram_arch
                    )

                httpd_start_script = mount_point / "httpd_start.sh"
                cleaned = self._strip_comments(httpd_command)
                with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as tf:
                    if cleaned.strip().startswith("#!/"):
                        tf.write(cleaned)
                    else:
                        tf.write("#!/bin/sh\n")
                        # 加入 LD_PRELOAD（如果需要且可用）
                        if nvram_needed and use_ld_preload:
                            tf.write("export LD_PRELOAD=./libnvram-faker.so\n")
                        tf.write(f"{cleaned.strip()}\n")
                    temp_script = tf.name
                self._run_sudo(f"cp {temp_script} {httpd_start_script}")
                self._run_sudo(f"chmod +x {httpd_start_script}")
                print(f"[*] 已注入 HTTPD 启动脚本: /httpd_start.sh")
                if nvram_needed:
                    if use_ld_preload:
                        print(f"[*] 已加入 LD_PRELOAD=./libnvram-faker.so")
                    else:
                        print(f"[*] 已通过 DT_NEEDED 注入 libnvram-faker.so 到 httpd 二进制")
        except Exception as e:
            print(f"[!] 注入启动脚本失败: {e}")

    def _detect_and_patch_ld_preload(self, mount_point: Path, httpd_command: str,
                                      nvram_arch: Optional[str] = None) -> bool:
        """
        检测固件 LD_PRELOAD 支持，不可用时对 httpd 二进制执行 DT_NEEDED 注入。

        Returns:
            True  - 使用 LD_PRELOAD 环境变量
            False - 已通过 DT_NEEDED 注入，不需要 LD_PRELOAD 环境变量
        """
        try:
            from scripts.ld_preload_open import detect_ld_preload, ELFPatcher
        except ImportError:
            import importlib.util
            base = Path(__file__).resolve().parent.parent / "scripts" / "ld_preload_open"
            spec = importlib.util.spec_from_file_location(
                "ld_preload_open_detect", base / "detect_ld_preload.py"
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            spec2 = importlib.util.spec_from_file_location(
                "ld_preload_open_main", base / "main.py"
            )
            mod2 = importlib.util.module_from_spec(spec2)
            spec2.loader.exec_module(mod2)
            detect_ld_preload = mod.detect_ld_preload
            ELFPatcher = mod2.ELFPatcher

        print("[*] 检测 LD_PRELOAD 支持...")
        result = detect_ld_preload(str(mount_point), verbose=True)

        # True 或 None (不确定) → 使用 LD_PRELOAD
        if result is not False:
            print("[*] LD_PRELOAD 可用 (或不确定)，使用环境变量方式")
            return True

        # False → LD_PRELOAD 不可用，执行 DT_NEEDED 注入
        print("[!] LD_PRELOAD 不可用，切换到 DT_NEEDED 注入模式")

        # 从 httpd_command 中提取二进制路径
        httpd_binary_path = self._extract_httpd_binary(mount_point, httpd_command)
        if not httpd_binary_path:
            print("[!] 无法定位 httpd 二进制文件，回退到 LD_PRELOAD")
            return True

        if not httpd_binary_path.exists():
            print(f"[!] httpd 二进制不存在: {httpd_binary_path}，回退到 LD_PRELOAD")
            return True

        try:
            with open(httpd_binary_path, 'rb') as f:
                raw = f.read()

            patcher = ELFPatcher(raw)
            lib_name = "libnvram-faker.so"

            if patcher.patch(lib_name, position='first'):
                patched_data = patcher.get_data()
                # 备份原文件
                bak_path = str(httpd_binary_path) + '.bak'
                if not os.path.exists(bak_path):
                    self._run_sudo(f"cp {httpd_binary_path} {bak_path}")
                # 写入修补后的文件
                with tempfile.NamedTemporaryFile(delete=False) as tf:
                    tf.write(patched_data)
                    temp_patched = tf.name
                self._run_sudo(f"cp {temp_patched} {httpd_binary_path}")
                os.unlink(temp_patched)
                # 恢复执行权限
                self._run_sudo(f"chmod +x {httpd_binary_path}")
                print(f"[+] DT_NEEDED 注入成功: {httpd_binary_path} → {lib_name}")
            else:
                print(f"[*] {lib_name} 已在依赖列表中，无需重复注入")

            # 将 libnvram-faker.so 放到 /lib/ 目录（DT_NEEDED 搜索路径）
            self._ensure_nvram_lib_in_lib_dir(mount_point)

            return False

        except Exception as e:
            print(f"[!] DT_NEEDED 注入失败: {e}，回退到 LD_PRELOAD")
            return True

    def _extract_httpd_binary(self, mount_point: Path, httpd_command: str) -> Optional[Path]:
        """从 httpd_command 中提取实际的二进制文件路径"""
        # 清理命令，去除注释
        cleaned = self._strip_comments(httpd_command).strip()
        # 去除 shebang
        if cleaned.startswith("#!"):
            lines = cleaned.split('\n')
            cleaned = '\n'.join(lines[1:]).strip()

        # 逐行尝试提取命令路径
        for line in cleaned.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # 提取命令的第一个 token（可能是路径）
            tokens = line.split()
            if not tokens:
                continue
            cmd = tokens[0]
            # 如果是绝对路径
            if cmd.startswith('/'):
                binary_path = mount_point / cmd.lstrip('/')
                if binary_path.exists():
                    return binary_path
            # 如果是相对路径或命令名，尝试在常见目录中查找
            for search_dir in ['bin', 'sbin', 'usr/bin', 'usr/sbin']:
                candidate = mount_point / search_dir / cmd
                if candidate.exists():
                    return candidate
        return None

    def _ensure_nvram_lib_in_lib_dir(self, mount_point: Path):
        """确保 libnvram-faker.so 在 /lib/ 目录中（DT_NEEDED 搜索路径）"""
        lib_dest = mount_point / "lib" / "libnvram-faker.so"
        if lib_dest.exists():
            return

        # 如果根目录已有，复制到 /lib/
        root_lib = mount_point / "libnvram-faker.so"
        if root_lib.exists():
            self._run_sudo(f"cp {root_lib} {lib_dest}")
            self._run_sudo(f"chmod 755 {lib_dest}")
            print(f"[*] 已复制 libnvram-faker.so 到 /lib/ (DT_NEEDED 搜索路径)")
        else:
            print(f"[!] libnvram-faker.so 未找到，无法复制到 /lib/")

    def _inject_nvram(self, mount_point: Path, nvram_arch: str,
                      nvram_libc: str = "glibc", vendor: str = ""):
        """注入 libnvram-faker 库 + NVRAM 配置到 rootfs（参照 Greenhouse Planter.py）"""
        try:
            from config import get_libnvram_dir
            libnvram_base = get_libnvram_dir()

            # 1. 查找 faker 库文件
            faker_source = libnvram_base / "lib" / nvram_arch / nvram_libc / "libnvram-faker.so"
            if not faker_source.exists():
                # 回退到 glibc
                faker_source = libnvram_base / "lib" / nvram_arch / "glibc" / "libnvram-faker.so"
                if faker_source.exists():
                    print(f"[!] libc '{nvram_libc}' 不存在，回退到 glibc")

            if not faker_source.exists():
                print(f"[!] libnvram-faker.so ({nvram_arch}/{nvram_libc}) 未找到，跳过")
                return

            # 2. 复制 libnvram-faker.so 到根目录
            faker_dest = mount_point / "libnvram-faker.so"
            self._run_sudo(f"cp {faker_source} {faker_dest}")
            self._run_sudo(f"chmod 755 {faker_dest}")
            print(f"[*] 已注入 libnvram-faker.so: {nvram_arch}/{nvram_libc}")

            # 3. 注入 NVRAM 配置（gh_nvram.ini + gh_nvram/）
            self._inject_nvram_config(mount_point, libnvram_base, vendor)

        except Exception as e:
            print(f"[!] NVRAM 注入失败: {e}")

    def _inject_nvram_config(self, mount_point: Path, libnvram_base: Path, vendor: str = ""):
        """合并 generic + vendor nvram.ini，写入 rootfs，并创建 gh_nvram/ 目录"""
        nvram_map = {}

        # 读取通用默认值
        generic_ini = libnvram_base / "conf" / "nvram.ini"
        if generic_ini.exists():
            with open(generic_ini) as f:
                for line in f:
                    line = line.strip()
                    if line and "=" in line and not line.startswith("#"):
                        key, _, value = line.partition("=")
                        nvram_map[key.strip()] = value.strip()

        # 叠加厂商特定值
        vendor_dir = self._normalize_vendor(vendor)
        if vendor_dir:
            vendor_ini = libnvram_base / "conf" / vendor_dir / "nvram.ini"
            if vendor_ini.exists():
                with open(vendor_ini) as f:
                    for line in f:
                        line = line.strip()
                        if line and "=" in line and not line.startswith("#"):
                            key, _, value = line.partition("=")
                            nvram_map[key.strip()] = value.strip()
                print(f"[*] 已叠加厂商 NVRAM 配置: {vendor_dir}")

        # 写入 gh_nvram.ini 到 rootfs（faker 库读取 /gh_nvram.ini）
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as tf:
            for key, value in nvram_map.items():
                tf.write(f"{key}={value}\n")
            temp_ini = tf.name
        nvram_ini_dest = mount_point / "gh_nvram.ini"
        self._run_sudo(f"cp {temp_ini} {nvram_ini_dest}")
        os.unlink(temp_ini)
        print(f"[*] 已注入 gh_nvram.ini ({len(nvram_map)} keys)")

        # 创建 gh_nvram/ 目录（per-key 文件，libnvram-faker 运行时读取格式）
        gh_dir = mount_point / "gh_nvram"
        self._run_sudo(f"mkdir -p {gh_dir}")
        count = 0
        for key, value in nvram_map.items():
            # 跳过含 null 字节或不可打印字符的 key
            if '\x00' in key or '\x00' in value:
                continue
            safe_key = key.replace("/", "_").replace("\\", "_").strip("/.")
            if not safe_key:
                continue
            try:
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as tf:
                    tf.write(value)
                    temp_key = tf.name
                self._run_sudo(f"cp {temp_key} {gh_dir / safe_key}")
                os.unlink(temp_key)
                count += 1
            except Exception:
                continue
        self._run_sudo(f"chmod -R a+rw {gh_dir}")
        print(f"[*] 已创建 gh_nvram/ ({count} key-value 文件)")

    @staticmethod
    def _normalize_vendor(vendor: str) -> str:
        """将厂商名标准化为 Greenhouse conf 目录名"""
        v = vendor.lower().strip().replace("-", "").replace(" ", "")
        vendor_map = {
            "asus": "asus",
            "belkin": "belkin",
            "dlink": "dlink",
            "linksys": "linksys",
            "netgear": "netgear",
            "tplink": "tplink",
            "trendnet": "trendnet",
            "zyxel": "ZyXEL",
        }
        return vendor_map.get(v, "")

    def _cleanup(self, loop_dev: str):
        try:
            self._run_sudo(f"kpartx -d {loop_dev}", check=False)
        except:
            pass
        self._run_sudo(f"losetup -d {loop_dev}", check=False)

    def _get_directory_size(self, path: Path) -> int:
        total_size = 0
        for item in path.rglob('*'):
            try:
                if item.is_file() and not item.is_symlink():
                    total_size += item.stat().st_size
            except (PermissionError, OSError):
                pass
        return total_size

    def _get_directory_allocated_size(self, path: Path) -> int:
        total_size = 0

        try:
            total_size += os.lstat(path).st_blocks * 512
        except (PermissionError, OSError):
            pass

        for root, dirs, files in os.walk(path, followlinks=False):
            for name in dirs + files:
                item_path = os.path.join(root, name)
                try:
                    total_size += os.lstat(item_path).st_blocks * 512
                except (PermissionError, OSError):
                    pass

        return total_size
