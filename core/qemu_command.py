#!/usr/bin/env python3
"""
QEMU 命令生成器

根据架构配置生成QEMU启动命令
"""

import os
from pathlib import Path
from typing import Dict, Optional

from .qemu_config import (
    Architecture,
    MachineType,
    DiskInterface,
    QEMUCommandTemplate,
    QEMUCommand,
    normalize_architecture,
    get_qemu_params,
)


class QEMUCommandGenerator:
    """QEMU 命令生成器"""

    DEFAULT_MEMORY = "256M"
    DEFAULT_NANDSIM_PARTS = "nandsim.parts=64,64,64,64,64,64,64,64,64,64"

    ARCH_TO_QEMU = {
        "arm": "arm",
        "armel": "arm",
        "armhf": "arm",
        "arm64": "aarch64",
        "aarch64": "aarch64",
        "mips": "mips",
        "mipsel": "mipsel",
        "i386": "i386",
        "x86_64": "x86_64",
    }

    MACHINE_MAP = {
        "versatilepb": MachineType.ARM_VERSATILEPB,
        "vexpress-a9": MachineType.ARM_VEXPRESS_A9,
        "malta": MachineType.MALTA,
        "pc": MachineType.PC,
        "virt": MachineType.VIRT,
    }

    INTERFACE_MAP = {
        "ide": DiskInterface.IDE,
        "sd": DiskInterface.SD,
        "virtio": DiskInterface.VIRTIO,
        "scsi": DiskInterface.SCSI,
    }

    def generate(
        self,
        architecture: str,
        kernel_path: str,
        qcow2_path: str,
        initrd_path: Optional[str] = None,
        memory: Optional[str] = None,
        root_device: Optional[str] = None,
        cpu: Optional[str] = None,
        filesystem: Optional[str] = None,
        extra_append: Optional[str] = None,
        dtb_path: Optional[str] = None,
    ) -> QEMUCommand:
        arch = normalize_architecture(architecture)
        params = get_qemu_params(arch)

        if not params:
            raise ValueError(f"不支持的架构: {architecture}")

        machine_type = self.MACHINE_MAP.get(params["machine"], MachineType.MALTA)
        disk_interface = self.INTERFACE_MAP.get(params["interface"], DiskInterface.IDE)
        root_dev = root_device or params.get("root_device", "/dev/sda1")
        console = params.get("console", "ttyS0")
        fs_type = filesystem or params.get("filesystem", "ext4")
        resolved_cpu = cpu or params.get("cpu", "")
        resolved_memory = memory or params.get("memory", self.DEFAULT_MEMORY)

        qemu_arch = self.ARCH_TO_QEMU.get(arch, arch)

        # 使用绝对路径
        abs_kernel_path = os.path.abspath(kernel_path)
        abs_qcow2_path = os.path.abspath(qcow2_path)
        abs_initrd_path = os.path.abspath(initrd_path) if initrd_path else None

        cmd_parts = [f"qemu-system-{qemu_arch}"]
        cmd_parts.append(f"-M {params['machine']}")
        if resolved_cpu:
            cmd_parts.append(f"-cpu {resolved_cpu}")
        cmd_parts.append(f"-m {resolved_memory}")
        cmd_parts.append(f"-kernel {abs_kernel_path}")

        # DTB（设备树）文件 — ARM vexpress 等平台需要
        abs_dtb_path = os.path.abspath(dtb_path) if dtb_path else None
        if abs_dtb_path:
            cmd_parts.append(f"-dtb {abs_dtb_path}")

        if abs_initrd_path:
            cmd_parts.append(f"-initrd {abs_initrd_path}")

        if arch == "arm64":
            cmd_parts.append(f"-drive file={abs_qcow2_path},if=none,id=hd")
            cmd_parts.append("-device virtio-blk-pci,drive=hd")
        elif disk_interface == DiskInterface.IDE:
            cmd_parts.append(f"-hda {abs_qcow2_path}")
        elif disk_interface == DiskInterface.SD:
            cmd_parts.append(f"-drive if=sd,file={abs_qcow2_path}")
        else:
            cmd_parts.append(f"-drive file={abs_qcow2_path},if={disk_interface.value}")

        append_parts = [
            f"root={root_dev}",
            f"console={console}",
            "init=/bin/sh",
            f"rootfstype={fs_type}",
            "rw",
        ]

        # 固件中的 libapmib/libmtdapi 经常依赖内核侧 NAND/MTD 分区。
        # FirmAE 会默认传入 nandsim.parts；FirmCure 之前只在 qemu_shell 的
        # fallback 命令里携带了这个参数，导致实际 Phase2/run_qemu.sh 丢失。
        extra_parts = []
        if extra_append:
            extra_parts.extend(str(extra_append).split())

        has_nandsim_parts = any(part.startswith("nandsim.parts=") for part in extra_parts)
        if not has_nandsim_parts:
            extra_parts.append(self.DEFAULT_NANDSIM_PARTS)

        append_parts.extend(extra_parts)
        cmd_parts.append(f'-append "{" ".join(append_parts)}"')

        cmd_parts.append("-nographic")
        if arch == "arm64":
            cmd_parts.append("-device virtio-net-pci,netdev=net")
            cmd_parts.append("-netdev tap,id=net,ifname=tap0,script=no,downscript=no")
        else:
            cmd_parts.append("-net nic")
            cmd_parts.append("-net tap,ifname=tap0")
        cmd_parts.append("-s")

        full_command = " ".join(cmd_parts)

        arch_enum_map = {
            "arm": Architecture.ARM,
            "armel": Architecture.ARMEL,
            "armhf": Architecture.ARMHF,
            "arm64": Architecture.ARM64,
            "aarch64": Architecture.ARM64,
            "mips": Architecture.MIPS,
            "mipsel": Architecture.MIPSEL,
            "i386": Architecture.X86,
            "x86_64": Architecture.X86_64,
        }

        template = QEMUCommandTemplate(
            architecture=arch_enum_map.get(arch, Architecture.ARM),
            machine_type=machine_type,
            cpu=resolved_cpu,
            kernel_path=os.path.abspath(kernel_path),
            drive_path=os.path.abspath(qcow2_path),
            initrd_path=os.path.abspath(initrd_path) if initrd_path else None,
            interface=disk_interface,
            memory=resolved_memory,
            network=True,
            kernel_params={
                "root": root_dev,
                "console": console,
                "init": "/bin/sh",
                "rootfstype": fs_type,
                "rw": "",
            }
        )

        command = QEMUCommand(template=template)
        command.full_command = full_command

        return command

    def generate_run_script(
        self,
        command: QEMUCommand,
        output_path: Path,
    ) -> Path:
        script_path = output_path / "run_qemu.sh"

        qemu_cmd = command.full_command

        script_content = f'''#!/bin/bash
# QEMU 启动脚本 (FirmCure Phase 2)

set -e

RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[0;33m'
NC='\\033[0m'

echo ""
echo "========================================"
echo "  FirmCure QEMU 启动脚本"
echo "========================================"
echo ""

cleanup() {{
    echo ""
    echo -e "${{YELLOW}}[!]${{NC}} 清理资源..."

    if [ -f /etc/qemu-ifup.bak ]; then
        sudo mv /etc/qemu-ifup.bak /etc/qemu-ifup 2>/dev/null || true
    fi

    if ip link show tap0 &>/dev/null; then
        sudo ip link set tap0 down 2>/dev/null || true
        sudo ip tuntap del mode tap name tap0 2>/dev/null || true
    fi

    echo -e "${{GREEN}}[+]${{NC}} 清理完成"
}}
trap cleanup EXIT

echo -e "${{YELLOW}}[*]${{NC}} 配置 tap0 网络接口..."

if ! ip link show tap0 &>/dev/null; then
    sudo tunctl -t tap0 -u $(whoami) 2>/dev/null || \\
    sudo ip tuntap add mode tap user $(whoami) name tap0 2>/dev/null || true
fi

if ! ip link show tap0 &>/dev/null; then
    echo -e "${{RED}}[x]${{NC}} 创建 tap0 失败"
    exit 1
fi

if ! ip addr show tap0 | grep -q "10.10.10.1"; then
    sudo ip addr add 10.10.10.1/24 dev tap0 2>/dev/null || true
fi

sudo ip link set dev tap0 up
ip addr show tap0
echo -e "${{GREEN}}[+]${{NC}} tap0 配置完成: 10.10.10.1/24"
echo ""

echo -e "${{YELLOW}}[*]${{NC}} 配置 /etc/qemu-ifup..."
if [ -f /etc/qemu-ifup ]; then
    sudo mv /etc/qemu-ifup /etc/qemu-ifup.bak
fi

cat <<'QEMU_IFUP' | sudo tee /etc/qemu-ifup >/dev/null
#!/bin/sh
# FirmCure auto-generated qemu-ifup
QEMU_IFUP

sudo chmod +x /etc/qemu-ifup
echo -e "${{GREEN}}[+]${{NC}} qemu-ifup 配置完成"
echo ""

echo -e "${{GREEN}}[+]${{NC}} 启动 QEMU..."
echo ""
echo "========================================"
echo "  虚拟机内网络配置命令"
echo "========================================"
echo ""
echo "  ifconfig eth0 10.10.10.2/24"
echo "  ping -c 4 10.10.10.1"
echo ""
echo "========================================"
echo ""

# 运行 QEMU
{qemu_cmd}
'''

        with open(script_path, 'w') as f:
            f.write(script_content)

        script_path.chmod(0o755)
        print(f"[✓] 启动脚本已生成: {script_path}")

        return script_path
