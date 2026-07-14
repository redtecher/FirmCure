#!/usr/bin/env python3
"""
QEMU Configuration Data Structures

定义 QEMU 仿真所需的所有数据结构:
- Architecture (架构枚举)
- DiskInterface (磁盘接口)
- MachineType (机器类型)
- DiskImageSpec (磁盘镜像规格)
- QEMUCommandTemplate (QEMU命令模板)
- QEMUCommand (QEMU命令)
- ExecutionResult (执行结果)
"""

import os
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Optional


class Architecture(Enum):
    """CPU 架构枚举"""
    ARM = "arm"
    ARMEL = "armel"
    ARMHF = "armhf"
    ARM64 = "aarch64"
    MIPS = "mips"
    MIPSEL = "mipsel"
    X86 = "i386"
    X86_64 = "x86_64"


class DiskInterface(Enum):
    """磁盘接口类型"""
    IDE = "ide"
    SCSI = "scsi"
    VIRTIO = "virtio"
    SD = "sd"
    NONE = "none"


class MachineType(Enum):
    """QEMU 机器类型"""
    ARM_VERSATILEPB = "versatilepb"
    ARM_VEXPRESS_A9 = "vexpress-a9"
    ARM_VEXPRESS_A15 = "vexpress-a15"
    MALTA = "malta"
    PC = "pc"
    VIRT = "virt"


@dataclass
class DiskImageSpec:
    """磁盘镜像规格"""
    size_gb: float = 2.0
    format: str = "qcow2"
    partition_table: str = "msdos"
    filesystem: str = "ext4"
    label: str = "rootfs"


@dataclass
class QEMUCommandTemplate:
    """QEMU 命令模板"""
    architecture: Architecture
    machine_type: MachineType
    cpu: str
    kernel_path: str
    drive_path: str
    initrd_path: Optional[str] = None
    interface: DiskInterface = DiskInterface.IDE
    memory: str = "256M"
    enable_graphic: bool = False
    network: bool = True
    kernel_params: Dict[str, str] = field(default_factory=dict)


@dataclass
class QEMUCommand:
    """QEMU 命令封装"""
    template: QEMUCommandTemplate
    full_command: str = ""

    def get_command_line(self) -> str:
        """生成完整的 QEMU 命令行"""
        if self.full_command:
            return self.full_command

        # 架构映射
        arch_to_qemu = {
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

        arch_value = self.template.architecture.value
        qemu_arch = arch_to_qemu.get(arch_value, arch_value)

        cmd_parts = ["qemu-system-" + qemu_arch]
        cmd_parts.append(f"-M {self.template.machine_type.value}")
        cmd_parts.append(f"-kernel {self.template.kernel_path}")

        if self.template.initrd_path:
            cmd_parts.append(f"-initrd {self.template.initrd_path}")

        # 磁盘接口
        interface = self.template.interface.value
        if interface != "none":
            if arch_value == "aarch64":
                cmd_parts.append(f"-drive file={self.template.drive_path},if=none,id=hd")
                cmd_parts.append("-device virtio-blk-pci,drive=hd")
            elif interface == "ide":
                cmd_parts.append(f"-hda {self.template.drive_path}")
            elif interface == "sd":
                cmd_parts.append(f"-drive if=sd,file={self.template.drive_path}")
            else:
                cmd_parts.append(f"-drive file={self.template.drive_path},if={interface}")

        # 内核参数
        append_parts = []
        for key, value in self.template.kernel_params.items():
            if value:
                append_parts.append(f"{key}={value}")
            else:
                append_parts.append(key)

        if append_parts:
            cmd_parts.append(f'-append "{" ".join(append_parts)}"')

        if not self.template.enable_graphic:
            cmd_parts.append("-nographic")

        if self.template.network:
            if arch_value == "aarch64":
                cmd_parts.append("-device virtio-net-pci,netdev=net")
                cmd_parts.append("-netdev tap,id=net,ifname=tap0,script=no,downscript=no")
            else:
                cmd_parts.append("-net nic")
                cmd_parts.append("-net tap,ifname=tap0")

        cmd_parts.append("-s")

        self.full_command = " ".join(cmd_parts)
        return self.full_command


@dataclass
class ExecutionResult:
    """QEMU 执行结果"""
    success: bool
    command: Optional[QEMUCommand] = None
    logs: str = ""
    rootfs_mounted: bool = False
    execution_time: float = 0.0
    error_message: str = ""


# ============================================================================
# 架构配置常量
# ============================================================================

ARCH_ALIASES = {
    "arm": "armel",
    "arm 32-bit eabi5": "armel",
    "arm 32-bit": "armel",
    "arm 32-bit (arm eabi5)": "armel",
    "arm eabi5": "armel",
    "armv5": "armel",
    "armv7": "armhf",
    "armv7l": "armhf",
    "armv8": "arm64",
    "arm64": "arm64",
    "aarch64": "arm64",
    "mips 32-bit": "mips",
    "mips big endian": "mips",
    "mips little endian": "mipsel",
    "mipseb": "mips",
}

KERNEL_CONFIG = {
    "armel": {
        "kernel": "zImage-2.6.29.6-versatile",
        "initrd": None,
        "base_url": "",
    },
    "armhf": {
        "kernel": "v3-armhf",
        "kernel_dir": "pre_compile",
        "initrd": None,
        "fallback_kernel": "zImage-2.6.39.4-vexpress",
        "fallback_initrd": None,
        "base_url": "",
    },
    "arm64": {
        "kernel": "vmlinuz-5.10.0-29-arm64",
        "initrd": "initrd.img-5.10.0-29-arm64",
        "base_url": "",
    },
    "mips": {
        # 使用 FirmCure 自编译的 Malta big-endian 内核。
        # 该产物会保持 Debian 风格的磁盘枚举（/dev/sdX），同时显式启用 nandsim/MTD。
        "kernel": "vmlinux-3.18.109-malta-be",
        "initrd": None,
        "base_url": "https://people.debian.org/~aurel32/qemu/mips/",
    },
    "mipsel": {
        # Malta little-endian 默认使用预编译 v2 内核，而不是旧的 3.18 产物。
        "kernel": "v2-mipsel",
        "kernel_dir": "pre_compile",
        "initrd": None,
        "base_url": "https://people.debian.org/~aurel32/qemu/mipsel/",
    },
    "x86_64": {
        # 使用本地编译的内核
        "kernel": "v3-x86_64",
        "initrd": None,
        "base_url": "",  # 本地编译，不下载
    },
    "i386": {
        "kernel": "v3-i386",
        "initrd": None,
        "base_url": "",  # 本地编译，不下载
    },
}

QEMU_PARAMS = {
    "armel": {
        "machine": "versatilepb",
        "interface": "ide",
        "root_device": "/dev/sda1",
        "console": "ttyAMA0",
        "filesystem": "ext4",
    },
    "armhf": {
        "machine": "vexpress-a9",
        "interface": "sd",
        "root_device": "/dev/mmcblk0p2",
        "console": "ttyAMA0",
        "filesystem": "ext4",
    },
    "arm64": {
        "machine": "virt",
        "interface": "virtio",
        "root_device": "/dev/vda1",
        "console": "ttyAMA0",
        "filesystem": "ext4",
        "cpu": "cortex-a57",
        "memory": "1G",
    },
    "mips": {
        "machine": "malta",
        "interface": "ide",
        "root_device": "/dev/hda1",
        "console": "ttyS0",
        "filesystem": "ext4",
    },
    "mipsel": {
        "machine": "malta",
        "interface": "ide",
        "root_device": "/dev/hda1",
        "console": "ttyS0",
        "filesystem": "ext4",
    },
    "x86_64": {
        "machine": "pc",
        "interface": "ide",
        "root_device": "/dev/sda1",
        "console": "ttyS0",
        "filesystem": "ext4",
        "cpu": "qemu64",
        "memory": "512M",
    },
    "i386": {
        "machine": "pc",
        "interface": "ide",
        "root_device": "/dev/sda1",
        "console": "ttyS0",
        "filesystem": "ext4",
        "cpu": "qemu32",
        "memory": "256M",
    },
}


def normalize_architecture(architecture: str) -> str:
    """标准化架构名称"""
    arch_lower = architecture.lower().strip()
    return ARCH_ALIASES.get(arch_lower, arch_lower)


def get_kernel_config(architecture: str) -> Optional[Dict]:
    """获取内核配置"""
    arch = normalize_architecture(architecture)
    return KERNEL_CONFIG.get(arch)


def get_qemu_params(architecture: str) -> Optional[Dict]:
    """获取 QEMU 参数配置"""
    arch = normalize_architecture(architecture)
    return QEMU_PARAMS.get(arch)


def is_supported_architecture(architecture: str) -> bool:
    """检查是否支持该架构"""
    arch = normalize_architecture(architecture)
    return arch in KERNEL_CONFIG
