"""
Core 模块 - Phase 2 核心功能
"""

from .qemu_config import (
    Architecture,
    MachineType,
    DiskInterface,
    DiskImageSpec,
    QEMUCommandTemplate,
    QEMUCommand,
    ExecutionResult,
    normalize_architecture,
    get_kernel_config,
    get_qemu_params,
    is_supported_architecture,
    ARCH_ALIASES,
    KERNEL_CONFIG,
    QEMU_PARAMS,
)

from .kernel_manager import KernelManager
from .disk_builder import DiskBuilder
from .qemu_launcher import QEMULauncher
from .qemu_command import QEMUCommandGenerator
from .qemu_shell import QemuShell
from .boot_analyzer import BootAnalyzer, BootStatus

from .network_setup import (
    setup_network,
    setup_qemu_ifup,
    restore_qemu_ifup,
    cleanup_network,
    run_sudo_command,
)

__all__ = [
    "Architecture",
    "MachineType",
    "DiskInterface",
    "DiskImageSpec",
    "QEMUCommandTemplate",
    "QEMUCommand",
    "ExecutionResult",
    "normalize_architecture",
    "get_kernel_config",
    "get_qemu_params",
    "is_supported_architecture",
    "ARCH_ALIASES",
    "KERNEL_CONFIG",
    "QEMU_PARAMS",
    "KernelManager",
    "DiskBuilder",
    "QEMULauncher",
    "QEMUCommandGenerator",
    "QemuShell",
    "BootAnalyzer",
    "BootStatus",
    "setup_network",
    "setup_qemu_ifup",
    "restore_qemu_ifup",
    "cleanup_network",
    "run_sudo_command",
]
