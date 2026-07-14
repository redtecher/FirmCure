#!/usr/bin/env python3
"""
启动分析器 - 分析QEMU启动日志，检测挂载状态
"""

import re
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class BootStatus:
    success: bool
    rootfs_mounted: bool
    kernel_panic: bool
    error_patterns: List[str]


class BootAnalyzer:
    """分析QEMU启动日志"""

    SUCCESS_PATTERNS = [
        "VFS: Mounted root",
        "EXT4-fs",
        "SquashFS",
        "Welcome to",
        "login:",
        "Please press Enter",
        "/ #",
        "/ $",
    ]

    FAILURE_PATTERNS = [
        "Kernel panic",
        "not syncing",
        "No init found",
        "Unable to mount root",
    ]

    def __init__(self, log_file: Optional[Path] = None):
        self.log_file = log_file

    def analyze(self, log_content: str) -> BootStatus:
        success = False
        rootfs_mounted = False
        kernel_panic = False
        error_patterns = []

        for pattern in self.SUCCESS_PATTERNS:
            if pattern in log_content:
                success = True
                if "VFS: Mounted" in pattern or "EXT4-fs" in pattern or "SquashFS" in pattern:
                    rootfs_mounted = True

        for pattern in self.FAILURE_PATTERNS:
            if pattern in log_content:
                kernel_panic = True
                error_patterns.append(pattern)

        return BootStatus(
            success=success and not kernel_panic,
            rootfs_mounted=rootfs_mounted,
            kernel_panic=kernel_panic,
            error_patterns=error_patterns,
        )

    def extract_error_info(self, log_content: str) -> Dict:
        errors = {}

        kernel_panic_match = re.search(r"Kernel panic - (.+)", log_content)
        if kernel_panic_match:
            errors["kernel_panic"] = kernel_panic_match.group(1)

        mount_error_match = re.search(r"(?:Unable to|Failed to) mount (.+)", log_content)
        if mount_error_match:
            errors["mount_error"] = mount_error_match.group(1)

        init_error_match = re.search(r"(?:No init found|init not found)", log_content)
        if init_error_match:
            errors["init_error"] = True

        return errors

    def suggest_fixes(self, boot_status: BootStatus) -> List[str]:
        suggestions = []

        if boot_status.kernel_panic:
            suggestions.append("检测到内核崩溃，尝试调整内核参数")
            suggestions.append("检查 root= 参数是否正确指向设备节点")

        if not boot_status.rootfs_mounted:
            suggestions.append("rootfs 未成功挂载")
            suggestions.append("检查磁盘镜像格式 (ext4)")
            suggestions.append("验证 root_device 参数 (如 /dev/sda1)")

        if "No init found" in boot_status.error_patterns:
            suggestions.append("未找到 init 程序")
            suggestions.append("检查 rootfs 中 /bin/sh 是否存在")

        return suggestions

    def is_boot_successful(self, log_content: str) -> bool:
        status = self.analyze(log_content)
        return status.rootfs_mounted and not status.kernel_panic
