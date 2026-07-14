#!/usr/bin/env python3
"""
内核管理器 - 下载和管理 QEMU 内核文件
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple

from .qemu_config import (
    KERNEL_CONFIG,
    ARCH_ALIASES,
    normalize_architecture,
    is_supported_architecture,
)


# DTB 文件映射：某些架构+内核版本需要额外的设备树文件
DTB_MAP = {
    "armhf": "vexpress-v2p-ca9.dtb",
}

# 按架构列出所有可用的预编译内核（resources/pre_compile/kernels/{arch}/）
PRECOMPILE_KERNELS = {
    "armhf": {
        "v3": "v3-armhf",
        "v4": "v4-armhf",
        "v5": "v5-armhf",  # v5 通常不需要，当前无此文件
    },
    "armel": {
        "v3": "v3-armel",
        "v4": "v4-armel",
        "v5": "v5-armel",
    },
    "mipsel": {
        "v3": "v3-mipsel",
        "v4": "v4-mipsel",
        "v5": "v5-mipsel",
    },
    "mips": {
        "v3": "v3-mipseb",
        "v4": "v4-mipseb",
        "v5": "v5-mipseb",
    },
    "x86_64": {
        "v3": "v3-x86_64",
        "v4": "v4-x86_64",
        "v5": "v5-x86_64",
    },
    "i386": {
        "v3": "v3-i386",
        "v4": "v4-i386",
        "v5": "v5-i386",
    },
}


class KernelManager:
    """内核下载和管理"""

    def __init__(self, resource_dir: str = None, pre_compile_dir: str = None):
        if resource_dir is None:
            from config import get_kernels_dir
            resource_dir = str(get_kernels_dir())
        self.resource_dir = Path(resource_dir)

        if pre_compile_dir is None:
            from config import get_pre_compile_kernels_dir
            pre_compile_dir = str(get_pre_compile_kernels_dir())
        self.pre_compile_dir = Path(pre_compile_dir)

    def _get_kernel_dir_for_config(self, architecture: str, config: Dict) -> Path:
        """根据配置返回默认内核所在目录。"""
        if config.get("kernel_dir") == "pre_compile":
            return self.pre_compile_dir / architecture
        return self.resource_dir / architecture

    def find_kernel_and_initrd(self, architecture: str) -> Tuple[str, Optional[str]]:
        """
        查找或下载内核和 initrd 文件

        Returns:
            (kernel_path, initrd_path or None)
        """
        arch = normalize_architecture(architecture)

        if not is_supported_architecture(arch):
            supported = ", ".join(KERNEL_CONFIG.keys())
            raise ValueError(f"不支持的架构: {architecture}。支持的架构: {supported}")

        config = KERNEL_CONFIG[arch]

        # kernel_dir: "pre_compile" 表示使用预编译内核目录
        arch_dir = self._get_kernel_dir_for_config(arch, config)
        if config.get("kernel_dir") != "pre_compile":
            arch_dir.mkdir(parents=True, exist_ok=True)

        kernel_path = arch_dir / config["kernel"]
        initrd_path = None

        # 主内核
        if kernel_path.exists():
            print(f"[✓] 找到内核: {kernel_path}")
        else:
            # 尝试 fallback 内核（在 resource_dir 中查找）
            fallback = config.get("fallback_kernel")
            if fallback:
                fallback_dir = self.resource_dir / arch
                fallback_path = fallback_dir / fallback
                if fallback_path.exists():
                    print(f"[!] 主内核不存在，使用 fallback: {fallback_path}")
                    kernel_path = fallback_path
                else:
                    print(f"[!] 内核不存在: {kernel_path}")
                    print(f"[*] 从 Debian 官方源下载...")
                    self._download_file(arch_dir, config["kernel"], config["base_url"])
                    if kernel_path.exists():
                        print(f"[✓] 内核下载完成: {kernel_path}")
                    else:
                        raise FileNotFoundError(f"无法获取内核: {kernel_path}")
            else:
                print(f"[!] 内核不存在: {kernel_path}")
                print(f"[*] 从 Debian 官方源下载...")
                self._download_file(arch_dir, config["kernel"], config["base_url"])
                if kernel_path.exists():
                    print(f"[✓] 内核下载完成: {kernel_path}")
                else:
                    raise FileNotFoundError(f"无法获取内核: {kernel_path}")

        # initrd
        initrd_name = config.get("initrd")
        if not initrd_name:
            # 如果主内核用的是 fallback，也用对应的 fallback initrd
            if kernel_path.name == config.get("fallback_kernel"):
                initrd_name = config.get("fallback_initrd")
        if initrd_name:
            initrd_path = arch_dir / initrd_name
            if initrd_path.exists():
                print(f"[✓] 找到 initrd: {initrd_path}")
            else:
                base = config.get("base_url", "")
                if base:
                    print(f"[*] 下载 initrd...")
                    self._download_file(arch_dir, initrd_name, base)
                if not initrd_path.exists():
                    initrd_path = None

        return str(kernel_path), str(initrd_path) if initrd_path else None

    def find_kernel_by_version(self, architecture: str, version: str) -> Optional[str]:
        """
        根据版本号查找预编译内核

        Args:
            architecture: 标准化后的架构名（如 'armhf', 'mipsel'）
            version: 版本号（'v3', 'v4', 'v5'）

        Returns:
            内核文件的绝对路径，不存在返回 None
        """
        arch = normalize_architecture(architecture)
        arch_dir = self.pre_compile_dir / arch

        kernels = PRECOMPILE_KERNELS.get(arch, {})
        filename = kernels.get(version)
        if not filename:
            return None

        kernel_path = arch_dir / filename
        if kernel_path.exists():
            print(f"[✓] 找到 {version} 内核: {kernel_path}")
            return str(kernel_path.resolve())
        else:
            print(f"[!] {version} 内核不存在: {kernel_path}")
            return None

    def find_dtb(self, architecture: str) -> Optional[str]:
        """
        查找架构对应的 DTB（设备树）文件

        Returns:
            DTB 文件的绝对路径，不存在返回 None
        """
        arch = normalize_architecture(architecture)
        dtb_name = DTB_MAP.get(arch)
        if not dtb_name:
            return None

        dtb_path = self.pre_compile_dir / arch / dtb_name
        if dtb_path.exists():
            print(f"[✓] 找到 DTB: {dtb_path}")
            return str(dtb_path.resolve())
        return None

    def list_available_kernels(self, architecture: str) -> Dict:
        """
        列出指定架构所有可用的内核

        Returns:
            {"default": path, "v3": path, "v4": path, ...}
        """
        arch = normalize_architecture(architecture)
        result = {}

        # 默认内核（从 resource_dir 查找）
        config = KERNEL_CONFIG.get(arch, {})
        arch_dir = self._get_kernel_dir_for_config(arch, config)
        default_kernel = config.get("kernel", "")
        default_path = arch_dir / default_kernel
        if default_kernel and default_path.exists():
            result["default"] = str(default_path.resolve())

        # 版本化预编译内核（从 pre_compile_dir 查找）
        pre_arch_dir = self.pre_compile_dir / arch
        for ver, filename in PRECOMPILE_KERNELS.get(arch, {}).items():
            path = pre_arch_dir / filename
            if path.exists():
                result[ver] = str(path.resolve())

        # DTB
        dtb_path = self.find_dtb(arch)
        if dtb_path:
            result["dtb"] = dtb_path

        return result

    def check_kernel_exists(self, architecture: str) -> Dict:
        """检查内核文件是否存在"""
        arch = normalize_architecture(architecture)

        if not is_supported_architecture(arch):
            return {"error": f"不支持的架构: {architecture}"}

        config = KERNEL_CONFIG[arch]
        arch_dir = self._get_kernel_dir_for_config(arch, config)

        kernel_path = arch_dir / config["kernel"]
        initrd_path = arch_dir / config["initrd"] if config["initrd"] else None

        return {
            "architecture": arch,
            "kernel_exists": kernel_path.exists(),
            "kernel_path": str(kernel_path),
            "initrd_exists": initrd_path.exists() if initrd_path else None,
            "initrd_path": str(initrd_path) if initrd_path else None,
        }

    def download_kernel(self, architecture: str) -> Dict:
        """下载内核文件"""
        arch = normalize_architecture(architecture)

        if not is_supported_architecture(arch):
            return {"error": f"不支持的架构: {architecture}"}

        config = KERNEL_CONFIG[arch]
        if config.get("kernel_dir") == "pre_compile":
            return {"error": f"{arch} 默认内核使用预编译目录，不支持自动下载"}

        arch_dir = self._get_kernel_dir_for_config(arch, config)
        arch_dir.mkdir(parents=True, exist_ok=True)

        results = {"downloaded": [], "architecture": arch}

        # 下载内核
        kernel_path = arch_dir / config["kernel"]
        if not kernel_path.exists():
            try:
                self._download_file(arch_dir, config["kernel"], config["base_url"])
                results["downloaded"].append({"file": "kernel", "path": str(kernel_path)})
            except Exception as e:
                results["error"] = f"下载内核失败: {e}"
        else:
            results["kernel_exists"] = str(kernel_path)

        # 下载 initrd
        if config["initrd"]:
            initrd_path = arch_dir / config["initrd"]
            if not initrd_path.exists():
                try:
                    self._download_file(arch_dir, config["initrd"], config["base_url"])
                    results["downloaded"].append({"file": "initrd", "path": str(initrd_path)})
                except Exception as e:
                    results["initrd_error"] = str(e)
            else:
                results["initrd_exists"] = str(initrd_path)

        return results

    def _download_file(self, dest_dir: Path, filename: str, base_url: str):
        """下载单个文件"""
        url = base_url + filename
        dest = dest_dir / filename
        print(f"[*] 下载: {url}")

        result = subprocess.run(
            ["wget", "-q", "--show-progress", "-O", str(dest), url],
            timeout=120,
            capture_output=False
        )

        if result.returncode != 0:
            raise IOError(f"下载失败: {url}")
