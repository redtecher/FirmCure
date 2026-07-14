#!/usr/bin/env python3
"""
FirmCure MCP Server — 纯 MCP 接口层

所有业务逻辑委托给后端 tool 文件夹实现：
  - vm-tool/      → VM 操作（通过 relay 与 QEMU 通信）
  - file-tool/    → rootfs 文件读写、搜索、ELF 分析
  - network-tool/ → 网络诊断、HTTP 请求

逆向工具由 radare2-mcp 独立提供，GDB 工具由 mcp-gdb 独立提供。

环境变量配置：
  RELAY_SOCKET: QemuRelay Unix socket 路径（Phase 3 必需）
  ROOTFS_PATH:  rootfs 目录路径
  ARCHITECTURE: 目标架构 (mips/mipsel/armhf/armel)
  PHASE3_DIR:   Phase 3 日志目录
"""

import os
import sys
import json
from pathlib import Path

# 添加项目根目录到 Python 路径
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastmcp import FastMCP

# 动态加载后端模块（目录名含连字符，无法直接 import）
import importlib.util

def _load_backend(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_vm_mod = _load_backend("tools.vm-tool.tool", os.path.join(os.path.dirname(__file__), "vm-tool", "tool.py"))
VmTool = _vm_mod.VmTool

_file_mod = _load_backend("tools.file-tool.tool", os.path.join(os.path.dirname(__file__), "file-tool", "tool.py"))
FileTool = _file_mod.FileTool

_net_mod = _load_backend("tools.network-tool.tool", os.path.join(os.path.dirname(__file__), "network-tool", "tool.py"))
NetworkTool = _net_mod.NetworkTool

mcp = FastMCP("FirmCure Tools")

# ─── 从环境变量读取配置 ───
RELAY_SOCKET = os.environ.get("RELAY_SOCKET", "")
ROOTFS_PATH = os.environ.get("ROOTFS_PATH", "")
ARCHITECTURE = os.environ.get("ARCHITECTURE", "mips")
PHASE3_DIR = os.environ.get("PHASE3_DIR", "")

# ─── 初始化后端 ───
vm: VmTool | None = None
if RELAY_SOCKET:
    vm = VmTool(relay_socket=RELAY_SOCKET, rootfs_path=ROOTFS_PATH)

file: FileTool | None = None
if ROOTFS_PATH:
    file = FileTool(rootfs_path=ROOTFS_PATH)

net: NetworkTool | None = None
if ROOTFS_PATH:
    net = NetworkTool()


# ══════════════════════════════════════════════════════════════════
# VM 操作工具（委托 vm-tool 后端）
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
def vm_exec(command: str, timeout: int | None = None) -> str:
    """在QEMU虚拟机中执行shell命令。BusyBox环境，命令参数有限。

    Args:
        command: 要执行的shell命令
        timeout: 超时秒数，默认30
    """
    return vm.vm_exec(command, timeout=timeout or 30)


@mcp.tool()
def check_service_running(service_name: str | None = None) -> str:
    """检查服务是否正在运行（检查进程和端口）。

    Args:
        service_name: 服务名称，默认httpd
    """
    return vm.check_service_running(service_name or "httpd")


@mcp.tool()
def get_httpd_logs(lines: int | None = None) -> str:
    """获取HTTPD服务的日志（从VM内读取）。

    Args:
        lines: 读取的行数，默认50
    """
    return vm.get_httpd_logs(lines or 50)


# ══════════════════════════════════════════════════════════════════
# 文件操作工具（委托 file-tool 后端，默认操作 rootfs）
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
def read_file(path: str, encoding: str | None = None) -> str:
    """读取rootfs中的文件内容。

    Args:
        path: 文件路径，如 /etc/httpd.conf
        encoding: 编码格式，默认utf-8
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.read_file(path, encoding or "utf-8")


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """写入文件到rootfs。

    Args:
        path: 目标文件路径
        content: 要写入的内容
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.write_file(path, content)


@mcp.tool()
def remove(path: str) -> str:
    """删除rootfs中的文件或目录。

    Args:
        path: 要删除的文件路径
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.remove(path)


@mcp.tool()
def mkdir(path: str) -> str:
    """在rootfs中创建目录（含父目录）。

    Args:
        path: 要创建的目录路径
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.mkdir(path)


@mcp.tool()
def copy_to_rootfs(src: str, dst: str) -> str:
    """从主机复制文件到rootfs。

    Args:
        src: 源文件路径（主机绝对路径）
        dst: 目标路径（rootfs中）
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.copy_to_rootfs(src, dst)


@mcp.tool()
def list_dir(path: str, recursive: bool | None = None) -> str:
    """列出rootfs目录内容。

    Args:
        path: 目录路径
        recursive: 是否递归列出，默认False
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.list_dir(path, recursive or False)


@mcp.tool()
def find_files(root: str | None = None, pattern: str | None = None, recursive: bool | None = None) -> str:
    """在rootfs中搜索文件（glob模式匹配）。

    Args:
        root: 搜索起始目录，默认 /
        pattern: glob模式，如 *.conf, httpd*, etc/**/*.sh
        recursive: 是否递归搜索，默认True
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.find_files(root or "/", pattern or "*", recursive if recursive is not None else True)


@mcp.tool()
def file_exists(path: str) -> str:
    """检查rootfs中的文件或目录是否存在。

    Args:
        path: 文件路径
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.file_exists(path)


@mcp.tool()
def file_stat(path: str) -> str:
    """获取文件详细元信息：权限、大小、uid/gid、mtime、symlink目标等。

    Args:
        path: 文件路径
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.file_stat(path)


@mcp.tool()
def read_json(path: str) -> str:
    """读取rootfs中的JSON文件并返回解析后的内容。

    Args:
        path: JSON文件路径
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.read_json(path)


@mcp.tool()
def elf_info(path: str) -> str:
    """获取ELF二进制文件信息（架构、位数、字节序等）。

    Args:
        path: 二进制文件路径
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.elf_info(path)


@mcp.tool()
def readelf_deps(path: str) -> str:
    """查看ELF二进制的共享库依赖（NEEDED条目）。

    Args:
        path: ELF文件路径
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.readelf_deps(path)


@mcp.tool()
def list_lib_base() -> str:
    """列出lib_base中可用的替换库文件。"""
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.list_lib_base()


@mcp.tool()
def check_kernel(kernel_path: str) -> str:
    """检查内核架构信息。

    Args:
        kernel_path: 内核文件路径（主机绝对路径）
    """
    if not file:
        return "ERROR: ROOTFS_PATH not set"
    return file.check_kernel(kernel_path)


# ══════════════════════════════════════════════════════════════════
# 网络工具（委托 network-tool 后端）
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
def network_ping(host: str, count: int | None = None) -> str:
    """Ping主机检查网络连通性。

    Args:
        host: 目标主机地址
        count: Ping次数，默认3
    """
    return net.ping(host, count or 3)


@mcp.tool()
def network_scan_ports(host: str, ports: str) -> str:
    """扫描指定端口是否开放。

    Args:
        host: 目标主机地址
        ports: 端口号列表，逗号分隔，如 '80,443,8080'
    """
    return net.scan_ports(host, ports)


@mcp.tool()
def http_request(url: str, method: str | None = None, timeout: int | None = None) -> str:
    """发送HTTP请求，返回状态码和响应大小（用于验证Web服务）。

    Args:
        url: 请求URL，如 http://10.10.10.2/
        method: HTTP方法，默认GET
        timeout: 超时秒数，默认10
    """
    return net.http_request(url, method or "GET", timeout or 10)


@mcp.tool()
def http_get_body(url: str, timeout: int | None = None) -> str:
    """发送HTTP GET请求，返回响应体内容（用于检查页面内容）。

    Args:
        url: 请求URL，如 http://10.10.10.2/index.html
        timeout: 超时秒数，默认10
    """
    return net.http_get_body(url, timeout or 10)


if __name__ == "__main__":
    mcp.run()
