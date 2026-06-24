"""VM 操作工具 - 通过 Unix socket relay 与 QEMU VM 通信"""

import json
import re
import socket
from typing import Dict


class VmTool:
    """VM 操作工具类

    通过 Unix socket relay (QemuRelay) 与 QEMU VM 通信。
    不再直接持有 QemuShell 引用，改为 relay 转发。
    """

    def __init__(self, relay_socket: str, rootfs_path: str = ""):
        """初始化 VM 工具

        Args:
            relay_socket: QemuRelay Unix socket 路径
            rootfs_path: 宿主机上的 rootfs 目录路径
        """
        self.relay_socket = relay_socket
        self.rootfs_path = rootfs_path
        # VM 内禁止执行宿主机逆向/调试工具，必须走专用 MCP 工具。
        self._forbidden_tool_pattern = re.compile(
            r"(^|[\s;|&()])"
            r"(r2|radare2|gdb|gdb-multiarch|gdbserver|objdump|readelf)"
            r"(?=$|[\s;|&()])"
        )

    def _validate_vm_command(self, command: str) -> str | None:
        """阻止在 VM 内调用逆向/调试工具。

        这些工具要么不存在于 BusyBox VM 中，要么会把智能体带偏到错误执行环境。
        """
        lowered = command.strip().lower()
        if self._forbidden_tool_pattern.search(lowered):
            return (
                "禁止在 vm_exec 中执行逆向/调试工具命令。"
                "请改用 radare2 工具(open_file/analyze/disassemble_function/xrefs_to 等)"
                "或 GDB 工具(gdb_run_script/gdb_backtrace/gdb_trace_crash 等)。"
            )
        return None

    # ─── Relay 通信 ───

    def relay_call(self, command: str, timeout: float = 30.0, monitor: bool = True) -> str:
        """通过 Unix socket relay 执行 VM 命令"""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout + 10)
        sock.connect(self.relay_socket)
        request = json.dumps({
            "command": command,
            "timeout": int(timeout),
            "monitor": monitor,
        })
        sock.sendall(request.encode() + b"\n")

        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        sock.close()

        result = json.loads(data.decode().strip())
        if result.get("error"):
            return f"ERROR: {result['error']}"
        return result.get("output", "")

    # ─── VM 操作 ───

    def vm_exec(self, command: str, timeout: int = 30) -> str:
        """在QEMU虚拟机中执行shell命令。BusyBox环境，命令参数有限。

        Args:
            command: 要执行的shell命令
            timeout: 超时秒数，默认30
        """
        blocked_reason = self._validate_vm_command(command)
        if blocked_reason:
            return f"ERROR: {blocked_reason}"
        return self.relay_call(command, timeout=timeout)

    def check_service_running(self, service_name: str = "httpd") -> str:
        """检查服务是否正在运行（检查进程和端口）。

        Args:
            service_name: 服务名称，默认httpd
        """
        # 检查进程
        ps_output = self.relay_call("ps w 2>/dev/null", timeout=5)
        process_running = False
        httpd_names = ["httpd", "lighttpd", "boa", "goahead", "nginx"]
        for line in ps_output.split("\n"):
            line_lower = line.lower().strip()
            if not line_lower or line_lower.startswith("pid") or "grep" in line_lower:
                continue
            for name in httpd_names:
                if name in line_lower:
                    process_running = True
                    break

        # 检查端口
        port_output = self.relay_call(
            "netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null",
            timeout=5,
        )
        port_open = ":80 " in port_output or "0.0.0.0:80" in port_output

        return json.dumps({
            "service_name": service_name,
            "process_running": process_running,
            "port_80_open": port_open,
            "ps_output": ps_output[:500],
        }, ensure_ascii=False)

    def get_httpd_logs(self, lines: int = 50) -> str:
        """获取HTTPD服务的日志（从VM内读取）。

        Args:
            lines: 读取的行数，默认50
        """
        log_paths = [
            "/var/log/httpd.log",
            "/var/log/messages",
            "/tmp/httpd.log",
            "/var/log/lighttpd/error.log",
        ]
        for log_path in log_paths:
            output = self.relay_call(f"tail -n {lines} {log_path} 2>/dev/null", timeout=5)
            if output and "No such file" not in output:
                return output

        # 没有日志文件，返回最近的 dmesg
        return self.relay_call(f"dmesg | tail -n {lines} 2>/dev/null", timeout=5)
