"""FirmCure 工具 — VM / 文件 / 网络 (CrewAI BaseTool 封装)

替代原 firmcure_mcp_server.py，所有工具直接作为 CrewAI tool 注册。
VmTool 直接使用 QemuShell（不再经过 relay socket）。
FileTool 和 NetworkTool 保持不变。
"""

import json
import os
import re
import socket
import shutil
import subprocess
import tempfile
from pathlib import Path

from crewai.tools import tool


# ════════════════════════════════════════════════════════════════
# Backend: VM 操作（直接使用 QemuShell，不经过 relay）
# ════════════════════════════════════════════════════════════════

class VmBackend:
    """VM 操作后端 — 直接持有 QemuShell 引用"""

    _FORBIDDEN = re.compile(
        r"(^|[\s;|&()])"
        r"(r2|radare2|gdb|gdb-multiarch|gdbserver|objdump|readelf|curl|wget)"
        r"(?=$|[\s;|&()])"
    )

    def __init__(self, shell=None, rootfs_path: str = ""):
        self.shell = shell
        self.rootfs_path = rootfs_path

    def _validate(self, command: str) -> str | None:
        if self._FORBIDDEN.search(command.strip().lower()):
            return (
                "禁止在 vm_exec 中执行逆向/调试工具或 HTTP 探测命令。"
                "请改用 radare2 工具(open_file/analyze 等)、"
                "GDB 工具(gdb_run_script/gdb_trace_crash 等)，"
                "网页连通性由外层验证器负责。"
            )
        return None

    def vm_exec(self, command: str, timeout: int = 30) -> str:
        blocked = self._validate(command)
        if blocked:
            return f"ERROR: {blocked}"
        if not self.shell:
            return "ERROR: QEMU shell not available (no relay)"
        return self.shell.execute_command(command, timeout=float(timeout), monitor=True) or ""

    def check_service_running(self, service_name: str = "httpd") -> str:
        if not self.shell:
            return json.dumps({"error": "QEMU shell not available"})
        ps_output = self.shell.execute_command("ps w 2>/dev/null", timeout=5.0, monitor=False) or ""
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
        port_output = self.shell.execute_command(
            "netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null",
            timeout=5.0, monitor=False,
        ) or ""
        port_open = ":80 " in port_output or "0.0.0.0:80" in port_output
        return json.dumps({
            "service_name": service_name,
            "process_running": process_running,
            "port_80_open": port_open,
            "ps_output": ps_output[:500],
        }, ensure_ascii=False)

    def get_httpd_logs(self, lines: int = 50) -> str:
        if not self.shell:
            return "ERROR: QEMU shell not available"
        log_paths = [
            "/var/log/httpd.log",
            "/var/log/messages",
            "/tmp/httpd.log",
            "/var/log/lighttpd/error.log",
        ]
        for log_path in log_paths:
            output = self.shell.execute_command(
                f"tail -n {lines} {log_path} 2>/dev/null",
                timeout=5.0, monitor=False,
            ) or ""
            if output and "No such file" not in output:
                return output
        return self.shell.execute_command(
            f"dmesg | tail -n {lines} 2>/dev/null",
            timeout=5.0, monitor=False,
        ) or ""


# ════════════════════════════════════════════════════════════════
# Backend: 文件操作（rootfs 文件系统读写、搜索、ELF 分析）
# ════════════════════════════════════════════════════════════════

class FileBackend:
    """rootfs 文件操作后端"""

    def __init__(self, rootfs_path: str = ""):
        self.rootfs_path = rootfs_path

    def _full(self, path: str) -> Path:
        return Path(self.rootfs_path) / path.lstrip("/")

    def read_file(self, path: str, encoding: str = "utf-8") -> str:
        full = self._full(path)
        if not full.exists():
            return f"ERROR: File not found: {path}"
        try:
            return full.read_text(encoding=encoding, errors='replace')[:10000]
        except Exception as e:
            return f"ERROR: {e}"

    def read_json(self, path: str) -> str:
        full = self._full(path)
        if not full.exists():
            return f"ERROR: File not found: {path}"
        try:
            content = json.loads(full.read_text(encoding='utf-8'))
            return json.dumps(content, ensure_ascii=False, indent=2)[:10000]
        except Exception as e:
            return f"ERROR: {e}"

    def write_file(self, path: str, content: str) -> str:
        full = self._full(path)
        full.parent.mkdir(parents=True, exist_ok=True)
        try:
            full.write_text(content, encoding='utf-8')
            return f"Written {len(content)} bytes to {path}"
        except Exception as e:
            return f"ERROR: {e}"

    def remove(self, path: str) -> str:
        full = self._full(path)
        if not full.exists() and not full.is_symlink():
            return f"ERROR: Not found: {path}"
        try:
            if full.is_symlink() or full.is_file():
                full.unlink()
            elif full.is_dir():
                shutil.rmtree(full)
            return f"Removed: {path}"
        except Exception as e:
            return f"ERROR: {e}"

    def mkdir(self, path: str) -> str:
        full = self._full(path)
        full.mkdir(parents=True, exist_ok=True)
        return f"Created: {path}"

    def copy_to_rootfs(self, src: str, dst: str) -> str:
        full_dst = self._full(dst)
        full_dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, str(full_dst))
            return f"Copied {src} -> {full_dst}"
        except Exception as e:
            return f"ERROR: {e}"

    def list_dir(self, path: str, recursive: bool = False) -> str:
        import glob as glob_mod
        full = self._full(path)
        if not full.exists():
            return f"ERROR: Directory not found: {path}"
        entries = []
        max_entries = 200
        try:
            if recursive:
                for p in sorted(full.rglob("*")):
                    prefix = "[D] " if p.is_dir() else "[F] "
                    entries.append(f"{prefix}{p.relative_to(full)}")
                    if len(entries) >= max_entries:
                        entries.append(f"... (truncated, {max_entries} entries max)")
                        break
            else:
                for p in sorted(full.iterdir()):
                    prefix = "[D] " if p.is_dir() else "[F] "
                    entries.append(f"{prefix}{p.name}")
                    if len(entries) >= max_entries:
                        break
        except Exception as e:
            return f"ERROR: {e}"
        return "\n".join(entries)

    def find_files(self, root: str, pattern: str, recursive: bool = True) -> str:
        import glob as glob_mod
        base = self.rootfs_path.rstrip("/")
        search_root = f"{base}/{root.lstrip('/')}"
        if recursive:
            matches = glob_mod.glob(f"{search_root}/**/{pattern}", recursive=True)
        else:
            matches = glob_mod.glob(f"{search_root}/{pattern}")
        rel_paths = [m[len(base):] for m in matches[:100]]
        return json.dumps({"files": rel_paths, "count": len(rel_paths)}, ensure_ascii=False)

    def file_exists(self, path: str) -> str:
        full = self._full(path)
        if full.exists():
            info = {
                "exists": True,
                "is_dir": full.is_dir(),
                "is_file": full.is_file(),
                "is_symlink": full.is_symlink(),
                "size": full.stat().st_size if full.is_file() else 0,
            }
            return json.dumps(info)
        return json.dumps({"exists": False})

    def file_stat(self, path: str) -> str:
        full = self._full(path)
        if not full.exists() and not full.is_symlink():
            return json.dumps({"exists": False})
        try:
            st = full.lstat()
            info = {
                "exists": True, "path": path,
                "is_file": full.is_file(), "is_dir": full.is_dir(),
                "is_symlink": full.is_symlink(),
                "size": st.st_size, "mode_oct": oct(st.st_mode),
                "permissions": oct(st.st_mode & 0o777),
                "uid": st.st_uid, "gid": st.st_gid, "mtime": st.st_mtime,
            }
            if full.is_symlink():
                try:
                    info["symlink_target"] = str(full.readlink())
                except Exception:
                    info["symlink_target"] = "(unreadable)"
            return json.dumps(info, ensure_ascii=False)
        except Exception as e:
            return f"ERROR: {e}"

    def elf_info(self, path: str) -> str:
        full = self._full(path)
        if not full.exists():
            return f"ERROR: File not found: {path}"
        try:
            result = subprocess.run(
                ["file", "-b", str(full)], capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
        except Exception as e:
            return f"ERROR: {e}"

    def readelf_deps(self, path: str) -> str:
        full = self._full(path)
        if not full.exists():
            return f"ERROR: File not found: {path}"
        try:
            result = subprocess.run(
                ["readelf", "-d", str(full)], capture_output=True, text=True, timeout=10
            )
            lines = [l.strip() for l in result.stdout.split("\n") if "NEEDED" in l]
            return "\n".join(lines) if lines else result.stdout.strip()
        except Exception as e:
            return f"ERROR: {e}"

    def check_kernel(self, kernel_path: str) -> str:
        try:
            result = subprocess.run(
                ["file", kernel_path], capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
        except Exception as e:
            return f"ERROR: {e}"

    def list_lib_base(self) -> str:
        try:
            from config import get_lib_base_dir
            lib_base = get_lib_base_dir()
            if not lib_base.exists():
                return "lib_base目录不存在"
            entries = sorted(str(p.relative_to(lib_base)) for p in lib_base.rglob("*") if p.is_file())
            return json.dumps(entries, ensure_ascii=False)
        except Exception as e:
            return f"ERROR: {e}"

    def list_precompiled_kernels(self, architecture: str) -> str:
        try:
            from core.kernel_manager import KernelManager
            km = KernelManager()
            result = km.list_available_kernels(architecture)
            if not result:
                return f"No kernels available for {architecture}"
            return json.dumps(result, ensure_ascii=False, indent=2)
        except Exception as e:
            return f"ERROR: {e}"


# ════════════════════════════════════════════════════════════════
# Backend: 网络操作（宿主机网络诊断）
# ════════════════════════════════════════════════════════════════

class NetworkBackend:
    """宿主机网络操作后端"""

    def ping(self, host: str, count: int = 3) -> str:
        try:
            result = subprocess.run(
                ["ping", "-c", str(count), "-W", "2", host],
                capture_output=True, text=True, timeout=count * 2 + 5,
            )
            return result.stdout + result.stderr
        except Exception as e:
            return f"ERROR: {e}"

    def scan_ports(self, host: str, ports: str) -> str:
        results = []
        for port_str in ports.split(","):
            try:
                port = int(port_str.strip())
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                result = s.connect_ex((host, port))
                s.close()
                results.append({"port": port, "open": result == 0})
            except Exception as e:
                results.append({"port": port_str.strip(), "error": str(e)})
        return json.dumps(results, ensure_ascii=False)

    def http_request(self, url: str, method: str = "GET", timeout: int = 10) -> str:
        try:
            cookie_jar = tempfile.mktemp(suffix=".cookies")
            cmd = [
                "curl", "-s", "-D", "-", "-L",
                "-c", cookie_jar, "-b", cookie_jar,
                "-m", str(timeout), "-X", method, url,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)

            raw = result.stdout or ""
            all_statuses = []
            for line in raw.split("\n"):
                line = line.strip()
                if line.startswith("HTTP/"):
                    parts = line.split()
                    if len(parts) >= 2:
                        all_statuses.append(parts[1])

            initial_status = int(all_statuses[0]) if all_statuses and all_statuses[0].isdigit() else 0
            final_status = int(all_statuses[-1]) if all_statuses and all_statuses[-1].isdigit() else 0

            if "\r\n\r\n" in raw:
                body = raw.rsplit("\r\n\r\n", 1)[-1]
            elif "\n\n" in raw:
                body = raw.rsplit("\n\n", 1)[-1]
            else:
                body = raw

            final_url = url
            try:
                probe = subprocess.run(
                    [
                        "curl", "-s", "-o", "/dev/null", "-L",
                        "-c", cookie_jar, "-b", cookie_jar,
                        "-w", "%{url_effective}",
                        "-m", str(timeout), "-X", method, url,
                    ],
                    capture_output=True, text=True, timeout=timeout + 5
                )
                final_url = probe.stdout.strip() or url
            except Exception:
                pass

            try:
                Path(cookie_jar).unlink(missing_ok=True)
            except Exception:
                pass

            return json.dumps({
                "url": url,
                "status_code": initial_status,
                "final_http_status": final_status,
                "all_http_statuses": all_statuses,
                "size": len(body),
                "final_url": final_url,
                "redirect_followed": len(all_statuses) > 1,
                "response_sample": body[:300] if body else "",
            }, ensure_ascii=False)
        except Exception as e:
            return f"ERROR: {e}"

    def http_get_body(self, url: str, timeout: int = 10) -> str:
        try:
            cookie_jar = tempfile.mktemp(suffix=".cookies")
            cmd = ["curl", "-s", "-L", "-c", cookie_jar, "-b", cookie_jar, "-m", str(timeout), url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            try:
                Path(cookie_jar).unlink(missing_ok=True)
            except Exception:
                pass
            return result.stdout[:5000]
        except Exception as e:
            return f"ERROR: {e}"


# ════════════════════════════════════════════════════════════════
# CrewAI 工具工厂
# ════════════════════════════════════════════════════════════════

def create_firmcure_tools(
    shell=None,
    rootfs_path: str = "",
    architecture: str = "",
    phase3_dir: str = "",
    **_kwargs,
) -> list:
    """创建所有 FirmCure CrewAI 工具（VM/文件/网络）。

    Args:
        shell: QemuShell 实例（Phase 3 需要传入，Phase 1/2 传 None）
        rootfs_path: 固件 rootfs 宿主机路径
        architecture: 目标架构
        phase3_dir: Phase3 输出目录

    Returns:
        CrewAI tool 对象列表。
    """
    vm = VmBackend(shell=shell, rootfs_path=rootfs_path)
    fb = FileBackend(rootfs_path=rootfs_path)
    nb = NetworkBackend()
    tools = []

    # ── VM 操作 ──

    @tool("vm_exec")
    def vm_exec(command: str, timeout: int = 30) -> str:
        """Execute a shell command inside the QEMU virtual machine (BusyBox environment).
        Args:
            command: Shell command to execute in the VM
            timeout: Timeout in seconds (default: 30)
        """
        return vm.vm_exec(command, timeout=timeout)

    tools.append(vm_exec)

    @tool("check_service_running")
    def check_service_running(service_name: str = "httpd") -> str:
        """Check if a service (default httpd) is running inside the QEMU VM. Checks both process and port status.
        Args:
            service_name: Service name to check (default: 'httpd')
        """
        return vm.check_service_running(service_name)

    tools.append(check_service_running)

    @tool("get_httpd_logs")
    def get_httpd_logs(lines: int = 50) -> str:
        """Get HTTPD service logs from the QEMU VM.
        Args:
            lines: Number of log lines to read (default: 50)
        """
        return vm.get_httpd_logs(lines)

    tools.append(get_httpd_logs)

    # ── HTTPD 启动工具（自动处理断点链） ──

    _start_httpd_ctx = {
        "shell": shell,
        "rootfs_path": rootfs_path,
        "architecture": architecture,
        "phase3_dir": Path(phase3_dir) if phase3_dir else None,
    }

    @tool("start_httpd")
    def start_httpd() -> str:
        """Start httpd service inside QEMU VM. Always kills existing processes first, then starts fresh.
        If gdb_break.gdb or gdb_chain.gdb exists in phase3_dir, executes it via gdb-multiarch before starting.

        IMPORTANT: Always use this tool to start httpd. Never use vm_exec('./httpd_start.sh &') directly.
        """
        import time as _time

        _shell = _start_httpd_ctx["shell"]
        _p3dir = _start_httpd_ctx["phase3_dir"]

        if not _shell:
            return json.dumps({"success": False, "error": "QEMU shell not available"})

        # 1. 查找 GDB 断点脚本（直接用，不解析）
        gdb_script = None
        if _p3dir:
            for name in ("gdb_break.gdb", "gdb_chain.gdb"):
                candidate = _p3dir / name
                if candidate.exists():
                    gdb_script = candidate
                    print(f"  [start_httpd] Found GDB script: {name}")
                    break

        # 2. 清理残留进程
        subprocess.run(["killall", "gdb-multiarch"], capture_output=True, timeout=3)
        _shell.execute_command(
            "killall httpd boa goahead lighttpd nginx 2>/dev/null",
            timeout=2.0, monitor=False
        )
        _time.sleep(1)

        # 3. 启动（与 validator.validate 同样的逻辑）
        gdb_proc = None
        if gdb_script:
            gdb_proc = subprocess.Popen(
                f"timeout 30 gdb-multiarch -batch -x {gdb_script}",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            print(f"  [start_httpd] GDB 启动 (PID={gdb_proc.pid})")
            _time.sleep(2)

        _shell.execute_command("./httpd_start.sh &", timeout=3.0, monitor=False)
        _time.sleep(3)

        # 清理 GDB
        gdb_output = ""
        if gdb_proc:
            try:
                gdb_proc.wait(timeout=15)
                gdb_output = gdb_proc.stdout.read() if gdb_proc.stdout else ""
            except subprocess.TimeoutExpired:
                gdb_proc.terminate()
            _time.sleep(2)

        # 4. 检查存活
        ps_out = _shell.execute_command("ps w 2>/dev/null", timeout=5.0, monitor=False) or ""
        alive = any(name in ps_out.lower() for name in ["httpd", "lighttpd", "boa", "goahead"])

        result = {
            "success": alive,
            "method": "gdb_script" if gdb_script else "direct_start",
            "process_alive": alive,
        }
        if gdb_output:
            result["gdb_output_sample"] = gdb_output[:500]
        print(f"  [start_httpd] Done, alive={alive}, method={result['method']}")
        return json.dumps(result, ensure_ascii=False)

    tools.append(start_httpd)

    # ── 文件操作 ──

    @tool("read_file")
    def read_file(path: str, encoding: str = "utf-8") -> str:
        """Read a file from the firmware rootfs. Returns file content as text.
        Args:
            path: File path relative to rootfs (e.g., '/etc/httpd.conf')
            encoding: Text encoding (default: 'utf-8')
        """
        return fb.read_file(path, encoding)

    tools.append(read_file)

    @tool("write_file")
    def write_file(path: str, content: str) -> str:
        """Write content to a file in the firmware rootfs. Creates parent directories if needed.
        Args:
            path: Target file path relative to rootfs
            content: Content to write
        """
        return fb.write_file(path, content)

    tools.append(write_file)

    @tool("remove")
    def remove(path: str) -> str:
        """Remove a file or directory from the firmware rootfs.
        Args:
            path: Path to remove
        """
        return fb.remove(path)

    tools.append(remove)

    @tool("mkdir")
    def mkdir(path: str) -> str:
        """Create a directory in the firmware rootfs (with parent directories).
        Args:
            path: Directory path to create
        """
        return fb.mkdir(path)

    tools.append(mkdir)

    @tool("copy_to_rootfs")
    def copy_to_rootfs(src: str, dst: str) -> str:
        """Copy a file from the host machine to the firmware rootfs.
        Args:
            src: Source file path on host (absolute path)
            dst: Destination path in rootfs
        """
        return fb.copy_to_rootfs(src, dst)

    tools.append(copy_to_rootfs)

    @tool("list_dir")
    def list_dir(path: str, recursive: bool = False) -> str:
        """List directory contents in the firmware rootfs.
        Args:
            path: Directory path
            recursive: Whether to list recursively (default: False)
        """
        return fb.list_dir(path, recursive)

    tools.append(list_dir)

    @tool("find_files")
    def find_files(root: str = "/", pattern: str = "*", recursive: bool = True) -> str:
        """Search for files in the firmware rootfs using glob pattern matching.
        Args:
            root: Search starting directory (default: '/')
            pattern: Glob pattern (e.g., '*.conf', 'httpd*', 'etc/**/*.sh')
            recursive: Whether to search recursively (default: True)
        """
        return fb.find_files(root, pattern, recursive)

    tools.append(find_files)

    @tool("file_exists")
    def file_exists(path: str) -> str:
        """Check if a file or directory exists in the firmware rootfs. Returns JSON with existence info.
        Args:
            path: File path to check
        """
        return fb.file_exists(path)

    tools.append(file_exists)

    @tool("file_stat")
    def file_stat(path: str) -> str:
        """Get detailed file metadata: permissions, size, uid/gid, mtime, symlink target.
        Args:
            path: File path
        """
        return fb.file_stat(path)

    tools.append(file_stat)

    @tool("read_json")
    def read_json(path: str) -> str:
        """Read and parse a JSON file from the firmware rootfs.
        Args:
            path: JSON file path
        """
        return fb.read_json(path)

    tools.append(read_json)

    @tool("elf_info")
    def elf_info(path: str) -> str:
        """Get ELF binary info (architecture, bits, endianness) using the 'file' command.
        Args:
            path: Binary file path in rootfs
        """
        return fb.elf_info(path)

    tools.append(elf_info)

    @tool("readelf_deps")
    def readelf_deps(path: str) -> str:
        """List shared library dependencies (NEEDED entries) of an ELF binary.
        Args:
            path: ELF file path in rootfs
        """
        return fb.readelf_deps(path)

    tools.append(readelf_deps)

    @tool("list_lib_base")
    def list_lib_base() -> str:
        """List available replacement library files in the lib_base resource directory."""
        return fb.list_lib_base()

    tools.append(list_lib_base)

    @tool("check_kernel")
    def check_kernel(kernel_path: str) -> str:
        """Check kernel architecture info using the 'file' command.
        Args:
            kernel_path: Kernel file path on host (absolute path)
        """
        return fb.check_kernel(kernel_path)

    tools.append(check_kernel)

    @tool("list_precompiled_kernels")
    def list_precompiled_kernels(architecture: str) -> str:
        """List all available precompiled kernels for a given architecture.
        Use this tool when you need to switch kernel version to fix 'Kernel too old' errors.
        Returns available kernel versions (v3, v4, v5) and their paths, plus DTB availability.
        Args:
            architecture: Target architecture (e.g. 'armhf', 'mipsel', 'mips', 'armel')
        """
        return fb.list_precompiled_kernels(architecture)

    tools.append(list_precompiled_kernels)

    # ── 网络操作 ──

    @tool("network_ping")
    def network_ping(host: str, count: int = 3) -> str:
        """Ping a host to check network connectivity.
        Args:
            host: Target host address
            count: Number of ping attempts (default: 3)
        """
        return nb.ping(host, count)

    tools.append(network_ping)

    @tool("network_scan_ports")
    def network_scan_ports(host: str, ports: str) -> str:
        """Scan specified ports on a host to check if they are open.
        Args:
            host: Target host address
            ports: Comma-separated port list (e.g., '80,443,8080')
        """
        return nb.scan_ports(host, ports)

    tools.append(network_scan_ports)

    @tool("http_request")
    def http_request(url: str, method: str = "GET", timeout: int = 10) -> str:
        """Send an HTTP request and return status code and response size. Used for validating web services.
        Args:
            url: Request URL (e.g., 'http://10.10.10.2/')
            method: HTTP method (default: 'GET')
            timeout: Timeout in seconds (default: 10)
        """
        return nb.http_request(url, method, timeout)

    tools.append(http_request)

    @tool("http_get_body")
    def http_get_body(url: str, timeout: int = 10) -> str:
        """Send HTTP GET request and return response body content. Used for checking page content.
        Args:
            url: Request URL (e.g., 'http://10.10.10.2/index.html')
            timeout: Timeout in seconds (default: 10)
        """
        return nb.http_get_body(url, timeout)

    tools.append(http_get_body)

    return tools
