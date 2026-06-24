"""验证器 - 非LLM驱动的服务状态验证"""

import os
import subprocess
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ValidationResult:
    """验证结果"""
    passed: bool
    network_reachable: bool
    port_open: bool
    http_status: str
    process_running: bool
    http_response: str
    logs: str
    details: Dict[str, Any]
    is_crash: bool = False
    crash_signal: str = ""
    is_hung: bool = False
    startup_log: str = ""


class ServiceValidator:
    """服务验证器 - 启动HTTPD → 检测状态 → 等待循环杀进程读日志"""

    def __init__(self, guest_ip: str = "10.10.10.2", httpd_port: int = 80,
                 phase3_dir: Optional[str] = None, rootfs_path: str = "",
                 httpd_binary: str = "/bin/httpd", architecture: str = "mips"):
        self.guest_ip = guest_ip
        self.httpd_port = httpd_port
        self.phase3_dir = Path(phase3_dir) if phase3_dir else None
        self.rootfs_path = rootfs_path
        self.httpd_binary = httpd_binary
        self.architecture = architecture
        self._startup_log = ""

    @staticmethod
    def _clean_pty_output(*outputs: str) -> str:
        """清理 PTY 输出：去掉命令回显、提示符、标记行"""
        combined = "\n".join(outputs)
        cleaned = []
        for line in combined.split("\n"):
            s = line.strip()
            if not s or s in ("~ #", "~ $"):
                continue
            if s.startswith("./httpd_start.sh") and "&" in s:
                continue
            if s.startswith("echo '===READ"):
                continue
            if "===READ===" in s:
                continue
            if s.startswith("killall "):
                continue
            cleaned.append(line)
        return "\n".join(cleaned).strip()

    def _detect_crash(self, log_text: str) -> tuple:
        """检测日志中的崩溃信号"""
        if not log_text:
            return False, ""
        crash_keywords = [
            ("SIGSEGV", "SIGSEGV"), ("Segmentation fault", "SIGSEGV"),
            ("segfault", "SIGSEGV"), ("SIGABRT", "SIGABRT"),
            ("Illegal instruction", "SIGILL"), ("core dumped", "CRASH"),
        ]
        log_lower = log_text.lower()
        for kw, sig in crash_keywords:
            if kw.lower() in log_lower:
                return True, sig
        return False, ""

    def _run_gdb_replay(self, gdb_script: Path, logs: list):
        """启动 GDB 回放断点链（后台运行）"""
        logs.append(f"[GDB回放] 检测到断点链脚本: {gdb_script}")
        try:
            proc = subprocess.Popen(
                f"timeout 30 gdb-multiarch -batch -x {gdb_script}",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            logs.append("[GDB回放] gdb-multiarch 已启动，等待断点设置...")
            time.sleep(2)
            return proc
        except Exception as e:
            logs.append(f"[GDB回放] 启动失败: {e}")
            return None

    def _kill_httpd_processes(self, shell):
        """杀掉 QEMU 内所有 httpd 相关进程。返回 PTY 输出"""
        out = shell.execute_command(
            "for n in httpd lighttpd boa goahead nginx; do "
            "  PID=$(ps w 2>/dev/null | grep $n | grep -v grep | awk '{print $1}'); "
            "  [ -n \"$PID\" ] && kill $PID 2>/dev/null; "
            "done",
            timeout=3.0, monitor=False
        )
        time.sleep(2)
        return out or ""

    def validate(self, shell=None, skip_restart=False) -> ValidationResult:
        """验证流程：启动HTTPD → 检测状态 → 等待循环则杀进程读日志

        Args:
            skip_restart: 如果为 True，跳过 kill+restart 步骤，直接检测当前状态。
                          适用于专家已经成功启动服务的场景。
        """
        logs = []
        is_crash = False
        crash_signal = ""
        is_hung = False
        startup_log = ""
        gdb_proc = None

        # === 0. GDB 回放断点链（如有） ===
        gdb_script = None
        phase3_path = Path(self.phase3_dir) if self.phase3_dir else None
        if phase3_path and not skip_restart:
            for name in ("gdb_break.gdb", "gdb_chain.gdb"):
                gdb_candidate = phase3_path / name
                if gdb_candidate.exists():
                    gdb_script = gdb_candidate
                    logs.append(f"[GDB回放] 找到断点链: {name}")
                    break

        # === 1. 启动 HTTPD（或跳过，直接检测） ===
        if skip_restart:
            logs.append("=== 跳过重启，直接检测当前服务状态 ===")
        else:
            logs.append("=== 启动 HTTPD ===")
        if shell and not skip_restart:
            # 宿主机: 清理残留 GDB 进程
            subprocess.run(["killall", "gdb-multiarch"], capture_output=True, timeout=3)
            # QEMU 内: 杀掉残留 httpd 进程
            shell.execute_command("killall httpd boa goahead lighttpd nginx 2>/dev/null", timeout=2.0, monitor=False)
            time.sleep(1)

            # 如果有 GDB 断点链，先启动 GDB 回放
            if gdb_script:
                gdb_proc = self._run_gdb_replay(gdb_script, logs)

            # 启动 httpd（不重定向到文件，让输出直接到 PTY，PTY 是行缓冲的）
            # execute_command 的返回值就包含 httpd 的输出
            raw_output = shell.execute_command(
                "./httpd_start.sh &",
                timeout=3.0, monitor=False
            )
            logs.append("执行: ./httpd_start.sh (后台，输出到PTY)")
            time.sleep(3)

            # 先排空 PTY 缓冲区中 httpd 已产生的输出，
            # 避免后续 echo 标记与 httpd 输出混在同一行
            import os as _os
            flushed = ""
            try:
                _os.set_blocking(shell.master_fd, False)
                while True:
                    try:
                        chunk = _os.read(shell.master_fd, 4096)
                        if chunk:
                            flushed += chunk.decode(errors='replace')
                        else:
                            break
                    except BlockingIOError:
                        break
            except Exception:
                pass
            if flushed:
                raw_output = (raw_output or "") + flushed
                # 同步写入 e2e_test.log
                if shell.log_file:
                    shell.log_file.write(flushed)
                    shell.log_file.flush()

            # raw_output 包含 httpd 的启动输出（init_core_dump、Welcome 等）
            # 再发一个命令把 PTY 缓冲区剩余也读出来
            tail_output = shell.execute_command("echo '===READ==='", timeout=5.0, monitor=False)

            # 合并两次输出，清理命令回显和提示符
            startup_log = self._clean_pty_output(raw_output or "", tail_output or "")
            self._startup_log = startup_log or ""
            logs.append(f"启动日志:\n{startup_log if startup_log else '(空)'}")

            # 崩溃检测
            is_crash, crash_signal = self._detect_crash(startup_log or "")
            if is_crash:
                logs.append(f"[崩溃检测] 检测到崩溃信号: {crash_signal}")

            # 清理 GDB 进程
            if gdb_proc:
                try:
                    gdb_proc.terminate()
                    gdb_proc.wait(timeout=3)
                except Exception:
                    gdb_proc.kill()
                logs.append("[GDB回放] 已清理 GDB 进程")

        # === 2. 检测状态 ===
        logs.append("\n=== 检测服务状态 ===")

        # 进程检测
        process_running = False
        if shell:
            ps_output = shell.execute_command("ps w 2>/dev/null", timeout=5.0, monitor=False)
            if ps_output:
                httpd_names = ["httpd", "lighttpd", "boa", "goahead", "nginx"]
                for line in ps_output.split("\n"):
                    line_lower = line.lower().strip()
                    if not line_lower or line_lower.startswith("pid") or "grep" in line_lower or "ps w" in line_lower:
                        continue
                    # 跳过 shell 脚本
                    if ".sh" in line_lower and ("/bin/sh" in line_lower or "{" in line):
                        continue
                    for name in httpd_names:
                        if name in line_lower:
                            process_running = True
                            break
                    if process_running:
                        break
        logs.append(f"进程: {'运行' if process_running else '未运行'}")

        # 网络
        network_reachable = False
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", self.guest_ip],
                capture_output=True, text=True, timeout=5
            )
            network_reachable = result.returncode == 0
        except Exception:
            pass
        logs.append(f"网络: {'可达' if network_reachable else '不可达'}")

        # 端口
        port_open = False
        try:
            result = subprocess.run(
                ["nc", "-z", "-w", "2", self.guest_ip, str(self.httpd_port)],
                capture_output=True, timeout=5
            )
            port_open = result.returncode == 0
        except Exception:
            pass
        logs.append(f"端口: {'开放' if port_open else '关闭'}")

        # === 3. 等待循环检测 ===
        # 进程在 + 端口不开 = 等待循环 → SIGTERM 杀进程 → 读PTY输出
        if process_running and not port_open and shell:
            is_hung = True
            logs.append("\n=== 等待循环检测 ===")
            logs.append("[!] 进程运行中但端口未开放 → 等待循环，杀进程读日志")

            # SIGTERM 先，让进程 flush 缓冲区；再 SIGKILL 兜底
            term_output = self._kill_httpd_processes(shell)
            logs.append("[!] 已杀掉等待循环进程")

            # 把 SIGTERM/SIGKILL 产生的输出追加到 startup_log
            if term_output and term_output.strip():
                term_clean = self._clean_pty_output(term_output)
                if term_clean:
                    startup_log = f"{startup_log}\n[进程被杀]\n{term_clean}" if startup_log else f"[等待循环 - 进程已杀]\n{term_clean}"

            logs.append(f"完整启动日志:\n{startup_log}")

        # HTTP 响应（使用 cookie jar 处理嵌入式 httpd 认证重定向）
        http_status = "000"
        http_response = ""
        all_statuses = []
        if port_open:
            import tempfile
            cookie_jar = tempfile.mktemp(suffix=".cookies")
            try:
                result = subprocess.run(
                    ["curl", "-s", "-D", "-", "-L", "-c", cookie_jar, "-b", cookie_jar,
                     "-m", "8", f"http://{self.guest_ip}:{self.httpd_port}/"],
                    capture_output=True, text=True, timeout=15
                )
                raw = result.stdout or ""
                # 提取所有 HTTP 状态码（-L 可能产生多次响应头）
                for line in raw.split("\n"):
                    line = line.strip()
                    if line.startswith("HTTP/"):
                        parts = line.split()
                        if len(parts) >= 2:
                            all_statuses.append(parts[1])

                # 最终状态码是最后一个
                http_status = all_statuses[-1] if all_statuses else "000"
                # 响应体是最后一个空行后的内容
                if "\r\n\r\n" in raw:
                    body = raw.rsplit("\r\n\r\n", 1)[-1]
                elif "\n\n" in raw:
                    body = raw.rsplit("\n\n", 1)[-1]
                else:
                    body = raw
                http_response = body[:500] if body else ""
            except Exception:
                pass
            finally:
                try:
                    os.unlink(cookie_jar)
                except Exception:
                    pass
            logs.append(f"HTTP: {http_status} (all: {all_statuses})")

            if http_response:
                logs.append(f"响应: {http_response[:200]}")

        # === 综合判定 ===
        # HTTP 状态码：只有跟随重定向后最终 20x 才算成功
        http_ok = http_status.startswith("2")
        # 如果跟随重定向后最终是 30x/40x/50x，都不算成功
        if http_status.startswith(("3", "4", "5")):
            http_ok = False
        passed = network_reachable and port_open and http_ok

        logs.append(f"\n结果: 网络={network_reachable} 端口={port_open} HTTP={http_status} 进程={'运行' if process_running else '无'} 等待循环={'是' if is_hung else '否'} → {'通过' if passed else '失败'}")

        return ValidationResult(
            passed=passed,
            network_reachable=network_reachable,
            port_open=port_open,
            http_status=http_status,
            process_running=process_running,
            http_response=http_response,
            logs="\n".join(logs),
            details={"guest_ip": self.guest_ip, "httpd_port": self.httpd_port},
            is_crash=is_crash if shell else False,
            crash_signal=crash_signal if shell else "",
            is_hung=is_hung,
            startup_log=startup_log,
        )
