#!/usr/bin/env python3
"""
QEMU 启动器 - 启动QEMU并监控日志
"""

import os
import pty
import select
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from .qemu_config import ExecutionResult, QEMUCommand
from .network_setup import setup_network, setup_qemu_ifup, restore_qemu_ifup, cleanup_network


class QEMULauncher:
    """QEMU 启动和执行监控"""

    SUCCESS_PATTERNS = [
        "/ #",
        "/ $",
        "/ ~",
        "# ",
        "login:",
    ]

    FAILURE_PATTERNS = [
        "Kernel panic",
        "not syncing",
        "No init found",
        "can't load library",
    ]

    def __init__(self, timeout: int = 180, log_dir: Path = None, sudo_password: str = ""):
        self.timeout = timeout
        self.log_dir = log_dir or Path(".")
        self.sudo_password = sudo_password

    def execute(self, command: QEMUCommand) -> ExecutionResult:
        print(f"\n[*] 执行 QEMU...")
        print(f"    超时: {self.timeout}s")

        cmd = command.get_command_line()
        print(f"\n[命令]\n{cmd}\n")

        log_file = self.log_dir / "qemu.log"
        success = False
        rootfs_mounted = False
        failure_detected = False
        success_lines = 0
        logs = ""
        start_time = time.time()
        master_fd = None

        try:
            with open(log_file, 'w') as log_f:
                # 预认证 sudo，刷新时间戳
                if self.sudo_password:
                    try:
                        subprocess.run(
                            f"echo '{self.sudo_password}' | sudo -S -v",
                            shell=True, capture_output=True, timeout=5,
                        )
                    except Exception:
                        pass
                full_cmd = f"sudo {cmd}"

                # 使用 pty 代替 pipe，强制 QEMU 行缓冲
                # 解决 sudo 缓冲导致 launcher 读不到 kernel panic 等输出的问题
                master_fd, slave_fd = pty.openpty()

                process = subprocess.Popen(
                    full_cmd,
                    shell=True,
                    stdin=subprocess.PIPE,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    close_fds=True,
                    preexec_fn=os.setpgrp,
                )
                os.close(slave_fd)

                while True:
                    if process.poll() is not None:
                        logs += self._drain_fd(master_fd, log_f)
                        break

                    elapsed = time.time() - start_time
                    if elapsed > self.timeout:
                        print(f"[!] 超时 ({elapsed:.1f}s)，终止进程...")
                        self._terminate(process)
                        break

                    # select 检查是否有数据可读，超时 1 秒
                    try:
                        ready, _, _ = select.select([master_fd], [], [], 1.0)
                    except (ValueError, OSError):
                        break

                    if not ready:
                        # 启动后 8 秒无新数据，发送 Enter 触发 shell 提示符
                        if elapsed > 8 and not success and not failure_detected:
                            try:
                                os.write(master_fd, b"\n")
                            except OSError:
                                pass
                        continue

                    # 非阻塞读取
                    try:
                        data = os.read(master_fd, 4096)
                    except OSError:
                        break
                    if not data:
                        break

                    text = data.decode("utf-8", errors="replace")
                    logs += text
                    log_f.write(text)
                    log_f.flush()

                    # 逐行检查模式
                    for line in text.splitlines():
                        stripped = line.strip()
                        for pattern in self.SUCCESS_PATTERNS:
                            if stripped == pattern.strip():
                                print(f"[✓] 检测到 shell 提示符: {pattern}")
                                rootfs_mounted = True
                                success = True

                        if success:
                            success_lines += 1
                            if success_lines >= 1:
                                time.sleep(3)
                                logs += self._drain_fd(master_fd, log_f)
                                self._terminate(process)
                                break

                        for pattern in self.FAILURE_PATTERNS:
                            if pattern in line:
                                print(f"[!] 检测到: {pattern}")
                                success = False
                                failure_detected = True

                        if failure_detected:
                            self._terminate(process)
                            break

                    if (success and success_lines >= 1) or failure_detected:
                        break

                self._terminate(process)

        except Exception as e:
            print(f"[!] 执行错误: {e}")
            logs += f"\n[ERROR] {e}"
        finally:
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except OSError:
                    pass

        execution_time = time.time() - start_time

        print(f"\n[结果]")
        print(f"    成功: {success}")
        print(f"    Rootfs 挂载: {rootfs_mounted}")
        print(f"    执行时间: {execution_time:.2f}s")
        print(f"    日志: {log_file}")

        return ExecutionResult(
            success=success,
            command=command,
            logs=logs,
            rootfs_mounted=rootfs_mounted,
            execution_time=execution_time,
        )

    @staticmethod
    def _terminate(process, timeout=5):
        """安全终止进程及其整个进程组"""
        if process.poll() is not None:
            return
        try:
            # 先尝试杀死整个进程组（shell + sudo + qemu）
            pgid = os.getpgid(process.pid)
            os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                pgid = os.getpgid(process.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                process.kill()
            try:
                process.wait(timeout=3)
            except Exception:
                pass

    @staticmethod
    def _drain_fd(fd, log_f) -> str:
        """读取 fd 中残留数据，返回新增的日志文本"""
        new_text = ""
        try:
            os.set_blocking(fd, False)
            while True:
                try:
                    data = os.read(fd, 4096)
                    if not data:
                        break
                    text = data.decode("utf-8", errors="replace")
                    new_text += text
                    log_f.write(text)
                except BlockingIOError:
                    break
            log_f.flush()
        except (BlockingIOError, OSError):
            pass
        return new_text

    def run_with_network(self, command: QEMUCommand, tap_name: str = "tap0") -> ExecutionResult:
        setup_network(tap_name)
        setup_qemu_ifup()

        try:
            result = self.execute(command)
        finally:
            restore_qemu_ifup()
            cleanup_network(tap_name)

        return result
