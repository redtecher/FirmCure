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

    # 启动成功的标志：shell 提示符或登录/console 激活提示。
    # 匹配时取累计日志的尾部做子串判断（pty 可能把提示符切分到多次读取），不再用整行精确匹配。
    SUCCESS_PATTERNS = [
        "/ #",
        "/ $",
        "~ #",
        "~ $",
        "login:",
        "Please press Enter to activate this console",
        "Welcome to",
    ]

    # 启动失败的标志：出现即立即终止，不再干等到超时。
    FAILURE_PATTERNS = [
        "Kernel panic",
        "not syncing",
        "Attempted to kill init",
        "No working init found",
        "No init found",
        "Unable to mount root",
        "can't load library",
        "error while loading shared libraries",
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
        logs = ""
        start_time = time.time()
        master_fd = None

        try:
            with open(log_file, 'w') as log_f:
                # 不要用 sudo 包装 qemu：tap0 已由 setup_network() 以 `-u $(whoami)` 创建
                # （属主为当前用户），/etc/qemu-ifup 也被替换为 no-op，qemu 可直接以普通用户
                # 身份 attach tap0，无需 root。
                # 此前 `sudo qemu` 会在 pty 子进程里因 tty_tickets 不延续而卡在密码提示，
                # 导致 qemu 根本没启动、qemu.log 几乎为空、启动检测永远不触发，最终干等 180s 超时。
                full_cmd = cmd

                # pty 同时作为 qemu 的 stdin/stdout/stderr：
                #   1) 强制行缓冲，能实时读到 kernel panic / shell 提示符并 flush 进 qemu.log；
                #   2) stdin 也接到 pty，向 master 写入 "\n" 才能真正送到 guest 串口触发提示符。
                master_fd, slave_fd = pty.openpty()

                process = subprocess.Popen(
                    full_cmd,
                    shell=True,
                    stdin=slave_fd,
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

                    # 实时检查启动结果：每读到一段就判一次，命中即排空残留输出并立即终止，
                    # 不再干等到超时。
                    if not success and self._match_success(logs[-300:]):
                        rootfs_mounted = True
                        print("[✓] 检测到 shell 提示符/登录提示，判定启动成功")
                        success = True
                        logs += self._drain_fd(master_fd, log_f)
                        self._terminate(process)
                        break

                    if not failure_detected:
                        for pattern in self.FAILURE_PATTERNS:
                            if pattern in text:
                                print(f"[!] 检测到失败标志: {pattern}")
                                success = False
                                failure_detected = True
                                break
                        if failure_detected:
                            logs += self._drain_fd(master_fd, log_f)
                            self._terminate(process)
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

    def _match_success(self, tail: str) -> bool:
        """判断日志尾部是否出现 shell 提示符或登录/console 激活提示。

        取累计日志的尾部做子串匹配，避免 pty 把提示符切分到多次读取时漏判。
        """
        return any(pattern in tail for pattern in self.SUCCESS_PATTERNS)

    def run_with_network(self, command: QEMUCommand, tap_name: str = "tap0") -> ExecutionResult:
        setup_network(tap_name)
        setup_qemu_ifup()

        try:
            result = self.execute(command)
        finally:
            restore_qemu_ifup()
            cleanup_network(tap_name)

        return result
