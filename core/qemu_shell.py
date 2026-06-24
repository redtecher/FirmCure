#!/usr/bin/env python3
"""
QEMU Shell - PTY 交互式 QEMU 管理
"""

import os
import re
import pty
import subprocess
import time
from datetime import datetime
from pathlib import Path


class QemuShell:
    """QEMU Shell 交互类 - 使用 PTY 实现非阻塞交互"""

    def __init__(self):
        self.master_fd = None
        self.slave_fd = None
        self.proc = None
        self.log_file = None
        self.interaction_log = []
        self.qemu_binary = "qemu-system-mipsel"

    def start(self, kernel, rootfs, log_file, qemu_binary=None, phase2_dir=None):
        """启动 QEMU 并建立 PTY 连接

        优先从 phase2_dir/run_qemu.sh 读取最终调整过的 QEMU 命令，
        如果不存在则使用默认命令。
        """
        if qemu_binary:
            self.qemu_binary = qemu_binary

        if not Path(kernel).exists():
            print(f"[ERROR] 内核不存在: {kernel}")
            return False

        if not Path(rootfs).exists():
            print(f"[ERROR] rootfs 不存在: {rootfs}")
            return False

        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        self.log_file = open(log_file, "w")

        self.master_fd, self.slave_fd = pty.openpty()

        cmd = None

        # 从 run_qemu.sh 读取 Phase 2 最终调整过的命令
        if phase2_dir:
            run_sh = Path(phase2_dir) / "run_qemu.sh"
            if run_sh.exists():
                try:
                    content = run_sh.read_text()
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#') and 'qemu-system-' in line:
                            import shlex
                            cmd = shlex.split(line)
                            print(f"[*] 从 run_qemu.sh 读取最终 QEMU 命令")
                            break
                except Exception as e:
                    print(f"[!] 读取 run_qemu.sh 失败: {e}")

        if not cmd:
            cmd = [
                self.qemu_binary,
                "-M", "malta",
                "-m", "256M",
                "-kernel", kernel,
                "-hda", str(rootfs),
                "-append", "root=/dev/hda1 console=ttyS0 init=/bin/sh rootfstype=ext4 rw nandsim.parts=64,64,64,64,64,64,64,64,64,64",
                "-nographic",
                "-net", "nic",
                "-net", "tap,ifname=tap0",
                "-s",
            ]

        print(f"\n[*] QEMU 命令:")
        print(f"    {' '.join(cmd)}")
        print()

        self.proc = subprocess.Popen(
            cmd,
            stdin=self.slave_fd,
            stdout=self.slave_fd,
            stderr=self.slave_fd,
            start_new_session=True
        )

        os.close(self.slave_fd)

        self._log("SYSTEM", f"QEMU 已启动, PID: {self.proc.pid}")
        print(f"[+] QEMU 已启动, PID: {self.proc.pid}")
        return True

    def _log(self, source, message):
        """记录交互日志"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        entry = f"[{timestamp}] [{source}] {message}"
        self.interaction_log.append(entry)
        print(f"  {entry}")

    def wait_for_prompt(self, timeout=30):
        """等待 shell 提示符"""
        self._log("QEMU", "等待 shell 提示符...")
        start = time.time()
        enter_sent = False

        while time.time() - start < timeout:
            if self.proc and self.proc.poll() is not None:
                exit_code = self.proc.returncode
                self._log("ERROR", f"QEMU 已退出，返回码: {exit_code}")
                try:
                    os.set_blocking(self.master_fd, False)
                    while True:
                        data = os.read(self.master_fd, 4096)
                        if not data:
                            break
                        text = data.decode(errors='replace')
                        self.log_file.write(text)
                        self.log_file.flush()
                except Exception:
                    pass
                return False

            try:
                os.set_blocking(self.master_fd, False)
                data = os.read(self.master_fd, 4096)
                if data:
                    text = data.decode(errors='replace')
                    self.log_file.write(text)
                    self.log_file.flush()
                    if re.search(r'[#$]\s', text) or "/ $" in text or text.rstrip().endswith("$") or text.rstrip().endswith("#"):
                        self._log("QEMU", "找到 shell 提示符")
                        time.sleep(0.3)
                        try:
                            os.write(self.master_fd, b"stty -echo tab0\n")
                            time.sleep(0.3)
                            os.read(self.master_fd, 4096)  # drain response
                        except Exception:
                            pass
                        return True
                elif not enter_sent and time.time() - start > 5:
                    # 启动后无数据输出，发Enter触发提示符
                    self._log("QEMU", "发送Enter触发提示符...")
                    try:
                        os.write(self.master_fd, b"\n")
                    except Exception:
                        pass
                    enter_sent = True
            except BlockingIOError:
                if not enter_sent and time.time() - start > 5:
                    self._log("QEMU", "发送Enter触发提示符...")
                    try:
                        os.write(self.master_fd, b"\n")
                    except Exception:
                        pass
                    enter_sent = True
            except Exception as e:
                if self.proc and self.proc.poll() is not None:
                    self._log("ERROR", f"QEMU 已退出，返回码: {self.proc.returncode}")
                    return False
                self._log("ERROR", f"读取失败: {e}")

            time.sleep(0.5)

        self._log("ERROR", "等待超时")
        return False

    def execute_command(self, command, timeout=2.0, monitor=True):
        """执行命令并返回输出"""
        if not self.master_fd:
            return ""

        self._log("AGENT", f"执行命令: {command}")

        os.set_blocking(self.master_fd, True)
        os.write(self.master_fd, (command + "\n").encode())

        if monitor:
            return self._monitor_output(timeout)
        else:
            time.sleep(timeout)
            os.set_blocking(self.master_fd, False)
            output = b""

            while True:
                try:
                    chunk = os.read(self.master_fd, 4096)
                    if chunk:
                        output += chunk
                    else:
                        break
                except BlockingIOError:
                    break
                except Exception as e:
                    self._log("ERROR", f"读取失败: {e}")
                    break

            result = output.decode(errors='replace')
            self.log_file.write(result)
            self.log_file.flush()

            self._log("QEMU", f"输出:\n{result[:500]}")

            return result

    def _monitor_output(self, timeout):
        """实时输出监控"""
        start = time.time()
        output = b""

        while time.time() - start < timeout:
            try:
                os.set_blocking(self.master_fd, False)
                chunk = os.read(self.master_fd, 4096)
                if chunk:
                    output += chunk
                    self.log_file.write(chunk.decode(errors='replace'))
                    self.log_file.flush()
            except BlockingIOError:
                pass
            except Exception as e:
                self._log("ERROR", f"监控失败: {e}")
                break

            time.sleep(0.1)

        result = output.decode(errors='replace')
        self._log("QEMU", f"输出:\n{result[:500]}")

        return result

    @staticmethod
    def _clean_interactive_output(command: str, output: str) -> str:
        """清理交互模式输出，去掉命令回显和 shell 提示符。"""
        if not output:
            return ""
        cleaned = []
        command_stripped = command.strip()
        for raw_line in output.splitlines():
            line = raw_line.rstrip("\r")
            stripped = line.strip()
            if not stripped:
                continue
            if stripped == command_stripped:
                continue
            if stripped in ("~ #", "~ $", "/ #", "/ $"):
                continue
            cleaned.append(line)
        return "\n".join(cleaned).strip()

    def execute_interactive_command(self, command, timeout=10.0):
        """执行交互模式命令，不打印 [AGENT]/[QEMU] 包裹日志。"""
        if not self.master_fd:
            return ""

        os.set_blocking(self.master_fd, True)
        os.write(self.master_fd, (command + "\n").encode())
        time.sleep(timeout)
        os.set_blocking(self.master_fd, False)

        output = b""
        while True:
            try:
                chunk = os.read(self.master_fd, 4096)
                if chunk:
                    output += chunk
                else:
                    break
            except BlockingIOError:
                break
            except Exception:
                break

        result = output.decode(errors='replace')
        if self.log_file and result:
            self.log_file.write(result)
            self.log_file.flush()
        return self._clean_interactive_output(command, result)

    def get_interaction_log(self):
        """获取交互日志"""
        return self.interaction_log

    def interactive_mode(self):
        """进入交互模式 - Ctrl+C 第一次交互，第二次退出"""
        import sys
        if not self.master_fd:
            print("[!] QEMU 未启动")
            return

        self._log("SYSTEM", "进入交互模式 (Ctrl+C: 第一次交互, 第二次退出)")
        print("\n=== 进入 QEMU 交互模式 ===")
        print("提示: 按 Ctrl+C 第一次进入交互，再按一次退出。\n")

        ctrl_c_count = 0
        os.set_blocking(self.master_fd, False)

        try:
            while True:
                # 读取 QEMU 输出
                try:
                    chunk = os.read(self.master_fd, 4096)
                    if chunk:
                        text = chunk.decode(errors='replace')
                        sys.stdout.write(text)
                        sys.stdout.flush()
                        self.log_file.write(text)
                        self.log_file.flush()
                except BlockingIOError:
                    pass

                # 读取用户输入
                try:
                    import select
                    ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                    if ready:
                        user_input = sys.stdin.read(1)
                        if user_input:
                            os.write(self.master_fd, user_input.encode())
                            self.log_file.write(user_input)
                            self.log_file.flush()
                except Exception:
                    pass

                time.sleep(0.05)
        except KeyboardInterrupt:
            ctrl_c_count += 1
            if ctrl_c_count == 1:
                self._log("SYSTEM", "Ctrl+C 捕获 - 进入交互模式（再按一次退出）")
                print("\n[*] 已进入交互模式，按 Ctrl+C 再次退出...\n")
            elif ctrl_c_count >= 2:
                self._log("SYSTEM", "Ctrl+C 第二次 - 退出交互模式")
                print("\n[*] 退出交互模式\n")
                raise
        except Exception as e:
            self._log("ERROR", f"交互模式异常: {e}")

    def stop(self, preserve=False):
        """停止 QEMU

        Args:
            preserve: 如果为 True，保留 QEMU 进程和日志文件不关闭
        """
        if preserve:
            self._log("SYSTEM", "保留 QEMU 进程（成功完成，不自动清理）")
            if self.master_fd:
                try:
                    os.close(self.master_fd)
                    self.master_fd = None
                except Exception:
                    pass
            return

        if self.proc:
            self._log("SYSTEM", "停止 QEMU...")
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()

        if self.master_fd:
            try:
                os.close(self.master_fd)
            except Exception:
                pass

        if self.log_file:
            try:
                self.log_file.close()
            except Exception:
                pass

        self._log("SYSTEM", "QEMU 已停止")
