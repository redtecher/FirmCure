"""GDB 工具 - 基于 gdb-multiarch 的动态调试和崩溃分析 (CrewAI BaseTool 封装)"""

import os
import re
import json
import time
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

from crewai.tools import tool


class GdbBackend:
    """GDB 动态调试后端

    通过 gdb-multiarch subprocess + 临时 .gdb 脚本文件实现远程调试。
    直接与 QEMU shell 交互（启动/停止 httpd、检查进程状态），
    无需经过 MCP relay。
    """

    def __init__(self, shell=None, rootfs_path: str = "",
                 phase3_dir: Optional[Path] = None, architecture: str = ""):
        self.shell = shell
        self.rootfs_path = rootfs_path
        self.phase3_dir = phase3_dir
        self._arch = self._normalize_arch(architecture)

    @staticmethod
    def _normalize_arch(arch: str) -> str:
        if not arch:
            return "mips"
        a = arch.lower().strip()
        arch_map = {
            "mips": "mips", "mipseb": "mips", "mipsbe": "mips",
            "mipsel": "mips", "mipsle": "mips",
            "arm": "arm", "armhf": "arm", "armel": "arm",
            "armeb": "arm", "armv7": "arm", "armv7l": "arm",
            "aarch64": "aarch64", "arm64": "aarch64",
            "x86": "i386", "i386": "i386",
            "x86_64": "i386:x86-64", "x64": "i386:x86-64",
        }
        return arch_map.get(a, "mips")

    # ── PTY 输出清理 ─────────────────────────────────────────

    @staticmethod
    def _clean_pty_output(*outputs: str) -> str:
        combined = "\n".join(outputs)
        cleaned = []
        for line in combined.split("\n"):
            s = line.strip()
            if not s or s in ("~ #", "~ $"):
                continue
            if s.startswith("./httpd_start.sh") and "&" in s:
                continue
            if s.startswith("echo '===READ") or "===READ===" in s:
                continue
            if s.startswith("killall "):
                continue
            cleaned.append(line)
        return "\n".join(cleaned).strip()

    # ── QEMU 内 httpd 管理 ───────────────────────────────────

    def _check_httpd_alive(self) -> bool:
        ps_output = self.shell.execute_command("ps w 2>/dev/null", timeout=3.0, monitor=False)
        if not ps_output:
            return False
        httpd_names = ["httpd", "lighttpd", "boa", "goahead", "nginx"]
        for line in ps_output.split("\n"):
            line_lower = line.lower().strip()
            if not line_lower or line_lower.startswith("pid") or "grep" in line_lower or "ps w" in line_lower:
                continue
            if ".sh" in line_lower and ("/bin/sh" in line_lower or "{" in line):
                continue
            for name in httpd_names:
                if name in line_lower:
                    return True
        return False

    def _kill_httpd(self):
        self.shell.execute_command(
            "for n in httpd lighttpd boa goahead nginx; do "
            "  PID=$(ps w 2>/dev/null | grep $n | grep -v grep | awk '{print $1}'); "
            "  [ -n \"$PID\" ] && kill $PID 2>/dev/null; "
            "done",
            timeout=3.0, monitor=False
        )
        time.sleep(1)
        if self._check_httpd_alive():
            print("  [gdb_tool] httpd 进程未完全退出，使用 kill -9 强制终止")
            self.shell.execute_command(
                "for n in httpd lighttpd boa goahead nginx; do "
                "  PID=$(ps w 2>/dev/null | grep $n | grep -v grep | awk '{print $1}'); "
                "  [ -n \"$PID\" ] && kill -9 $PID 2>/dev/null; "
                "done",
                timeout=3.0, monitor=False
            )
            time.sleep(1)

    def _start_httpd_pty(self, start_cmd: str = "./httpd_start.sh",
                         wait: float = 3.0) -> str:
        self.shell.execute_command("echo '===CLEAR==='", timeout=2.0, monitor=False)
        raw_output = self.shell.execute_command(
            f"{start_cmd} &", timeout=3.0, monitor=False
        )
        time.sleep(wait)
        tail_output = self.shell.execute_command("echo '===READ==='", timeout=5.0, monitor=False)
        prev_output = tail_output
        for _ in range(3):
            time.sleep(2)
            new_output = self.shell.execute_command("echo '===READ==='", timeout=5.0, monitor=False)
            if new_output == prev_output or not new_output:
                break
            prev_output = new_output
            tail_output = new_output
        return self._clean_pty_output(raw_output or "", tail_output or "")

    # ── 路径解析 ─────────────────────────────────────────────

    def _resolve_binary_path(self, binary_path: str) -> str:
        if not binary_path:
            return ""
        if os.path.isabs(binary_path) and os.path.exists(binary_path):
            return binary_path
        if self.rootfs_path:
            full = Path(self.rootfs_path) / binary_path.lstrip("/")
            if full.exists():
                return str(full)
        return binary_path

    # ── GDB 脚本管理 ─────────────────────────────────────────

    def _save_gdb_script(self, script_content: str, tool_name: str = "gdb", append: bool = False):
        if not self.phase3_dir:
            return
        from datetime import datetime
        gdb_file = self.phase3_dir / "gdb_tool_log.gdb"
        timestamp = datetime.now().strftime("%H:%M:%S")
        mode = 'a' if append else 'w'
        with open(gdb_file, mode) as f:
            f.write(f"\n# === {tool_name} @ {timestamp} ===\n")
            f.write(script_content)
            f.write("\n")

    def _save_confirmed_gdb_script(self, script_content: str, breakpoints: list,
                                    register_values: dict, append: bool = False):
        if not self.phase3_dir:
            return
        from datetime import datetime
        gdb_file = self.phase3_dir / "gdb_break.gdb"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if isinstance(breakpoints, str):
            if ',' in breakpoints:
                breakpoints = [bp.strip() for bp in breakpoints.split(',') if bp.strip()]
            elif '\n' in breakpoints:
                breakpoints = [bp.strip() for bp in breakpoints.split('\n') if bp.strip()]
            else:
                breakpoints = [breakpoints.strip()]

        valid_breakpoints = [bp.strip() for bp in breakpoints
                             if re.match(r'^0x[0-9a-fA-F]+$', bp.strip())]
        if not valid_breakpoints:
            return
        breakpoints = valid_breakpoints

        header_lines = [line for line in script_content.split('\n')
                        if line.strip().startswith(('set architecture', 'file ', 'target remote'))]

        if append and gdb_file.exists():
            existing_bps = set()
            existing_blocks = []
            with open(gdb_file, 'r') as f:
                content = f.read()
            for match in re.finditer(r'^\s*b\s+\*\s*(0x[0-9a-fA-F]+)', content, re.MULTILINE):
                existing_bps.add(match.group(1).lower())
            for line in content.split('\n'):
                stripped = line.strip()
                if stripped == "detach" or stripped.startswith("# === 增量追加"):
                    continue
                existing_blocks.append(line)
            while existing_blocks and not existing_blocks[-1].strip():
                existing_blocks.pop()

            new_bps = [bp for bp in breakpoints if bp.lower() not in existing_bps]
            if new_bps:
                with open(gdb_file, 'w') as f:
                    f.write('\n'.join(existing_blocks))
                    if existing_blocks and existing_blocks[-1].strip():
                        f.write('\n')
                    f.write(f"\n# === 增量追加 @ {timestamp} ===\n")
                    for bp in new_bps:
                        bp_regs = register_values.get(bp, {})
                        f.write(f"\nb *{bp}\nc\n")
                        if isinstance(bp_regs, dict) and bp_regs:
                            for reg, val in bp_regs.items():
                                f.write(f"set {reg}={val}\n")
                    f.write("\ndetach\n")
                print(f"  [gdb_break] 增量追加 {len(new_bps)} 个新断点到 gdb_break.gdb")
        else:
            with open(gdb_file, 'w') as f:
                f.write(f"# === 确认成功的 GDB 断点链 @ {timestamp} ===\n")
                f.write(f"# 成功绕过崩溃的断点: {', '.join(breakpoints)}\n#\n")
                for line in header_lines:
                    f.write(f"{line}\n")
                f.write("\n")
                for bp in breakpoints:
                    bp_regs = register_values.get(bp, {})
                    f.write(f"b *{bp}\nc\n")
                    if isinstance(bp_regs, dict) and bp_regs:
                        for reg, val in bp_regs.items():
                            f.write(f"set {reg}={val}\n")
                    f.write("\n")
                f.write("detach\n")
            print(f"  [gdb_break] 保存 {len(breakpoints)} 个成功断点到 gdb_break.gdb")

    # ── 核心分析方法 ──────────────────────────────────────────

    def gdb_get_backtrace(self, binary_path: str = "") -> dict:
        """获取调用栈和寄存器状态"""
        try:
            full_path = self._resolve_binary_path(binary_path)
            script = "\n".join([
                f"set architecture {self._arch}",
                f"file {full_path}" if full_path else "",
                "target remote :1234",
                "bt",
                "info registers",
            ])
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                f.write(script)
                script_path = f.name
            result = subprocess.run(
                f"gdb-multiarch -batch -x {script_path}",
                shell=True, capture_output=True, text=True, timeout=15
            )
            os.unlink(script_path)
            return {"success": True, "output": result.stdout + result.stderr}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def gdb_run_script(self, binary_path: str = "", breakpoints: list = None,
                       register_values: dict = None, commands: list = None) -> dict:
        """GDB 断点链脚本：设置断点 → 修改寄存器 → 继续执行

        完整流程：
        1. 清理残留 GDB/httpd
        2. 生成链式 GDB 脚本（先设所有断点，再依次 continue + 修改寄存器）
        3. 后台启动 GDB（等待断点命中）
        4. 在 QEMU 里启动 httpd（触发断点）
        5. 等 GDB 处理完
        6. 检查 httpd 存活/崩溃状态
        7. 如果成功，保存到 gdb_break.gdb
        """
        try:
            # 参数容错
            if isinstance(breakpoints, str):
                try:
                    parsed = json.loads(breakpoints)
                    breakpoints = parsed if isinstance(parsed, list) else [breakpoints]
                except (json.JSONDecodeError, ValueError):
                    breakpoints = [breakpoints]
            breakpoints = breakpoints or []

            if isinstance(register_values, str):
                try:
                    register_values = json.loads(register_values)
                except (json.JSONDecodeError, ValueError):
                    register_values = {}
            if not isinstance(register_values, dict):
                register_values = {}
            for addr in list(register_values.keys()):
                if isinstance(register_values[addr], str):
                    try:
                        register_values[addr] = json.loads(register_values[addr])
                    except (json.JSONDecodeError, ValueError):
                        register_values[addr] = {}

            if isinstance(commands, str):
                commands = [c.strip() for c in commands.split('\n') if c.strip()]
            commands = commands or []

            full_path = self._resolve_binary_path(binary_path)

            # 从 commands 中提取断点、寄存器修改
            other_commands = []
            for cmd in commands:
                stripped = cmd.strip()
                if re.match(r'^\s*set\s+\$', stripped, re.IGNORECASE):
                    m = re.match(r'set\s+(\$\w+)\s*=\s*(.+)', stripped, re.IGNORECASE)
                    if m and breakpoints:
                        last_bp = breakpoints[-1]
                        if last_bp not in register_values:
                            register_values[last_bp] = {}
                        register_values[last_bp][m.group(1)] = m.group(2).strip()
                elif re.match(r'^(?:b|break)\s+\*?\s*0x', stripped, re.IGNORECASE):
                    bp_match = re.match(r'^(?:b|break)\s+\*?\s*(0x[0-9a-fA-F]+)', stripped, re.IGNORECASE)
                    if bp_match:
                        bp_addr = bp_match.group(1)
                        breakpoints.append(bp_addr)
                        if bp_addr not in register_values:
                            register_values[bp_addr] = {}
                elif stripped in ('c', 'continue'):
                    pass
                else:
                    other_commands.append(cmd)

            # 1. 清理残留
            subprocess.run(["killall", "gdb-multiarch"], capture_output=True, timeout=3)
            self._kill_httpd()

            # 2. 生成 GDB 脚本
            script_lines = [
                f"set architecture {self._arch}",
                f"file {full_path}",
                "target remote :1234",
                "",
            ]
            for bp_addr in breakpoints:
                script_lines.append(f"b *{bp_addr}")
            script_lines.append("")
            for bp_addr in breakpoints:
                script_lines.append("c")
                bp_regs = register_values.get(bp_addr, {})
                if isinstance(bp_regs, dict) and bp_regs:
                    for reg, val in bp_regs.items():
                        script_lines.append(f"set {reg}={val}")
                script_lines.append("")
            if other_commands:
                script_lines.extend(other_commands)
                script_lines.append("")
            script_lines.append("detach")
            script_content = "\n".join(script_lines)
            self._save_gdb_script(script_content, "gdb_run_script")

            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                f.write(script_content)
                script_path = f.name

            # 3. 后台启动 GDB
            gdb_proc = subprocess.Popen(
                f"timeout 30 gdb-multiarch -batch -x {script_path}",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            print(f"  [gdb_run_script] GDB 后台启动, PID={gdb_proc.pid}")
            time.sleep(3)

            # 4. 启动 httpd
            httpd_output = self._start_httpd_pty(wait=5)
            print(f"  [gdb_run_script] httpd 已启动")

            # 5. 等 GDB 退出
            try:
                gdb_proc.wait(timeout=15)
                gdb_output = gdb_proc.stdout.read() if gdb_proc.stdout else ""
            except subprocess.TimeoutExpired:
                gdb_proc.terminate()
                try:
                    gdb_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    gdb_proc.kill()
                gdb_output = gdb_proc.stdout.read() if gdb_proc.stdout else ""
                gdb_output += "\n[GDB 超时终止]"

            os.unlink(script_path)

            # 6. 检查结果
            tail = self.shell.execute_command("echo '===READ==='", timeout=3.0, monitor=False)
            tail_clean = self._clean_pty_output(tail or "")
            if tail_clean:
                httpd_output = f"{httpd_output}\n{tail_clean}" if httpd_output else tail_clean

            httpd_alive = self._check_httpd_alive()
            crashed = any(kw in (httpd_output or "")
                          for kw in ["SIGSEGV", "SIGABRT", "Segmentation fault"])
            if isinstance(gdb_output, bytes):
                gdb_output = gdb_output.decode(errors='replace')

            bp_hits = [bp for bp in breakpoints if bp in gdb_output]
            gdb_ok = gdb_proc.returncode == 0 or "detach" in gdb_output

            print(f"  [gdb_run_script] GDB退出码={gdb_proc.returncode}, 命中断点={bp_hits}")
            print(f"  [gdb_run_script] httpd存活={httpd_alive}, 崩溃={crashed}")

            success = gdb_ok and httpd_alive and not crashed

            # 保存成功的断点链
            if success and breakpoints:
                gdb_break_file = self.phase3_dir / "gdb_break.gdb" if self.phase3_dir else None
                append_mode = gdb_break_file and gdb_break_file.exists()
                if append_mode:
                    existing_bps = set()
                    if gdb_break_file.exists():
                        with open(gdb_break_file, 'r') as f:
                            content = f.read()
                        for match in re.finditer(r'^\s*b\s+\*\s*(0x[0-9a-fA-F]+)', content, re.MULTILINE):
                            existing_bps.add(match.group(1).lower())
                    new_bps = [bp for bp in breakpoints if bp.lower() not in existing_bps]
                    confirmed_new_bps = [bp for bp in new_bps if bp in gdb_output]
                    if confirmed_new_bps:
                        confirmed_reg = {bp: register_values.get(bp, {}) for bp in confirmed_new_bps}
                        self._save_confirmed_gdb_script(script_content, confirmed_new_bps, confirmed_reg, append=True)
                else:
                    self._save_confirmed_gdb_script(script_content, breakpoints, register_values, append=False)

            return {
                "success": success,
                "gdb_output": gdb_output[-2000:],
                "breakpoints_hit": bp_hits,
                "httpd_alive": httpd_alive,
                "crashed": crashed,
                "httpd_output": httpd_output[:1000] if httpd_output else "",
                "gdb_exit_code": gdb_proc.returncode,
            }
        except subprocess.TimeoutExpired:
            subprocess.run(["killall", "gdb-multiarch"], capture_output=True, timeout=3)
            return {"success": False, "error": "GDB run_script timed out (30s)"}
        except Exception as e:
            subprocess.run(["killall", "gdb-multiarch"], capture_output=True, timeout=3)
            return {"success": False, "error": str(e)}

    def gdb_modify_register(self, binary_path: str = "", breakpoint_address: str = "",
                            register: str = "", value: str = "") -> dict:
        """在指定断点修改寄存器值（简化版 gdb_run_script）"""
        return self.gdb_run_script(
            binary_path=binary_path,
            breakpoints=[breakpoint_address],
            register_values={breakpoint_address: {register: value}}
        )

    def gdb_trace_crash_source(self, binary_path: str = "", run_command: str = "") -> dict:
        """动态捕获崩溃点并追溯根因

        在 GDB 中运行程序，捕获 SIGSEGV/SIGABRT 信号，
        返回崩溃地址、寄存器、调用栈，并通过 r2 静态分析找到所有外部函数调用点。
        """
        try:
            full_path = self._resolve_binary_path(binary_path)
            self._kill_httpd()

            start_cmd = run_command if run_command else "./httpd_start.sh"
            vm_log = self._start_httpd_pty(start_cmd=start_cmd, wait=3)
            print(f"  [gdb_trace_crash] httpd 已启动")

            crash_in_log = "SIGSEGV" in vm_log or "SIGABRT" in vm_log or "Segmentation" in vm_log
            if not crash_in_log:
                return {"success": False, "crash_found": False, "error": "No crash detected", "vm_log": vm_log}

            print(f"  [gdb_trace_crash] 检测到崩溃")

            gdb_batch_script = f"""
set architecture {self._arch}
file {full_path}
target remote :1234
set pagination off
set confirm off
echo \\n=== CRASH DETECTED ===\\n
info program
echo \\n=== PC ===\\n
p/x $pc
echo \\n=== REGISTERS ===\\n
info registers
echo \\n=== BACKTRACE ===\\n
bt 30
echo \\n=== DISASSEMBLY ===\\n
x/10i $pc
quit
"""
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                f.write(gdb_batch_script)
                gdb_script_path = f.name

            gdb_result = subprocess.run(
                f"timeout 15 gdb-multiarch -batch -n -x {gdb_script_path}",
                shell=True, capture_output=True, text=True, timeout=20
            )
            output = gdb_result.stdout + gdb_result.stderr
            os.unlink(gdb_script_path)

            # 解析崩溃信息
            crash_address = ""
            crash_function = ""
            registers = {}
            backtrace = ""

            program_match = re.search(r'Program stopped at (0x[0-9a-fA-F]+)', output)
            if program_match:
                crash_address = program_match.group(1)

            pc_match = re.search(r'\$\d+\s*=\s*(0x[0-9a-fA-F]+)', output)
            if pc_match and not crash_address:
                crash_address = pc_match.group(1)

            bt_first = re.search(r'#0\s+(0x[0-9a-fA-F]+)\s+in\s+(.+)', output)
            if bt_first:
                if not crash_address:
                    crash_address = bt_first.group(1)
                crash_function = bt_first.group(2).strip()

            bt_section = re.search(r'=== BACKTRACE ===\s*\n(.*?)(?:===|$)', output, re.DOTALL)
            if bt_section:
                backtrace = bt_section.group(1).strip()
            else:
                all_frames = re.findall(r'(#\d+\s+.+)', output)
                if all_frames:
                    backtrace = "\n".join(all_frames[:15])

            reg_section = re.search(r'=== REGISTERS ===\s*\n(.*?)(?:===|$)', output, re.DOTALL)
            reg_text = reg_section.group(1) if reg_section else output
            for reg_name in ['v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3',
                             't4', 't5', 't6', 't7', 't8', 't9',
                             's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
                             'sp', 'ra', 'pc', 'gp', 'fp']:
                reg_match = re.search(rf'\b{reg_name}\s+(0x[0-9a-fA-F]+)', reg_text, re.IGNORECASE)
                if reg_match:
                    registers[f'${reg_name}'] = reg_match.group(1)

            crash_found = ("CRASH DETECTED" in output or "SIGSEGV" in output) and crash_address != ""

            # 静态分析：找所有外部函数调用点
            external_call_sites = []
            try:
                imports_result = subprocess.run(
                    f"r2 -qj -c 'iij' {full_path}",
                    shell=True, capture_output=True, text=True, timeout=30
                )
                imports = []
                if imports_result.stdout.strip():
                    try:
                        imports = json.loads(imports_result.stdout.strip())
                    except json.JSONDecodeError:
                        pass

                r2_commands = ["aae", "aac"]
                for imp in imports:
                    sym_name = imp.get("name", "")
                    plt_addr = imp.get("plt", 0) or imp.get("offset", 0)
                    if not sym_name or not plt_addr:
                        continue
                    plt_hex = hex(plt_addr) if isinstance(plt_addr, int) else plt_addr
                    r2_commands.append(f"echo ===PLT:{plt_hex}:{sym_name}===")
                    r2_commands.append(f"axt @ {plt_hex}")

                batch_cmd = "; ".join(r2_commands)
                batch_result = subprocess.run(
                    ["r2", "-q", "-c", batch_cmd, full_path],
                    capture_output=True, text=True, timeout=30
                )

                current_symbol = None
                for line in batch_result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith("===PLT:"):
                        parts = line.split(":")
                        if len(parts) >= 3:
                            current_symbol = parts[2].rstrip("=")
                    elif current_symbol and line and ("[CALL]" in line or "[DATA]" in line):
                        parts = line.split()
                        if len(parts) >= 2:
                            external_call_sites.append({
                                "call_address": parts[1],
                                "target_function": current_symbol,
                                "containing_function": parts[0],
                                "instruction": " ".join(parts[2:]) if len(parts) > 2 else "",
                            })
            except Exception as e:
                print(f"  [gdb_trace_crash] 外部函数分析失败: {e}")

            root_cause_info = {
                "crash_address": crash_address,
                "external_call_sites": external_call_sites,
                "total_external_calls": len(external_call_sites),
                "note": "崩溃地址是无效地址，说明程序执行了外部函数调用但 GOT 未填充。",
                "bypass_recommendation": (
                    "对每个 external_call_sites 中的 call_address 设置 GDB 断点，"
                    "命中后修改 $v0=0 并跳过调用指令。"
                ),
            }

            return {
                "success": crash_found,
                "crash_found": crash_found,
                "crash_address": crash_address,
                "crash_function": crash_function,
                "registers": registers,
                "backtrace": backtrace,
                "gdb_output": output[-3000:],
                "vm_log": (vm_log or "")[:1000],
                "binary_path": full_path,
                "root_cause_info": root_cause_info,
            }
        except subprocess.TimeoutExpired:
            subprocess.run(["killall", "gdb-multiarch"], capture_output=True, timeout=3)
            return {"success": False, "error": "GDB trace timed out"}
        except Exception as e:
            subprocess.run(["killall", "gdb-multiarch"], capture_output=True, timeout=3)
            return {"success": False, "error": str(e)}

    def gdb_read_memory(self, address: str, size: int = 64, binary_path: str = "") -> dict:
        """读取指定地址的内存内容"""
        try:
            full_path = self._resolve_binary_path(binary_path)
            script = f"""
set architecture {self._arch}
file {full_path}
target remote :1234
x/{size}xb {address}
quit
"""
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                f.write(script)
                script_path = f.name
            result = subprocess.run(
                f"timeout 10 gdb-multiarch -batch -x {script_path}",
                shell=True, capture_output=True, text=True, timeout=15
            )
            os.unlink(script_path)
            output = result.stdout + result.stderr
            hex_values = re.findall(r'0x[0-9a-fA-F]+', output)
            return {"success": True, "memory_dump": output, "hex_values": hex_values, "address": address, "size": size}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def gdb_disassemble(self, address: str, count: int = 20, binary_path: str = "") -> dict:
        """通过 GDB 反汇编指定地址的指令"""
        try:
            full_path = self._resolve_binary_path(binary_path)
            script = f"""
set architecture {self._arch}
file {full_path}
target remote :1234
disassemble /r {address},{address}+{count*4}
quit
"""
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                f.write(script)
                script_path = f.name
            result = subprocess.run(
                f"timeout 10 gdb-multiarch -batch -x {script_path}",
                shell=True, capture_output=True, text=True, timeout=15
            )
            os.unlink(script_path)
            output = result.stdout + result.stderr
            instructions = [line.strip() for line in output.split('\n')
                            if re.match(r'^\s*0x[0-9a-fA-F]+', line)]
            return {"success": True, "disassembly": output, "instructions": instructions, "address": address, "count": len(instructions)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def gdb_get_symbols(self, binary_path: str = "") -> dict:
        """获取二进制文件的符号表"""
        try:
            full_path = self._resolve_binary_path(binary_path)
            script = f"""
set architecture {self._arch}
file {full_path}
info functions
info variables
quit
"""
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                f.write(script)
                script_path = f.name
            result = subprocess.run(
                f"timeout 10 gdb-multiarch -batch -x {script_path}",
                shell=True, capture_output=True, text=True, timeout=15
            )
            os.unlink(script_path)
            output = result.stdout + result.stderr
            functions = re.findall(r'(0x[0-9a-fA-F]+)\s+(\w+)', output)
            return {
                "success": True,
                "output": output,
                "functions": [{"address": addr, "name": name} for addr, name in functions],
                "binary_path": full_path
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


# ════════════════════════════════════════════════════════════════
# CrewAI 工具工厂
# ════════════════════════════════════════════════════════════════

_backends: list[GdbBackend] = []


def create_gdb_tools(shell=None, rootfs_path: str = "",
                     phase3_dir=None, architecture: str = "") -> list:
    """创建所有 GDB CrewAI 工具。

    Args:
        shell: QemuShell 实例，用于与 QEMU VM 交互
        rootfs_path: 宿主机 rootfs 路径
        phase3_dir: Phase3 输出目录（Path 或 str）
        architecture: 目标架构 (mipsel, armhf 等)

    Returns:
        CrewAI tool 对象列表。
    """
    p3_dir = Path(phase3_dir) if phase3_dir and not isinstance(phase3_dir, Path) else phase3_dir
    backend = GdbBackend(shell=shell, rootfs_path=rootfs_path,
                         phase3_dir=p3_dir, architecture=architecture)
    _backends.append(backend)
    tools = []

    # ── gdb_backtrace: 获取调用栈和寄存器 ──
    @tool("gdb_backtrace")
    def gdb_backtrace(binary_path: str = "") -> str:
        """Get the current backtrace (call stack) and register state from the running program in QEMU.
        Connects to QEMU's GDB stub at :1234. Use this when the program has crashed or is paused.
        Args:
            binary_path: Path to the binary on host (e.g., '/home/user/rootfs/bin/httpd')
        """
        result = backend.gdb_get_backtrace(binary_path)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(gdb_backtrace)

    # ── gdb_run_script: 断点链执行（核心工具）──
    @tool("gdb_run_script")
    def gdb_run_script(binary_path: str = "", breakpoints: str = "",
                       register_values: str = "", commands: str = "") -> str:
        """Execute a GDB breakpoint chain: set all breakpoints, then continue and modify registers at each.

        This is the PRIMARY GDB tool for crash bypass. It handles the full workflow:
        1. Kills residual GDB/httpd processes
        2. Sets all breakpoints at once
        3. Starts GDB in background (waits for breakpoints)
        4. Starts httpd in QEMU (triggers breakpoints)
        5. At each breakpoint hit, modifies specified registers
        6. Checks if httpd survived

        CRITICAL: Always pass ALL breakpoints (old chain + new) together, not just new ones.

        Args:
            binary_path: Path to the binary on host
            breakpoints: JSON array of hex addresses, e.g. '["0x408c14", "0x417f68"]'
            register_values: JSON object mapping addresses to register changes, e.g.
                '{"0x408c14": {"$v0": "1"}, "0x417f68": {"$v0": "0"}}'
            commands: Additional GDB commands (one per line), optional
        """
        bp_list = []
        if breakpoints:
            try:
                bp_list = json.loads(breakpoints) if isinstance(breakpoints, str) else breakpoints
            except json.JSONDecodeError:
                bp_list = [breakpoints]

        reg_dict = {}
        if register_values:
            try:
                reg_dict = json.loads(register_values) if isinstance(register_values, str) else register_values
            except json.JSONDecodeError:
                reg_dict = {}

        cmd_list = []
        if commands:
            cmd_list = [c.strip() for c in commands.split('\n') if c.strip()]

        result = backend.gdb_run_script(
            binary_path=binary_path,
            breakpoints=bp_list,
            register_values=reg_dict,
            commands=cmd_list,
        )
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(gdb_run_script)

    # ── gdb_modify_register: 简化版单断点修改 ──
    @tool("gdb_modify_register")
    def gdb_modify_register(binary_path: str = "", breakpoint_address: str = "",
                            register: str = "", value: str = "") -> str:
        """Set a single breakpoint and modify a register value when hit. Simplified version of gdb_run_script.
        Args:
            binary_path: Path to the binary on host
            breakpoint_address: Hex address for the breakpoint (e.g., '0x408c14')
            register: Register name (e.g., '$v0', '$a0', '$pc')
            value: Value to set (e.g., '1', '0x0')
        """
        result = backend.gdb_modify_register(binary_path, breakpoint_address, register, value)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(gdb_modify_register)

    # ── gdb_trace_crash: 崩溃根因分析 ──
    @tool("gdb_trace_crash")
    def gdb_trace_crash(binary_path: str = "", run_command: str = "") -> str:
        """Dynamically capture crash point and trace root cause.

        Starts httpd in QEMU, detects SIGSEGV/SIGABRT, captures PC/registers/backtrace,
        then uses radare2 to find ALL external function call sites (PLT xrefs).

        Returns crash address, registers, backtrace, and a list of external call sites
        with bypass recommendations.

        Use when: crash address is 0x80xxxxxx or 0x000000, or repeated debugging shows no progress.
        Args:
            binary_path: Path to the binary on host
            run_command: Optional startup command in VM (default: './httpd_start.sh')
        """
        result = backend.gdb_trace_crash_source(binary_path, run_command)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(gdb_trace_crash)

    # ── gdb_read_memory: 读取内存 ──
    @tool("gdb_read_memory")
    def gdb_read_memory(address: str, size: int = 64, binary_path: str = "") -> str:
        """Read memory at a specific address via GDB.
        Args:
            address: Hex address to read from (e.g., '0x400000')
            size: Number of bytes to read (default: 64)
            binary_path: Path to the binary on host
        """
        result = backend.gdb_read_memory(address, size, binary_path)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(gdb_read_memory)

    # ── gdb_disassemble: GDB 反汇编 ──
    @tool("gdb_disassemble")
    def gdb_disassemble(address: str, count: int = 20, binary_path: str = "") -> str:
        """Disassemble instructions at a given address via GDB (runtime disassembly from live memory).
        Args:
            address: Hex address to start disassembly (e.g., '0x40a1c0')
            count: Number of instructions (default: 20)
            binary_path: Path to the binary on host
        """
        result = backend.gdb_disassemble(address, count, binary_path)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(gdb_disassemble)

    # ── gdb_get_symbols: 获取符号表 ──
    @tool("gdb_get_symbols")
    def gdb_get_symbols(binary_path: str = "") -> str:
        """Get symbol table (functions and variables) from the binary via GDB.
        Args:
            binary_path: Path to the binary on host
        """
        result = backend.gdb_get_symbols(binary_path)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(gdb_get_symbols)

    return tools


def cleanup_all():
    _backends.clear()
