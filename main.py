#!/usr/bin/env python3
"""
FirmCure - 基于CrewAI的固件自动化仿真框架
主入口点
"""

import sys
import os
import json
import logging
import argparse
import time
from pathlib import Path
from datetime import datetime


# 确保项目根目录在sys.path中
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))


class _Tee:
    """将 stdout/stderr 同时写入终端和日志文件"""

    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log_file = log_file

    def write(self, text):
        self._terminal.write(text)
        if text:
            self._log_file.write(text)
            self._log_file.flush()
        return len(text)

    def flush(self):
        self._terminal.flush()
        self._log_file.flush()

    def __getattr__(self, name):
        return getattr(self._terminal, name)


def _setup_tee(log_path: Path):
    """安装 stdout/stderr tee，所有输出同时写入日志文件"""
    log_file = open(log_path, "w", buffering=1, encoding="utf-8")
    sys.stdout = _Tee(sys.__stdout__, log_file)
    sys.stderr = _Tee(sys.__stderr__, log_file)


def _setup_tool_event_logger():
    """注册 CrewAI 事件监听，仅打印工具调用和工具结果。
    Agent verbose=False 隐藏 schema/prompt 噪音，通过事件总线只输出工具交互。
    """
    from crewai.events import crewai_event_bus
    from crewai.events.types.tool_usage_events import (
        ToolUsageStartedEvent,
        ToolUsageFinishedEvent,
    )

    @crewai_event_bus.on(ToolUsageStartedEvent)
    def _on_tool_start(source, event):
        agent = event.agent_role or "?"
        tool = event.tool_name
        args = event.tool_args
        # 精简参数显示
        if isinstance(args, dict):
            args_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
        else:
            args_str = str(args)
        if len(args_str) > 200:
            args_str = args_str[:200] + "..."
        print(f"  [{agent}] {tool}({args_str})")

    @crewai_event_bus.on(ToolUsageFinishedEvent)
    def _on_tool_finish(source, event):
        output = event.output
        if output is None:
            return
        text = str(output)
        if len(text) > 500:
            text = text[:500] + "..."
        print(f"  → {text}")


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def banner():
    print(f"""
{Colors.HEADER}{Colors.BOLD}
███████╗██╗██████╗ ███╗   ███╗ ██████╗██╗   ██╗██████╗ ███████╗
██╔════╝██║██╔══██╗████╗ ████║██╔════╝██║   ██║██╔══██╗██╔════╝
█████╗  ██║██████╔╝██╔████╔██║██║     ██║   ██║██████╔╝█████╗
██╔══╝  ██║██╔══██╗██║╚██╔╝██║██║     ██║   ██║██╔══██╗██╔══╝
██║     ██║██║  ██║██║ ╚═╝ ██║╚██████╗╚██████╔╝██║  ██║███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
{Colors.ENDC}
  {Colors.OKCYAN}CrewAI-Powered 固件仿真与漏洞分析平台{Colors.ENDC}
  {Colors.OKBLUE}Phase1 分析 → Phase2 仿真 → Phase3 干预{Colors.ENDC}
""")


def print_phase(phase: str, title: str):
    print(f"\n{'=' * 70}")
    print(f"{Colors.BOLD}  {phase}: {title}{Colors.ENDC}")
    print(f"{'=' * 70}\n")


def print_step(step: str, msg: str):
    print(f"  {Colors.OKCYAN}[{step}]{Colors.ENDC} {msg}")


def print_ok(msg: str):
    print(f"  {Colors.OKGREEN}[OK]{Colors.ENDC} {msg}")


def print_fail(msg: str):
    print(f"  {Colors.FAIL}[FAIL]{Colors.ENDC} {msg}")


def print_warn(msg: str):
    print(f"  {Colors.WARNING}[WARN]{Colors.ENDC} {msg}")


def main():
    parser = argparse.ArgumentParser(
        description="FirmCure - 基于CrewAI的固件自动化仿真框架",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 完整三阶段流程
  python -m FirmCure.main -i /path/to/rootfs

  # 从 Phase 2 开始（使用已有 Phase 1 结果）
  python -m FirmCure.main -i /path/to/rootfs --start 2 --case 005

  # 只运行 Phase 1 分析
  python -m FirmCure.main -i /path/to/rootfs --start 1 --end 1

  # 指定 case 编号
  python -m FirmCure.main -i /path/to/rootfs --case 010
""",
    )

    parser.add_argument(
        "-i", "--input",
        required=True,
        help="固件 rootfs 目录路径",
    )
    parser.add_argument(
        "--case",
        help="Case 编号 (如 005), 不指定则自动分配",
    )
    parser.add_argument(
        "--start",
        type=int,
        default=1,
        choices=[1, 2, 3],
        help="起始阶段 (默认: 1)",
    )
    parser.add_argument(
        "--end",
        type=int,
        default=3,
        choices=[1, 2, 3],
        help="结束阶段 (默认: 3)",
    )
    parser.add_argument(
        "--max-time-phase1",
        type=int,
        default=1000,
        help="Phase 1 最大探索时间，秒 (默认: 1000)",
    )
    parser.add_argument(
        "--timeout-phase2",
        type=int,
        default=180,
        help="Phase 2 QEMU 超时，秒 (默认: 180)",
    )
    parser.add_argument(
        "--timeout-phase3",
        type=int,
        default=600,
        help="Phase 3 干预超时，秒 (默认: 600)",
    )

    args = parser.parse_args()

    banner()

    rootfs = Path(args.input).resolve()
    if not rootfs.exists():
        print_fail(f"Rootfs 路径不存在: {args.input}")
        sys.exit(1)

    print_step("Input", f"Rootfs: {rootfs}")
    print_step("Input", f"起始阶段: Phase {args.start}")
    print_step("Input", f"结束阶段: Phase {args.end}")

    # ── Case 管理 ──
    from core.case_manager import CaseManager
    case_manager = CaseManager()

    if args.case:
        case_dir = case_manager.scratch_dir / args.case
        if not case_dir.exists():
            case_dir = case_manager.create_case_dir(args.case)
        case_number = args.case
    elif args.start > 1:
        print_fail(f"从 Phase {args.start} 开始时，请用 --case 指定 case 目录编号")
        sys.exit(1)
    else:
        case_number = case_manager.get_next_case_number()
        case_dir = case_manager.create_case_dir(case_number)

    print_step("Case", f"编号: {case_number}")
    print_step("Case", f"目录: {case_dir}")

    # ── 设置 case 目录（Memory/Knowledge 存储路径） ──
    from config import set_case_dir
    set_case_dir(str(case_dir))

    # ── 日志保存到 scratch/<case>/run.log ──
    log_path = case_dir / "run.log"
    _setup_tee(log_path)
    _setup_tool_event_logger()
    print_step("Log", f"日志文件: {log_path}")
    print()

    # ── 运行Flow ──
    from flow import FirmCureFlow, FirmCureState

    flow = FirmCureFlow()
    flow.state.rootfs_path = str(rootfs)
    flow.state.case_dir = str(case_dir)
    flow.state.case_number = case_number
    flow.state.max_time_phase1 = args.max_time_phase1
    flow.state.timeout_phase2 = args.timeout_phase2
    flow.state.timeout_phase3 = args.timeout_phase3
    flow.state.start_phase = args.start
    flow.state.end_phase = args.end

    try:
        result = flow.kickoff()
    except FileNotFoundError as e:
        print_fail(str(e))
        sys.exit(1)
    except Exception as e:
        print_fail(f"Flow执行失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # ── 结果汇总 ──
    print()
    print("=" * 70)
    print(f"{Colors.BOLD}  FirmCure 执行完毕{Colors.ENDC}")
    print("=" * 70)
    print(f"  Case 目录: {case_dir}")
    print(f"  Phase 1 分析: {case_dir / 'phase1'}")
    print(f"  Phase 2 仿真: {case_dir / 'phase2'}")
    print(f"  Phase 3 干预: {case_dir / 'phase3'}")

    if flow.state.phase1_result:
        arch = flow.state.phase1_result.get("architecture", {})
        if isinstance(arch, dict):
            print(f"  架构: {arch.get('arch', 'N/A')}")
        httpd = flow.state.phase1_result.get("httpd_service", {})
        if isinstance(httpd, dict):
            print(f"  HTTPD: {httpd.get('binary_path', 'N/A')}")

    if flow.state.phase3_result:
        success = flow.state.phase3_result.get("success", False)
        if success:
            print_ok("HTTPD 服务已成功运行!")
            print()

            # QEMU交互模式
            shell = flow.state.qemu_shell
            if shell and shell.proc and shell.proc.poll() is None:
                print_step("QEMU", f"进程 PID={shell.proc.pid}，进入交互模式")
                print("  输入命令发送到QEMU shell，输入 'exit' 退出")
                print("  示例: ps | grep httpd, netstat -tlnp, cat /etc/config/httpd")
                print()

                last_interrupt_at = 0.0
                while True:
                    try:
                        cmd = input("~ # ")
                        if not cmd.strip():
                            continue
                        if cmd.strip() == 'exit':
                            break
                        output = shell.execute_interactive_command(cmd, timeout=2.0)
                        if output:
                            for line in output.split("\n"):
                                if line.strip():
                                    print(f"  {line}")
                        print()
                    except EOFError:
                        break
                    except KeyboardInterrupt:
                        print()
                        now = time.time()
                        if now - last_interrupt_at <= 2.0:
                            break
                        last_interrupt_at = now
                        print_warn("再按一次 Ctrl+C 退出并关闭 QEMU，或输入 'exit'")
                        continue
                    except Exception as e:
                        print(f"  命令执行出错: {e}")

                # 退出时清理
                shell.stop()
                print_ok("QEMU 已关闭")
            else:
                print_warn("QEMU进程已结束，无法进入交互模式")
        else:
            print_fail("HTTPD 服务未能成功运行")

    print()


if __name__ == "__main__":
    main()
