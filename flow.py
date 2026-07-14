"""
FirmCure Flow - 基于CrewAI Flow的三阶段流水线编排

Phase 1 (分析) -> Phase 2 (仿真) -> Phase 3 (干预)
"""

import os
import json
import time
import logging
import subprocess
import importlib.util
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel
from crewai.flow.flow import Flow, start, listen

logger = logging.getLogger(__name__)


def _import_tool_module(tool_dir: str):
    """从 tools/<tool_dir>/tool.py 导入模块（支持带连字符的目录名）"""
    base = os.path.dirname(os.path.abspath(__file__))
    tool_path = os.path.join(base, "tools", tool_dir, "tool.py")
    mod_name = tool_dir.replace("-", "_")
    spec = importlib.util.spec_from_file_location(mod_name, tool_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FirmCureState(BaseModel):
    """Flow状态"""
    rootfs_path: str = ""
    case_dir: str = ""
    case_number: str = ""
    phase1_result: Optional[Dict[str, Any]] = None
    phase2_result: Optional[Dict[str, Any]] = None
    phase3_result: Optional[Dict[str, Any]] = None
    max_time_phase1: int = 1000
    timeout_phase2: int = 180
    timeout_phase3: int = 600
    start_phase: int = 1
    end_phase: int = 3
    qemu_shell: Any = None  # 成功时保留的QEMU shell引用

    # 时间记录
    phase1_start_time: Optional[float] = None
    phase1_end_time: Optional[float] = None
    phase2_start_time: Optional[float] = None
    phase2_end_time: Optional[float] = None
    phase3_start_time: Optional[float] = None
    phase3_end_time: Optional[float] = None


class FirmCureFlow(Flow[FirmCureState]):
    """FirmCure三阶段流水线Flow"""

    NVRAM_TRIGGER_KEYWORDS = (
        "apmib",
        "nvram",
        "flash_read_raw_mib",
        "flash_write_raw_mib",
        "tcapi",
    )

    # ────────────────────────────────────────────────────────────
    # Phase 1: 固件分析
    # ────────────────────────────────────────────────────────────
    @start()
    def run_phase1(self):
        """Phase 1: 智能固件分析"""
        self.state.phase1_start_time = time.time()

        if self.state.start_phase > 1:
            # 尝试加载已有结果
            phase1_json = Path(self.state.case_dir) / "phase1" / "phase1_analysis.json"
            if phase1_json.exists():
                with open(phase1_json) as f:
                    self.state.phase1_result = json.load(f)
                self._infer_nvram_requirement(self.state.phase1_result)
                logger.info("Loaded existing Phase 1 result")
                return self.state.phase1_result
            else:
                raise FileNotFoundError(
                    f"Phase 1 result not found: {phase1_json}. "
                    "Please run Phase 1 first or specify correct case directory."
                )

        rootfs_path = self.state.rootfs_path
        case_dir = self.state.case_dir
        output_dir = os.path.join(case_dir, "phase1")
        os.makedirs(output_dir, exist_ok=True)

        logger.info(f"Phase 1: Analyzing firmware at {rootfs_path}")

        from config import get_llm
        from crews.phase1_crew import create_phase1_crew

        # 启动 MCP 服务器（文件工具 + radare2）
        mcp_tools_p1 = self._start_phase1_mcp(rootfs_path)

        llm = get_llm()
        crew = create_phase1_crew(rootfs_path=rootfs_path, llm=llm, tools=mcp_tools_p1)

        result = crew.kickoff()

        # 停止 Phase 1 MCP 服务器
        self._stop_mcp_adapters(p1=True)

        # 从多子任务中合并结果
        phase1_data = self._merge_task_results(result, rootfs_path)

        # 记录 token 使用情况
        if hasattr(result, 'token_usage') and result.token_usage:
            token_usage = {
                'total_tokens': result.token_usage.total_tokens,
                'prompt_tokens': result.token_usage.prompt_tokens,
                'cached_prompt_tokens': result.token_usage.cached_prompt_tokens,
                'completion_tokens': result.token_usage.completion_tokens,
                'successful_requests': result.token_usage.successful_requests
            }
            phase1_data['token_usage'] = token_usage
            logger.info(f"Phase 1 Token Usage: {token_usage['total_tokens']} tokens "
                       f"({token_usage['prompt_tokens']} prompt + {token_usage['completion_tokens']} completion)")
        else:
            phase1_data['token_usage'] = None
            logger.warning("Phase 1: No token usage data available")

        # 确保关键字段存在
        if "rootfs_dir" not in phase1_data:
            phase1_data["rootfs_dir"] = rootfs_path

        # 保存结果
        self.state.phase1_result = phase1_data
        output_file = os.path.join(output_dir, "phase1_analysis.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(phase1_data, f, ensure_ascii=False, indent=2)

        # 后处理: 使用file命令硬检测架构，输出标准化标签
        self._detect_architecture(phase1_data, rootfs_path, output_dir)

        # 后处理: 只要检测到 apmib/nvram 相关依赖，就自动开启 NVRAM 注入
        self._infer_nvram_requirement(phase1_data)

        # 保存启动脚本
        self._save_scripts(phase1_data, output_dir, rootfs_path)

        # 保存上下文报告和分散的分析文件
        self._save_reports(phase1_data, output_dir)

        # _verify_architecture可能修改了arch，重新保存JSON
        output_file = os.path.join(output_dir, "phase1_analysis.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(phase1_data, f, ensure_ascii=False, indent=2)

        self.state.phase1_end_time = time.time()
        phase1_duration = self.state.phase1_end_time - self.state.phase1_start_time
        logger.info(f"Phase 1 complete. Architecture: {phase1_data.get('architecture', {}).get('arch', 'unknown')}")
        logger.info(f"Phase 1 duration: {phase1_duration:.2f}s")

        # 保存 Phase1 汇总
        self._save_phase_summary("phase1")

        return phase1_data

    def _detect_architecture(self, data: dict, rootfs_path: str, output_dir: str):
        """使用file命令硬检测架构，输出标准化标签: armhf/armel/arm64/mipseb/mipsel"""
        # 候选二进制: httpd > busybox > libc
        httpd_info = data.get("httpd_service", {})
        httpd_path = httpd_info.get("binary_path", "") if isinstance(httpd_info, dict) else ""

        candidates = []
        if httpd_path:
            candidates.append(os.path.join(rootfs_path, httpd_path.lstrip("/")))
        for fb in ["bin/busybox", "lib/libc.so.0", "lib/ld-uClibc.so.0",
                    "usr/bin/httpd", "sbin/httpd", "bin/boa"]:
            p = os.path.join(rootfs_path, fb)
            if os.path.exists(p) and p not in candidates:
                candidates.append(p)

        arch_label = None
        file_output = ""
        for binary in candidates:
            if not os.path.exists(binary):
                continue
            try:
                result = subprocess.run(
                    ["file", "-b", binary],
                    capture_output=True, text=True, timeout=10
                )
                output = result.stdout.strip()
                if not output:
                    continue
                file_output = output
                lower = output.lower()

                if "aarch64" in lower or "arm64" in lower:
                    arch_label = "arm64"
                elif "mips" in lower:
                    if "msb" in lower or "big" in lower:
                        arch_label = "mipseb"
                    else:
                        arch_label = "mipsel"
                elif "arm" in lower:
                    if "eabi5" in lower or "v7" in lower or "hard-float" in lower:
                        arch_label = "armhf"
                    else:
                        arch_label = "armel"

                if arch_label:
                    logger.info(f"Architecture detected from {os.path.basename(binary)}: {arch_label}")
                    break
            except Exception:
                continue

        if arch_label:
            # 从 file 输出检测 libc 类型
            libc_type = "glibc"  # 默认
            lower = file_output.lower()
            if "uclibc" in lower or "ld-uclibc" in lower:
                libc_type = "uclibc"
            elif "musl" in lower:
                libc_type = "musl"

            # 备选：检查 rootfs 内动态链接器
            if libc_type == "glibc":
                if os.path.exists(os.path.join(rootfs_path, "lib/ld-uClibc.so.0")):
                    libc_type = "uclibc"
                elif any(Path(rootfs_path, "lib").glob("ld-musl-*.so*")):
                    libc_type = "musl"

            data["architecture"] = {
                "arch": arch_label,
                "bits": 64 if arch_label == "arm64" else 32,
                "endian": "big" if arch_label == "mipseb" else "little",
                "libc": libc_type,
            }
            logger.info(f"Detected libc: {libc_type}")
        else:
            logger.warning("Architecture detection failed, keeping LLM result")

        # 保存file输出
        if file_output:
            with open(os.path.join(output_dir, "architecture.txt"), "w") as f:
                f.write(file_output + "\n")

    def _resolve_nvram_arch(self, data: dict) -> Optional[str]:
        """将 FirmCure 架构名映射到 Greenhouse libnvram_faker 目录名。"""
        arch_info = data.get("architecture", {})
        if not isinstance(arch_info, dict):
            return None

        arch = str(arch_info.get("arch", "")).lower().strip()
        endian = str(arch_info.get("endian", "")).lower().strip()

        # FirmCure arch → Greenhouse directory
        arch_map = {
            "mipsel": "mipsel",
            "mipseb": "mips",
            "armhf": "arm",
            "armel": "arm",
            "arm64": "arm64",
            "aarch64": "arm64",
        }
        if arch in arch_map:
            return arch_map[arch]
        if arch == "mips":
            return "mips" if endian == "big" else "mipsel"
        if arch in ("arm", "arm32"):
            return "arm"
        return None

    def _infer_nvram_requirement(self, data: dict):
        """根据依赖库/导入函数自动推断是否需要 NVRAM 模拟。

        用户要求：只要检测到 httpd 依赖或导入了 apmib/nvram 等相关函数，
        Phase 2 就必须注入 libnvram.so，并在 httpd_start.sh 中设置 LD_PRELOAD。
        """
        if not isinstance(data, dict):
            return

        deps = data.get("dependencies", {})
        if not isinstance(deps, dict):
            deps = {}

        trigger_values = []
        for key in ("shared_libraries", "direct_dependencies", "nvram_functions"):
            values = deps.get(key, [])
            if isinstance(values, list):
                trigger_values.extend(str(v).lower() for v in values)

        nvram_detected = any(
            keyword in value
            for value in trigger_values
            for keyword in self.NVRAM_TRIGGER_KEYWORDS
        )

        if nvram_detected and not data.get("nvram_needed", False):
            data["nvram_needed"] = True
            logger.info("Phase 1: inferred nvram_needed=true from httpd dependencies/imports")

        if data.get("nvram_needed", False) and not data.get("nvram_arch"):
            resolved_arch = self._resolve_nvram_arch(data)
            if resolved_arch:
                data["nvram_arch"] = resolved_arch
                logger.info(f"Phase 1: inferred nvram_arch={resolved_arch}")

        # 提取 libc 类型
        if data.get("nvram_needed", False) and not data.get("nvram_libc"):
            arch_info = data.get("architecture", {})
            if isinstance(arch_info, dict):
                libc = arch_info.get("libc", "")
                if libc:
                    data["nvram_libc"] = libc
                    logger.info(f"Phase 1: inferred nvram_libc={libc}")

    # 硬件依赖守护进程黑名单 - QEMU中启动会死循环或崩溃
    HW_DAEMON_BLACKLIST = [
        "cfmd", "cmd_agent", "system_manager", "rc", "cfm", "netctrl",
        "udevd", "moniter", "watchdog", "wdt",
        "switch", "phy", "vlan_ctrl",
        "wifi", "wps", "hostapd",
    ]

    def _filter_hardware_daemons(self, content: str) -> str:
        """从startup.sh中过滤硬件依赖的守护进程"""
        lines = content.split("\n")
        filtered = []
        for line in lines:
            stripped = line.strip()
            # 检查是否是启动守护进程的命令（以 & 结尾或包含 daemon/启动相关关键词）
            if stripped.endswith("&") or " start" in stripped:
                cmd_part = stripped.split()[0] if stripped.split() else ""
                cmd_name = os.path.basename(cmd_part)
                is_blacklisted = any(
                    bl == cmd_name or bl in cmd_name.lower()
                    for bl in self.HW_DAEMON_BLACKLIST
                )
                if is_blacklisted:
                    logger.info(f"Filtered hardware daemon from startup.sh: {stripped}")
                    continue
            filtered.append(line)
        return "\n".join(filtered)

    def _save_scripts(self, data: dict, output_dir: str, rootfs_path: str):
        """保存启动脚本"""
        # startup.sh
        startup_content = data.get("startup_script_content", "")
        if startup_content:
            # 黑名单过滤硬件依赖守护进程
            startup_content = self._filter_hardware_daemons(startup_content)
            data["startup_script_content"] = startup_content
            with open(os.path.join(output_dir, "startup.sh"), "w") as f:
                f.write(startup_content)
            os.chmod(os.path.join(output_dir, "startup.sh"), 0o755)

        # httpd_start.sh
        httpd_cmd = data.get("httpd_command", "")
        if httpd_cmd:
            with open(os.path.join(output_dir, "httpd_start.sh"), "w") as f:
                f.write(f"#!/bin/sh\n{httpd_cmd}\n")
            os.chmod(os.path.join(output_dir, "httpd_start.sh"), 0o755)

        # vendor.txt
        vendor = data.get("vendor", "unknown")
        with open(os.path.join(output_dir, "vendor.txt"), "w") as f:
            f.write(vendor)

    def _save_reports(self, data: dict, output_dir: str):
        """保存上下文报告和分散的分析文件"""
        # CONTEXT_SUMMARY.md
        context_summary = data.get("context_summary", "")
        if context_summary:
            with open(os.path.join(output_dir, "CONTEXT_SUMMARY.md"), "w", encoding="utf-8") as f:
                f.write(context_summary)

        # httpd_info.json
        httpd = data.get("httpd_service", {})
        if httpd and isinstance(httpd, dict):
            with open(os.path.join(output_dir, "httpd_info.json"), "w", encoding="utf-8") as f:
                json.dump(httpd, f, ensure_ascii=False, indent=2)

        # startup_analysis.json
        startup = data.get("startup_sequence", {})
        if startup and isinstance(startup, dict):
            with open(os.path.join(output_dir, "startup_analysis.json"), "w", encoding="utf-8") as f:
                json.dump(startup, f, ensure_ascii=False, indent=2)

        # dependencies.json
        deps = data.get("dependencies", {})
        if deps and isinstance(deps, dict):
            with open(os.path.join(output_dir, "dependencies.json"), "w", encoding="utf-8") as f:
                json.dump(deps, f, ensure_ascii=False, indent=2)

        # config_analysis.json
        config_files = data.get("config_files", [])
        if config_files:
            with open(os.path.join(output_dir, "config_analysis.json"), "w", encoding="utf-8") as f:
                json.dump({"configs": config_files}, f, ensure_ascii=False, indent=2)

    def _save_phase_summary(self, phase_name: str):
        """保存单个阶段的时间和 token 使用情况"""
        from datetime import datetime

        phase_data = {}

        if phase_name == "phase1":
            if self.state.phase1_start_time and self.state.phase1_end_time:
                duration = self.state.phase1_end_time - self.state.phase1_start_time
                phase_data = {
                    "phase": "phase1",
                    "start_time": datetime.fromtimestamp(self.state.phase1_start_time).isoformat(),
                    "end_time": datetime.fromtimestamp(self.state.phase1_end_time).isoformat(),
                    "duration_seconds": round(duration, 2),
                    "token_usage": None
                }
                if self.state.phase1_result and 'token_usage' in self.state.phase1_result:
                    phase_data['token_usage'] = self.state.phase1_result['token_usage']

        elif phase_name == "phase2":
            if self.state.phase2_start_time and self.state.phase2_end_time:
                duration = self.state.phase2_end_time - self.state.phase2_start_time
                phase_data = {
                    "phase": "phase2",
                    "start_time": datetime.fromtimestamp(self.state.phase2_start_time).isoformat(),
                    "end_time": datetime.fromtimestamp(self.state.phase2_end_time).isoformat(),
                    "duration_seconds": round(duration, 2),
                    "token_usage": None,
                }
                if self.state.phase2_result and 'token_usage' in self.state.phase2_result:
                    phase_data['token_usage'] = self.state.phase2_result['token_usage']

        elif phase_name == "phase3":
            if self.state.phase3_start_time and self.state.phase3_end_time:
                duration = self.state.phase3_end_time - self.state.phase3_start_time
                phase_data = {
                    "phase": "phase3",
                    "start_time": datetime.fromtimestamp(self.state.phase3_start_time).isoformat(),
                    "end_time": datetime.fromtimestamp(self.state.phase3_end_time).isoformat(),
                    "duration_seconds": round(duration, 2),
                    "token_usage": None,
                    "iterations": 0,
                    "success": False
                }
                if self.state.phase3_result:
                    if 'token_usage' in self.state.phase3_result:
                        phase_data['token_usage'] = self.state.phase3_result['token_usage']
                    if 'iterations' in self.state.phase3_result:
                        phase_data['iterations'] = self.state.phase3_result['iterations']
                    if 'success' in self.state.phase3_result:
                        phase_data['success'] = self.state.phase3_result['success']

        if phase_data:
            # 保存到 scratch/{case_id}/{phase_name}_summary.json
            summary_file = os.path.join(self.state.case_dir, f"{phase_name}_summary.json")
            with open(summary_file, "w", encoding="utf-8") as f:
                json.dump(phase_data, f, ensure_ascii=False, indent=2)

            logger.info(f"{phase_name.upper()} summary saved: duration={phase_data['duration_seconds']:.2f}s")
            if phase_data.get('token_usage'):
                logger.info(f"{phase_name.upper()} tokens: {phase_data['token_usage']['total_tokens']:,}")

    def _save_summary(self):
        """保存三阶段时间和 token 使用汇总"""
        from datetime import datetime

        summary = {
            "case_id": self.state.case_number,
            "timestamp": datetime.now().isoformat(),
            "phases": {}
        }

        # Phase1
        if self.state.phase1_start_time and self.state.phase1_end_time:
            phase1_duration = self.state.phase1_end_time - self.state.phase1_start_time
            phase1_data = {
                "start_time": datetime.fromtimestamp(self.state.phase1_start_time).isoformat(),
                "end_time": datetime.fromtimestamp(self.state.phase1_end_time).isoformat(),
                "duration_seconds": round(phase1_duration, 2),
                "token_usage": None
            }
            if self.state.phase1_result and 'token_usage' in self.state.phase1_result:
                phase1_data['token_usage'] = self.state.phase1_result['token_usage']
            summary['phases']['phase1'] = phase1_data

        # Phase2
        if self.state.phase2_start_time and self.state.phase2_end_time:
            phase2_duration = self.state.phase2_end_time - self.state.phase2_start_time
            phase2_data = {
                "start_time": datetime.fromtimestamp(self.state.phase2_start_time).isoformat(),
                "end_time": datetime.fromtimestamp(self.state.phase2_end_time).isoformat(),
                "duration_seconds": round(phase2_duration, 2),
                "token_usage": None,
            }
            if self.state.phase2_result and 'token_usage' in self.state.phase2_result:
                phase2_data['token_usage'] = self.state.phase2_result['token_usage']
            summary['phases']['phase2'] = phase2_data

        # Phase3
        if self.state.phase3_start_time and self.state.phase3_end_time:
            phase3_duration = self.state.phase3_end_time - self.state.phase3_start_time
            phase3_data = {
                "start_time": datetime.fromtimestamp(self.state.phase3_start_time).isoformat(),
                "end_time": datetime.fromtimestamp(self.state.phase3_end_time).isoformat(),
                "duration_seconds": round(phase3_duration, 2),
                "token_usage": None,
                "iterations": 0,
                "success": False
            }
            if self.state.phase3_result:
                if 'token_usage' in self.state.phase3_result:
                    phase3_data['token_usage'] = self.state.phase3_result['token_usage']
                if 'iterations' in self.state.phase3_result:
                    phase3_data['iterations'] = self.state.phase3_result['iterations']
                if 'success' in self.state.phase3_result:
                    phase3_data['success'] = self.state.phase3_result['success']
            summary['phases']['phase3'] = phase3_data

        # 总计
        total_duration = 0
        total_tokens = {
            'total_tokens': 0,
            'prompt_tokens': 0,
            'completion_tokens': 0
        }

        for phase_name, phase_data in summary['phases'].items():
            total_duration += phase_data.get('duration_seconds', 0)
            if phase_data.get('token_usage'):
                for key in total_tokens:
                    total_tokens[key] += phase_data['token_usage'].get(key, 0)

        summary['total'] = {
            "duration_seconds": round(total_duration, 2),
            "duration_minutes": round(total_duration / 60, 2),
            "token_usage": total_tokens if total_tokens['total_tokens'] > 0 else None
        }

        # 保存到 scratch/{case_id}/summary.json
        summary_file = os.path.join(self.state.case_dir, "summary.json")
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

        logger.info(f"Summary saved to {summary_file}")

    def _extract_json_from_text(self, text: str) -> dict | None:
        """从文本中提取JSON"""
        try:
            if "```json" in text:
                start = text.index("```json") + 7
                end = text.index("```", start)
                return json.loads(text[start:end].strip())
            elif "```" in text:
                start = text.index("```") + 3
                end = text.index("```", start)
                return json.loads(text[start:end].strip())
            elif "{" in text and "}" in text:
                start = text.index("{")
                end = text.rindex("}") + 1
                return json.loads(text[start:end])
        except (json.JSONDecodeError, ValueError):
            pass
        return None

    def _merge_task_results(self, result, rootfs_path: str) -> dict:
        """从多个子任务结果合并最终的Phase 1分析数据"""
        # 优先使用最终任务(task4)的完整JSON
        final_text = str(result)
        final_data = self._extract_json_from_text(final_text)

        if final_data and "architecture" in final_data and "httpd_service" in final_data:
            logger.info("Phase 1: Using final task complete JSON")
            return final_data

        # 否则从各子任务分别提取并合并
        logger.info("Phase 1: Merging results from individual tasks")
        merged = {"rootfs_dir": rootfs_path}

        # CrewAI CrewOutput 可能包含 tasks_output
        tasks_output = getattr(result, 'tasks_output', None)
        if tasks_output:
            for task_output in tasks_output:
                text = str(task_output)
                data = self._extract_json_from_text(text)
                if not data:
                    continue

                step = data.get("step", "")
                if step == "architecture":
                    merged["architecture"] = {
                        k: data[k] for k in ("arch", "bits", "endian", "libc", "cpu")
                        if k in data
                    }
                elif step == "httpd_discovery":
                    merged["httpd_service"] = data.get("httpd_service", {})
                    merged["config_files"] = data.get("config_files", [])
                elif step == "startup_analysis":
                    merged["startup_sequence"] = data.get("startup_sequence", {})
                    merged["dependencies"] = data.get("dependencies", {})
                    merged["nvram_needed"] = data.get("nvram_needed", False)
                    merged["nvram_arch"] = data.get("nvram_arch")
                    merged["vendor"] = data.get("vendor", "unknown")
                elif step is None or "architecture" in data:
                    # 最终报告或无step标记的完整JSON
                    for k, v in data.items():
                        if v:
                            merged[k] = v

        # 如果最终任务有结果但不是完整JSON，也尝试合并
        if final_data:
            for k, v in final_data.items():
                if v and k not in merged:
                    merged[k] = v

        # 确保必要字段
        merged.setdefault("architecture", {"arch": "mips", "bits": 32, "endian": "little"})
        merged.setdefault("httpd_service", {})
        merged.setdefault("startup_sequence", {})
        merged.setdefault("dependencies", {})
        merged.setdefault("nvram_needed", False)
        merged.setdefault("vendor", "unknown")

        return merged

    # ────────────────────────────────────────────────────────────
    # Phase 2: QEMU仿真环境构建
    # ────────────────────────────────────────────────────────────
    @listen(run_phase1)
    def run_phase2(self, phase1_result):
        """Phase 2: QEMU命令生成与执行"""
        self.state.phase2_start_time = time.time()

        if self.state.start_phase > 2:
            # 尝试加载已有结果
            phase2_json = Path(self.state.case_dir) / "phase2" / "phase2_result.json"
            if phase2_json.exists():
                with open(phase2_json) as f:
                    self.state.phase2_result = json.load(f)
                logger.info("Loaded existing Phase 2 result")
                return self.state.phase2_result
            raise FileNotFoundError(f"Phase 2 result not found: {phase2_json}")

        if self.state.end_phase < 2:
            return phase1_result

        case_dir = self.state.case_dir
        output_dir = os.path.join(case_dir, "phase2")
        os.makedirs(output_dir, exist_ok=True)

        logger.info("Phase 2: Building QEMU emulation environment")

        # 加载sudo密码
        from config import inject_sudo_password
        inject_sudo_password()

        # 导入核心模块
        from core import (
            KernelManager, DiskBuilder, QEMUCommandGenerator,
            QEMULauncher,
        )
        from core.qemu_config import get_qemu_params
        from config import get_sudo_password, get_kernels_dir

        phase1 = self.state.phase1_result
        self._infer_nvram_requirement(phase1)
        arch_info = phase1.get("architecture", {})
        arch = arch_info.get("arch", "mips") if isinstance(arch_info, dict) else str(arch_info)

        rootfs_path = phase1.get("rootfs_dir", self.state.rootfs_path)

        # 1. 查找内核
        logger.info(f"Finding kernel for architecture: {arch}")
        kernels_dir = str(get_kernels_dir())
        kernel_manager = KernelManager(resource_dir=kernels_dir)
        kernel_path, initrd_path = kernel_manager.find_kernel_and_initrd(arch)
        if not kernel_path:
            raise RuntimeError(f"No kernel found for architecture: {arch}")
        logger.info(f"Kernel: {kernel_path}, initrd: {initrd_path}")

        # 2. 构建QCOW2磁盘
        logger.info("Building QCOW2 disk image...")
        sudo_pw = get_sudo_password()
        disk_builder = DiskBuilder(sudo_password=sudo_pw)
        qcow2_path = os.path.join(output_dir, "rootfs.qcow2")

        # 注入NVRAM库
        nvram_needed = phase1.get("nvram_needed", False)
        nvram_arch = phase1.get("nvram_arch", "")
        nvram_libc = phase1.get("nvram_libc", "glibc")

        # 从 architecture.txt 补充 libc（旧数据可能没有）
        if nvram_needed and nvram_libc in (None, "", "glibc"):
            arch_txt = os.path.join(case_dir, "phase1", "architecture.txt")
            if os.path.exists(arch_txt):
                try:
                    with open(arch_txt) as f:
                        atxt = f.read().lower()
                    if "uclibc" in atxt:
                        nvram_libc = "uclibc"
                    elif "musl" in atxt:
                        nvram_libc = "musl"
                    logger.info(f"NVRAM libc from architecture.txt: {nvram_libc}")
                except Exception:
                    pass

        # 映射 nvram_arch 到 Greenhouse 目录名（旧数据可能是 mipseb 而非 mips）
        arch_to_gh = {"mipseb": "mips", "mipsel": "mipsel", "armhf": "arm", "armel": "arm", "arm64": "arm64", "aarch64": "arm64"}
        if nvram_arch in arch_to_gh:
            nvram_arch = arch_to_gh[nvram_arch]

        startup_script_content = phase1.get("startup_script_content", "")
        httpd_command = phase1.get("httpd_command", "")
        vendor = phase1.get("vendor", "")

        from pathlib import Path as _Path

        # 获取架构默认root_device，确保DiskBuilder使用正确的分区布局
        arch_params = get_qemu_params(arch)
        default_root_device = arch_params.get("root_device", "/dev/sda1") if arch_params else "/dev/sda1"

        _, root_device = disk_builder.build_qcow2(
            rootfs_path=_Path(rootfs_path),
            output_path=_Path(qcow2_path),
            root_device=default_root_device,
            startup_script_content=startup_script_content,
            httpd_command=httpd_command,
            nvram_needed=nvram_needed,
            nvram_arch=nvram_arch,
            nvram_libc=nvram_libc,
            vendor=vendor,
            architecture=arch,
        )
        logger.info(f"QCOW2 disk: {qcow2_path}, root_device: {root_device}")

        # 3. 生成QEMU命令
        cmd_generator = QEMUCommandGenerator()

        qemu_command = cmd_generator.generate(
            architecture=arch,
            kernel_path=kernel_path,
            qcow2_path=qcow2_path,
            initrd_path=initrd_path,
            root_device=root_device,
        )

        # 使用generate_run_script生成完整启动脚本
        run_script_path = cmd_generator.generate_run_script(
            command=qemu_command,
            output_path=_Path(output_dir),
        )
        run_script = str(run_script_path)

        # QEMU命令已保存到run_qemu.sh
        cmd_str = qemu_command.full_command
        logger.info(f"QEMU command saved: {run_script}")

        # 4. 启动QEMU并检查
        logger.info("Launching QEMU...")
        self._kill_stale_qemu()

        launcher = QEMULauncher(
            timeout=self.state.timeout_phase2,
            log_dir=_Path(output_dir),
            sudo_password=sudo_pw,
        )

        boot_success = False
        max_attempts = 3
        repair_history_list = []  # 追踪修复历史

        # 加载历史修复记录（跨运行持久化）
        history_file = os.path.join(output_dir, "repair_history.json")
        if os.path.exists(history_file):
            try:
                with open(history_file) as f:
                    repair_history_list = json.load(f)
                if repair_history_list:
                    logger.info(f"Loaded {len(repair_history_list)} previous repair records")
                    # 直接应用上次的 qemu_adjustments
                    last_adj = repair_history_list[-1].get("qemu_adjustments", {})
                    if last_adj:
                        logger.info(f"Applying previous qemu_adjustments: {last_adj}")
                        qemu_command = cmd_generator.generate(
                            architecture=arch,
                            kernel_path=kernel_path,
                            qcow2_path=qcow2_path,
                            initrd_path=initrd_path,
                            root_device=root_device,
                            memory=last_adj.get("memory"),
                            cpu=last_adj.get("cpu"),
                            filesystem=last_adj.get("rootfstype"),
                            extra_append=last_adj.get("extra_append") or last_adj.get("kernel_params"),
                        )
                        cmd_str = qemu_command.full_command
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Failed to load repair history: {e}")
                repair_history_list = []

        for attempt in range(1, max_attempts + 1):
            logger.info(f"QEMU boot attempt {attempt}/{max_attempts}")
            try:
                launch_result = launcher.run_with_network(command=qemu_command)

                # 检查启动结果 (ExecutionResult)
                if launch_result.success:
                    boot_success = True
                    break

                # 读取日志检查
                boot_log = launch_result.logs or ""
                if not boot_success and os.path.exists(os.path.join(output_dir, "qemu.log")):
                    with open(os.path.join(output_dir, "qemu.log")) as f:
                        boot_log = f.read()

                if "Please press Enter to activate this console" in boot_log or \
                   "login:" in boot_log or "/ #" in boot_log or "/ $" in boot_log:
                    boot_success = True
                    break

                # 启动失败 - 尝试LLM修复
                if attempt < max_attempts:
                    logger.info(f"Boot failed, invoking repair crew (attempt {attempt})")
                    # 构建修复历史字符串
                    repair_history_str = ""
                    if repair_history_list:
                        lines = ["## 历史修复记录（之前的修复已经应用，不需要重复）"]
                        for i, h in enumerate(repair_history_list, 1):
                            lines.append(f"第{i}次修复: {h.get('diagnosis', 'N/A')}")
                            for r in h.get("repairs_applied", []):
                                lines.append(f"  - {r}")
                            adj = h.get("qemu_adjustments")
                            if adj:
                                lines.append(f"  - QEMU调整: {adj}")
                            lines.append(f"  - 结果: 仍然失败")
                        repair_history_str = "\n".join(lines)

                    repair_data = self._repair_boot(
                        rootfs_path, boot_log, cmd_str, arch, output_dir,
                        repair_history=repair_history_str,
                        iteration=attempt,
                    )
                    repair_history_list.append(repair_data)

                    # 应用修复结果到启动参数
                    qemu_adjustments = repair_data.get("qemu_adjustments") or {}
                    repairs_applied = repair_data.get("repairs_applied") or []

                    # 处理内核版本切换（解决 "Kernel too old" 错误）
                    kernel_version = qemu_adjustments.get("kernel_version")
                    if kernel_version:
                        new_kernel = kernel_manager.find_kernel_by_version(arch, kernel_version)
                        if new_kernel:
                            kernel_path = new_kernel
                            logger.info(f"  Applying repair: kernel switched to {kernel_version} → {kernel_path}")
                        else:
                            logger.warning(f"  Kernel version {kernel_version} not found for {arch}")

                    # 处理 DTB（设备树）文件
                    dtb_file = qemu_adjustments.get("dtb")
                    dtb_path_arg = None
                    if dtb_file:
                        dtb_path_arg = kernel_manager.find_dtb(arch)
                        if dtb_path_arg:
                            logger.info(f"  Applying repair: dtb={dtb_path_arg}")
                        else:
                            logger.warning(f"  DTB file not found for {arch}")

                    if qemu_adjustments:
                        if "memory" in qemu_adjustments:
                            logger.info(f"  Applying repair: memory={qemu_adjustments['memory']}")
                        if "cpu" in qemu_adjustments:
                            logger.info(f"  Applying repair: cpu={qemu_adjustments['cpu']}")
                        if "root_device" in qemu_adjustments:
                            root_device = qemu_adjustments["root_device"]
                            logger.info(f"  Applying repair: root_device={root_device}")
                        if "extra_append" in qemu_adjustments or "kernel_params" in qemu_adjustments:
                            logger.info(f"  Applying repair: kernel_params={qemu_adjustments.get('extra_append') or qemu_adjustments.get('kernel_params')}")

                    # ① 先生成新 QEMU 命令（即使后续 QCOW2 重建失败也能用新参数）
                    if qemu_adjustments:
                        qemu_command = cmd_generator.generate(
                            architecture=arch,
                            kernel_path=kernel_path,
                            qcow2_path=qcow2_path,
                            initrd_path=initrd_path,
                            root_device=root_device,
                            memory=qemu_adjustments.get("memory"),
                            cpu=qemu_adjustments.get("cpu"),
                            filesystem=qemu_adjustments.get("rootfstype"),
                            extra_append=qemu_adjustments.get("extra_append") or qemu_adjustments.get("kernel_params"),
                            dtb_path=dtb_path_arg,
                        )
                        cmd_str = qemu_command.full_command
                        logger.info(f"  QEMU command updated with adjustments")

                    # ② 只有 rootfs 被修改时才重建 QCOW2
                    need_rebuild = bool(repairs_applied)
                    if need_rebuild:
                        # 重建前确保 QEMU 进程已退出，释放 QCOW2 文件锁
                        self._kill_stale_qemu()
                        time.sleep(1)
                        logger.info(f"  Rootfs modified ({len(repairs_applied)} repairs), rebuilding QCOW2...")
                        # 应用修复后的启动脚本/httpd命令（如有更新）
                        repaired_startup = repair_data.get("startup_script_content")
                        if repaired_startup:
                            startup_script_content = repaired_startup
                        repaired_httpd = repair_data.get("httpd_command")
                        if repaired_httpd:
                            httpd_command = repaired_httpd

                        try:
                            _, root_device = disk_builder.build_qcow2(
                                rootfs_path=_Path(rootfs_path),
                                output_path=_Path(qcow2_path),
                                root_device=root_device if qemu_adjustments.get("root_device") else None,
                                startup_script_content=startup_script_content,
                                httpd_command=httpd_command,
                                nvram_needed=nvram_needed,
                                nvram_arch=nvram_arch,
                                nvram_libc=nvram_libc,
                                vendor=vendor,
                                architecture=arch,
                            )
                            logger.info(f"  QCOW2 rebuilt successfully, root_device={root_device}")
                        except Exception as build_err:
                            logger.error(f"  QCOW2 rebuild failed: {build_err}")
                            # QCOW2 重建失败，但 QEMU 命令已更新，继续尝试启动
                    else:
                        logger.info(f"  No rootfs modifications, skipping QCOW2 rebuild")

                    # 保存修复历史（持久化）
                    history_file = os.path.join(output_dir, "repair_history.json")
                    with open(history_file, "w", encoding="utf-8") as f:
                        json.dump(repair_history_list, f, ensure_ascii=False, indent=2)

            except Exception as e:
                logger.error(f"QEMU launch error: {e}")
                if attempt == max_attempts:
                    boot_success = False

            self._kill_stale_qemu()
            time.sleep(2)

        # 使用最终 QEMU 命令重新生成 run_qemu.sh（确保 Phase 3 使用修复后的命令）
        run_script_path = cmd_generator.generate_run_script(
            command=qemu_command,
            output_path=_Path(output_dir),
        )
        run_script = str(run_script_path)
        logger.info(f"run_qemu.sh regenerated with final QEMU command")

        # 保存结果
        # 汇总 Phase 2 token 使用量
        total_phase2_tokens = {
            'total_tokens': 0,
            'prompt_tokens': 0,
            'cached_prompt_tokens': 0,
            'completion_tokens': 0,
            'successful_requests': 0
        }
        for h in repair_history_list:
            if h.get('token_usage'):
                for key in total_phase2_tokens:
                    total_phase2_tokens[key] += h['token_usage'].get(key, 0)
        has_tokens = total_phase2_tokens['total_tokens'] > 0

        phase2_data = {
            "qcow2_path": qcow2_path,
            "run_script": run_script,
            "kernel": kernel_path,
            "initrd": initrd_path,
            "root_device": root_device,
            "architecture": arch,
            "boot_success": boot_success,
            "qemu_command": cmd_str,
            "token_usage": total_phase2_tokens if has_tokens else None,
        }
        self.state.phase2_result = phase2_data

        result_file = os.path.join(output_dir, "phase2_result.json")
        with open(result_file, "w") as f:
            json.dump(phase2_data, f, ensure_ascii=False, indent=2)

        # 清理QEMU（Phase 3会重新启动）
        self._kill_stale_qemu()

        self.state.phase2_end_time = time.time()
        phase2_duration = self.state.phase2_end_time - self.state.phase2_start_time
        logger.info(f"Phase 2 complete. Boot success: {boot_success}")
        logger.info(f"Phase 2 duration: {phase2_duration:.2f}s")

        # 保存 Phase2 汇总
        self._save_phase_summary("phase2")

        return phase2_data

    def _repair_boot(self, rootfs_path: str, boot_log: str, qemu_cmd: str, arch: str,
                     output_dir: str, repair_history: str = "", iteration: int = 1) -> dict:
        """使用CrewAI修复QEMU启动故障，返回修复结果供下游消费"""
        from config import get_llm
        from crews.phase2_crew import create_phase2_repair_crew

        # 启动 Phase 2 MCP 服务器（文件工具）
        mcp_tools_p2 = self._start_phase2_mcp(rootfs_path)

        llm = get_llm()
        crew = create_phase2_repair_crew(
            rootfs_path=rootfs_path,
            boot_log=boot_log,
            qemu_command=qemu_cmd,
            architecture=arch,
            llm=llm,
            tools=mcp_tools_p2,
            repair_history=repair_history,
            iteration=iteration,
        )
        result = crew.kickoff()

        # 停止 Phase 2 MCP 服务器
        self._stop_mcp_adapters(p2=True)

        # 记录 token 使用情况
        iteration_token_usage = None
        if hasattr(result, 'token_usage') and result.token_usage:
            iteration_token_usage = {
                'total_tokens': result.token_usage.total_tokens,
                'prompt_tokens': result.token_usage.prompt_tokens,
                'cached_prompt_tokens': result.token_usage.cached_prompt_tokens,
                'completion_tokens': result.token_usage.completion_tokens,
                'successful_requests': result.token_usage.successful_requests
            }
            logger.info(f"Phase 2 Repair (attempt {iteration}) Token Usage: "
                       f"{iteration_token_usage['total_tokens']} tokens "
                       f"({iteration_token_usage['prompt_tokens']} prompt + "
                       f"{iteration_token_usage['completion_tokens']} completion)")

        # 解析修复结果并应用
        repair_data = {}
        try:
            result_text = str(result)
            if "```json" in result_text:
                start = result_text.index("```json") + 7
                end = result_text.index("```", start)
                parsed = json.loads(result_text[start:end].strip())
            elif "{" in result_text:
                start = result_text.index("{")
                end = result_text.rindex("}") + 1
                parsed = json.loads(result_text[start:end])
            else:
                parsed = {}

            # json.loads 可能返回 None（JSON 内容为 null）
            repair_data = parsed if isinstance(parsed, dict) else {}

            logger.info(f"Repair diagnosis: {repair_data.get('diagnosis', 'N/A')}")
            for repair in repair_data.get("repairs_applied", []):
                logger.info(f"  Repair: {repair}")

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse repair result: {e}")

        # 将 token 使用情况写入 repair_data
        if iteration_token_usage:
            repair_data['token_usage'] = iteration_token_usage

        return repair_data

    def _kill_stale_qemu(self):
        """清理残留QEMU进程（Phase 2 通过 sudo 启动，需 sudo kill）"""
        from config import get_sudo_password
        sudo_pw = get_sudo_password()

        # Phase 2 QEMULauncher 用 sudo 启动，必须用 sudo 才能杀
        if sudo_pw:
            subprocess.run(
                f"echo '{sudo_pw}' | sudo -S killall -9 "
                "qemu-system-mipsel qemu-system-mips qemu-system-arm "
                "qemu-system-aarch64 qemu-system-x86_64 2>/dev/null",
                shell=True, capture_output=True, timeout=5,
            )
        # 普通用户权限兜底（Phase 3 直接启动的情况）
        subprocess.run(["killall", "-9", "qemu-system-mipsel", "qemu-system-mips",
                         "qemu-system-arm"], capture_output=True, timeout=5)
        subprocess.run(["pkill", "-9", "-f", "qemu-system-"], capture_output=True, timeout=5)

        # 等待进程真正退出，验证端口 1234 (GDB -s) 已释放
        time.sleep(1)
        for _ in range(10):
            r = subprocess.run(["pgrep", "-f", "qemu-system-"], capture_output=True, timeout=3)
            if r.returncode != 0:
                break
            logger.info("Waiting for QEMU processes to exit...")
            time.sleep(1)

    # ────────────────────────────────────────────────────────────
    # Phase 3: 运行时干预
    # ────────────────────────────────────────────────────────────
    @listen(run_phase2)
    def run_phase3(self, phase2_result):
        """Phase 3: 自动化运行时干预"""
        self.state.phase3_start_time = time.time()

        if self.state.start_phase > 3 or self.state.end_phase < 3:
            return phase2_result

        case_dir = self.state.case_dir
        phase3_dir = os.path.join(case_dir, "phase3")
        os.makedirs(phase3_dir, exist_ok=True)

        logger.info("Phase 3: Runtime intervention starting...")

        from config import inject_sudo_password, get_llm
        inject_sudo_password()
        llm = get_llm()

        phase1 = self.state.phase1_result
        phase2 = self.state.phase2_result

        rootfs_path = phase1.get("rootfs_dir", self.state.rootfs_path)
        arch_info = phase1.get("architecture", {})
        architecture = arch_info.get("arch", "mips") if isinstance(arch_info, dict) else "mips"

        httpd_info = phase1.get("httpd_service", {})
        httpd_binary = httpd_info.get("binary_path", "/bin/httpd") if isinstance(httpd_info, dict) else "/bin/httpd"
        httpd_port = httpd_info.get("port", 80) if isinstance(httpd_info, dict) else 80
        # 确保 port 是整数
        try:
            httpd_port = int(httpd_port)
        except (ValueError, TypeError):
            httpd_port = 80

        # 1. 启动QEMU
        from core import QemuShell
        from core.validator import ServiceValidator
        from core.network_setup import (
            setup_network,
            setup_qemu_ifup,
            restore_qemu_ifup,
            cleanup_network,
        )
        self._kill_stale_qemu()

        # 配置tap0网络
        if not setup_network():
            logger.error("Failed to setup tap0 network")
            return {"success": False, "error": "Network setup failed"}
        if not setup_qemu_ifup():
            logger.error("Failed to setup /etc/qemu-ifup")
            cleanup_network()
            return {"success": False, "error": "qemu-ifup setup failed"}

        # 确定QEMU二进制文件
        arch_lower = architecture.lower()
        if "arm64" in arch_lower or "aarch64" in arch_lower:
            qemu_binary = "qemu-system-aarch64"
        elif "mipsel" in arch_lower or arch_lower == "mipsel":
            qemu_binary = "qemu-system-mipsel"
        elif "mips" in arch_lower:
            qemu_binary = "qemu-system-mips"
        elif "arm" in arch_lower:
            qemu_binary = "qemu-system-arm"
        else:
            qemu_binary = "qemu-system-mipsel"

        kernel = phase2.get("kernel", "")
        qcow2 = phase2.get("qcow2_path", "")
        log_file = os.path.join(phase3_dir, "e2e_test.log")
        phase2_dir = os.path.join(case_dir, "phase2")

        # 初始化需要在 finally 中清理的资源引用
        shell = None
        network_set_up = True
        qemu_ifup_set_up = True

        try:
            shell = QemuShell()
            if not shell.start(kernel, qcow2, log_file, qemu_binary=qemu_binary, phase2_dir=phase2_dir):
                logger.error("Failed to start QEMU for Phase 3")
                return {"success": False, "error": "QEMU start failed"}

            # 等待shell提示符 (wait_for_prompt内部已包含stty -echo)
            logger.info("Waiting for QEMU shell...")
            if not shell.wait_for_prompt(timeout=60):
                logger.error("QEMU boot timeout")
                return {"success": False, "error": "QEMU boot timeout"}

            # 2. 配置环境
            logger.info("Setting up QEMU environment...")

            # 运行启动脚本 (由DiskBuilder注入到/startup.sh)
            shell.execute_command("./startup.sh", timeout=15.0, monitor=True)
            time.sleep(2)

            # 设置网络 (由DiskBuilder注入到/bin/setup_network.sh)
            logger.info("Configuring network...")
            network_ok = False
            for _ in range(5):
                shell.execute_command("/bin/setup_network.sh", timeout=10.0, monitor=True)
                time.sleep(3)
                try:
                    r = subprocess.run(
                        ["ping", "-c", "2", "-W", "2", "10.10.10.2"],
                        capture_output=True, text=True, timeout=10,
                    )
                    if r.returncode == 0:
                        logger.info("Network configured successfully")
                        network_ok = True
                        break
                except Exception:
                    pass
                time.sleep(2)

            # 3. 创建所有 CrewAI 工具
            # FirmCure 工具（VM/文件/网络，直接使用 QemuShell）
            _fc_mod = _import_tool_module("firmcure-tool")
            fc_tools = _fc_mod.create_firmcure_tools(
                shell=shell, rootfs_path=rootfs_path,
                architecture=architecture, phase3_dir=phase3_dir,
            )

            # radare2 工具（Python r2pipe 原生）
            _r2_mod = _import_tool_module("radare2-tool")
            r2_tools = _r2_mod.create_radare2_tools(rootfs_path)

            # GDB 工具（gdb-multiarch subprocess）
            _gdb_mod = _import_tool_module("gdb-tool")
            gdb_tools = _gdb_mod.create_gdb_tools(
                shell=shell, rootfs_path=rootfs_path,
                phase3_dir=phase3_dir, architecture=architecture,
            )

            # 创建验证工具（三层网络验证）
            _validation_mod = _import_tool_module("validation-tool")
            validation_tools = _validation_mod.create_validation_tools(
                guest_ip="10.10.10.2",
                httpd_port=httpd_port,
            )

            # 合并所有 CrewAI 工具
            mcp_tools = list(fc_tools)
            mcp_tools.extend(r2_tools)
            mcp_tools.extend(gdb_tools)
            mcp_tools.extend(validation_tools)  # ← 添加验证工具
            logger.info(f"Total tools: {len(mcp_tools)} (firmcure: {len(fc_tools)}, r2: {len(r2_tools)}, GDB: {len(gdb_tools)}, validation: {len(validation_tools)})")

            # 5. 干预循环
            max_iterations = 5
            timeout = self.state.timeout_phase3
            start_time = time.time()

            # 结构化断点链追踪（替代 gdb_chain 字符串拼接）
            breakpoint_chain = []  # List[Dict]: [{"address": "0x...", "register_values": {"$r3": "1"}}]
            repair_history = []    # List[Dict]: [{"expert_name": "..., "actions_taken": [...], ...}]
            next_fault_hint = ""

            # 预构建共享上下文字符串（所有专家共享）
            endian = arch_info.get("endian", "little") if isinstance(arch_info, dict) else "little"
            httpd_command = phase1.get("httpd_command", "")
            vendor = phase1.get("vendor", "")
            context_summary = phase1.get("context_summary", "")

            for iteration in range(1, max_iterations + 1):
                if time.time() - start_time > timeout:
                    logger.warning("Phase 3 timeout reached")
                    break

                logger.info(f"--- Intervention iteration {iteration}/{max_iterations} ---")

                # 验证服务
                validator = ServiceValidator(
                    guest_ip="10.10.10.2",
                    httpd_port=httpd_port,
                    phase3_dir=phase3_dir,
                    rootfs_path=rootfs_path,
                    httpd_binary=httpd_binary,
                    architecture=architecture,
                )
                validation = validator.validate(shell=shell)

                last_reported_full_stack_success = (
                    bool(repair_history)
                    and bool(repair_history[-1].get("reported_full_stack_success", False))
                )

                if validation.passed and (not repair_history or last_reported_full_stack_success):
                    logger.info("HTTPD service is running and responding!")
                    self.state.phase3_result = {
                        "success": True,
                        "iterations": iteration,
                        "validation": {
                            "network_reachable": validation.network_reachable,
                            "port_open": validation.port_open,
                            "http_status": validation.http_status,
                            "process_running": validation.process_running,
                        },
                    }
                    break
                elif validation.passed and repair_history and not last_reported_full_stack_success:
                    logger.warning(
                        "Service is healthy, but the last expert did not return a passing "
                        "validate_network_stack result. Refusing to mark success=true."
                    )
                    self.state.phase3_result = {
                        "success": False,
                        "iterations": iteration,
                        "error": "Expert omitted required validate_network_stack success before completion",
                        "validation": {
                            "network_reachable": validation.network_reachable,
                            "port_open": validation.port_open,
                            "http_status": validation.http_status,
                            "process_running": validation.process_running,
                        },
                        "repair_history": repair_history,
                    }
                    break

                # 收集诊断信息
                status_dict = {
                    "network_reachable": validation.network_reachable,
                    "port_open": validation.port_open,
                    "http_status": validation.http_status,
                    "process_running": validation.process_running,
                    "is_crash": validation.is_crash,
                    "crash_signal": validation.crash_signal,
                    "is_hung": validation.is_hung,
                    "startup_log": validation.startup_log,
                    "logs": validation.logs,
                }
                service_status = json.dumps(status_dict, ensure_ascii=False, default=str)
                httpd_output = validation.startup_log or validation.logs or ""

                # 快速路径: 网络+端口OK但HTTP错误 -> 直接WebExpert
                from crews.phase3_crew import create_phase3_hierarchical_crew

                fault_hint = next_fault_hint
                next_fault_hint = ""
                if not fault_hint:
                    log_tail_hint = self._infer_fault_from_log_tail(httpd_output)
                    if log_tail_hint:
                        logger.info(f"Fast-path: log-tail hint detected, routing to {log_tail_hint}")
                        fault_hint = log_tail_hint
                    elif validation.process_running and validation.port_open and validation.http_status not in ("200", "000"):
                        logger.info("Fast-path: HTTP error, routing to web expert")
                        fault_hint = "WEB_ERROR"
                    elif validation.is_hung:
                        logger.info("Fast-path: Process hung, routing to crash expert")
                        fault_hint = "DEPENDENCY_WAIT"

                # 构建共享上下文字符串
                breakpoint_chain_str = self._build_breakpoint_chain_str(breakpoint_chain)
                repair_history_str = self._build_repair_history_str(repair_history)
                phase1_data_str = self._build_phase1_context_str(phase1)

                # ── Hierarchical Crew: 单次 kickoff 完成诊断+修复 ──
                logger.info(f"Iteration {iteration}: launching hierarchical intervention crew")
                intervention_crew = create_phase3_hierarchical_crew(
                    rootfs_path=rootfs_path,
                    architecture=architecture,
                    httpd_binary=httpd_binary,
                    endian=endian,
                    service_status=service_status,
                    httpd_output=httpd_output,
                    iteration=iteration,
                    breakpoint_chain_str=breakpoint_chain_str,
                    repair_history_str=repair_history_str,
                    phase1_data_str=phase1_data_str,
                    fault_hint=fault_hint,
                    llm=llm,
                    tools=mcp_tools,  # 传入全部工具，由 crew 内部按专家过滤
                )
                expert_result = intervention_crew.kickoff()

                # 记录 token 使用情况
                if hasattr(expert_result, 'token_usage') and expert_result.token_usage:
                    iteration_token_usage = {
                        'total_tokens': expert_result.token_usage.total_tokens,
                        'prompt_tokens': expert_result.token_usage.prompt_tokens,
                        'cached_prompt_tokens': expert_result.token_usage.cached_prompt_tokens,
                        'completion_tokens': expert_result.token_usage.completion_tokens,
                        'successful_requests': expert_result.token_usage.successful_requests
                    }
                    logger.info(f"Iteration {iteration} Token Usage: {iteration_token_usage['total_tokens']} tokens")
                else:
                    iteration_token_usage = None

                # 解析专家结果并更新状态
                result_text = str(expert_result)
                parsed_result = self._parse_expert_result(result_text)
                expert_validation_summary = self._extract_expert_validation_summary(parsed_result)
                reported_full_stack_success = bool(expert_validation_summary.get("overall_success"))

                # 从 hierarchical 结果中提取 fault_type
                fault_type = parsed_result.get("fault_type", fault_hint or "UNKNOWN")
                is_crash_expert = fault_type in ("PREMATURE_EXIT", "DEPENDENCY_WAIT")

                # 更新断点链（仅 crash_expert 成功时）
                if is_crash_expert and parsed_result.get("success"):
                    reg_changes = parsed_result.get("register_changes", {})
                    bp_chain = parsed_result.get("breakpoint_chain", [])
                    if reg_changes and bp_chain:
                        # 用专家返回的完整断点链覆盖本地追踪
                        breakpoint_chain = []
                        for bp_entry in bp_chain:
                            if isinstance(bp_entry, dict):
                                addr = bp_entry.get("address", "")
                                entry_reg_values = bp_entry.get("register_values")
                                if entry_reg_values is None:
                                    entry_reg_values = reg_changes.get(addr, {}) if addr else {}
                            else:
                                addr = bp_entry
                                entry_reg_values = reg_changes.get(addr, {}) if addr else {}

                            if not addr:
                                continue

                            breakpoint_chain.append({
                                "address": addr,
                                "register_values": entry_reg_values,
                                "iteration": iteration,
                            })
                        logger.info(f"Breakpoint chain updated: {len(breakpoint_chain)} breakpoints")

                # 更新修复历史
                repair_history.append({
                    "expert_name": fault_type,
                    "iteration": iteration,
                    "actions_taken": parsed_result.get("actions_taken", []),
                    "success": parsed_result.get("success", False),
                    "reported_full_stack_success": reported_full_stack_success,
                    "expert_validation": parsed_result.get("validation"),
                    "token_usage": iteration_token_usage,  # 添加 token 使用记录
                })

                if parsed_result.get("success") and not reported_full_stack_success:
                    logger.warning(
                        "Expert reported success=true without a passing validate_network_stack result. "
                        "Treating this as incomplete."
                    )
                    repair_history[-1]["missing_required_validation"] = True

                # ── 专家返回后，不信任其 success 声明，做一次实际验证 ──
                logger.info("Expert finished. Running full validation to verify actual state...")
                post_validator = ServiceValidator(
                    guest_ip="10.10.10.2",
                    httpd_port=httpd_port,
                    phase3_dir=phase3_dir,
                    rootfs_path=rootfs_path,
                    httpd_binary=httpd_binary,
                    architecture=architecture,
                )

                # 快速检测专家是否已成功启动服务，如果是则跳过重启
                service_already_running = False
                if shell:
                    try:
                        quick_check = subprocess.run(
                            ["nc", "-z", "-w", "2", "10.10.10.2", str(httpd_port)],
                            capture_output=True, timeout=5
                        )
                        if quick_check.returncode == 0:
                            service_already_running = True
                            logger.info("Service already running after expert, skipping restart for validation")
                    except Exception:
                        pass

                post_validation = post_validator.validate(
                    shell=shell,
                    skip_restart=service_already_running,
                )

                actual_validation = {
                    "network_reachable": post_validation.network_reachable,
                    "port_open": post_validation.port_open,
                    "http_status": post_validation.http_status,
                    "process_running": post_validation.process_running,
                    "is_crash": post_validation.is_crash,
                    "crash_signal": post_validation.crash_signal,
                    "is_hung": post_validation.is_hung,
                    "startup_log": post_validation.startup_log,
                    "logs": post_validation.logs,
                }

                if post_validation.passed and reported_full_stack_success:
                    logger.info("✅ Expert-reported full-stack validation and post-validation both PASSED")
                    repair_history[-1]["validation"] = actual_validation

                    # 计算 Phase3 总 token 使用量
                    total_phase3_tokens = {
                        'total_tokens': 0,
                        'prompt_tokens': 0,
                        'cached_prompt_tokens': 0,
                        'completion_tokens': 0,
                        'successful_requests': 0
                    }
                    for repair in repair_history:
                        if repair.get('token_usage'):
                            for key in total_phase3_tokens:
                                total_phase3_tokens[key] += repair['token_usage'].get(key, 0)

                    self.state.phase3_result = {
                        "success": True,
                        "iterations": iteration,
                        "expert_type": fault_type,
                        "breakpoint_chain": parsed_result.get("breakpoint_chain", []),
                        "register_changes": parsed_result.get("register_changes", {}),
                        "expert_validation": parsed_result.get("validation"),
                        "validation": actual_validation,
                        "repair_history": repair_history,
                        "token_usage": total_phase3_tokens,
                    }
                    logger.info(f"Phase 3 Total Token Usage: {total_phase3_tokens['total_tokens']} tokens "
                               f"across {iteration} iterations")
                    break
                elif post_validation.passed and not reported_full_stack_success:
                    logger.warning(
                        "Post-validation passed, but expert did not provide a passing "
                        "validate_network_stack result. Continuing as incomplete."
                    )
                    repair_history[-1]["validation"] = actual_validation
                    repair_history[-1]["expert_claimed_success_without_required_validation"] = bool(
                        parsed_result.get("success")
                    )
                    next_fault_hint = fault_type or "UNKNOWN"
                    continue

                # ── 验证未通过：记录专家声称成功但实际失败的情况，继续下一轮 ──
                if parsed_result.get("success"):
                    logger.warning(
                        f"⚠️ Expert claimed success but validation FAILED! "
                        f"network={post_validation.network_reachable}, port={post_validation.port_open}, "
                        f"http={post_validation.http_status}, process={post_validation.process_running}"
                    )
                    repair_history[-1]["validation"] = actual_validation
                    repair_history[-1]["expert_claimed_success_but_validation_failed"] = True

                    # 生成下一轮的故障提示，帮助 Manager 重新路由
                    next_fault_hint = self._infer_fault_from_validation(post_validation)
                    logger.info(f"Next iteration will re-diagnose with hint: {next_fault_hint}")
                else:
                    repair_history[-1]["validation"] = actual_validation

                    # 处理任务移交：专家发现新问题需要重新诊断
                    if parsed_result.get("needs_rediagnosis") and parsed_result.get("new_issue_detected"):
                        new_issue = parsed_result.get("new_issue_description", "unknown")
                        logger.info(f"Expert requests rediagnosis: {new_issue}")
                        repair_history[-1]["new_issue_detected"] = True
                        repair_history[-1]["new_issue_description"] = new_issue

                logger.info(
                    f"Iteration {iteration} complete: expert={fault_type}, "
                    f"claimed={'success' if parsed_result.get('success') else 'failed'}, "
                    f"actual={'PASSED' if post_validation.passed else 'FAILED'}"
                )

            # 保存最终结果
            if not self.state.phase3_result:
                # 计算失败情况下的总 token 使用量
                total_phase3_tokens = {
                    'total_tokens': 0,
                    'prompt_tokens': 0,
                    'cached_prompt_tokens': 0,
                    'completion_tokens': 0,
                    'successful_requests': 0
                }
                for repair in repair_history:
                    if repair.get('token_usage'):
                        for key in total_phase3_tokens:
                            total_phase3_tokens[key] += repair['token_usage'].get(key, 0)

                self.state.phase3_result = {
                    "success": False,
                    "iterations": max_iterations,
                    "error": "Max iterations reached without success",
                    "repair_history": repair_history,
                    "token_usage": total_phase3_tokens,
                }
                logger.info(f"Phase 3 failed after {max_iterations} iterations. "
                           f"Total tokens: {total_phase3_tokens['total_tokens']}")

            result_file = os.path.join(phase3_dir, "phase3_result.json")
            with open(result_file, "w") as f:
                json.dump(self.state.phase3_result, f, ensure_ascii=False, indent=2)

            self.state.phase3_end_time = time.time()
            phase3_duration = self.state.phase3_end_time - self.state.phase3_start_time

            # 保存 Phase3 汇总
            self._save_phase_summary("phase3")

            # 保存总体汇总
            self._save_summary()

            # 保存结构化GDB断点链回放脚本
            if breakpoint_chain:
                self._save_gdb_chain_script(breakpoint_chain, phase3_dir, rootfs_path, httpd_binary, architecture)
            # 注：实际应用的断点已由 GDB 工具自动保存到 gdb_break.gdb

            # 保存交互日志
            if shell:
                interaction_log = shell.get_interaction_log()
                if interaction_log:
                    with open(os.path.join(phase3_dir, "interaction.log"), "w") as f:
                        f.write("\n".join(interaction_log))

            logger.info(f"Phase 3 complete. Success: {self.state.phase3_result.get('success', False)}")

        finally:
            # 成功时保留 QEMU 和网络，失败时清理所有资源
            is_success = self.state.phase3_result and self.state.phase3_result.get("success", False)

            if is_success:
                logger.info("Phase 3 succeeded - preserving QEMU and network for inspection")
                # 保存shell引用供main.py交互使用
                self.state.qemu_shell = shell
                # 仅清理 CrewAI 工具后端，保留 QEMU 和网络
                try:
                    _r2_cleanup = _import_tool_module("radare2-tool")
                    _r2_cleanup.cleanup_all()
                    _gdb_cleanup = _import_tool_module("gdb-tool")
                    _gdb_cleanup.cleanup_all()
                except Exception:
                    pass
                # 记录 QEMU 进程信息供用户查看
                if shell and shell.proc:
                    logger.info(f"QEMU process preserved: PID {shell.proc.pid}")
            else:
                # 失败时清理所有资源
                logger.info("Phase 3: cleaning up resources...")
                # 清理 CrewAI 工具后端
                try:
                    _r2_cleanup = _import_tool_module("radare2-tool")
                    _r2_cleanup.cleanup_all()
                    _gdb_cleanup = _import_tool_module("gdb-tool")
                    _gdb_cleanup.cleanup_all()
                except Exception:
                    pass
                if shell:
                    try:
                        shell.stop()
                    except Exception:
                        pass
                if qemu_ifup_set_up:
                    try:
                        restore_qemu_ifup()
                    except Exception:
                        pass
                if network_set_up:
                    cleanup_network()
                self._kill_stale_qemu()

        return self.state.phase3_result

    def _parse_diagnosis(self, result_text: str, fallback_status: str):
        """解析诊断结果"""
        try:
            if "```json" in result_text:
                start = result_text.index("```json") + 7
                end = result_text.index("```", start)
                data = json.loads(result_text[start:end].strip())
            elif "{" in result_text:
                start = result_text.index("{")
                end = result_text.rindex("}") + 1
                data = json.loads(result_text[start:end])
            else:
                data = {}

            fault_type = data.get("fault_type", "UNKNOWN")
            reasoning = data.get("reasoning", "")
            fault_info = f"{reasoning}\n\nRaw diagnosis: {result_text[:2000]}"
            return fault_type, fault_info

        except (json.JSONDecodeError, ValueError):
            return "UNKNOWN", f"Diagnosis parsing failed. Status:\n{fallback_status}\n\nRaw: {result_text[:2000]}"

    def _parse_expert_result(self, result_text: str) -> dict:
        """从专家输出中解析结构化 JSON 结果"""
        try:
            # 尝试提取 JSON
            if "```json" in result_text:
                start = result_text.index("```json") + 7
                end = result_text.index("```", start)
                return json.loads(result_text[start:end].strip())
            elif "{" in result_text and "}" in result_text:
                start = result_text.index("{")
                end = result_text.rindex("}") + 1
                data = json.loads(result_text[start:end])
                if "success" in data:
                    return data
        except (json.JSONDecodeError, ValueError):
            pass
        return {"success": False, "raw": result_text}

    def _extract_expert_validation_summary(self, parsed_result: dict) -> dict:
        """提取专家返回中的 validation.summary。"""
        if not isinstance(parsed_result, dict):
            return {}

        validation = parsed_result.get("validation", {})
        if isinstance(validation, str):
            try:
                validation = json.loads(validation)
            except Exception:
                return {}

        if not isinstance(validation, dict):
            return {}

        summary = validation.get("summary", {})
        if isinstance(summary, dict):
            return summary
        return {}

    def _infer_fault_from_log_tail(self, httpd_output: str) -> str:
        """优先根据日志末尾的具体报错快速推断故障类型。

        原则：
        - 优先看最后几行“最接近失败点”的日志，而不是只依赖 is_hung / process_running
        - 明确的文件/脚本/Lua/CGI 错误，优先交给 file_expert
        - 明确的网络/地址族错误，优先交给 network_expert
        """
        if not httpd_output:
            return ""

        tail = "\n".join(httpd_output.splitlines()[-20:]).lower()

        network_patterns = [
            "address family not supported",
            "protocol family not supported",
            "af_inet6",
            "network is unreachable",
            "no route to host",
            "connection refused",
            "cannot assign requested address",
        ]
        if any(p in tail for p in network_patterns):
            return "NETWORK_ERROR"

        file_patterns = [
            "not found",
            "no such file",
            "lua handler had runtime error",
            "url-routing.lua",
            "unknown distribution",
            "cgi-bin",
            "net-cgi",
        ]
        if any(p in tail for p in file_patterns):
            return "FILE_MISSING"

        web_patterns = [
            "404",
            "500",
            "forbidden",
            "bad gateway",
        ]
        if any(p in tail for p in web_patterns):
            return "WEB_ERROR"

        return ""

    def _infer_fault_from_validation(self, validation) -> str:
        """根据验证结果推断故障类型，帮助 Manager 重新路由到合适的专家。

        原则：
        - 网络不可达 → network_expert
        - 端口不开 → 取决于进程是否在运行
        - HTTP 状态码异常 → web_expert 或 file_expert
        """
        # 网络不可达
        if not getattr(validation, "network_reachable", True):
            return "NETWORK_ERROR"

        # 进程不在运行
        if not getattr(validation, "process_running", True):
            return "PROCESS_CRASH"

        http_status = getattr(validation, "http_status", "000")

        # 端口不开但进程在运行 → 可能是配置或绑定问题
        if not getattr(validation, "port_open", True):
            return "CONFIG_ERROR"

        # HTTP 状态码异常
        if http_status not in ("200", "000", ""):
            if http_status.startswith("4"):
                return "WEB_ERROR"
            if http_status.startswith("5"):
                return "WEB_ERROR"
            if http_status.startswith("3"):
                return "WEB_ERROR"

        return ""

    def _build_breakpoint_chain_str(self, breakpoint_chain: list) -> str:
        """构建断点链上下文字符串，供 LLM 感知已有断点"""
        if not breakpoint_chain:
            return ""

        lines = ["## 已确认的断点链（之前迭代成功绕过的崩溃点）"]
        lines.append("**重要**: 新的断点设置必须包含以下所有断点 + 新崩溃点。")
        lines.append("")
        for i, bp in enumerate(breakpoint_chain, 1):
            addr = bp["address"]
            reg_vals = bp.get("register_values", {})
            reg_str = ", ".join(f"{r}={v}" for r, v in reg_vals.items())
            lines.append(f"  {i}. {addr} → {reg_str}")
        lines.append("")

        # 给出断点链示例
        all_addrs = [bp["address"] for bp in breakpoint_chain]
        reg_dict = {}
        for bp in breakpoint_chain:
            reg_dict[bp["address"]] = bp.get("register_values", {})
        lines.append(f"示例: breakpoints={all_addrs} + [新地址], register_values={reg_dict}")
        return "\n".join(lines)

    def _build_repair_history_str(self, repair_history: list) -> str:
        """构建历史修复上下文字符串"""
        if not repair_history:
            return ""
        lines = ["## 历史修复记录"]
        for i, record in enumerate(repair_history, 1):
            lines.append(f"### 第 {i} 轮修复")
            lines.append(f"- 专家: {record.get('expert_name', 'unknown')}")
            lines.append(f"- 执行动作: {record.get('actions_taken', [])}")
            lines.append(f"- 结果: {'成功' if record.get('success') else '失败'}")
            lines.append("")
        return "\n".join(lines)

    def _build_phase1_context_str(self, phase1: dict) -> str:
        """构建 Phase1 分析数据上下文"""
        if not phase1:
            return ""

        parts = ["## Phase1 完整分析数据"]

        # 架构信息
        arch_info = phase1.get("architecture", {})
        if arch_info:
            parts.append(f"- 架构: {arch_info.get('arch', 'unknown')} {arch_info.get('endian', '')}端序")

        # HTTPD 信息
        httpd_info = phase1.get("httpd_service", {})
        if httpd_info:
            parts.append(f"- HTTPD 二进制: {httpd_info.get('binary_path', '')}")
            parts.append(f"- HTTPD 类型: {httpd_info.get('type', '')}")
            config = httpd_info.get("config_file", "")
            if config:
                parts.append(f"- 配置文件: {config}")

        # 启动序列
        startup = phase1.get("startup_sequence", {})
        if startup:
            start_cmds = startup.get("httpd_startup", [])
            if start_cmds:
                parts.append(f"- 启动命令: {start_cmds}")

        # 依赖
        deps = phase1.get("dependencies", {})
        if deps:
            missing = deps.get("missing_libs", [])
            if missing:
                parts.append(f"- 缺失依赖: {missing[:10]}")

        # 上下文摘要
        context_summary = phase1.get("context_summary", "")
        if context_summary:
            parts.append(f"\n### CONTEXT_SUMMARY\n{context_summary[:2000]}")

        # 启动脚本内容
        startup_content = phase1.get("startup_script_content", "")
        if startup_content:
            parts.append(f"\n### startup.sh\n```\n{startup_content[:1500]}\n```")

        return "\n".join(parts)

    def _restart_httpd_with_breakpoints(self, shell, phase3_dir: str):
        """杀死旧 httpd，用 gdb_run_script 重新应用断点链，启动新 httpd

        不依赖 gdb_break.gdb 文件，而是直接用 gdb_run_script 工具重新应用断点。
        """
        logger.info("Restarting httpd with breakpoint chain replay")

        # 清理所有旧 httpd 进程
        logger.info("Killing stale httpd processes...")
        shell.execute_command(
            "killall -9 httpd lighttpd boa goahead nginx 2>/dev/null",
            timeout=3.0, monitor=False
        )
        time.sleep(1)

        # 不使用 gdb-multiarch -x，直接启动新 httpd
        # GDB 工具（gdb_run_script）会在 ./httpd_start.sh & 时自动应用断点
        logger.info("Starting fresh httpd process...")
        shell.execute_command("./httpd_start.sh &", timeout=5.0, monitor=True)
        time.sleep(2)

    def _save_gdb_chain_script(self, breakpoint_chain: list, phase3_dir: str,
                                rootfs_path: str, httpd_binary: str, architecture: str):
        """将断点链保存为干净的 GDB 回放脚本"""
        import os
        from pathlib import Path

        phase3_path = Path(phase3_dir)
        phase3_path.mkdir(parents=True, exist_ok=True)
        gdb_file = phase3_path / "gdb_chain.gdb"

        arch_map = {"mips": "mips", "mipsel": "mips", "mipseb": "mips",
                    "armhf": "arm", "armel": "arm"}
        gdb_arch = arch_map.get(architecture, "mips")
        full_path = f"{rootfs_path.rstrip('/')}/{httpd_binary.lstrip('/')}" if rootfs_path else httpd_binary

        lines = [
            f"set architecture {gdb_arch}",
            f"file {full_path}",
            "target remote :1234",
        ]

        for bp in breakpoint_chain:
            lines.append(f"b *{bp['address']}")

        lines.append("c")  # 初始 continue，命中第一个断点

        for i, bp in enumerate(breakpoint_chain):
            for reg, val in bp.get("register_values", {}).items():
                lines.append(f"set {reg}={val}")
            if i < len(breakpoint_chain) - 1:
                lines.append("c")
            else:
                lines.append("detach")

        with open(gdb_file, 'w') as f:
            f.write("\n".join(lines) + "\n")

        logger.info(f"GDB chain script saved: {gdb_file} ({len(breakpoint_chain)} breakpoints)")

    def _filter_mcp_tools(self, mcp_tools, agent_type=None, expert_key=None):
        """按 agent 类型过滤 MCP 工具，如果 mcp_tools 为 None 则返回 None（降级到 BaseTool）"""
        if mcp_tools is None:
            return None

        # 确定 agent 类型（兼容 expert_key 和 agent_type 两种参数）
        key = expert_key or agent_type or ""
        key_map = {
            "PREMATURE_EXIT": "crash_expert",
            "DEPENDENCY_WAIT": "crash_expert",
            "FILE_MISSING": "file_expert",
            "PERMISSION_ERROR": "file_expert",
            "SYMLINK_CORRUPTION": "file_expert",
            "NETWORK_ERROR": "network_expert",
            "PORT_CONFLICT": "network_expert",
            "WEB_ERROR": "web_expert",
            "UNKNOWN": "generic_expert",
        }
        agent_key = key_map.get(key, key)

        # 各 agent 可用的工具名
        agent_tool_map = {
            "crash_expert": {
                "vm_exec", "check_service_running", "get_httpd_logs",
                "read_file", "list_dir", "find_files", "file_stat",
                # GDB CrewAI 工具
                "gdb_backtrace", "gdb_run_script", "gdb_modify_register",
                "gdb_trace_crash", "gdb_read_memory", "gdb_disassemble", "gdb_get_symbols",
                # radare2 CrewAI 工具
                "open_file", "analyze", "list_strings", "list_all_strings",
                "disassemble", "disassemble_function", "xrefs_to",
                "list_functions", "list_imports", "show_info",
                "run_command",
            },
            "file_expert": {
                "vm_exec", "read_file", "find_files",
                "copy_to_rootfs", "write_file", "remove", "mkdir",
                "file_stat", "list_strings", "open_file",
            },
            "network_expert": {
                "vm_exec", "check_service_running", "get_httpd_logs",
                "network_ping", "network_scan_ports",
                "http_request", "http_get_body", "read_file",
            },
            "web_expert": {
                "vm_exec", "read_file", "find_files",
                "check_service_running",
                "http_request", "http_get_body",
            },
            "diagnosis_agent": {
                "vm_exec", "read_file", "find_files",
                "check_service_running", "get_httpd_logs",
                "gdb_backtrace", "gdb_trace_crash",
                "list_strings", "open_file",
                "http_request",
            },
            "generic_expert": None,  # None 表示全部工具
            "verification_agent": {
                "vm_exec", "check_service_running", "get_httpd_logs",
                "network_ping", "network_scan_ports",
                "http_request", "http_get_body",
            },
        }

        allowed = agent_tool_map.get(agent_key)
        if allowed is None:
            # generic_expert 或未知类型：返回全部工具
            return mcp_tools

        filtered = [t for t in mcp_tools if t.name in allowed]
        logger.info(f"MCP tools for {agent_key}: {[t.name for t in filtered]}")
        return filtered

    # ────────────────────────────────────────────────────────────
    # MCP 服务器启动/停止（Phase 1/2/3 共用）
    # ────────────────────────────────────────────────────────────

    # 实例级缓存
    _p1_r2_tools = None
    _p2_r2_tools = None

    def _start_firmcure_mcp(self, rootfs_path: str, architecture: str = "",
                             phase3_dir: str = "", shell=None):
        """创建 FirmCure CrewAI 工具（文件/VM/网络）"""
        _fc_mod = _import_tool_module("firmcure-tool")
        tools = _fc_mod.create_firmcure_tools(
            shell=shell, rootfs_path=rootfs_path,
            architecture=architecture, phase3_dir=phase3_dir,
        )
        logger.info(f"FirmCure tools: {[t.name for t in tools]}")
        return tools

    def _start_phase1_mcp(self, rootfs_path: str) -> list:
        """启动 Phase 1 所需的工具，返回合并后的工具列表"""
        # FirmCure CrewAI 工具（Phase 1 无 shell，VM 工具不可用）
        fc_tools = self._start_firmcure_mcp(rootfs_path)

        # radare2 CrewAI 工具
        _r2_mod = _import_tool_module("radare2-tool")
        self._p1_r2_tools = _r2_mod.create_radare2_tools(rootfs_path)

        tools = list(fc_tools)
        tools.extend(self._p1_r2_tools)

        # Phase 1 只需要文件 + radare2 工具，过滤掉 VM/网络工具
        p1_allowed = {
            "list_dir", "read_file", "find_files", "file_exists", "file_stat",
            "read_json", "elf_info", "readelf_deps",
        }
        for t in self._p1_r2_tools:
            p1_allowed.add(t.name)

        filtered = [t for t in tools if t.name in p1_allowed]
        logger.info(f"Phase 1 tools: {[t.name for t in filtered]}")
        return filtered

    def _start_phase2_mcp(self, rootfs_path: str) -> list:
        """启动 Phase 2 所需的工具，返回工具列表"""
        fc_tools = self._start_firmcure_mcp(rootfs_path)

        # Phase 2 需要文件 + rootfs 操作工具
        p2_allowed = {
            "read_file", "write_file", "remove", "mkdir",
            "list_dir", "find_files", "file_exists", "read_json",
            "file_stat", "copy_to_rootfs",
            "elf_info", "readelf_deps", "check_kernel", "list_lib_base", "list_precompiled_kernels",
        }

        tools = [t for t in fc_tools if t.name in p2_allowed]

        # radare2 CrewAI 工具
        _r2_mod = _import_tool_module("radare2-tool")
        self._p2_r2_tools = _r2_mod.create_radare2_tools(rootfs_path)

        r2_allowed = {
            "open_file", "analyze", "show_info", "list_strings",
            "list_imports", "list_functions", "disassemble",
            "disassemble_function", "list_sections", "run_command",
        }
        tools.extend([t for t in self._p2_r2_tools if t.name in r2_allowed])

        logger.info(f"Phase 2 tools: {[t.name for t in tools]}")
        return tools

    def _stop_mcp_adapters(self, p1=False, p2=False, adapters=None):
        """清理工具资源"""
        if p1:
            self._p1_r2_tools = None
        if p2:
            self._p2_r2_tools = None
