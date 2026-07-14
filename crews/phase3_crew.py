"""
Phase 3 Crews - 运行时干预团队
Hierarchical Process: Manager(诊断+分配) + 5个专家(执行修复)

工具必须由外部通过 MCP Server 传入（tools 参数），不提供降级机制。
"""

import logging

from crewai import Crew, Process, Task

from agents.phase3_agents import (
    create_phase3_manager,
    create_crash_expert,
    create_file_expert,
    create_network_expert,
    create_web_expert,
    create_generic_expert,
)
from config import get_embedder_config, get_llm

logger = logging.getLogger(__name__)

# 各专家可用的工具名白名单
EXPERT_TOOL_MAP = {
    "crash_expert": {
        "vm_exec",  # 仅用于简单诊断（ps、cat日志），禁止验证和重启
        "get_httpd_logs", "read_file",  # 读日志诊断
        "start_httpd",  # 启动 httpd（自动处理断点链）
        "validate_network_stack",
        # GDB CrewAI 工具（高级封装）- 核心工具
        "gdb_backtrace", "gdb_run_script", "gdb_modify_register",
        "gdb_trace_crash", "gdb_read_memory", "gdb_disassemble", "gdb_get_symbols",
        # radare2 CrewAI 工具 - 逆向分析
        "open_file", "analyze", "list_strings", "list_all_strings",
        "disassemble", "disassemble_function", "xrefs_to",
        "list_functions", "list_imports", "show_info", "run_command",
    },
    "file_expert": {
        "vm_exec", "read_file", "find_files",
        "copy_to_rootfs", "write_file", "remove", "mkdir",
        "file_stat", "list_strings", "open_file",
        "start_httpd",  # 启动 httpd（自动处理断点链）
        "validate_network_stack",
    },
    "network_expert": {
        "vm_exec", "check_service_running", "get_httpd_logs",
        "network_ping", "network_scan_ports",
        "http_request", "http_get_body", "read_file",
        "start_httpd",  # 启动 httpd（自动处理断点链）
        "validate_network_stack",
    },
    "web_expert": {
        "vm_exec", "read_file", "find_files",
        "check_service_running",
        "http_request", "http_get_body",
        "start_httpd",  # 启动 httpd（自动处理断点链）
        "validate_network_stack",
        # radare2 — 用于从 httpd 二进制中提取硬编码路径（WebRoot、CGI 等）
        "open_file", "analyze", "list_strings", "list_all_strings",
        "disassemble", "disassemble_function", "xrefs_to",
        "list_functions", "list_imports", "show_info", "run_command",
    },
    "generic_expert": None,  # None = 全部工具
}


def _filter_tools(all_tools: list, expert_key: str) -> list:
    """按专家类型过滤工具"""
    allowed = EXPERT_TOOL_MAP.get(expert_key)
    if allowed is None:
        return all_tools
    return [t for t in all_tools if t.name in allowed]


def create_phase3_hierarchical_crew(
    rootfs_path: str = "",
    architecture: str = "",
    httpd_binary: str = "",
    endian: str = "little",
    service_status: str = "",
    httpd_output: str = "",
    iteration: int = 1,
    breakpoint_chain_str: str = "",
    repair_history_str: str = "",
    phase1_data_str: str = "",
    fault_hint: str = "",  # flow.py 快速路径的故障类型提示
    llm=None,
    tools: list = None,
) -> Crew:
    """创建 Hierarchical Phase 3 干预 Crew

    Manager 负责诊断故障并委派给专家。专家执行修复。
    单次 kickoff() 完成诊断+修复，替代原来的两步 crew 调用。
    """
    if tools is None:
        raise RuntimeError("MCP tools are required but not provided.")

    crew_llm = llm or get_llm()

    # ── Manager (不允许自带工具，只做诊断和分配) ──
    manager = create_phase3_manager(llm=crew_llm)
    # Hierarchical process: Manager 不允许有 tools，通过 delegation 分配给专家
    manager.tools = []

    # ── 专家们 (各自带过滤后的工具) ──
    crash = create_crash_expert(llm=crew_llm)
    crash.tools = _filter_tools(tools, "crash_expert")

    file_exp = create_file_expert(llm=crew_llm)
    file_exp.tools = _filter_tools(tools, "file_expert")

    net_exp = create_network_expert(llm=crew_llm)
    net_exp.tools = _filter_tools(tools, "network_expert")

    web_exp = create_web_expert(llm=crew_llm)
    web_exp.tools = _filter_tools(tools, "web_expert")

    gen_exp = create_generic_expert(llm=crew_llm)
    gen_exp.tools = tools  # 全部工具

    # ── 计算宿主机二进制路径 ──
    r2_binary_path = ""
    if rootfs_path and httpd_binary:
        r2_binary_path = f"{rootfs_path.rstrip('/')}/{httpd_binary.lstrip('/')}"

    # ── 高层干预任务 (交给 Manager 处理) ──
    fault_hint_section = ""
    if fault_hint:
        fault_hint_section = f"""
## 故障类型提示
系统快速诊断已判断故障类型为: **{fault_hint}**
你可以直接根据此提示分配专家，也可以根据日志信息自行判断。"""

    task = Task(
        description=f"""分析HTTPD服务故障，诊断类型并分配给合适的专家修复。

## 当前状态 (第{iteration}轮干预)
{service_status}

## HTTPD 启动日志
```
{httpd_output[:4000]}
```
{fault_hint_section}

## HTTPD 二进制信息
- 二进制路径(VM内): {httpd_binary}
- 二进制路径(宿主机，radare2/GDB 必须使用此路径): {r2_binary_path}
- 架构: {architecture} {endian}端序
- Rootfs: {rootfs_path}

{breakpoint_chain_str}

{repair_history_str}

{phase1_data_str}

## 你的任务
1. **诊断**: 分析上方日志和状态，判断故障类型
2. **分配**: 将修复任务分配给最合适的专家（只分配一个）
3. **审查**: 检查专家返回的结果
4. **决定**: 如果专家报告新问题(needs_rediagnosis=true)，重新诊断并分配

## 执行要求
- 优先根据**日志最后几行**给出故障提示，不要先做大范围抽象分析
- 要求专家先解决一个最具体的问题，再看结果有没有变化
- 不允许专家长时间停留在纯思考/纯逆向阶段而没有任何实际修复动作
- 每解决一个问题后，必须立即：
  - 如有必要调用 `start_httpd`
  - 再调用 `validate_network_stack()`
  - 根据结果决定是否继续下一位专家
- 如果当前专家不具备修复该问题的工具或职责，必须立即交给其他专家，而不是继续空转

## 故障路由规则
- 进程崩溃/退出 → crash_expert
- 进程在但端口不开(阻塞等待) → crash_expert
- 缺少文件/设备节点/权限错误 → file_expert
- 网络/DNS/端口问题 → network_expert
- HTTP错误码(500/404) → web_expert
- 不确定 → generic_expert

## 日志分析优先级
- 先看**日志最后几行**，优先处理离失败点最近的具体报错
- 如果日志尾部出现以下线索，优先按下面路由：
  - `not found`, `No such file`, `Lua handler had runtime error`, `url-routing.lua`, `unknown distribution`, `net-cgi`
    → file_expert
  - `Address family not supported`, `Protocol family not supported`, `AF_INET6`, 路由/绑定错误
    → network_expert
- 只有在日志里没有更具体线索时，才可使用“进程在但端口不开 → crash_expert”的兜底规则

## 关键路径说明（分配给专家时必须传达）
- **radare2 工具** (open_file) 必须使用**宿主机路径**: `{r2_binary_path}`
- **GDB 工具** 也使用宿主机路径
- **VM 操作** (vm_exec) 是在 **QEMU 全系统仿真** 里的 **BusyBox shell** 执行，不是在宿主机执行
- `vm_exec` 只适合基础命令：`ps`、`ls`、`cat`、`echo`、`netstat/ss`、`dmesg`等
- 不要让专家用 `vm_exec` 执行 `curl` / `wget` / 宿主机工具 / 逆向工具
- 委派任务时务必在上下文中明确告知专家这两个路径的区别
- 无论哪个专家，只要准备返回 `success=true`，都必须先调用 `validate_network_stack`
- 只有当专家返回的 `validation.summary.overall_success=true` 时，manager 才能接受该 `success=true`
- 如果专家没有带回通过的 `validate_network_stack` 结果，即使它声称修复成功，也必须视为未完成
- 如果分配给 `web_expert`，默认要求它按 **Web目录/内容 → 配置文件 → 最后才二进制分析** 的顺序排查
- 如果二进制已经启动并端口已开放，启动日志只作为辅助线索；不要把日志里的守护进程报错直接当成 WebExpert 的主分析对象

## 最终输出格式
请综合所有专家的工作结果，输出最终JSON:
```json
{{{{
  "success": true,
  "fault_type": "PREMATURE_EXIT",
  "expert_used": "crash_expert",
  "actions_taken": ["绕过 connect_cfm 检查"],
  "breakpoint_chain": [],
  "register_changes": {{{{}}}},
  "validation": {{"summary": {{"overall_success": true}}}},
  "new_issue_detected": false,
  "new_issue_description": "",
  "needs_rediagnosis": false
}}}}
```""",
        expected_output="JSON格式干预报告，包含 fault_type, success, actions_taken, new_issue_detected, needs_rediagnosis",
        # NOTE: 不设置 agent 参数！
        # CrewAI 1.14.1 hierarchical process 中，_update_manager_tools 会根据
        # task.agent 是否存在来决定 delegation coworker 列表：
        # - task.agent=None → 传入 self.agents（5个专家）→ 正确
        # - task.agent=manager → 传入 [manager]（只有自己）→ delegation 失败
    )

    return Crew(
        agents=[crash, file_exp, net_exp, web_exp, gen_exp],
        tasks=[task],
        process=Process.hierarchical,
        manager_agent=manager,
        verbose=False,
        memory=False,
        embedder=get_embedder_config(),
    )


# ────────────────────────────────────────────────────────────────
# 旧接口兼容 (保留供 flow.py 逐步迁移)
# ────────────────────────────────────────────────────────────────

FAULT_EXPERT_MAP = {
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


def create_expert_crew(
    fault_type: str,
    shell=None,
    rootfs_path: str = "",
    phase3_dir: str = "",
    architecture: str = "",
    fault_info: str = "",
    httpd_binary: str = "",
    http_status: str = "",
    iteration: int = 1,
    previous_chain: str = "",
    llm=None,
    endian: str = "little",
    httpd_output: str = "",
    breakpoint_chain_str: str = "",
    repair_history_str: str = "",
    phase1_data_str: str = "",
    tools: list = None,
) -> Crew:
    """兼容旧接口 — 仅创建单个专家 Crew (sequential)"""
    from tasks.phase3_tasks import (
        create_crash_repair_task,
        create_file_repair_task,
        create_network_repair_task,
        create_web_repair_task,
        create_generic_repair_task,
    )

    expert_key = FAULT_EXPERT_MAP.get(fault_type, "generic_expert")
    if tools is None:
        raise RuntimeError("MCP tools are required but not provided.")

    crew_llm = llm or get_llm()

    agent_creators = {
        "crash_expert": create_crash_expert,
        "file_expert": create_file_expert,
        "network_expert": create_network_expert,
        "web_expert": create_web_expert,
        "generic_expert": create_generic_expert,
    }
    agent = agent_creators[expert_key](llm=crew_llm)
    agent.tools = _filter_tools(tools, expert_key)

    task_creators = {
        "crash_expert": lambda a: create_crash_repair_task(
            agent=a, fault_info=fault_info,
            httpd_binary=httpd_binary, iteration=iteration,
            previous_chain=previous_chain,
            rootfs_path=rootfs_path,
            architecture=architecture,
            endian=endian,
            httpd_output=httpd_output,
            breakpoint_chain_str=breakpoint_chain_str,
            repair_history_str=repair_history_str,
            phase1_data_str=phase1_data_str,
        ),
        "file_expert": lambda a: create_file_repair_task(
            agent=a, fault_info=fault_info, iteration=iteration,
            rootfs_path=rootfs_path, httpd_binary=httpd_binary,
            architecture=architecture, httpd_output=httpd_output,
            repair_history_str=repair_history_str,
            phase1_data_str=phase1_data_str,
        ),
        "network_expert": lambda a: create_network_repair_task(
            agent=a, fault_info=fault_info, iteration=iteration,
            rootfs_path=rootfs_path, httpd_binary=httpd_binary,
            architecture=architecture, httpd_output=httpd_output,
            repair_history_str=repair_history_str,
            phase1_data_str=phase1_data_str,
        ),
        "web_expert": lambda a: create_web_repair_task(
            agent=a, fault_info=fault_info,
            http_status=http_status, iteration=iteration,
            rootfs_path=rootfs_path, httpd_binary=httpd_binary,
            architecture=architecture, httpd_output=httpd_output,
            repair_history_str=repair_history_str,
            phase1_data_str=phase1_data_str,
        ),
        "generic_expert": lambda a: create_generic_repair_task(
            agent=a, fault_info=fault_info, iteration=iteration,
            rootfs_path=rootfs_path, httpd_binary=httpd_binary,
            architecture=architecture, httpd_output=httpd_output,
            breakpoint_chain_str=breakpoint_chain_str,
            repair_history_str=repair_history_str,
            phase1_data_str=phase1_data_str,
        ),
    }
    task = task_creators[expert_key](agent)

    return Crew(
        agents=[agent],
        tasks=[task],
        process=Process.sequential,
        verbose=False,
        memory=False,
        embedder=get_embedder_config(),
    )
