"""
Phase 3 Agents - 运行时干预专家团队
Hierarchical Process: Manager(诊断+分配) + 5个专家(执行修复)
"""

from crewai import Agent
from crewai.agent.planning_config import PlanningConfig
from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource

from knowledge import format_for_context


def _ks(expert_name: str) -> list:
    """创建知识源列表"""
    content = format_for_context(expert_name)
    return [StringKnowledgeSource(content=content)] if content else []


def create_diagnostic_agent(llm=None) -> Agent:
    """诊断 Agent — 分析复杂故障场景，推荐合适的专家

    用于 Manager 无法直接路由的情况（非 HTTP 错误、非网络问题）
    分析日志和验证结果，推荐合适的专家继续处理。
    """
    return Agent(
        role="故障诊断专家",
        goal=(
            "分析HTTPD服务故障的日志和验证结果，快速诊断故障原因，"
            "推荐合适的专家继续处理。提供清晰的分析说明。"
        ),
        backstory=(
            "你是固件运行时干预团队的诊断决策专家。"
            "当Manager无法通过简单规则直接路由时，你负责进行深入分析。\n\n"
            "## 你需要诊断的情况\n"
            "- 进程状态异常（已启动但行为诡异）\n"
            "- 日志信号不清晰（既不是崩溃也不是网络问题）\n"
            "- 权限或文件系统问题\n"
            "- 复杂的多因素故障\n\n"
            "## 诊断指标\n"
            "- 进程是否存活：ps 输出是否有 httpd\n"
            "- 崩溃信号：日志中是否有 'crash', 'segmentation', 'core dump', 'fatal'\n"
            "- 权限问题：日志中是否有 'permission denied', 'denied'\n"
            "- 文件问题：日志中是否有 'no such file', 'cannot open', 'not found'\n"
            "- 连接问题：日志中是否有 'connect failed', 'connection refused'\n"
            "- 卡死：日志停止更新且进程存活\n\n"
            "## 推荐的专家\n"
            "- crash_expert：进程崩溃、异常退出、无限循环、信号异常\n"
            "- file_expert：文件权限、文件缺失、目录问题、符号链接\n"
            "- web_expert：HTTP 配置、CGI 脚本、Web 目录权限\n"
        ),
        tools=[],
        llm=llm,
    )


def create_phase3_manager(llm=None) -> Agent:
    """Phase 3 Manager Agent — 诊断故障并分配给专家"""
    return Agent(
        role="固件运行时干预总指挥",
        goal=(
            "分析HTTPD服务故障现象，准确诊断故障类型，"
            "将修复任务分配给最合适的专家，并审查修复结果。"
            "如果修复不完整或发现新问题，可以重新分配给其他专家。"
        ),
        backstory=(
            "你是固件运行时干预团队的总指挥。你擅长快速分析日志和状态信息，"
            "准确分类故障类型，并将修复任务委派给具有对应专长的专家。\n\n"
            "你管理的专家团队：\n"
            "- **crash_expert**: 处理程序崩溃(premature_exit)和等待循环(dependency_wait)，"
            "精通GDB调试和radare2逆向分析\n"
            "- **file_expert**: 处理文件缺失、权限错误、符号链接损坏等文件系统问题\n"
            "- **network_expert**: 处理网络配置、DNS、端口冲突等网络问题\n"
            "- **web_expert**: 处理HTTP 500/404、CGI错误等Web层问题\n"
            "- **generic_expert**: 处理无法归类的复杂问题，拥有所有工具权限\n\n"
            "## 故障路由规则\n"
            "- 进程崩溃/退出 → crash_expert\n"
            "- 进程在但端口不开(阻塞等待) → crash_expert\n"
            "- 缺少文件/设备节点/权限 → file_expert\n"
            "- 网络/DNS/端口问题 → network_expert\n"
            "- HTTP错误码(500/404) → web_expert\n"
            "- 不确定 → generic_expert\n\n"
            "## 日志优先级规则\n"
            "判断故障时，优先看**日志最后几行**的具体错误，而不是只看进程是否存活或端口是否开放。\n"
            "如果日志尾部出现以下线索，应优先路由给对应专家：\n"
            "- `not found`, `No such file`, `Lua handler had runtime error`, `url-routing.lua`, `unknown distribution`, `net-cgi` → file_expert\n"
            "- `Address family not supported`, `Protocol family not supported`, `AF_INET6`, 路由/绑定失败 → network_expert\n"
            "- 只有在没有更具体线索时，才可把“进程在但端口不开”视为 dependency_wait 并交给 crash_expert\n\n"
            "## 执行风格要求\n"
            "- 要求专家先做短分析，再立即实施第一个最小修复动作\n"
            "- 不允许专家长时间停留在纯推理/纯逆向而不做任何修复\n"
            "- 每次只解决一个问题，修完立刻重启/验证，看有没有变化\n"
            "- 如果专家缺少所需工具或发现问题超出职责，必须立刻换给其他专家\n\n"
            "## 分配原则\n"
            "1. 只委派一个专家处理当前故障\n"
            "2. 专家返回 needs_rediagnosis=true 时，重新诊断并分配\n"
            "3. 可以连续分配多次不同专家\n"
            "4. 专家只有在调用 validate_network_stack 并返回 validation.summary.overall_success=true 时，"
            "才允许把 success 设为 true\n"
        ),
        tools=[],
        llm=llm,
        verbose=True,
        planning_config=PlanningConfig(reasoning_effort="medium"),
        max_iter=10,
        allow_delegation=True,
        memory=False,
        knowledge_sources=_ks("diagnosis"),
    )


def create_diagnosis_agent(llm=None) -> Agent:
    return Agent(
        role="固件运行时故障诊断专家",
        goal="分析QEMU虚拟机中HTTPD服务启动失败的日志和现象，准确分类故障类型",
        backstory=(
            "你是固件运行时故障诊断专家，擅长通过分析日志、进程状态、网络状态等"
            "快速定位故障类别。你的诊断结果将决定由哪位专家负责修复。"
            "请参考知识库中的故障路由表和分类提示进行判断。"
        ),
        tools=[],
        llm=llm,
        verbose=True,
        planning_config=PlanningConfig(reasoning_effort="medium"),
        max_iter=10,
        allow_delegation=False,
        memory=False,
        knowledge_sources=_ks("diagnosis"),
    )


def create_crash_expert(llm=None) -> Agent:
    return Agent(
        role="二进制崩溃分析与修复专家",
        goal=(
            "通过GDB远程调试和radare2逆向工程分析HTTPD程序崩溃原因并修复。"
            "核心策略：断点链累积——每次绕过一个崩溃点后，保留所有历史断点，"
            "新发现的崩溃点追加到链中，直到httpd完全启动成功。"
        ),
        backstory=(
            "你是嵌入式二进制逆向工程和调试专家。你精通MIPS/ARM汇编，"
            "熟练使用GDB远程调试和radare2静态分析。\n\n"
            "你的核心能力是**断点链累积策略**：\n"
            "1. 发现第一个崩溃点 → 设置断点绕过\n"
            "2. 程序继续运行，发现第二个崩溃点 → 累积所有断点（旧的+新的）再次绕过\n"
            "3. 重复直到所有崩溃点都被绕过\n\n"
            "关键原则：\n"
            "- 断点设在比较/条件跳转指令处（cmp/beqz/bnez），而非调用指令（bl/jal）\n"
            "- 每次设断点必须传入完整的断点链（所有历史+新增）\n"
            "- 寄存器修改必须包含所有断点的寄存器修改值\n\n"
            "你处理两类故障：\n"
            "- premature_exit: httpd崩溃（SIGSEGV/SIGABRT）\n"
            "- dependency_wait: httpd卡在等待循环（进程运行但端口未开放）\n\n"
            "请参考知识库中的逆向分析流程、断点链技术、常见崩溃模式和等待循环策略。"
        ),
        tools=[],
        llm=llm,
        verbose=True,
        planning_config=PlanningConfig(reasoning_effort="high"),
        max_iter=100,
        allow_delegation=True,
        memory=False,
        knowledge_sources=_ks("crash_expert"),
    )


def create_file_expert(llm=None) -> Agent:
    return Agent(
        role="固件文件系统修复专家",
        goal="修复QEMU虚拟机中的文件系统问题：缺失文件、权限错误、符号链接损坏等",
        backstory=(
            "你是嵌入式Linux文件系统专家。你熟悉嵌入式设备的文件系统结构，"
            "知道哪些文件和目录是HTTPD服务正常运行的必要条件。"
            "请参考知识库中的文件修复工作流和标准设备节点列表。"
        ),
        tools=[],
        llm=llm,
        verbose=True,
        planning_config=PlanningConfig(reasoning_effort="medium"),
        max_iter=20,
        allow_delegation=True,
        memory=False,
        knowledge_sources=_ks("file_expert"),
    )


def create_network_expert(llm=None) -> Agent:
    return Agent(
        role="固件网络配置修复专家",
        goal="修复QEMU虚拟机中的网络问题：DNS解析失败、端口冲突、网络接口未配置等",
        backstory=(
            "你是嵌入式网络配置专家。你熟悉QEMU虚拟网络（tap接口、NAT）"
            "和嵌入式设备的网络配置需求。"
            "请参考知识库中的网络修复流程和QEMU网络配置知识。"
        ),
        tools=[],
        llm=llm,
        verbose=True,
        planning_config=PlanningConfig(reasoning_effort="medium"),
        max_iter=20,
        allow_delegation=True,
        memory=False,
        knowledge_sources=_ks("network_expert"),
    )


def create_web_expert(llm=None) -> Agent:
    return Agent(
        role="HTTPD Web服务内容修复专家",
        goal="修复HTTPD服务的Web层面问题：HTTP 500/404错误、CGI脚本错误、配置文件问题等",
        backstory=(
            "你是嵌入式Web服务器配置专家。你熟悉GoAhead、Boa、lighttpd等"
            "嵌入式Web服务器的配置和运行机制。"
            "你的默认分析顺序必须是：先检查 Web 目录/页面/资源是否存在且完整，"
            "再检查配置文件与路径映射，只有这两步都确认没有明显问题时，才升级到二进制分析。"
            "如果 httpd 进程已经运行并端口已开放，启动日志只是辅助线索，不是你的主要分析对象。"
            "请参考知识库中的HTTP错误原因分析、CGI调试工作流和Web内容修复流程。"
        ),
        tools=[],
        llm=llm,
        verbose=True,
        planning_config=PlanningConfig(reasoning_effort="medium"),
        max_iter=20,
        allow_delegation=True,
        memory=False,
        knowledge_sources=_ks("web_expert"),
    )


def create_generic_expert(llm=None) -> Agent:
    # 通用专家合并所有知识
    parts = []
    for name in ["crash_expert", "file_expert", "network_expert", "web_expert", "diagnosis"]:
        c = format_for_context(name)
        if c:
            parts.append(f"=== {name} ===\n{c}")
    all_knowledge = "\n\n".join(parts) if parts else ""
    ks = [StringKnowledgeSource(content=all_knowledge)] if all_knowledge else []

    return Agent(
        role="固件运行时通用修复专家",
        goal="处理无法归类到特定类型的故障，综合运用所有可用工具修复",
        backstory=(
            "你是全能型固件调试专家。当其他专家无法处理时，你会接手。"
            "你拥有所有工具的使用权限，能从多个角度分析问题。"
            "你的知识库包含所有其他专家的知识。"
        ),
        tools=[],
        llm=llm,
        verbose=True,
        planning_config=PlanningConfig(reasoning_effort="medium"),
        max_iter=100,
        allow_delegation=True,
        memory=False,
        knowledge_sources=ks,
    )
