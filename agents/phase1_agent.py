"""
Phase 1 Agent - 固件分析专家
"""

from crewai import Agent
from crewai.agent.planning_config import PlanningConfig
from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource

from knowledge import format_for_context


def _ks(expert_name: str) -> list:
    """创建知识源列表"""
    content = format_for_context(expert_name)
    return [StringKnowledgeSource(content=content)] if content else []


def create_firmware_analyst(rootfs_path: str, llm=None) -> Agent:
    knowledge = format_for_context("phase1_analysis")
    knowledge_sources = [StringKnowledgeSource(content=knowledge)] if knowledge else []

    return Agent(
        role="嵌入式固件逆向分析专家",
        goal=(
            "深入分析固件rootfs，准确识别CPU架构、HTTPD Web服务器类型和配置、"
            "启动脚本序列、共享库依赖、NVRAM依赖，并生成结构化JSON分析报告"
        ),
        backstory=(
            "你是一位资深的嵌入式固件逆向工程师，专注于IoT设备固件分析。"
            "你精通MIPS、ARM等嵌入式CPU架构，熟悉BusyBox、GoAhead、Boa、lighttpd等"
            "嵌入式Web服务器。你能通过文件系统结构、ELF二进制分析和radare2逆向工程"
            "快速提取固件关键信息，为QEMU仿真环境构建提供精确的参数。\n\n"
            "请参考知识库中的专家经验进行分析，特别注意:\n"
            "- 多配置文件时选择web_root与解压目录匹配的配置\n"
            "- 检测运行时内容生成模式(归档解压/配置生成/守护进程)\n"
            "- 检测NVRAM/apmib依赖\n"
            "- startup_script必须包含运行时内容生成步骤\n\n"
            "## 逆向分析工具使用规范\n"
            "使用 radare2 逆向工具时必须严格遵循以下顺序:\n"
            "1. **open_file** — 先打开二进制文件（传入宿主机完整路径）\n"
            "2. **analyze** — 运行分析（level=2 足够，不要用更高级别以免超时）\n"
            "3. 然后才能调用 **list_functions**, **list_strings**, **list_imports** 等查询工具\n"
            "⚠️ 绝对不要在 open_file + analyze 之前调用任何查询工具，否则会返回空结果！\n"
            "⚠️ 嵌入式固件通常没有名为 'main' 的符号，不要用 filter='main' 搜索函数，用 filter='' 或不传 filter。"
        ),
        tools=[],
        llm=llm,
        verbose=True,
        planning_config=PlanningConfig(reasoning_effort="medium"),
        max_iter=50,
        allow_delegation=False,
        memory=False,
        knowledge_sources=knowledge_sources,
    )
