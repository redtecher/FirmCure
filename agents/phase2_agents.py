"""
Phase 2 Agents - QEMU仿真环境构建
"""

from crewai import Agent
from crewai.agent.planning_config import PlanningConfig
from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource

from knowledge import format_for_context


def create_synthesis_engineer(rootfs_path: str = "", llm=None) -> Agent:
    knowledge = format_for_context("phase2_synthesis")
    knowledge_sources = [StringKnowledgeSource(content=knowledge)] if knowledge else []

    return Agent(
        role="QEMU仿真环境诊断修复工程师",
        goal=(
            "分析QEMU启动失败日志，检查rootfs文件系统完整性，"
            "找出启动失败根因，**立即执行修复**（补充缺失库、修复符号链接、调整QEMU参数），"
            "使固件能在QEMU虚拟机中成功启动。"
            "**严禁空想不行动**——发现问题后必须立刻调用工具修复，不要反复分析。"
        ),
        backstory=(
            "你是QEMU虚拟化与嵌入式Linux系统专家。你擅长诊断MIPS/ARM架构的"
            "QEMU启动故障，包括Kernel Panic、共享库缺失、符号链接悬挂、"
            "init程序缺失等问题。\n\n"
            "## 工作原则（严格遵守）\n"
            "1. **先执行后总结**：发现问题后，立即调用工具修复，不要等分析完再修\n"
            "2. **每次只修一个关键问题**：修完一个就返回结果，让外层重新测试\n"
            "3. **不要反复分析同一个问题**：如果你已经确定了根因，直接修\n"
            "## 常见故障与修复方案\n"
            "- Kernel panic + VFS: rootfs挂载失败 → 检查磁盘镜像分区表\n"
            "- CPU ISA不匹配 → 调整QEMU -cpu参数\n"
            "- 共享库缺失 → 从lib_base复制或创建符号链接\n"
            "- /bin/sh缺失 → 确保busybox存在且/bin/sh符号链接正确\n"
            "- 权限问题 → 修复关键文件权限（755 for binaries）\n\n"
            "请参考知识库中的CPU ISA兼容性、内核参数配置和常见故障模式进行诊断。"
        ),
        tools=[],
        llm=llm,
        verbose=True,
        planning_config=PlanningConfig(reasoning_effort="low"),
        max_iter=10,
        allow_delegation=False,
        memory=False,
        knowledge_sources=knowledge_sources,
    )
