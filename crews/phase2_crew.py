"""
Phase 2 Crew - QEMU启动修复团队
仅在QEMU启动失败时使用

工具由外部通过 tools 参数传入。
"""

from crewai import Crew, Process

from agents.phase2_agents import create_synthesis_engineer
from tasks.phase2_tasks import create_boot_diagnosis_task
from config import get_embedder_config, get_llm


def create_phase2_repair_crew(
    rootfs_path: str,
    boot_log: str,
    qemu_command: str,
    architecture: str,
    llm=None,
    tools: list = None,
    repair_history: str = "",
    iteration: int = 1,
) -> Crew:
    if tools is None:
        raise RuntimeError("MCP tools are required but not provided. Phase 2 requires tools.")

    crew_llm = llm or get_llm()
    engineer = create_synthesis_engineer(rootfs_path, llm=crew_llm)
    engineer.tools = tools
    task = create_boot_diagnosis_task(
        rootfs_path=rootfs_path,
        boot_log=boot_log,
        qemu_command=qemu_command,
        architecture=architecture,
        agent=engineer,
        repair_history=repair_history,
        iteration=iteration,
    )

    return Crew(
        agents=[engineer],
        tasks=[task],
        process=Process.sequential,
        verbose=False,
        memory=False,
        embedder=get_embedder_config(),
    )
