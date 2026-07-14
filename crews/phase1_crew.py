"""
Phase 1 Crew - 固件分析团队 (多子任务)

工具由外部通过 MCP 传入（tools 参数）。
"""

from crewai import Crew, Process

from agents.phase1_agent import create_firmware_analyst
from tasks.phase1_tasks import (
    create_architecture_task,
    create_httpd_discovery_task,
    create_startup_analysis_task,
    create_report_task,
)
from config import get_embedder_config, get_llm


def create_phase1_crew(rootfs_path: str, llm=None, tools: list = None) -> Crew:
    if tools is None:
        raise RuntimeError("MCP tools are required but not provided. Phase 1 requires MCP Server to be running.")

    crew_llm = llm or get_llm()
    analyst = create_firmware_analyst(rootfs_path, llm=crew_llm)
    analyst.tools = tools

    t1 = create_architecture_task(rootfs_path, analyst)
    t2 = create_httpd_discovery_task(rootfs_path, analyst)
    t3 = create_startup_analysis_task(rootfs_path, analyst)
    t4 = create_report_task(rootfs_path, analyst)

    return Crew(
        agents=[analyst],
        tasks=[t1, t2, t3, t4],
        process=Process.sequential,
        verbose=False,
        memory=False,
        embedder=get_embedder_config(),
    )
