"""
CrewAI Agent 定义 - 所有阶段的智能体
"""

from .phase1_agent import create_firmware_analyst
from .phase2_agents import create_synthesis_engineer
from .phase3_agents import (
    create_diagnosis_agent,
    create_crash_expert,
    create_file_expert,
    create_network_expert,
    create_web_expert,
    create_generic_expert,
)

__all__ = [
    "create_firmware_analyst",
    "create_synthesis_engineer",
    "create_diagnosis_agent",
    "create_crash_expert",
    "create_file_expert",
    "create_network_expert",
    "create_web_expert",
    "create_generic_expert",
]
