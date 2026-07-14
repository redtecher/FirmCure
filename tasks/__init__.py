"""
Task 定义导出
"""

from .phase1_tasks import (
    create_architecture_task,
    create_httpd_discovery_task,
    create_startup_analysis_task,
    create_report_task,
)
from .phase2_tasks import create_boot_diagnosis_task
from .phase3_tasks import (
    create_diagnosis_task,
    create_crash_repair_task,
    create_file_repair_task,
    create_network_repair_task,
    create_web_repair_task,
    create_generic_repair_task,
)

__all__ = [
    "create_architecture_task",
    "create_httpd_discovery_task",
    "create_startup_analysis_task",
    "create_report_task",
    "create_boot_diagnosis_task",
    "create_diagnosis_task",
    "create_crash_repair_task",
    "create_file_repair_task",
    "create_network_repair_task",
    "create_web_repair_task",
    "create_generic_repair_task",
]
