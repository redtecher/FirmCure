"""
FirmCure 知识库管理

加载原始知识文件，创建 CrewAI KnowledgeSource 实例，
为各阶段 Agent 注入专家知识。

支持两种模式:
  1. CrewAI Knowledge (RAG) - 通过 knowledge_sources 注入 Agent/Crew
  2. 直接上下文注入 - 通过 format_for_context() 将知识注入 Task description
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

KNOWLEDGE_DIR = Path(__file__).resolve().parent

# ────────────────────────────────────────────────────────────────
# 原始知识加载 (复用 loader.py)
# ────────────────────────────────────────────────────────────────

_cache: Dict[str, dict] = {}


def _load_json(relative_path: str) -> dict:
    """加载知识 JSON 文件"""
    if relative_path in _cache:
        return _cache[relative_path]
    fp = KNOWLEDGE_DIR / relative_path
    if not fp.exists():
        logger.warning(f"Knowledge file not found: {fp}")
        return {}
    try:
        with open(fp, encoding="utf-8") as f:
            data = json.load(f)
        _cache[relative_path] = data
        return data
    except Exception as e:
        logger.error(f"Failed to load {fp}: {e}")
        return {}


def load_expert_knowledge(expert_name: str) -> dict:
    """加载专家知识 (phase1_analysis, crash_expert, file_expert 等)"""
    return _load_json(f"experts/{expert_name}.json")


def load_intervention_strategy(strategy_name: str) -> dict:
    """加载干预策略"""
    return _load_json(f"intervention/{strategy_name}.json")


def load_filesystem_signatures() -> dict:
    """加载文件系统签名库"""
    return _load_json("filesystem_signatures.json")


# ────────────────────────────────────────────────────────────────
# 知识格式化为上下文文本
# ────────────────────────────────────────────────────────────────

def format_for_context(expert_name: str, section: str = "") -> str:
    """将专家知识格式化为 LLM 可读的上下文字符串

    Args:
        expert_name: 专家名称
        section: 可选，只返回特定章节

    Returns:
        格式化后的知识文本
    """
    data = load_expert_knowledge(expert_name)
    if not data:
        return ""

    if section:
        data = data.get(section, {})
        if not data:
            return ""

    # 移除 schema 元数据
    clean = {k: v for k, v in data.items() if not k.startswith("$")}
    return json.dumps(clean, indent=2, ensure_ascii=False)


def format_intervention_for_context(strategy_name: str) -> str:
    """将干预策略格式化为上下文文本"""
    data = load_intervention_strategy(strategy_name)
    if not data:
        return ""
    clean = {k: v for k, v in data.items() if not k.startswith("$")}
    return json.dumps(clean, indent=2, ensure_ascii=False)


def retrieve_relevant_knowledge(expert_name: str, diagnosis: dict,
                                root_cause: str = "") -> dict:
    """根据诊断结果检索相关知识

    Args:
        expert_name: 专家名称
        diagnosis: 诊断报告 {"fault_type": "...", ...}
        root_cause: 根本原因描述
    """
    data = load_expert_knowledge(expert_name)
    if not data:
        return {}

    fault_type = diagnosis.get("fault_type", "unknown").lower()
    root_cause_lower = root_cause.lower() if root_cause else ""
    relevant = {}

    # 故障类型 -> 知识章节映射
    fault_keywords = {
        "file_missing": ["file_missing_workflow", "httpd_config_repair", "web_content_repair"],
        "permission_error": ["permission_fix", "file_missing_workflow"],
        "symlink_corruption": ["file_missing_workflow", "standard_device_nodes"],
        "premature_exit": ["boot_flow_analysis"],
        "network_error": ["boot_flow_analysis"],
        "web_error": ["http_500_causes", "http_404_causes", "cgi_debug_workflow"],
    }

    sections = fault_keywords.get(fault_type, ["file_missing_workflow"])
    for s in sections:
        if s in data:
            relevant[s] = data[s]

    # 关键词匹配
    keyword_map = {
        "rgdb": "httpd_config_repair", "config": "httpd_config_repair",
        "httpd.cfg": "httpd_config_repair", "boot": "boot_flow_analysis",
        "rcs": "boot_flow_analysis", "permission": "permission_fix",
        "denied": "permission_fix", "archive": "archive_handling",
        "tgz": "archive_handling", "www": "web_content_repair",
        "cgi": "cgi_debug_workflow", "500": "http_500_causes",
        "404": "http_404_causes", "breakpoint": "breakpoint_chaining_technique",
        "gdb": "breakpoint_chaining_technique", "crash": "breakpoint_chaining_technique",
        "segfault": "breakpoint_chaining_technique", "register": "breakpoint_chaining_technique",
    }
    for kw, sec in keyword_map.items():
        if kw in root_cause_lower and sec in data and sec not in relevant:
            relevant[sec] = data[sec]

    return relevant


def format_knowledge_for_llm(knowledge: dict) -> str:
    """将检索到的知识格式化为 LLM 可读字符串"""
    if not knowledge:
        return ""
    parts = []
    for section, content in knowledge.items():
        parts.append(f"## {section}")
        if isinstance(content, dict):
            parts.append(json.dumps(content, indent=2, ensure_ascii=False))
        else:
            parts.append(str(content))
        parts.append("")
    return "\n".join(parts)


# ────────────────────────────────────────────────────────────────
# CrewAI KnowledgeSource 创建
# ────────────────────────────────────────────────────────────────

def create_expert_knowledge_sources(expert_name: str) -> list:
    """为指定专家创建 CrewAI KnowledgeSource 列表

    使用 StringKnowledgeSource 将知识文本直接注入 Agent 上下文，
    不依赖外部 embedding 服务。

    Args:
        expert_name: phase1_analysis, crash_expert, file_expert 等

    Returns:
        CrewAI knowledge source 列表
    """
    try:
        from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource
    except ImportError:
        logger.warning("CrewAI knowledge module not available")
        return []

    content = format_for_context(expert_name)
    if not content:
        return []

    return [StringKnowledgeSource(content=content)]


def create_phase1_knowledge_sources() -> list:
    """Phase 1 固件分析知识"""
    return create_expert_knowledge_sources("phase1_analysis")


def create_phase2_knowledge_sources() -> list:
    """Phase 2 QEMU启动修复知识"""
    return create_expert_knowledge_sources("phase2_synthesis")


def create_diagnosis_knowledge_sources() -> list:
    """诊断知识"""
    return create_expert_knowledge_sources("diagnosis")


def create_crash_expert_knowledge_sources() -> list:
    """崩溃分析专家知识"""
    return create_expert_knowledge_sources("crash_expert")


def create_file_expert_knowledge_sources() -> list:
    """文件修复专家知识"""
    return create_expert_knowledge_sources("file_expert")


def create_network_expert_knowledge_sources() -> list:
    """网络修复专家知识"""
    return create_expert_knowledge_sources("network_expert")


def create_web_expert_knowledge_sources() -> list:
    """Web修复专家知识"""
    return create_expert_knowledge_sources("web_expert")


def create_generic_expert_knowledge_sources() -> list:
    """通用修复专家知识（合并所有专家知识）"""
    try:
        from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource
    except ImportError:
        return []

    parts = []
    for name in ["crash_expert", "file_expert", "network_expert", "web_expert", "diagnosis"]:
        content = format_for_context(name)
        if content:
            parts.append(f"=== {name} 知识 ===\n{content}")

    if not parts:
        return []
    return [StringKnowledgeSource(content="\n\n".join(parts))]
