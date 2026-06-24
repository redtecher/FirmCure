"""
专家知识库加载器

从 agent/knowledge/experts/ 加载 JSON 知识文件，
为各 Agent 提供精简的上下文注入。
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

EXPERTS_DIR = Path(__file__).parent

# 缓存已加载的知识
_cache: Dict[str, dict] = {}


def load_expert_knowledge(expert_name: str) -> dict:
    """加载指定专家的知识库"""
    if expert_name in _cache:
        return _cache[expert_name]

    json_file = EXPERTS_DIR / f"{expert_name}.json"
    if not json_file.exists():
        logger.warning(f"[KnowledgeLoader] 知识文件不存在: {json_file}")
        return {}

    try:
        with open(json_file) as f:
            data = json.load(f)
        _cache[expert_name] = data
        logger.info(f"[KnowledgeLoader] 已加载 {expert_name} 知识库 ({len(json.dumps(data))} bytes)")
        return data
    except Exception as e:
        logger.error(f"[KnowledgeLoader] 加载失败 {json_file}: {e}")
        return {}


def get_knowledge_context(expert_name: str, section: str = "") -> str:
    """
    获取专家知识作为 LLM 上下文字符串。

    Args:
        expert_name: 专家名称 (phase1_analysis, diagnosis, crash_expert, file_expert, network_expert, verification)
        section: 可选，只返回特定章节的内容
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


def retrieve_relevant_knowledge(expert_name: str, diagnosis: dict, root_cause: str = "") -> dict:
    """
    根据诊断结果检索相关知识。

    在专家形成方案前调用，匹配故障类型和关键词。

    Args:
        expert_name: 专家名称
        diagnosis: 诊断报告字典 {"fault_type": "...", "severity": "..."}
        root_cause: 根本原因描述

    Returns:
        匹配的知识片段字典
    """
    data = load_expert_knowledge(expert_name)
    if not data:
        return {}

    fault_type = diagnosis.get("fault_type", "unknown").lower()
    root_cause_lower = root_cause.lower() if root_cause else ""

    relevant = {}

    # 故障类型映射
    fault_keywords = {
        "file_missing": ["file_missing_workflow", "httpd_config_repair", "web_content_repair"],
        "permission_error": ["permission_fix", "file_missing_workflow"],
        "symlink_corruption": ["file_missing_workflow", "standard_device_nodes"],
        "premature_exit": ["boot_flow_analysis"],
        "network_error": ["boot_flow_analysis"],
        "web_error": ["http_500_causes", "http_404_causes", "cgi_debug_workflow"],
    }

    # 根据故障类型提取相关章节
    sections_to_extract = fault_keywords.get(fault_type, ["file_missing_workflow"])

    for section in sections_to_extract:
        if section in data:
            relevant[section] = data[section]

    # 关键词匹配：检查 root_cause 中的关键词
    keyword_mapping = {
        "rgdb": "httpd_config_repair",
        "config": "httpd_config_repair",
        "httpd.cfg": "httpd_config_repair",
        "webs_start": "httpd_config_repair",
        "boot": "boot_flow_analysis",
        "rcs": "boot_flow_analysis",
        "init.d": "boot_flow_analysis",
        "gpio": "boot_flow_analysis",
        "permission": "permission_fix",
        "denied": "permission_fix",
        "archive": "archive_handling",
        "tgz": "archive_handling",
        "tar": "archive_handling",
        "dev/": "standard_device_nodes",
        "device": "standard_device_nodes",
        "www": "web_content_repair",
        "web": "web_content_repair",
        "cgi": "cgi_debug_workflow",
        "500": "http_500_causes",
        "404": "http_404_causes",
        "internal server": "http_500_causes",
        "not found": "http_404_causes",
        "script error": "http_500_causes",
        "breakpoint": "breakpoint_chaining_technique",
        "断点": "breakpoint_chaining_technique",
        "gdb": "breakpoint_chaining_technique",
        "crash": "breakpoint_chaining_technique",
        "segmentation": "breakpoint_chaining_technique",
        "segfault": "breakpoint_chaining_technique",
        "register": "breakpoint_chaining_technique",
        "寄存器": "breakpoint_chaining_technique",
    }

    for keyword, section in keyword_mapping.items():
        if keyword in root_cause_lower and section in data:
            if section not in relevant:
                relevant[section] = data[section]

    return relevant


def format_knowledge_for_llm(knowledge: dict) -> str:
    """将检索到的知识格式化为 LLM 可读的字符串"""
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


def get_phase1_knowledge() -> str:
    """获取 Phase1 分析知识（运行时内容检测模式 + httpd 类型 + 启动脚本模板）"""
    return get_knowledge_context("phase1_analysis")


def get_diagnosis_routing() -> str:
    """获取诊断路由表"""
    data = load_expert_knowledge("diagnosis")
    if not data:
        return ""
    routing = data.get("fault_routing", {})
    hints = data.get("classification_hints", {})
    parts = []
    if routing:
        parts.append(json.dumps(routing, indent=2, ensure_ascii=False))
    if hints:
        parts.append(json.dumps(hints, indent=2, ensure_ascii=False))
    return "\n\n".join(parts)


def get_crash_workflow() -> str:
    """获取崩溃修复逆向分析流程"""
    data = load_expert_knowledge("crash_expert")
    if not data:
        return ""
    return json.dumps(
        {k: v for k, v in data.items() if not k.startswith("$")},
        indent=2, ensure_ascii=False
    )


def get_file_expert_workflow() -> str:
    """获取文件修复工作流"""
    data = load_expert_knowledge("file_expert")
    if not data:
        return ""
    return json.dumps(
        {k: v for k, v in data.items() if not k.startswith("$")},
        indent=2, ensure_ascii=False
    )


def get_network_knowledge() -> str:
    """获取网络修复知识"""
    return get_knowledge_context("network_expert")


def get_verification_workflow() -> str:
    """获取验证流程知识"""
    return get_knowledge_context("verification")


def get_web_expert_knowledge() -> str:
    """获取Web内容修复知识"""
    return get_knowledge_context("web_expert")


def get_phase2_synthesis_knowledge() -> str:
    """获取 Phase2 SynthesisAgent 启动阶段知识（CPU ISA、内核参数、故障模式）"""
    return get_knowledge_context("phase2_synthesis")
