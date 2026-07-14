"""
配置管理 - 加载LLM和项目配置
所有配置优先从 FirmCure/resources/ 读取，兼容旧路径
"""

import os
import json
import sys
import logging
import tempfile
from pathlib import Path
from typing import Dict, Any

import yaml

logger = logging.getLogger(__name__)

# FirmCure 包目录
PACKAGE_DIR = Path(__file__).resolve().parent
# 项目根目录 (FirmCure/)
PROJECT_ROOT = PACKAGE_DIR.parent
# 配置目录 (FirmCure/config/)
CONFIG_DIR = PACKAGE_DIR / "config"
# 资源目录 (FirmCure/resources/)
RESOURCES_DIR = PACKAGE_DIR / "resources"

# 确保 sys.path 包含项目根目录
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def get_config_dir() -> Path:
    """获取配置目录路径"""
    return CONFIG_DIR


def load_config() -> Dict[str, Any]:
    """加载主配置文件 (config/config.yaml)"""
    p = CONFIG_DIR / "config.yaml"
    if p.exists():
        with open(p) as f:
            return yaml.safe_load(f) or {}
    return {}


def load_llm_config() -> Dict[str, Any]:
    """加载LLM配置 (config/config.json)"""
    p = CONFIG_DIR / "config.json"
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return {}


def get_resources_dir() -> Path:
    """获取资源目录路径"""
    return RESOURCES_DIR


def get_kernels_dir() -> Path:
    """获取内核文件目录"""
    return RESOURCES_DIR / "kernels"


def get_pre_compile_kernels_dir() -> Path:
    """获取预编译内核文件目录"""
    return RESOURCES_DIR / "pre_compile" / "kernels"


def get_lib_base_dir() -> Path:
    """获取替换库目录"""
    return RESOURCES_DIR / "lib_base"


def get_libnvram_dir() -> Path:
    """获取 libnvram-faker 资源目录（Greenhouse）"""
    return RESOURCES_DIR / "libnvram_faker"


def _setup_thinking_printer():
    """注册 litellm callback，将模型的思考过程打印到终端"""
    import litellm

    def _on_success(kwargs, completion_response, start_time, end_time):
        try:
            if not hasattr(completion_response, 'choices') or not completion_response.choices:
                return
            msg = completion_response.choices[0].message
            rc = getattr(msg, 'reasoning_content', None)
            if rc:
                print(f"\n\033[90m{'─' * 60}")
                print(f"💭 思考过程:")
                print(f"{'─' * 60}")
                text = rc if len(rc) <= 3000 else rc[:3000] + "\n... (已截断)"
                print(text)
                print(f"{'─' * 60}\033[0m\n")
        except Exception:
            pass

    # 保留现有 callback，避免覆盖别的行为。
    callbacks = list(getattr(litellm, "success_callback", []) or [])
    if _on_success not in callbacks:
        callbacks.append(_on_success)
    litellm.success_callback = callbacks


def _print_pre_tool_summary(text: str):
    """打印工具调用前的简短思考/计划摘要。

    这里打印的是模型已经显式返回的文本内容，不是额外推测的隐藏状态。
    """
    if not text:
        return
    cleaned = text.strip()
    if not cleaned:
        return
    if len(cleaned) > 3000:
        cleaned = cleaned[:3000] + "\n... (已截断)"
    print(f"\n\033[90m{'─' * 60}")
    print("📝 工具调用前思路:")
    print(f"{'─' * 60}")
    print(cleaned)
    print(f"{'─' * 60}\033[0m\n")


def _make_llm(temperature: float, max_tokens: int, enable_thinking: bool = False) -> "LLM":
    """创建 CrewAI LLM 实例，并修复国产模型的 function calling 兼容性问题。

    问题 1: litellm 无法识别 GLM 等国产模型，supports_function_calling() 返回 False，
    导致 CrewAI 退回到文本解析模式。实际上这些模型已支持 function calling。

    问题 2: GLM 等模型在返回 tool_calls 时同时返回文本内容(content)，
    而 CrewAI llm.py:1182 的逻辑是 "有文本就返回文本，忽略 tool_calls"。
    需要修正为：有 tool_calls 时优先返回 tool_calls。
    """
    from crewai import LLM

    llm_config = load_llm_config()

    api_key = llm_config.get("api_key", os.getenv("OPENAI_API_KEY", ""))
    base_url = llm_config.get("base_url", os.getenv("OPENAI_API_BASE", ""))
    model = llm_config.get("model", "gpt-4")
    max_tokens = llm_config.get("max_tokens", max_tokens)
    enable_thinking = llm_config.get("enable_thinking", enable_thinking)

    if "/" not in model:
        if "dashscope" in base_url:
            model = f"openai/{model}"
        elif "deepseek" in base_url:
            model = f"deepseek/{model}"
        else:
            model = f"openai/{model}"

    os.environ["OPENAI_API_KEY"] = api_key
    if base_url:
        os.environ["OPENAI_API_BASE"] = base_url
    os.environ["OPENAI_MODEL_NAME"] = model

    llm = LLM(
        model=model,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
        max_tokens=max_tokens,
    )

    if enable_thinking:
        _setup_thinking_printer()

    # 修复 1: 强制标记为支持 function calling（绕过 litellm 的模型白名单检测）
    llm.supports_function_calling = lambda: True

    # 修复 2: patch _handle_non_streaming_response，修正 tool_calls 被文本覆盖的 bug
    # 注意: DeepSeek (deepseek/ 前缀) 走 OpenAICompatibleCompletion，无此方法，跳过 patch
    if not hasattr(llm, '_handle_non_streaming_response'):
        return llm

    _original_handle_non_streaming = llm._handle_non_streaming_response

    def _patched_handle_non_streaming(params, **kwargs):
        import litellm as _litellm

        # 复用原始方法，但 hook litellm.completion 来拦截响应
        _real_completion = _litellm.completion

        def _intercepted_completion(**call_params):
            response = _real_completion(**call_params)
            # 检查响应：如果同时有 tool_calls 和 text，清空 text
            # 这样 CrewAI 的原始逻辑就能正确返回 tool_calls
            try:
                msg = response.choices[0].message
                if getattr(msg, "tool_calls", None) and msg.content:
                    _print_pre_tool_summary(str(msg.content))
                    msg.content = None  # 清空文本，让 CrewAI 走 tool_calls 路径
            except (AttributeError, IndexError):
                pass
            return response

        _litellm.completion = _intercepted_completion
        try:
            return _original_handle_non_streaming(params, **kwargs)
        finally:
            _litellm.completion = _real_completion

    llm._handle_non_streaming_response = _patched_handle_non_streaming

    return llm


def get_llm():
    """获取CrewAI兼容的LLM实例"""
    return _make_llm(temperature=0.7, max_tokens=64000, enable_thinking=True)


def get_memory_llm():
    """获取不带 enable_thinking 的 LLM，供 Memory 内部分析使用"""
    return _make_llm(temperature=0.3, max_tokens=4096)


# 当前 case 目录（由 main.py 在运行开始时设置）
_current_case_dir: str = ""


def set_case_dir(case_dir: str):
    """设置当前 case 目录路径"""
    global _current_case_dir
    _current_case_dir = case_dir
    # Knowledge/ChromaDB 使用共享存储目录
    os.environ["CREWAI_STORAGE_DIR"] = str(PACKAGE_DIR / ".crewai_storage")


def get_case_dir() -> str:
    """获取当前 case 目录"""
    return _current_case_dir


def get_memory_storage() -> str:
    """获取 Memory 存储路径（每次运行独立）"""
    if _current_case_dir:
        return str(Path(_current_case_dir) / ".memory")
    return str(Path(tempfile.mkdtemp()) / "memory")


def get_embedder_config() -> dict:
    """获取CrewAI Knowledge embedder配置，使用阿里云百炼embedding API"""
    llm_config = load_llm_config()
    embedding_api_key = llm_config.get("embedding_api_key", "")
    embedding_base_url = llm_config.get("embedding_base_url", "")
    embedding_model = llm_config.get("embedding_model", "text-embedding-v3")

    # 设置环境变量供 ChromaDB 的 OpenAIEmbeddingFunction 使用
    if embedding_api_key:
        os.environ["OPENAI_API_KEY"] = embedding_api_key
    if embedding_base_url:
        os.environ["OPENAI_BASE_URL"] = embedding_base_url

    return {
        "provider": "openai",
        "config": {
            "model_name": embedding_model,
            "api_key": embedding_api_key,
            "api_base": embedding_base_url,
        },
    }



def get_sudo_password() -> str:
    """获取sudo密码"""
    config = load_config()
    return config.get("sudo_password", os.getenv("SUDO_PASSWORD", ""))


def inject_sudo_password():
    """注入sudo密码到环境变量和核心模块"""
    password = get_sudo_password()
    if password:
        os.environ["SUDO_PASSWORD"] = password
        try:
            from core import network_setup as _ns
            _ns.SUDO_PASSWORD = password
        except Exception:
            pass
