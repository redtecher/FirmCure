"""Radare2 工具 - 基于 r2pipe 的二进制静态分析 (CrewAI BaseTool 封装)"""

import os
import re
import json
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any

import r2pipe
from crewai.tools import tool


R2_CMD_TIMEOUT = 60  # 增加到60秒，适应大型二进制文件


# ════════════════════════════════════════════════════════════════
# Backend: 纯 Python 封装 r2pipe，提供所有分析方法
# ════════════════════════════════════════════════════════════════

class Radare2Backend:
    """Radare2 静态分析后端

    提供 r2pipe 会话管理、路径解析、命令执行（带超时）等基础设施，
    以及反汇编、字符串提取、函数分析、交叉引用等高层分析方法。
    """

    def __init__(self, rootfs_path: str = ""):
        self._sessions: Dict[str, Any] = {}
        self.rootfs_path = rootfs_path

    # ── 路径解析 ──────────────────────────────────────────────

    def _resolve_binary_path(self, binary_path: str) -> str:
        if not binary_path:
            return ""
        if os.path.isabs(binary_path) and os.path.exists(binary_path):
            return binary_path
        if self.rootfs_path:
            full = Path(self.rootfs_path) / binary_path.lstrip("/")
            if full.exists():
                return str(full)
        return binary_path

    # ── 会话管理 ──────────────────────────────────────────────

    def _open_binary(self, binary_path: str) -> Any:
        if binary_path not in self._sessions:
            r2 = r2pipe.open(binary_path, flags=["-2"])
            self._cmd(r2, "aa")
            self._sessions[binary_path] = {
                "r2": r2,
                "strings_cache": None,
            }
        return self._sessions[binary_path]["r2"]

    def _get_r2(self, binary_path: str) -> Any:
        return self._open_binary(binary_path)

    def _close_binary(self, binary_path: str) -> bool:
        if binary_path in self._sessions:
            try:
                self._sessions[binary_path]["r2"].quit()
            except Exception:
                pass
            del self._sessions[binary_path]
            return True
        return False

    # ── 命令执行（线程 + 超时）────────────────────────────────

    def _cmd(self, r2, cmd: str, timeout: int = R2_CMD_TIMEOUT):
        result_box: list = [None]
        error_box: list = [None]

        def worker():
            try:
                result_box[0] = r2.cmd(cmd)
            except Exception as e:
                error_box[0] = e

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=timeout)

        if t.is_alive():
            return None
        if error_box[0] is not None:
            raise error_box[0]
        return result_box[0]

    def _cmdj(self, r2, cmd: str, timeout: int = R2_CMD_TIMEOUT):
        result_box: list = [None]
        error_box: list = [None]

        def worker():
            try:
                result_box[0] = r2.cmdj(cmd)
            except Exception as e:
                error_box[0] = e

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=timeout)

        if t.is_alive():
            return None
        if error_box[0] is not None:
            raise error_box[0]
        return result_box[0]

    # ── 基础分析方法 ──────────────────────────────────────────

    def get_info(self, binary_path: str) -> dict:
        """获取二进制文件基本信息（架构、位数、端序等）"""
        r2 = self._get_r2(binary_path)
        info = self._cmdj(r2, "ij")
        return info or {}

    def list_functions(self, binary_path: str, filter_name: str = "",
                       offset: int = 0, count: int = 100) -> dict:
        r2 = self._get_r2(binary_path)
        functions = self._cmdj(r2, "aflj") or []
        if filter_name:
            functions = [f for f in functions
                         if filter_name.lower() in f.get("name", "").lower()]
        total = len(functions)
        page = functions[offset:offset + count]
        return {"functions": page, "total": total, "offset": offset, "count": len(page)}

    def disassemble(self, binary_path: str, address: Optional[str] = None,
                    count: int = 20) -> str:
        r2 = self._get_r2(binary_path)
        if address:
            return self._cmd(r2, f"s {address}; pd {count}") or ""
        return self._cmd(r2, f"pd {count}") or ""

    def disassemble_function(self, binary_path: str, address: str) -> dict:
        """获取函数完整信息：反编译 + 汇编 + 签名"""
        r2 = self._get_r2(binary_path)
        self._cmd(r2, f"s {address}")
        info = self._cmdj(r2, f"afij @ {address}")
        signature = self._cmd(r2, f"afs @ {address}")
        decompiled = self._cmd(r2, "pdc")
        assembly = self._cmd(r2, "pdf")
        return {
            "address": address,
            "info": info[0] if info else None,
            "signature": signature.strip() if signature else None,
            "decompiled": decompiled,
            "assembly": assembly,
        }

    def analyze_function(self, binary_path: str, address: str) -> dict:
        """综合函数分析：信息 + xrefs + 字符串 + 反编译 + 签名"""
        r2 = self._get_r2(binary_path)
        info = self._cmdj(r2, f"afij @ {address}")
        xrefs_to = self._cmdj(r2, f"axtj @ {address}")
        xrefs_from = self._cmdj(r2, f"axfj @ {address}")
        strings = self._cmdj(r2, f"afsj @ {address}")
        assembly = self._cmd(r2, f"pdf @ {address}")
        decompiled = self._cmd(r2, f"pdc @ {address}")
        signature = self._cmd(r2, f"afs @ {address}")
        return {
            "address": address,
            "info": info[0] if info else None,
            "xrefs_to": xrefs_to or [],
            "xrefs_from": xrefs_from or [],
            "strings": strings or [],
            "assembly": assembly,
            "decompiled": decompiled,
            "signature": signature.strip() if signature else None,
        }

    def xrefs_to(self, binary_path: str, address: str) -> list:
        r2 = self._get_r2(binary_path)
        return self._cmdj(r2, f"axtj @ {address}") or []

    def xrefs_from(self, binary_path: str, address: str) -> list:
        r2 = self._get_r2(binary_path)
        return self._cmdj(r2, f"axfj @ {address}") or []

    def get_imports(self, binary_path: str) -> list:
        r2 = self._get_r2(binary_path)
        return self._cmdj(r2, "iij") or []

    def get_exports(self, binary_path: str) -> list:
        r2 = self._get_r2(binary_path)
        return self._cmdj(r2, "iEj") or []

    def get_symbols(self, binary_path: str) -> list:
        r2 = self._get_r2(binary_path)
        return self._cmdj(r2, "isj") or []

    def get_strings(self, binary_path: str, filter_text: str = "",
                    offset: int = 0, count: int = 100) -> dict:
        r2 = self._get_r2(binary_path)
        session = self._sessions[binary_path]
        if session["strings_cache"] is None:
            result = self._cmdj(r2, "izzj", timeout=60)
            session["strings_cache"] = result if result is not None else []
        strings = session["strings_cache"]
        if filter_text:
            strings = [s for s in strings
                       if filter_text.lower() in s.get("string", "").lower()]
        total = len(strings)
        page = strings[offset:offset + count]
        return {"strings": page, "total": total, "offset": offset, "count": len(page)}

    def get_segments(self, binary_path: str) -> list:
        r2 = self._get_r2(binary_path)
        return self._cmdj(r2, "iSj") or []

    def get_sections(self, binary_path: str) -> list:
        r2 = self._get_r2(binary_path)
        return self._cmdj(r2, "iSSj") or []

    def get_entrypoints(self, binary_path: str) -> list:
        r2 = self._get_r2(binary_path)
        return self._cmdj(r2, "iej") or []

    def execute_raw(self, binary_path: str, command: str) -> str:
        r2 = self._get_r2(binary_path)
        return self._cmd(r2, command) or ""

    # ── 独立分析方法（不使用会话缓存，每次新开 r2）──────────

    def r2_get_info(self, binary_path: str) -> dict:
        """独立获取二进制信息（新开 r2 会话）"""
        full_path = self._resolve_binary_path(binary_path)
        if not os.path.exists(full_path):
            return {"success": False, "error": f"文件不存在: {full_path}"}
        result_box = [None, None]

        def worker():
            r2 = None
            try:
                r2 = r2pipe.open(full_path)
                r2.cmd("aa")
                result_box[0] = r2.cmdj("ij")
            except Exception as e:
                result_box[1] = str(e)
            finally:
                if r2:
                    try:
                        r2.quit()
                    except Exception:
                        pass

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=30)
        if t.is_alive():
            return {"success": False, "error": "timeout"}
        if result_box[1]:
            return {"success": False, "error": result_box[1]}
        return {"success": True, "info": result_box[0], "path": full_path}

    def r2_get_strings(self, binary_path: str, filter_text: str = "") -> dict:
        """独立提取字符串（新开 r2 会话，含基地址修正）"""
        full_path = self._resolve_binary_path(binary_path)
        if not os.path.exists(full_path):
            return {"success": False, "error": f"文件不存在: {full_path}"}
        result_box = [None, None, 0]

        def worker():
            r2 = None
            baddr = 0
            try:
                r2 = r2pipe.open(full_path)
                info = r2.cmdj("ij")
                if info:
                    baddr = info.get("bin", {}).get("baddr", 0) or 0
                result_box[0] = r2.cmdj("izzj")
                result_box[2] = baddr
            except Exception as e:
                result_box[1] = str(e)
            finally:
                if r2:
                    try:
                        r2.quit()
                    except Exception:
                        pass

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=60)
        if t.is_alive():
            return {"success": False, "error": "timeout"}
        if result_box[1]:
            return {"success": False, "error": result_box[1]}

        baddr = result_box[2]
        strings = []
        raw = result_box[0]
        if raw:
            for s in raw:
                string_val = s.get("string", "")
                if len(string_val) >= 5:
                    if not filter_text or filter_text.lower() in string_val.lower():
                        vaddr_raw = s.get("vaddr", 0)
                        vaddr_fixed = vaddr_raw + baddr if vaddr_raw < baddr else vaddr_raw
                        strings.append({
                            "string": string_val,
                            "vaddr": hex(vaddr_fixed),
                            "paddr": hex(s.get("paddr", 0)),
                        })
                        if len(strings) >= 100:
                            break
        return {"success": True, "strings": strings[:50], "count": len(strings), "baddr": hex(baddr)}

    def r2_get_functions(self, binary_path: str) -> dict:
        """独立获取函数列表"""
        full_path = self._resolve_binary_path(binary_path)
        if not os.path.exists(full_path):
            return {"success": False, "error": f"文件不存在: {full_path}"}
        result_box = [None, None]

        def worker():
            r2 = None
            try:
                r2 = r2pipe.open(full_path)
                r2.cmd("aa")
                result_box[0] = r2.cmdj("aflj")
            except Exception as e:
                result_box[1] = str(e)
            finally:
                if r2:
                    try:
                        r2.quit()
                    except Exception:
                        pass

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=60)
        if t.is_alive():
            return {"success": False, "error": "timeout"}
        if result_box[1]:
            return {"success": False, "error": result_box[1]}
        functions = result_box[0] or []
        return {"success": True, "functions": functions[:100], "count": len(functions)}

    def r2_get_xrefs(self, binary_path: str, address: str) -> dict:
        """独立获取交叉引用（含两级分析：aa → aaa）"""
        full_path = self._resolve_binary_path(binary_path)
        if not os.path.exists(full_path):
            return {"success": False, "error": f"文件不存在: {full_path}"}
        if not address:
            return {"success": False, "error": "address 参数必须提供"}
        result_box = [None, None]

        def worker():
            r2 = None
            try:
                r2 = r2pipe.open(full_path)
                r2.cmd("e anal.strings=true")
                r2.cmd("aa")
                r2.cmd("aas")
                xrefs = r2.cmdj(f"axtj @ {address}") or []
                if not xrefs:
                    r2.cmd("aaa")
                    xrefs = r2.cmdj(f"axtj @ {address}") or []
                result_box[0] = xrefs
            except Exception as e:
                result_box[1] = str(e)
            finally:
                if r2:
                    try:
                        r2.quit()
                    except Exception:
                        pass

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=60)
        if t.is_alive():
            return {"success": False, "error": "timeout"}
        if result_box[1]:
            return {"success": False, "error": result_box[1]}
        xrefs = result_box[0] or []
        return {"success": True, "xrefs": xrefs[:50], "count": len(xrefs), "address": address}

    # ── 生命周期 ──────────────────────────────────────────────

    def cleanup(self):
        for binary_path in list(self._sessions.keys()):
            self._close_binary(binary_path)


# ════════════════════════════════════════════════════════════════
# CrewAI 工具工厂：生成与旧 MCP 工具同名的 CrewAI tool 实例
# ════════════════════════════════════════════════════════════════

_backends: list[Radare2Backend] = []


def create_radare2_tools(rootfs_path: str = "") -> list:
    """创建所有 Radare2 CrewAI 工具，共享同一个 Backend 实例。

    Args:
        rootfs_path: 固件 rootfs 宿主机路径，用于解析 VM 内路径。

    Returns:
        CrewAI tool 对象列表。
    """
    backend = Radare2Backend(rootfs_path=rootfs_path)
    _backends.append(backend)
    tools = []

    # ── open_file: 打开二进制文件，返回基本信息 ──
    @tool("open_file")
    def open_file(binary_path: str) -> str:
        """Open a binary file with radare2 for analysis. Returns binary info (arch, bits, endian, type, etc.).
        This must be called first before using other radare2 analysis tools.
        Args:
            binary_path: Absolute path to the binary file on the host machine (e.g., /home/user/rootfs/bin/httpd)
        """
        result = backend.get_info(binary_path)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(open_file)

    # ── analyze: 运行分析（已在 open_file 时自动执行 aa，此工具可执行深度分析）──
    @tool("analyze")
    def analyze(binary_path: str, command: str = "aaa") -> str:
        """Run deeper radare2 analysis on a binary (e.g., 'aaa' for full analysis, 'aac' for call analysis).
        Default runs 'aaa'. Use 'aas' for string analysis, 'aar' for reference analysis.
        Args:
            binary_path: Absolute path to the binary file
            command: Radare2 analysis command (default: 'aaa')
        """
        r2 = backend._get_r2(binary_path)
        result = backend._cmd(r2, command, timeout=60)
        return json.dumps({"success": True, "output": result or ""}, ensure_ascii=False)

    tools.append(analyze)

    # ── show_info: 获取二进制文件详细信息 ──
    @tool("show_info")
    def show_info(binary_path: str) -> str:
        """Get detailed binary information (architecture, bits, endian, compiler, libraries, etc.).
        Args:
            binary_path: Absolute path to the binary file
        """
        result = backend.get_info(binary_path)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(show_info)

    # ── list_strings: 列出数据段字符串 ──
    @tool("list_strings")
    def list_strings(binary_path: str, filter_text: str = "", offset: int = 0, count: int = 50) -> str:
        """List strings found in the binary's data sections. Supports filtering by keyword.
        Args:
            binary_path: Absolute path to the binary file
            filter_text: Optional keyword to filter strings (case-insensitive)
            offset: Pagination offset (default: 0)
            count: Number of strings to return (default: 50)
        """
        result = backend.get_strings(binary_path, filter_text=filter_text,
                                     offset=offset, count=count)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(list_strings)

    # ── list_all_strings: 列出全二进制字符串（含代码段）──
    @tool("list_all_strings")
    def list_all_strings(binary_path: str, filter_text: str = "", offset: int = 0, count: int = 50) -> str:
        """List ALL strings in the entire binary (including code sections). Uses izzj for comprehensive extraction.
        Args:
            binary_path: Absolute path to the binary file
            filter_text: Optional keyword to filter strings (case-insensitive)
            offset: Pagination offset (default: 0)
            count: Number of strings to return (default: 50)
        """
        result = backend.r2_get_strings(binary_path, filter_text=filter_text)
        strings = result.get("strings", [])
        if offset or count < len(strings):
            strings = strings[offset:offset + count]
        result["strings"] = strings
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(list_all_strings)

    # ── disassemble: 反汇编指定地址 ──
    @tool("disassemble")
    def disassemble(binary_path: str, address: str = "", count: int = 30) -> str:
        """Disassemble instructions at a given address. If no address given, disassembles from entry point.
        Args:
            binary_path: Absolute path to the binary file
            address: Hex address to start disassembly (e.g., '0x40a1c0')
            count: Number of instructions to disassemble (default: 30)
        """
        result = backend.disassemble(binary_path, address=address or None, count=count)
        return json.dumps({"success": True, "disassembly": result, "address": address}, ensure_ascii=False)

    tools.append(disassemble)

    # ── disassemble_function: 获取函数完整分析 ──
    @tool("disassemble_function")
    def disassemble_function(binary_path: str, address: str) -> str:
        """Get complete function analysis: assembly, decompiled pseudo-C, signature, and function info.
        Args:
            binary_path: Absolute path to the binary file
            address: Hex address of the function (e.g., '0x40a1c0')
        """
        result = backend.disassemble_function(binary_path, address)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(disassemble_function)

    # ── xrefs_to: 获取指向某地址的交叉引用 ──
    @tool("xrefs_to")
    def xrefs_to(binary_path: str, address: str) -> str:
        """Find all cross-references TO a given address (who calls/references this location).
        Uses two-pass analysis (aa then aaa) for ARM/MIPS firmware binaries.
        Args:
            binary_path: Absolute path to the binary file
            address: Target hex address (e.g., '0x40a1c0')
        """
        result = backend.r2_get_xrefs(binary_path, address)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(xrefs_to)

    # ── list_functions: 列出所有函数 ──
    @tool("list_functions")
    def list_functions(binary_path: str, filter_name: str = "", offset: int = 0, count: int = 50) -> str:
        """List all detected functions in the binary. Supports filtering by name.
        Args:
            binary_path: Absolute path to the binary file
            filter_name: Optional filter by function name (case-insensitive)
            offset: Pagination offset (default: 0)
            count: Number of functions to return (default: 50)
        """
        result = backend.list_functions(binary_path, filter_name=filter_name,
                                         offset=offset, count=count)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(list_functions)

    # ── list_imports: 列出导入符号 ──
    @tool("list_imports")
    def list_imports(binary_path: str) -> str:
        """List all imported symbols (PLT entries, external library functions).
        Args:
            binary_path: Absolute path to the binary file
        """
        result = backend.get_imports(binary_path)
        return json.dumps(result, ensure_ascii=False, indent=2)

    tools.append(list_imports)

    # ── list_sections: 列出段/节 ──
    @tool("list_sections")
    def list_sections(binary_path: str) -> str:
        """List binary sections and segments (.text, .data, .bss, etc.).
        Args:
            binary_path: Absolute path to the binary file
        """
        sections = backend.get_sections(binary_path)
        segments = backend.get_segments(binary_path)
        return json.dumps({"sections": sections, "segments": segments}, ensure_ascii=False, indent=2)

    tools.append(list_sections)

    # ── run_command: 执行任意 r2 命令 ──
    @tool("run_command")
    def run_command(binary_path: str, command: str) -> str:
        """Execute a raw radare2 command on an opened binary. Use for advanced analysis not covered by other tools.
        Args:
            binary_path: Absolute path to the binary file
            command: Radare2 command string (e.g., 'pdf @ sym.main', 'izj', 'aflj')
        """
        result = backend.execute_raw(binary_path, command)
        return json.dumps({"success": True, "output": result}, ensure_ascii=False)

    tools.append(run_command)

    return tools


def cleanup_all():
    """清理所有 Radare2Backend 实例的 r2pipe 会话"""
    for b in _backends:
        b.cleanup()
    _backends.clear()
