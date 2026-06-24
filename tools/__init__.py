"""
FirmCure 工具层

全部使用 CrewAI BaseTool 封装，无 MCP 依赖：
  - firmcure-tool/  → VM (QemuShell 直连) / 文件 / 网络工具
  - radare2-tool/   → 二进制静态分析 (r2pipe)
  - gdb-tool/       → GDB 动态调试 (gdb-multiarch subprocess)

旧 MCP 文件保留但不再使用：
  - firmcure_mcp_server.py, qemu_relay.py, radare2-mcp/, mcp-gdb/
"""
