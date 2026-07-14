#!/usr/bin/env python3
"""
Case 管理器 - 为 FirmCure 测试用例分配序号
"""

import os
from pathlib import Path
from typing import Dict, Any


class CaseManager:

    ARCH_ALIASES = {
        "arm": "armel",
        "arm 32-bit eabi5": "armel",
        "arm 32-bit": "armel",
        "arm 32-bit (arm eabi5)": "armel",
        "arm eabi5": "armel",
        "armv5": "armel",
        "armv7": "armhf",
        "armv7l": "armhf",
        "armv8": "arm64",
        "arm64": "arm64",
        "aarch64": "arm64",
        "mips 32-bit": "mips",
        "mips big endian": "mips",
        "mips little endian": "mipsel",
        "mipseb": "mips",
    }

    def __init__(self, scratch_dir: str = "scratch"):
        self.scratch_dir = Path(scratch_dir)
        self.scratch_dir.mkdir(parents=True, exist_ok=True)

    def get_next_case_number(self) -> str:
        """获取下一个用例序号（3位数字，例如 001, 002, ...）"""
        existing_cases = []

        for item in self.scratch_dir.iterdir():
            if item.is_dir() and item.name.isdigit():
                existing_cases.append(int(item.name))

        if existing_cases:
            next_num = max(existing_cases) + 1
        else:
            next_num = 1

        return f"{next_num:03d}"

    def _normalize_architecture(self, arch_raw: str) -> str:
        arch_lower = arch_raw.lower().strip()
        return self.ARCH_ALIASES.get(arch_lower, arch_lower)

    def create_case_dir(self, case_number: str = None) -> Path:
        if case_number is None:
            case_number = self.get_next_case_number()

        case_dir = self.scratch_dir / case_number
        case_dir.mkdir(parents=True, exist_ok=True)

        (case_dir / "phase1").mkdir(exist_ok=True)
        (case_dir / "phase2").mkdir(exist_ok=True)

        readme_path = case_dir / "README.md"
        if not readme_path.exists():
            with open(readme_path, 'w') as f:
                f.write(f"# Case {case_number}\n\n")
                f.write(f"## HTTPD Web 服务分析\n\n")
                f.write(f"- 创建时间: {self._get_timestamp()}\n\n")
                f.write(f"## 目录结构\n\n")
                f.write(f"```\n")
                f.write(f"scratch/{case_number}/\n")
                f.write(f"├── README.md\n")
                f.write(f"├── arch                      (架构: armel/armhf/mips/mipsel)\n")
                f.write(f"├── phase1/\n")
                f.write(f"│   ├── phase1_analysis.json  (完整分析结果)\n")
                f.write(f"│   ├── httpd_info.json       (HTTPD 服务信息)\n")
                f.write(f"│   ├── architecture.txt      (架构详细信息)\n")
                f.write(f"│   ├── startup.sh            (启动脚本)\n")
                f.write(f"│   └── CONTEXT_SUMMARY.md     (智能体上下文总结)\n")
                f.write(f"└── phase2/\n")
                f.write(f"    ├── rootfs.qcow2          (磁盘镜像)\n")
                f.write(f"    ├── run_qemu.sh           (QEMU 启动脚本)\n")
                f.write(f"    └── phase2_result.json    (Phase 2 结果)\n")
                f.write(f"```\n")

        return case_dir

    def save_case(self, case_number: str, data: Dict[str, Any]) -> Path:
        case_dir = self.create_case_dir(case_number)
        phase1_dir = case_dir / "phase1"

        import json
        with open(phase1_dir / "phase1_analysis.json", 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        arch_raw = data.get("architecture", "")
        arch_normalized = self._normalize_architecture(arch_raw)
        with open(case_dir / "arch", 'w') as f:
            f.write(arch_normalized)

        data["arch"] = arch_normalized

        httpd_info = {
            "firmware_name": data.get("firmware_name", "Unknown"),
            "rootfs_dir": data.get("rootfs_dir", ""),
            "architecture": data.get("architecture", ""),
            "httpd_binary": data.get("httpd_binary", ""),
            "httpd_type": data.get("httpd_type", ""),
            "web_root": data.get("web_root", ""),
            "port": data.get("port", ""),
            "startup_command": data.get("startup_command", ""),
        }
        with open(phase1_dir / "httpd_info.json", 'w') as f:
            json.dump(httpd_info, f, indent=2, ensure_ascii=False)

        arch_text = "HTTPD 服务信息\n"
        arch_text += "=" * 50 + "\n\n"
        arch_text += f"架构: {data.get('architecture', 'Unknown')}\n"
        arch_text += f"HTTPD: {data.get('httpd_binary', 'Unknown')}\n"
        arch_text += f"类型: {data.get('httpd_type', 'Unknown')}\n"
        arch_text += f"Web 根目录: {data.get('web_root', 'Unknown')}\n"
        arch_text += f"端口: {data.get('port', 'Unknown')}\n"
        arch_text += f"启动命令: {data.get('startup_command', 'Unknown')}\n\n"

        context = data.get("context", {})
        arch_text += "详细上下文:\n"
        arch_text += "-" * 50 + "\n"
        for key, value in context.items():
            arch_text += f"\n{key}:\n"
            if isinstance(value, list):
                for item in value[:5]:
                    arch_text += f"  - {item}\n"
                if len(value) > 5:
                    arch_text += f"  ... ({len(value)} items total)\n"
            elif isinstance(value, str) and len(value) > 100:
                arch_text += f"  {value[:100]}...\n"
            else:
                arch_text += f"  {value}\n"

        with open(phase1_dir / "architecture.txt", 'w') as f:
            f.write(arch_text)

        startup_script = self._generate_httpd_script(data)
        with open(phase1_dir / "startup.sh", 'w') as f:
            f.write(startup_script)

        context_summary = self._generate_context_summary(data)
        with open(phase1_dir / "CONTEXT_SUMMARY.md", 'w') as f:
            f.write(context_summary)

        self._update_case_index(case_number, data)

        return case_dir

    def _generate_httpd_script(self, data: Dict[str, Any]) -> str:
        """生成简化的 HTTPD 启动脚本（QEMU chroot 环境）"""
        httpd_binary = data.get("httpd_binary", "/bin/boa")
        web_root = data.get("web_root", "/web")
        port = data.get("port", 80)
        arch = data.get("architecture", "mips").lower()
        
        qemu_map = {
            "mips": "qemu-mips-static",
            "mipsel": "qemu-mipsel-static",
            "arm": "qemu-arm-static",
            "arm64": "qemu-aarch64-static",
            "aarch64": "qemu-aarch64-static",
            "x86": "qemu-i386-static",
            "x86_64": "qemu-x86_64-static",
        }
        qemu_binary = qemu_map.get(arch, "qemu-mips-static")
        
        script = f"""#!/bin/sh
# FirmCure - 简化HTTPD启动脚本
# 在QEMU chroot环境中运行

HTTPD="{httpd_binary}"
WEBROOT="{web_root}"
PORT="{port}"
QEMU="{qemu_binary}"

# 创建必要目录
mkdir -p /var/run /var/log /tmp

# 启动HTTPD
$HTTPD -p $PORT -h $WEBROOT
        """
        return script
    
    def _update_case_index(self, case_number: str, data: Dict[str, Any]):
        """更新 case 索引文件"""
        index_file = self.scratch_dir / "index.md"

        new_entry = f"""
## Case {case_number}

- **时间**: {self._get_timestamp()}
- **固件**: {data.get('firmware_name', 'Unknown')}
- **架构**: {data.get('architecture', 'Unknown')}
- **HTTPD**: {data.get('httpd_binary', 'Unknown')}
- **类型**: {data.get('httpd_type', 'Unknown')}
- **端口**: {data.get('port', 'Unknown')}
- **Rootfs**: {data.get('rootfs_dir', '')}

"""
        with open(index_file, 'a') as f:
            f.write(new_entry)

    def _generate_context_summary(self, data: Dict[str, Any]) -> str:
        """生成智能体上下文总结文档"""
        context = data.get("context", {})
        
        lines = []
        lines.append(f"# Case {data.get('case_number', 'XXX')} - 固件分析上下文总结")
        lines.append("")
        lines.append("> 本文档为后续智能体分析提供上下文，包含固件分析的关键发现和启动信息。")
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # 基本信息
        lines.append("## 1. 固件基本信息")
        lines.append("")
        lines.append(f"- **固件名称**: {data.get('firmware_name', 'Unknown')}")
        lines.append(f"- **Rootfs 路径**: `{data.get('rootfs_dir', 'Unknown')}`")
        lines.append(f"- **架构**: {data.get('architecture', 'Unknown')}")
        
        interpreter = context.get('interpreter', '')
        if interpreter:
            lines.append(f"- **解释器**: `{interpreter}`")
        else:
            lines.append(f"- **解释器**: `/lib/ld-uClibc.so.0` (默认)")
        
        libc_type = context.get('libc_type', 'Unknown')
        lines.append(f"- **Libc 类型**: {libc_type}")
        lines.append("")
        
        # HTTPD 服务
        lines.append("## 2. HTTPD Web 服务")
        lines.append("")
        lines.append(f"- **二进制文件**: `{data.get('httpd_binary', 'Unknown')}`")
        lines.append(f"- **服务类型**: {data.get('httpd_type', 'Unknown')}")
        lines.append(f"- **Web 根目录**: `{data.get('web_root', 'Unknown')}`")
        lines.append(f"- **监听端口**: {data.get('port', 'Unknown')}")
        lines.append(f"- **启动命令**: `{data.get('startup_command', 'Unknown')}`")
        lines.append("")
        
        # 启动流程
        startup_seq = context.get("startup_sequence", data.get("boot_sequence", []))
        startup_scripts = data.get("startup_scripts", [])
        services = context.get("services", data.get("services", []))
        
        lines.append("## 3. 启动流程")
        lines.append("")
        
        if startup_seq:
            lines.append("### 3.1 启动序列")
            lines.append("")
            lines.append("```")
            for step in startup_seq:
                lines.append(f"  {step}")
            lines.append("```")
            lines.append("")
        
        if startup_scripts:
            lines.append("### 3.2 启动脚本")
            lines.append("")
            for script in startup_scripts:
                lines.append(f"- `{script}`")
            lines.append("")
        
        if services:
            lines.append("### 3.3 启动的服务")
            lines.append("")
            for service in services[:10]:
                lines.append(f"- `{service}`")
            if len(services) > 10:
                lines.append(f"- ... (共 {len(services)} 个服务)")
            lines.append("")
        
        if not startup_seq and not startup_scripts and not services:
            lines.append("*未检测到启动流程信息*")
            lines.append("")
        
        # IPC 机制
        ipc = context.get("ipc_mechanism", {})
        if ipc:
            lines.append("## 4. IPC 通信机制")
            lines.append("")
            lines.append(f"- **Socket**: `{ipc.get('cfm_socket', 'Unknown')}`")
            lines.append(f"- **用途**: {ipc.get('purpose', 'Unknown')}")
            api_funcs = ipc.get("api_functions", [])
            if api_funcs:
                lines.append(f"- **API 函数**: `{', '.join(api_funcs[:5])}`")
                if len(api_funcs) > 5:
                    lines.append(f"  (共 {len(api_funcs)} 个函数)")
            lines.append("")
        else:
            lines.append("## 4. IPC 通信机制")
            lines.append("")
            lines.append("*未检测到IPC机制*")
            lines.append("")
        
        # NVRAM 配置
        nvram = context.get("nvram_config", {})
        if nvram:
            lines.append("## 5. NVRAM 配置")
            lines.append("")
            lines.append(f"- **设备**: `{nvram.get('device', 'Unknown')}`")
            lines.append(f"- **默认配置**: `{nvram.get('default_config', 'Unknown')}`")
            lines.append(f"- **NVRAM 工具**: `{nvram.get('nvram_binary', 'Unknown')}`")
            lines.append("")
        else:
            lines.append("## 5. NVRAM 配置")
            lines.append("")
            lines.append("*未检测到NVRAM配置*")
            lines.append("")
        
        # 依赖库
        deps = data.get("dependencies", [])
        if deps:
            lines.append("## 6. 关键依赖库")
            lines.append("")
            lib_paths = context.get("library_paths", {})
            for dep in deps[:8]:
                path_info = lib_paths.get(dep, "")
                if path_info:
                    lines.append(f"- `{dep}`: {path_info}")
                else:
                    lines.append(f"- `{dep}`")
            if len(deps) > 8:
                lines.append(f"- ... (共 {len(deps)} 个依赖)")
            lines.append("")
        
        # 需要的挂载
        mounts = data.get("required_mounts", [])
        if mounts:
            lines.append("## 7. 必需的文件系统挂载")
            lines.append("")
            for mnt in mounts:
                lines.append(f"- `{mnt}`")
            lines.append("")
        
        # 环境变量
        env_vars = data.get("environment_vars", {})
        if env_vars:
            lines.append("## 8. 环境变量")
            lines.append("")
            lines.append("```bash")
            for k, v in env_vars.items():
                lines.append(f'export {k}="{v}"')
            lines.append("```")
            lines.append("")
        else:
            lines.append("## 8. 环境变量")
            lines.append("")
            lines.append("*无特殊环境变量配置*")
            lines.append("")
        
        # 后续工作建议
        lines.append("## 9. 后续工作建议")
        lines.append("")
        lines.append("### Phase 2: QEMU 系统仿真")
        lines.append("```bash")
        lines.append(f"python phases/phase2_command_generation.py -a scratch/{data.get('case_number', 'XXX')}/phase1/phase1_analysis.json")
        lines.append("```")
        lines.append("")
        lines.append("### 启动脚本")
        lines.append("```bash")
        lines.append(f"cd scratch/{data.get('case_number', 'XXX')}/phase1")
        lines.append("chmod +x startup.sh")
        lines.append("./startup.sh")
        lines.append("```")
        lines.append("")
        
        lines.append("---")
        lines.append("")
        lines.append("## 文件列表")
        lines.append("")
        lines.append("| 文件 | 说明 |")
        lines.append("|------|------|")
        lines.append("| `phase1/phase1_analysis.json` | 完整分析结果 (JSON) |")
        lines.append("| `phase1/httpd_info.json` | HTTPD 服务基本信息 |")
        lines.append("| `phase1/architecture.txt` | 架构详细信息 |")
        lines.append("| `phase1/startup.sh` | 启动脚本 |")
        lines.append("| `phase1/CONTEXT_SUMMARY.md` | 本文档 |")
        lines.append("| `phase2/rootfs.ext2` | 磁盘镜像 |")
        lines.append("| `phase2/zImage-*` | 内核文件 |")
        lines.append("| `phase2/run_qemu.sh` | QEMU 启动脚本 |")
        lines.append("")
        
        return "\n".join(lines)

    def _get_timestamp(self) -> str:
        """获取当前时间戳"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def list_cases(self) -> list:
        """列出所有 cases"""
        cases = []
        for item in self.scratch_dir.iterdir():
            if item.is_dir() and item.name.isdigit():
                cases.append(item.name)
        return sorted(cases)
