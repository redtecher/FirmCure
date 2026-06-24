"""
Phase 1 Tasks - 固件分析任务定义 (多子任务拆分)
拆分为4个顺序子任务，确保Agent逐步完成完整分析
"""

from crewai import Task, Agent


def create_architecture_task(rootfs_path: str, agent: Agent) -> Task:
    """子任务1: 架构识别"""
    return Task(
        description=f"""识别固件的CPU架构信息。

固件rootfs路径: {rootfs_path}

步骤:
1. 使用 list_dir 查看 {rootfs_path} 的顶层目录结构
2. 使用 elf_info 检查以下关键二进制文件的架构:
   - {rootfs_path}/bin/busybox
   - {rootfs_path}/lib/libc.so.* 或 {rootfs_path}/lib/ld-*
   - {rootfs_path}/bin/httpd (如存在)
3. 根据file命令输出确定:
   - CPU架构: mips (大端) / mipsel (小端) / armhf / armel / x86_64
   - 位数: 32 或 64
   - 字节序: big 或 little
   - libc类型: uClibc / glibc / musl

你必须调用至少2次elf_info工具后才能给出结果。

输出JSON格式:
```json
{{{{
  "step": "architecture",
  "arch": "mipsel",
  "bits": 32,
  "endian": "little",
  "libc": "uClibc",
  "cpu": "mips32r2"
}}}}
```""",
        expected_output="JSON对象包含: step=architecture, arch, bits, endian, libc, cpu",
        agent=agent,
    )


def create_httpd_discovery_task(rootfs_path: str, agent: Agent) -> Task:
    """子任务2: HTTPD发现与配置分析"""
    return Task(
        description=f"""发现HTTPD Web服务器并分析其配置。

固件rootfs路径: {rootfs_path}

步骤:
1. 使用 find_files 在 {rootfs_path}/bin 和 {rootfs_path}/sbin 和 {rootfs_path}/usr/bin 和 {rootfs_path}/usr/sbin 中搜索以下二进制:
   httpd, mini_httpd, goahead, boa, lighttpd, nginx
2. 优先级: httpd > boa > lighttpd > nginx > 其他
   注意: 嵌入式固件中的httpd通常是厂商定制的，优先于nginx
3. 对找到的HTTPD二进制使用逆向工具提取字符串，查找:
   - 配置文件路径(如 /etc/*.conf)
   - web根目录路径
   - 端口号
   ⚠️ 逆向工具使用顺序: open_file(宿主机完整路径) → analyze(level=2) → list_strings/list_functions
   ⚠️ 嵌入式固件通常没有 'main' 符号，list_functions 不要用 filter='main'
4. 使用 read_file 读取HTTPD配置文件
5. 如果有多个配置文件，选择web_root与实际内容目录匹配的

你必须调用至少3次工具（find_files + 逆向字符串提取 + read_file）后才能给出结果。

输出JSON格式:
```json
{{{{
  "step": "httpd_discovery",
  "httpd_service": {{{{
    "binary_path": "/bin/httpd",
    "type": "goahead",
    "config_file": "/etc/goahead.conf",
    "port": 80,
    "web_root": "/web",
    "configs": []
  }}}},
  "config_files": [
    {{{{"file": "/etc/goahead.conf", "port": 80, "web_root": "/web", "matches_content": true}}}}
  ]
}}}}
```""",
        expected_output="JSON对象包含: step=httpd_discovery, httpd_service, config_files",
        agent=agent,
    )


def create_startup_analysis_task(rootfs_path: str, agent: Agent) -> Task:
    """子任务3: 启动序列与依赖分析"""
    return Task(
        description=f"""分析启动序列、后台守护进程和依赖关系。

固件rootfs路径: {rootfs_path}

步骤:
1. 使用 read_file 读取 {rootfs_path}/etc/inittab，确定init脚本路径
2. 使用 read_file 读取init脚本(通常是 /etc/init.d/rcS 或 /etc/rc.d/rcS)
3. 追踪启动流程: init → rcS → 各服务启动 → HTTPD启动
4. 识别rcS中启动的后台守护进程(如 system_manager, rc, cmd_agent 等带 & 的命令)
5. 对后台守护进程二进制使用逆向工具提取字符串，发现运行时操作(tar解压、目录创建、文件复制)
   ⚠️ 每个新二进制都必须先 open_file 再 analyze，然后才能查询
6. 使用 readelf_deps 检查HTTPD二进制的共享库依赖
7. 使用逆向工具检查HTTPD二进制的导入符号，识别NVRAM相关依赖(apmib_init, apmib_get, nvram_get, nvram_set, nvram_commit)
   ⚠️ open_file(httpd完整路径) → analyze(level=2) → list_imports
   ⚠️ 如果依赖库或导入函数里出现 apmib / nvram / flash_read_raw_mib / flash_write_raw_mib / tcapi 等痕迹，必须输出 `nvram_needed=true`
8. 从固件路径和文件内容推断厂商

你必须调用至少5次工具后才能给出结果。

输出JSON格式:
```json
{{{{
  "step": "startup_analysis",
  "startup_sequence": {{{{
    "init_script": "/etc/rc.d/rcS",
    "boot_flow": ["/etc/inittab", "/etc/rc.d/rcS", "网络初始化", "HTTPD启动"],
    "startup_scripts": ["/etc/rc.d/rcS"],
    "main_daemon": "rc",
    "httpd_startup": "/bin/httpd -p 80 -h /web"
  }}}},
  "dependencies": {{{{
    "shared_libraries": ["libpthread.so.0", "libc.so.0"],
    "direct_dependencies": ["libpthread.so.0", "libc.so.0"],
    "nvram_functions": [],
    "nvram_device": null,
    "missing_libs": []
  }}}},
  "nvram_needed": false,
  "nvram_arch": null,
  "vendor": "Tenda",
  "runtime_operations": "守护进程在启动时执行的运行时操作描述"
}}}}
```""",
        expected_output="JSON对象包含: step=startup_analysis, startup_sequence, dependencies, nvram_needed, nvram_arch, vendor",
        agent=agent,
    )


def create_report_task(rootfs_path: str, agent: Agent) -> Task:
    """子任务4: 汇总生成最终JSON报告"""
    return Task(
        description=f"""根据前面步骤收集的所有信息，生成最终的结构化JSON分析报告。

固件rootfs路径: {rootfs_path}

根据之前的分析结果，汇总并生成完整JSON。如果前面步骤遗漏了关键信息，
请使用工具补充调查。

特别注意:
- startup_script_content: 编写QEMU环境初始化shell脚本
  - 包含: 目录创建(/var/run /var/log /tmp等)、设备节点创建、文件系统挂载
  - 包含从守护进程分析发现的运行时操作(tar解压、配置复制等)
  - 不使用chroot、不启动HTTPD、不配置网络
  - **关键: 必须排除硬件依赖的守护进程**。QEMU仿真环境中以下类型程序会死循环或崩溃，绝对不能出现在startup.sh中:
    * 厂商定制硬件守护进程: cfmd, cmd_agent, system_manager, rc, cfm, netctrl
    * 设备管理器: udevd (mdev已在挂载阶段调用过)
    * 硬件监控/看门狗: moniter, watchdog, wdt
    * PHY/交换芯片控制: switch, phy, vlan_ctrl
    * 无线驱动相关: wifi, wps, hostapd
    只保留纯用户态服务
- httpd_command: 保持原始命令，不加LD_PRELOAD
- context_summary: 详细的中文Markdown分析报告

输出完整JSON:
```json
{{{{
  "architecture": {{{{
    "arch": "mipsel", "bits": 32, "endian": "little", "libc": "uClibc", "cpu": "mips32r2"
  }}}},
  "httpd_service": {{{{
    "binary_path": "/bin/httpd", "type": "goahead",
    "config_file": "/etc/goahead.conf", "port": 80, "web_root": "/web", "configs": []
  }}}},
  "startup_sequence": {{{{
    "init_script": "/etc/rc.d/rcS",
    "boot_flow": [], "startup_scripts": [],
    "main_daemon": "", "httpd_startup": ""
  }}}},
  "dependencies": {{{{
    "shared_libraries": [], "direct_dependencies": [],
    "nvram_functions": [], "nvram_device": null, "missing_libs": []
  }}}},
  "startup_script_content": "#!/bin/sh\\nmkdir -p /var/run /var/log /tmp\\n...",
  "httpd_command": "/bin/httpd -p 80 -h /web",
  "nvram_needed": false, "nvram_arch": null,
  "vendor": "Tenda",
  "context_summary": "## 固件分析报告\\n\\n### 架构信息\\n- CPU架构: ...\\n\\n### HTTPD服务\\n- ...\\n\\n### 启动序列\\n1. ...\\n\\n### NVRAM依赖\\n- ...\\n\\n### 关键发现\\n1. ...",
  "config_files": [],
  "rootfs_dir": "{rootfs_path}",
  "analysis_confidence": 0.7
}}}}
```""",
        expected_output=(
            "完整JSON对象，包含: architecture, httpd_service, startup_sequence, "
            "dependencies, startup_script_content, httpd_command, nvram_needed, "
            "nvram_arch, vendor, context_summary, config_files, rootfs_dir, analysis_confidence"
        ),
        agent=agent,
    )
