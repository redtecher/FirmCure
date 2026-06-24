"""
Phase 3 Tasks - 运行时干预任务定义
"""

from crewai import Task, Agent

from knowledge import format_for_context

EXECUTION_DISCIPLINE = """## 执行纪律（所有专家必须遵守）
- **优先解决日志靠后出现的问题**：日志越靠后的错误离实际失败点越近，越靠前的越可能是已经被后续逻辑绕过的旧问题。因此应从日志末尾向上扫描，先定位并修复最后出现的错误
- 一旦定位到第一个可操作问题，最多再做 **1 次**确认性工具调用，然后必须立即实施修复
- 不要连续多轮纯分析、纯逆向、纯猜测而不执行任何修复动作
- 每次只解决 **一个** 问题，不要一口气并行修很多层
- 修复一个问题后，立即观察变化：
  - 如需重启，调用 `start_httpd`
  - 然后调用 `validate_network_stack()`
- 如果修复后暴露出新问题，记录它并结束当前回合，不要继续长时间思考
- 如果问题超出你的职责或你缺少对应工具，立即返回 `needs_rediagnosis=true`
"""


def create_diagnosis_task(
    agent: Agent,
    service_status: str,
    httpd_logs: str,
    iteration: int = 1,
) -> Task:
    """创建故障诊断任务"""
    return Task(
        description=f"""分析HTTPD服务启动失败的原因，分类故障类型。

## 当前状态 (第{iteration}轮干预)
{service_status}

## HTTPD日志
```
{httpd_logs[:6000]}
```

## 你的任务
分析上述信息，判断故障类型。只输出以下类型之一:
- PREMATURE_EXIT: 程序立即崩溃或退出
- DEPENDENCY_WAIT: 程序阻塞等待依赖（如NVRAM设备）
- FILE_MISSING: 缺少必要的文件或设备节点
- PERMISSION_ERROR: 权限不足
- SYMLINK_CORRUPTION: 符号链接损坏
- NETWORK_ERROR: 网络配置问题
- PORT_CONFLICT: 端口被占用
- WEB_ERROR: HTTP请求返回错误（如500/404）
- UNKNOWN: 无法归类

## 输出格式
```json
{{{{
  "fault_type": "FAULT_TYPE_HERE",
  "confidence": 0.9,
  "reasoning": "详细分析原因",
  "suggested_action": "建议的修复方向"
}}}}
```""",
        expected_output="JSON格式故障分类，包含fault_type、confidence、reasoning、suggested_action",
        agent=agent,
    )


def create_crash_repair_task(
    agent: Agent,
    fault_info: str,
    httpd_binary: str,
    iteration: int = 1,
    previous_chain: str = "",
    rootfs_path: str = "",
    architecture: str = "mips",
    endian: str = "little",
    httpd_output: str = "",
    breakpoint_chain_str: str = "",
    repair_history_str: str = "",
    phase1_data_str: str = "",
) -> Task:
    """创建崩溃修复任务 — 包含完整的断点链累积指令"""
    chain_info = breakpoint_chain_str if breakpoint_chain_str else (
        f"\n## 已有断点链\n```\n{previous_chain}\n```" if previous_chain else ""
    )
    tool_rules_context = format_for_context("crash_expert", "tool_usage_rules")
    # 计算 r2 用的宿主机绝对路径
    r2_binary_path = f"{rootfs_path.rstrip('/')}/{httpd_binary.lstrip('/')}" if rootfs_path else httpd_binary

    return Task(
        description=f"""你是固件修复专家，处理两类故障：崩溃和等待循环。请分析并修复HTTPD程序崩溃。

## ⚠️ 工具执行环境说明

你拥有三类工具，使用前请先查看可用工具列表了解具体的工具名和参数：

**逆向分析工具**（radare2）：用于在宿主机上静态分析二进制文件
- ⚠️ 必须严格按顺序调用: open_file(宿主机完整路径) → analyze(level=2) → 然后才能查询(list_strings/list_functions/disassemble等)
- 绝对不要在 open_file+analyze 之前调用查询工具，否则返回空结果
- 嵌入式固件通常没有 'main' 符号，不要用 filter='main'
- ⚠️ `xrefs_to` 已经会返回函数名和引用地址。拿到 xref 结果后，优先直接 `disassemble_function(address="函数起始地址")` 或 `disassemble(address="引用地址", count=30)`，不要再用 `list_functions(filter='fcn.xxx')` 兜一圈

**GDB调试工具**：高级封装，用于远程调试运行中的程序
- `gdb_run_script` — 核心工具，一次调用完成：设断点 → 启动httpd → 命中断点 → 修改寄存器 → 检查存活
- `gdb_trace_crash` — 崩溃根因分析：自动启动httpd、捕获崩溃现场、追溯外部函数调用点
- `gdb_backtrace` — 获取当前调用栈和寄存器状态
- `gdb_modify_register` — 简化版：单个断点 + 单个寄存器修改
- ⚠️ 不再需要手动管理 GDB 会话（不需要 gdb_start/gdb_load/target remote 等），工具内部自动处理

**系统操作工具**（FirmCure MCP）：
- `vm_exec`：在 **QEMU 全系统仿真** 里的 **BusyBox shell** 中执行命令，不是在宿主机执行
- `vm_exec` 只适合跑能力有限的基础命令：`ps`、`ls`、`cat`、`echo`、`netstat/ss`、`dmesg`、`kill`
- `vm_exec` 不适合执行复杂网络探测、宿主机路径命令、逆向工具、包管理器命令；很多常见命令在固件里根本不存在或输出不可靠
- 文件操作工具（read_file, write_file, find_files 等）：在宿主机上操作 rootfs
- 网络、服务检查、HTTP请求等

**禁止行为** （必须严格遵守，违反视为任务失败）：
- ❌ **严禁** 在 VM 内执行 r2、radare2、objdump、gdb 等逆向工具（VM 内没有这些工具）
- ❌ **严禁** 在 VM 内用 `curl` / `wget` 做 HTTP 验证（包括 localhost:80、127.0.0.1、10.10.10.2）
- ❌ **严禁** 用 `vm_exec` 直接启动 httpd（必须用 `start_httpd` 工具）
- ❌ **严禁** 在专家内部反复验证成功条件（如循环执行 `ps`、`netstat` 检查）
- ✅ 使用逆向分析工具在宿主机上分析二进制文件
- ✅ 使用 vm_exec 执行简单的 busybox 命令（如 `ps`、`ls`、`cat`）仅用于诊断
- ✅ 成功绕过断点后，必须调用 `validate_network_stack` 工具验证当前状态，并将验证结果包含在返回的JSON中

## ⚠️ 核心原则：断点链条累积

**重要**：固件启动过程中可能有多个阻塞点，你需要**累积所有成功的断点**形成断点链。

**断点链条工作流程**：
1. 第1轮：发现第一个阻塞点 → 设置断点绕过
2. 第2轮：程序继续执行，发现第二个阻塞点 → **累积**所有断点（旧的+新的）再次绕过
3. 重复直到 httpd 完全启动成功

**关键点**：
- 每次设断点时，必须包含**所有历史成功的断点地址**
- 寄存器修改必须包含所有断点（历史+新增）的寄存器修改值

## HTTPD 二进制信息
- 二进制路径(VM内): {httpd_binary}
- 二进制路径(宿主机): {r2_binary_path}
- 架构: {architecture} {endian}端序
- Rootfs: {rootfs_path}

## 故障信息 (第{iteration}轮)
{fault_info}

## HTTPD 启动日志
```
{httpd_output[:3000]}
```

## 固定知识片段（直接注入，避免知识检索遗漏）
以下规则来自 `crash_expert` 知识库，执行时必须遵守：
```json
{tool_rules_context[:2500] if tool_rules_context else "{}"}
```

{EXECUTION_DISCIPLINE}

## 崩溃分析指引
检查上方日志中 httpd 的报错信息是否充分：
- 如果**有具体的功能性报错**（如 "Initialize AP MIB failed"、"Connect Cfm failed" 等）→ 直接分析这些报错，定位问题并修复
- 如果**只有崩溃信号**（如 "Segmentation fault"、"SIGSEGV"，没有具体错误描述）→ 使用 GDB 动态捕获
  - 崩溃地址是**有效代码地址** → GDB 获取调用栈 + 逆向分析
  - 崩溃地址是**无效地址**（0x80xxxxxx、0x000000 等）→ GDB 捕获现场，追溯外部函数调用点，在调用点设断点跳过

## 故障类型判断
根据故障信息判断：
- **premature_exit**：崩溃类，httpd 收到信号退出（SIGSEGV/SIGABRT 等）
- **dependency_wait**：等待循环，httpd 进程运行中但端口未开放，卡在某个阻塞调用

## 修复策略（严格按步骤执行）

### 第一步：提取日志中的关键字符串
从故障信息或 HTTPD 启动日志中提取**最后出现的、有意义的错误/输出字符串**。
- 崩溃类：提取报错信息（如 "connect cfm failed!"、"Initialize AP MIB failed"）
- 等待类：提取 httpd 最后打印的输出字符串（阻塞点就在这个字符串打印之后）

### 第二步：逆向分析 — 字符串定位（必须执行）
**每次分析新二进制都必须先 open_file 再 analyze，否则后续工具全部返回空！**

1. `open_file("{r2_binary_path}")` — 打开 httpd 二进制
2. `analyze(level=2)` — 运行分析
3. `list_strings(filter="提取的关键词")` — 搜索字符串，获取其**虚拟地址**
   - 注意返回格式中地址在前，如 `0x00405678 "connect cfm failed!"`
   - 记录这个地址！

### 第三步：逆向分析 — 交叉引用（必须执行）
1. `xrefs_to(address="上一步获得的地址")` — 查找哪些代码引用了这个字符串
2. **如果 xrefs_to 返回结果**：
   - 得到引用该字符串的代码地址（如 `0x00401234`）
   - `xrefs_to` 输出通常同时带函数名，例如 `fcn.0002e420 0x2e544 ...`
   - 这时直接从函数名中提取函数起始地址 `0x2e420`，调用 `disassemble_function(address="0x2e420")`
   - 或直接对引用地址调用 `disassemble(address="0x2e544", count=30)` 查看上下文
3. **如果 xrefs_to 为空**（ARM/MIPS 固件常见）：
   - 用 `disassemble` 从字符串地址附近反汇编，找到引用它的指令
   - 或用 `list_functions` 获取函数列表，`disassemble_function` 反汇编主函数找到调用链

### 第四步：逆向分析 — 反汇编关键区域（必须执行）
1. `disassemble_function(address="引用字符串的函数地址")` — 反汇编包含字符串引用的函数
   - 或 `disassemble(address="引用地址", count=30)` 查看上下文
2. 在反汇编代码中找到：
   - 打印字符串的调用（如 `jal sym.imp.printf` 或 `bl printf`）
   - **打印之后**的下一条关键调用（这就是导致崩溃/阻塞的调用）
   - 该调用返回后的**比较/条件跳转指令**：
     * MIPS: `beqz/bnez/beq/bne/bgez/bltz` 后面的分支
     * ARM: `cmp` 后面的 `bgt/blt/beq/bne` 分支
3. 记录比较指令的地址 — **这就是需要设断点的位置**

### 第五步：GDB 断点绕过
有了断点地址后，使用 `gdb_run_script` 一次调用完成所有操作：

```
gdb_run_script(
    binary_path="{r2_binary_path}",
    breakpoints='["0x断点地址1", "0x断点地址2", ...]',  // JSON数组，包含所有历史+新断点
    register_values='{{"0x断点1": {{"$v0": "1"}}, "0x断点2": {{"$v0": "1"}}}}'  // JSON对象
)
```

工具会自动：清理残留进程 → 设置所有断点 → 启动GDB → 启动httpd → 命中断点时修改寄存器 → 检查存活

如果崩溃地址是无效地址（0x80xxxxxx、0x000000），使用 `gdb_trace_crash` 自动分析根因并找到所有外部函数调用点。

⚠️ **断点设在比较/条件跳转指令处（cmp/beqz/bnez），绝不能设在调用指令（bl/jal）处！**
⚠️ **breakpoints 必须包含所有历史断点 + 新断点，形成完整的断点链！**

## 工作流程（严格按阶段执行）

### 阶段1：分析日志，提取关键字符串
- 从故障信息和 HTTPD 日志中提取最后出现的错误/输出字符串
- 确定是崩溃类（有错误信号）还是等待类（进程在但端口不开）

### 阶段2：逆向分析（必须按顺序执行！）
**严格按 open_file → analyze → list_strings → xrefs_to → disassemble 顺序执行**
1. open_file + analyze 打开并分析二进制
2. list_strings 搜索关键字符串 → 获取地址
3. xrefs_to 查找交叉引用 → 定位引用代码
4. 对 xref 结果直接 `disassemble_function(address=函数起始地址)` 或 `disassemble(address=引用地址)`，不要再对 `fcn.xxx` 调 `list_functions(filter=...)`
5. 确定断点地址和需要修改的寄存器

### 阶段3：GDB 断点绕过
根据逆向分析结果，调用 `gdb_run_script` 设断点并修改寄存器绕过检查。
传入完整的断点链（breakpoints JSON数组）和寄存器修改（register_values JSON对象）。

### 阶段4：验证结果

### 阶段4：调用验证工具并返回结果

**成功判定标准**（基于日志 + 三层网络验证）：

1. `gdb_run_script()` 返回 `success=true` 且 `httpd_alive=True`
2. **AND** httpd启动日志中出现**新的输出**（相比之前的日志）
3. **AND** 调用 `validate_network_stack()` 工具进行三层验证（ping + nmap + curl）
4. **AND** 验证工具返回：network_reachable=true, port_open=true, http_responding=true

**关键**：专家负责调用验证工具，Manager 接收验证结果并判定成功/失败。

**返回 JSON**（包含验证结果）：
```json
{
  "success": true,
  "actions_taken": ["绕过 check_network 循环", "绕过 ConnectCfm 检查"],
  "breakpoint_chain": ["0x2e514", "0x2e538"],
  "register_changes": {"0x2e514": {"$r3": "1"}, "0x2e538": {"$r3": "1"}},
  "validation": {
    "network_reachable": true,
    "port_open": true,
    "http_responding": true,
    "simulation_level": "✅ 完全仿真（网络+端口+应用）"
  },
  "new_issue_detected": false,
  "needs_rediagnosis": false
}
```

**验证工具说明**：
- 工具名：`validate_network_stack()`
- 功能：执行三层网络验证（**仅验证，不修改任何进程**）
  - **第1层（ping）**：ICMP 连通性检查 → 10.10.10.2
  - **第2层（nmap）**：端口扫描 → 10.10.10.2:80
  - **第3层（curl）**：HTTP 应用层检查 → http://10.10.10.2:80/
- **【重要】此工具不会**：
  - ❌ 杀进程、重启 httpd
  - ❌ 修改 QEMU 或网络状态
  - ❌ 调用任何破坏性命令
  - ✅ 只通过宿主机命令检查当前服务状态
- 返回：验证结果 JSON，包含 network_reachable, port_open, http_responding, simulation_level

**工作流**：
```
日志有变化（证明断点触发）
    ↓
调用 validate_network_stack() 工具
    ↓
工具返回验证结果
    ↓
将验证结果包含在返回 JSON 中
    ↓
Manager 接收后判定：
  ├─ 三层验证都通过 → ✅ 成功
  └─ 某层失败 → ❌ 重诊（继续迭代）
```

**禁止行为**（严格遵守）：
- ❌ 不要在 VM 内用 `vm_exec` 执行验证命令
- ❌ 不要用 `curl/wget` 自己测试网页
- ✅ 只调用 `validate_network_stack()` 工具（宿主机验证）

**何时继续修复**：
- 验证通过但发现新的崩溃/阻塞点 → 继续累积断点链
- 新问题不属于崩溃/等待循环 → 标记 `needs_rediagnosis=true`

{chain_info}

{repair_history_str}

{phase1_data_str}

## MIPS/ARM 寄存器约定
- MIPS: $a0-$a3 参数, $v0 返回值, $sp/$ra/$t0-$t9/$s0-$s7
- ARM: r0-r3 参数, r0 返回值, sp/lr/r4-r11
- 断点命中后设 $v0(或r0)=1 通常表示成功，设为0表示失败跳过

## 输出格式（严格遵守）
```json
{{{{
  "success": true,
  "actions_taken": ["绕过 check_network 循环"],
  "breakpoint_chain": ["0x2e514", "0x2e538"],
  "register_changes": {{"0x2e514": {{"$r3": "1"}}, "0x2e538": {{"$r3": "1"}}}},
  "new_issue_detected": false,
  "new_issue_description": "",
  "needs_rediagnosis": false,
  "validation": {
    "summary": {
      "network_reachable": true,
      "port_open": true,
      "http_responding": true,
      "overall_success": true
    }
  },
}}}}
```

**字段说明**：
- `breakpoint_chain`: 完整的断点链（包含所有历史成功的断点地址 + 新增地址）
- `register_changes`: 所有断点对应的寄存器修改（必须包含所有历史+新增，不要遗漏）
- `new_issue_detected`: 是否发现新问题
- `needs_rediagnosis`: 是否需要重新诊断（true 表示交给其他专家）
- `validation`: 验证结果（必须包含，即使修复失败也要说明）

**重要提醒**：
- 每次设断点时，必须传入完整的断点链（所有历史断点 + 新断点）
- 成功绕过一个阻塞点后，必须调用 `validate_network_stack` 工具验证
- 修复完成后必须包含验证结果在 `validation` 字段中
- 302重定向到main.html是正常行为，应该算成功

请一步步思考，先规划后执行，不要边想边做。

**注意**：修复成功后必须立即调用验证工具，将验证结果包含在返回中。""",
        expected_output="JSON格式崩溃修复报告，包含 success, actions_taken, breakpoint_chain, register_changes, new_issue_detected, needs_rediagnosis, validation",
        agent=agent,
    )


def create_file_repair_task(
    agent: Agent,
    fault_info: str,
    iteration: int = 1,
    rootfs_path: str = "",
    httpd_binary: str = "",
    architecture: str = "mips",
    httpd_output: str = "",
    repair_history_str: str = "",
    phase1_data_str: str = "",
) -> Task:
    """创建文件修复任务"""
    return Task(
        description=f"""你是固件文件系统修复专家。请修复文件系统问题。

## ⚠️ 工具执行环境说明

你拥有以下工具，使用前请先查看可用工具列表了解具体的工具名和参数：

**系统操作工具**（FirmCure MCP）：
- 文件操作工具：read_file, write_file, find_files, list_dir 等（默认操作 rootfs）
- `vm_exec`：在 QEMU VM 内执行 busybox shell 命令
- `start_httpd`：启动 httpd 服务（**必须使用此工具启动 httpd**，会自动处理断点链）

**逆向分析工具**（radare2 MCP）：如需分析二进制文件中的字符串，可使用逆向工具
- ⚠️ 顺序: open_file → analyze(level=2) → list_strings 等查询

**禁止行为**：
- ❌ 不要在 VM 内执行 r2、radare2、find 等工具（VM 内没有这些工具）
- ❌ 不要用 `vm_exec` 直接启动 httpd（必须用 `start_httpd` 工具）
- ✅ 使用文件操作工具在宿主机上检查 rootfs 文件
- ✅ 使用 vm_exec 执行简单的 busybox 命令

## 故障信息 (第{iteration}轮)
{fault_info}

## HTTPD 启动日志
```
{httpd_output[:2000]}
```

**说明**：
- 这里的启动日志只是辅助线索，不是 WebExpert 的主要分析对象
- 既然二进制已经启动并在监听端口，WebExpert 的主要任务是解决“访问为什么异常”，而不是重新判断“程序为什么启动”
- 你的主要分析对象应是：页面访问路径、重定向行为、WebRoot 内容、配置映射、CGI/脚本执行链路

## 环境信息
- Rootfs: {rootfs_path}
- HTTPD二进制: {httpd_binary}
- 架构: {architecture}

{EXECUTION_DISCIPLINE}

{repair_history_str}

{phase1_data_str}

## 工作流程

### 阶段1：分析
- 分析故障信息和日志，定位缺失/损坏的文件
- 使用 find_files 查找文件，read_file 读取内容
- **注意**：文件操作可能遇到权限问题，跳过无法访问的文件并继续

### 阶段2：规划
输出修复规划（不执行），列出需要创建/修复的文件

### 阶段3：执行修复
逐步执行修复，每步验证结果：
- 创建缺失的文件或设备节点
- 修改文件权限
- 修复损坏的符号链接
- 复制缺失的库文件或配置

### 阶段4：启动 httpd 并验证
**文件修复完成后，必须按顺序执行以下两步，不要做其他事情：**
1. 调用 `start_httpd()` 工具启动 httpd 服务（它会自动处理断点链）
2. 调用 `validate_network_stack()` 工具验证网络状态
3. 将验证结果包含在返回的 JSON 中，结束任务

**禁止**：不要在 VM 内搜索 startup.sh 或尝试手动启动 httpd，不要反复检查文件状态。

**重要**：
- 如果某个工具执行失败（如出现[F]错误），跳过该步骤并继续
- 不要因为单个文件访问失败而停止整个任务

## 输出格式（严格遵守）
```json
{{{{
  "success": true,
  "expert_name": "file_expert",
  "actions_taken": ["创建缺失的设备节点 /dev/nvram", "修复符号链接 /bin/sh"],
  "modified_files": ["/dev/nvram", "/bin/sh"],
  "new_issue_detected": false,
  "new_issue_description": "",
  "needs_rediagnosis": false,
  "validation": {
    "summary": {
      "network_reachable": true,
      "port_open": true,
      "http_responding": true,
      "overall_success": true
    }
  }
}}}}
```

**字段说明**：
- `actions_taken`: 执行的修复操作列表
- `modified_files`: 修改/创建的文件路径列表
- `new_issue_detected`: 修复后是否发现新问题
- `needs_rediagnosis`: 是否需要重新诊断并路由到其他专家
- `validation`: 验证结果（修复完成后必须调用 validate_network_stack 并包含结果）

请一步步思考，先规划后执行。""",
        expected_output="JSON格式文件修复报告，包含 success, actions_taken, modified_files, new_issue_detected, needs_rediagnosis, validation",
        agent=agent,
    )


def create_network_repair_task(
    agent: Agent,
    fault_info: str,
    iteration: int = 1,
    rootfs_path: str = "",
    httpd_binary: str = "",
    architecture: str = "",
    httpd_output: str = "",
    repair_history_str: str = "",
    phase1_data_str: str = "",
) -> Task:
    """创建网络修复任务"""
    return Task(
        description=f"""你是固件网络配置修复专家。请修复网络相关问题。

## ⚠️ 工具执行环境说明

**宿主机工具**（在宿主机上执行）：
- 可以在宿主机使用 ping、nmap、nc、curl 等工具检查网络连通性

**VM 内工具**（在 QEMU VM 内执行）：
- `vm_exec`：在 VM 内执行 shell 命令
- `start_httpd`：启动 httpd 服务（**必须使用此工具启动 httpd**，会自动处理断点链）
- 可以通过 vm_exec 配置网络接口、路由、DNS 等

## 故障信息 (第{iteration}轮)
{fault_info}

## HTTPD 启动日志
```
{httpd_output[:2000]}
```

## 环境信息
- Rootfs: {rootfs_path}
- HTTPD二进制: {httpd_binary}
- 架构: {architecture}
- VM IP: 10.10.10.2
- HTTPD端口: 80

{EXECUTION_DISCIPLINE}

{repair_history_str}

{phase1_data_str}

## 常见网络问题修复模式

1. **端口冲突**: 使用 vm_exec 找到占用端口的进程，kill 后重启
2. **DNS解析失败**: 在 VM 内通过 vm_exec 向 /etc/hosts 添加条目
3. **网络接口未配置**: 使用 vm_exec 配置 eth0 IP 地址
4. **路由缺失**: 使用 vm_exec 添加默认路由
5. **iptables 阻断**: 使用 vm_exec 清空 iptables 规则

## 工作流程

### 阶段1：探测
- 从宿主机 ping VM 检查网络连通性
- 使用 vm_exec 在 VM 内检查网络接口状态、路由、DNS

### 阶段2：规划
输出修复规划（不执行）

### 阶段3：执行
逐步执行修复，每步验证结果

### 阶段4：判断是否完成
- 如果你认为修复已生效，必须先调用 `validate_network_stack()`，把验证结果带回给 Manager
- 如果发现新问题且不属于网络范围，标记 needs_rediagnosis=true
- 如果没有新问题，标记任务完成

## 输出格式（严格遵守）
```json
{{{{
  "success": true,
  "expert_name": "network_expert",
  "actions_taken": ["配置 eth0 IP地址", "添加默认路由"],
  "new_issue_detected": false,
  "new_issue_description": "",
  "needs_rediagnosis": false,
  "validation": {
    "summary": {
      "network_reachable": true,
      "port_open": true,
      "http_responding": true,
      "overall_success": true
    }
  }
}}}}
```

**字段说明**：
- `validation`: 验证结果（修复完成后必须调用 validate_network_stack 并包含结果）

请一步步思考，先规划后执行。""",
        expected_output="JSON格式网络修复报告，包含 success, actions_taken, new_issue_detected, needs_rediagnosis, validation",
        agent=agent,
    )


def create_web_repair_task(
    agent: Agent,
    fault_info: str,
    http_status: str = "",
    iteration: int = 1,
    rootfs_path: str = "",
    httpd_binary: str = "",
    architecture: str = "",
    httpd_output: str = "",
    repair_history_str: str = "",
    phase1_data_str: str = "",
) -> Task:
    """创建Web服务修复任务"""
    return Task(
        description=f"""你是 HTTPD Web 服务内容修复专家。httpd 进程已经在运行，你的任务是处理 **Web 层** 问题，而不是二进制崩溃或底层网络问题。

## 职责边界

你负责分析和修复：
- Web 根目录内容是否完整、是否为空、是否映射错误
- 配置文件里的站点路径、别名、DocumentRoot/WebRoot、CGI/FastCGI 路径
- 页面文件、模板、静态资源、重定向规则
- CGI 脚本或页面依赖的权限、路径、可执行性
- 启动脚本或运行时初始化是否正确生成/拷贝了 Web 内容
- Web 层返回异常：302 循环、404、500、空白页、错误跳转、伪成功页面

你不负责：
- 二进制逆向和 GDB 断点修复
- 守护进程缺失、socket 依赖、崩溃类问题
- 纯网络连通性问题

如果你判断问题不属于 Web 层，请明确说明原因，并设置 `needs_rediagnosis=true`。

## 工具使用原则

- 宿主机文件工具用于检查和修改 rootfs 中的配置、页面、脚本
- `vm_exec` 只用于观察 QEMU 内当前文件状态、运行时目录状态、脚本执行结果
- `http_request` / `http_get_body` 用于理解当前 Web 行为
- `validate_network_stack()` 用于修复后的统一验证

不要预设某一种固件目录结构，也不要假设固定的 WebRoot 路径。应根据当前固件实际内容做判断。

## ⚠️ 启动 httpd 的规则

- **修复 Web 目录内容**（拷贝文件、创建目录、修改页面、修复权限等）→ **不需要重启 httpd**，直接调用 `validate_network_stack()` 验证即可
- **修改了 httpd 配置文件**（修改了 httpd.conf、lighttpd.conf 等）→ 才需要调用 `start_httpd` 重启服务使配置生效
- **发现问题属于二进制层面**（如硬编码逻辑、守护进程崩溃等）→ 不要尝试修复，设置 `needs_rediagnosis=true` 交回 Manager

## 故障信息 (第{iteration}轮)
{fault_info}

## HTTP状态
{http_status}

## HTTPD 启动日志
```
{httpd_output[:2000]}
```

## 环境信息
- Rootfs: {rootfs_path}
- HTTPD二进制: {httpd_binary}
- 架构: {architecture}

{EXECUTION_DISCIPLINE}

{repair_history_str}

{phase1_data_str}

## 分析思路

建议按下面的顺序推进，但不要机械套模板：

1. **先查 Web 目录问题**
- 先确认 Web 根目录、静态资源、首页文件、模板、CGI 目录是否存在
- 先判断目录是否为空、是否指向错误位置、是否缺少运行时生成内容
- 先检查权限、符号链接、脚本可执行性
- 如果在这一步已经发现明显问题，优先修这个，不要急着看配置或二进制

2. **再查配置文件问题**
- 只有在 Web 目录和资源看起来基本正常后，才继续检查配置文件
- 重点看配置中的 DocumentRoot/WebRoot、alias、rewrite、CGI/FastCGI 路径是否与实际文件一致
- 同时判断启动脚本或运行时初始化是否把内容部署到了配置所指向的位置

3. **只有前两步都确认没问题，才转到二进制分析**
- 如果 Web 目录和配置文件都没有明显问题，才考虑二进制中是否存在硬编码路径、特殊路由逻辑或厂商自定义 Web 初始化逻辑
- 二进制分析不是默认第一步，而是最后的升级路径

4. **重点理解当前访问行为**
- 当前是重定向、404、500、空白页，还是返回了错误内容
- 返回行为是否像“站点存在但资源路径不对”，还是“站点根本没有初始化好”
- 不要被启动日志中的守护进程报错牵着走，除非它能直接解释当前访问异常

5. 修复时优先做最小改动
- 优先修正明显错误的路径、权限、内容缺失
- 不要为了单一固件去硬编码某种目录结构
- 每次修改都应有明确理由，并说明它解决的是哪类 Web 层问题

6. 修复后统一验证
- 如果你判断修复已完成，调用 `validate_network_stack()`
- 将验证结果放进返回 JSON，交给 Manager 决定是否成功结束或继续路由

## ⚠️ 禁止循环验证

修复完成后，**只调用一次** `validate_network_stack()`，拿到结果后**立即**输出最终 JSON 并结束。
**禁止**反复调用 `http_request`、`vm_exec ps`、`check_service_running` 等工具做额外验证。
validate_network_stack 的结果就是最终判定，无论通过与否都必须立即返回。

## 判断标准

- 如果三层验证都通过，说明 Web 层已修复成功
- 如果网络和端口正常，但 HTTP 仍异常，说明仍是 Web 层问题，可继续分析
- 如果问题已经明显转化为二进制/守护进程/网络层问题，应交回 Manager 重路由

## 输出格式（严格遵守）
```json
{{{{
  "success": true,
  "expert_name": "web_expert",
  "actions_taken": ["拷贝 webroot_ro 到 /var/webroot", "修复 index.html 权限"],
  "new_issue_detected": false,
  "new_issue_description": "",
  "needs_rediagnosis": false,
  "validation": {{{{
    "summary": {{{{
      "network_reachable": true,
      "port_open": true,
      "http_responding": true,
      "overall_success": true
    }}}}
  }}}}
}}}}
```

请先诊断，再修复，最后验证。默认不要分析二进制；只有 Web 目录和配置文件都确认没问题时，才升级到二进制分析。""",
        expected_output="JSON格式Web修复报告，包含 success, actions_taken, validation",
        agent=agent,
    )


def create_generic_repair_task(
    agent: Agent,
    fault_info: str,
    iteration: int = 1,
    rootfs_path: str = "",
    httpd_binary: str = "",
    architecture: str = "",
    httpd_output: str = "",
    breakpoint_chain_str: str = "",
    repair_history_str: str = "",
    phase1_data_str: str = "",
) -> Task:
    """创建通用修复任务 — 注入全部专家知识，指导多维度问题解决"""
    # 注入各专家的核心知识片段
    crash_knowledge = format_for_context("crash_expert", "tool_usage_rules") or ""
    gdb_knowledge = format_for_context("crash_expert", "gdb_remote_debugging_workflow") or ""
    re_knowledge = format_for_context("crash_expert", "reverse_engineering_workflow") or ""
    file_knowledge = format_for_context("file_expert", "httpd_config_repair") or ""
    net_knowledge = format_for_context("network_expert", "network_error") or ""
    web_500 = format_for_context("web_expert", "http_500_causes") or ""
    web_404 = format_for_context("web_expert", "http_404_causes") or ""
    fault_routing = format_for_context("diagnosis", "fault_routing") or ""

    r2_binary_path = f"{rootfs_path.rstrip('/')}/{httpd_binary.lstrip('/')}" if rootfs_path else httpd_binary

    return Task(
        description=f"""你是全能型固件调试专家。当其他专家无法处理时，你会接手。
你拥有所有工具和全部专家知识，能从崩溃分析、文件修复、网络配置、Web调试等多个角度解决问题。

## ⚠️ 工具执行环境说明

你拥有所有工具，使用前请先查看可用工具列表了解具体的工具名和参数：

**逆向分析工具**（radare2）：在宿主机上静态分析二进制文件
- ⚠️ 顺序: open_file(宿主机完整路径) → analyze(level=2) → 查询工具(list_strings/disassemble等)
- ⚠️ 嵌入式固件通常没有 'main' 符号，不要用 filter='main'
- ⚠️ `xrefs_to` 已会返回函数名和引用地址，拿到结果后直接 `disassemble_function` 或 `disassemble`，不要再兜一圈

**GDB调试工具**：高级封装，用于远程调试运行中的程序
- `gdb_run_script` — 核心工具，一次调用完成：设断点 → 启动httpd → 命中断点 → 修改寄存器 → 检查存活
- `gdb_trace_crash` — 崩溃根因分析：自动启动httpd、捕获崩溃现场、追溯外部函数调用点
- `gdb_backtrace` — 获取当前调用栈和寄存器状态
- ⚠️ 不再需要手动管理 GDB 会话，工具内部自动处理

**系统操作工具**（FirmCure MCP）：
- `vm_exec`：在 QEMU VM 内的 BusyBox shell 中执行命令（只适合基础命令：ps/ls/cat/echo/netstat/dmesg/kill）
- 文件操作工具：read_file, write_file, find_files, copy_to_rootfs 等（操作宿主机 rootfs）
- `start_httpd`：启动 httpd 服务（**必须使用此工具启动 httpd**，会自动处理断点链）
- `http_request` / `http_get_body`：HTTP 请求工具

**禁止行为**（严格遵守）：
- ❌ 不要在 VM 内执行 r2、radare2、gdb、objdump 等逆向工具（VM 内没有这些工具）
- ❌ 不要在 VM 内用 curl/wget 做 HTTP 验证
- ❌ 不要用 vm_exec 直接启动 httpd（必须用 start_httpd 工具）
- ❌ 不要在专家内部反复验证成功条件

## 故障信息 (第{iteration}轮)
{fault_info}

## HTTPD 启动日志
```
{httpd_output[:3000]}
```

## 环境信息
- Rootfs: {rootfs_path}
- HTTPD二进制(VM内): {httpd_binary}
- HTTPD二进制(宿主机): {r2_binary_path}
- 架构: {architecture}
- VM IP: 10.10.10.2

{EXECUTION_DISCIPLINE}

{breakpoint_chain_str}

{repair_history_str}

{phase1_data_str}

## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## 专家知识库（根据问题类型查阅对应知识）
## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### 📌 故障路由知识（先判断问题类型）
```json
{fault_routing[:2000]}
```

### 📌 崩溃/GDB分析知识
**工具使用规则**:
```json
{crash_knowledge[:1500]}
```
**GDB远程调试流程**:
```json
{gdb_knowledge[:2000]}
```
**逆向分析5步流程**:
```json
{re_knowledge[:2000]}
```

### 📌 文件修复知识
```json
{file_knowledge[:2000]}
```

### 📌 网络修复知识
```json
{net_knowledge[:1500]}
```

### 📌 Web服务修复知识
**HTTP 500 原因**:
```json
{web_500[:1000]}
```
**HTTP 404 原因**:
```json
{web_404[:1000]}
```

## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## 工作流程（根据问题类型选择对应策略）
## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### 第一步：快速诊断 — 判断问题类型

根据上方故障路由知识和日志内容，快速判断问题属于哪类：
1. **崩溃类**（进程退出/信号异常）→ 使用 GDB + 逆向策略
2. **等待类**（进程在但端口不开）→ 使用 GDB 断点链策略
3. **文件类**（文件缺失/权限/符号链接）→ 使用文件修复策略
4. **网络类**（DNS/端口/路由）→ 使用网络修复策略
5. **Web类**（HTTP 500/404/CGI错误）→ 使用Web修复策略
6. **混合类**（多因素叠加）→ 按优先级逐个击破

### 第二步：按问题类型执行对应修复策略

#### 崩溃/等待类修复策略
1. 从日志提取最后出现的错误/输出字符串
2. 逆向分析：open_file → analyze(level=2) → list_strings(filter="关键词") → xrefs_to → disassemble
3. 定位断点地址（设在比较/条件跳转指令处，不是调用指令处）
4. GDB 断点绕过：gdb_run_script(breakpoints=[所有历史+新断点], register_values=...)
5. 验证：validate_network_stack()

#### 文件类修复策略
1. 用 find_files/read_file 定位缺失文件
2. 创建设备节点、修复权限、修复符号链接
3. 如需创建配置文件，参考上方 httpd_config_repair 知识
4. 启动验证：start_httpd → validate_network_stack()

#### 网络类修复策略
1. vm_exec 检查 ifconfig/route
2. 配置网络接口和路由
3. 验证：validate_network_stack()

#### Web类修复策略
1. 先检查 Web 目录内容（find_files/read_file 查看 /www 或 /web 目录）
2. 再检查 httpd 配置文件
3. 最后才升级到二进制分析（只有前两步都没问题时）
4. 验证：validate_network_stack()

### 第三步：验证并返回
- 调用 validate_network_stack() 验证
- 将验证结果包含在返回 JSON 中
- 如果发现新问题超出能力范围，标记 needs_rediagnosis=true

## 输出格式（严格遵守）
```json
{{{{
  "success": true,
  "expert_name": "generic_expert",
  "fault_type": "问题类型",
  "actions_taken": ["具体修复步骤"],
  "breakpoint_chain": [],
  "register_changes": {{{{}}}},
  "new_issue_detected": false,
  "new_issue_description": "",
  "needs_rediagnosis": false,
  "validation": {
    "summary": {
      "network_reachable": true,
      "port_open": true,
      "http_responding": true,
      "overall_success": true
    }
  }
}}}}
```

**字段说明**：
- `fault_type`: 你判断的实际问题类型
- `breakpoint_chain`/`register_changes`: 使用了 GDB 断点时必须填写
- `validation`: 修复完成后必须调用 validate_network_stack 并包含结果
- `new_issue_detected`: 修复过程中发现的新问题
- `needs_rediagnosis`: 问题超出能力范围，需要路由到专门专家

请先诊断问题类型，再选择对应策略执行。先规划后执行，不要边想边做。""",
        expected_output="JSON格式修复报告，包含 fault_type, success, actions_taken, breakpoint_chain, register_changes, new_issue_detected, needs_rediagnosis, validation",
        agent=agent,
    )
