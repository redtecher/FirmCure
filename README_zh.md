<p align="center">
  <img src="pic/image.png" alt="FirmCure" width="400"/>
</p>

<h1 align="center">FirmCure</h1>

<p align="center">
  <strong>基于 LLM 的固件自动化重托管与漏洞分析平台</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue" />
  <img src="https://img.shields.io/badge/CrewAI-1.14.1-green" />
  <img src="https://img.shields.io/badge/QEMU-系统重托管-orange" />
  <img src="https://img.shields.io/badge/License-MIT-yellow" />
</p>

---

## 什么是 FirmCure？

FirmCure 使用 LLM 驱动的智能体自动完成 IoT 固件重托管。给定已解压的固件 rootfs，它能自动分析固件、构建 QEMU 虚拟机、修复运行时崩溃——零人工干预实现完整的 Web 服务重托管。

## 发表论文

**FIRMCURE: Towards Autonomous and Adaptive Rehosting of Linux-Based Firmware**

📄 [arXiv:2606.24549](https://arxiv.org/abs/2606.24549) | [PDF](https://arxiv.org/pdf/2606.24549)


## 核心特性

- **自动分析**：深度固件分析，包括 CPU 架构、HTTPD 发现、启动流程追踪、依赖映射
- **QEMU 环境构建**：自动选择内核、创建磁盘镜像、配置启动参数
- **运行时干预**：多智能体系统诊断并修复运行时崩溃，使用 GDB、Radare2 和文件系统工具
- **零人工配置**：无需手动配置 QEMU 参数或调试崩溃
- **交互式 Shell**：重托管成功后获得完整的 QEMU 交互式环境

## 快速开始

### 1. 安装依赖

**Ubuntu/Debian：**
```bash
sudo apt update
sudo apt install -y qemu-system-arm qemu-system-mips gdb-multiarch nmap \
  radare2 parted dosfstools rsync uml-utilities binwalk
```

**macOS：**
```bash
brew install qemu gdb nmap radare2 binwalk
```

**Python 依赖：**
```bash
pip install -r requirements.txt
```

### 2. 配置 LLM API

```bash
cd config/
cp config.json.example config.json
cp config.yaml.example config.yaml
```

编辑 `config.json` 填入你的 API 信息：

```json
{
    "provider": "openai",
    "api_key": "your-api-key-here",
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-4",
    "temperature": 0.7,
    "max_tokens": 64000,
    "embedding_provider": "openai",
    "embedding_api_key": "your-embedding-api-key-here",
    "embedding_base_url": "",
    "embedding_model": "text-embedding-3-small"
}
```

**支持的提供商**：OpenAI、DeepSeek、阿里云通义千问、智谱 AI、Anthropic（通过代理）、或任何兼容 OpenAI 的 API。

编辑 `config.yaml` 填入 sudo 密码：
```yaml
sudo_password: "your-sudo-password"
```

### 3. 提取固件

使用内置的 FirmDissector 提取器：

```bash
python extrator/extractor.py firmware.bin
```

或使用 binwalk/firmware-mod-kit：
```bash
binwalk -e firmware.bin
```

### 4. 运行 FirmCure

```bash
python main.py -i ./extracted_firmware/squashfs-root/
```

**跳转到指定阶段：**
```bash
# 从 Phase 2 开始（如果已完成分析）
python main.py -i ./rootfs/ --start 2 --case 007

# 仅运行 Phase 1 分析
python main.py -i ./rootfs/ --start 1 --end 1
```

### 5. 访问重托管固件

重托管成功后进入 QEMU 交互式 Shell：

```bash
~ # ps | grep httpd
~ # netstat -tlnp
~ # cat /etc/config/httpd
```

在宿主机上访问：
```bash
curl http://10.10.10.2/
nmap -sV 10.10.10.2
```

## 工作原理

### Phase 1 — 固件分析

分析解压后的固件 rootfs，识别：
- CPU 架构（ARM/MIPS、位宽、端序）
- HTTPD 二进制位置和类型
- 启动脚本和启动序列
- 依赖项（NVRAM、设备节点、守护进程）

**输出**：结构化 JSON 报告 + 自动生成的启动脚本

### Phase 2 — 重托管环境构建

构建可启动的 QEMU 磁盘镜像：
- 根据检测到的架构选择合适的内核
- 创建分区磁盘并复制 rootfs
- 注入启动脚本和网络配置
- 测试 QEMU 启动，失败时自动修复

**支持的架构**：armel、armhf、mips、mipsel

### Phase 3 — 运行时干预

多智能体团队诊断并修复运行时故障：
- **总指挥** 分类故障类型
- **崩溃专家** 使用 GDB 断点链修复崩溃
- **文件专家** 修复缺失文件和权限问题
- **网络专家** 解决网络配置问题
- **Web 专家** 修复 HTTPD 特定问题
- **通用专家** 处理其他问题

最多 5 轮迭代，直到服务正常运行。

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                       FirmCure 流水线                            │
│                                                                 │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │ Phase 1  │───▶│   Phase 2    │───▶│      Phase 3         │   │
│  │ 固件分析  │    │  重托管环境    │    │    运行时干预        │   │
│  └──────────┘    └──────────────┘    └──────────────────────┘   │
│       │                │                      │                 │
│       ▼                ▼                      ▼                 │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │ 分析专家  │    │ 重托管工程师  │    │ 总指挥 + 专家团队    │   │
│  └──────────┘    └──────────────┘    │ (崩溃、文件、网络、   │   │
│                                     │  Web、通用)           │   │
│                                     └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## 命令行参数

```
用法: main.py -i ROOTFS [-h] [--case NUM] [--start PHASE] [--end PHASE]
                     [--max-time-phase1 SEC] [--timeout-phase2 SEC]
                     [--timeout-phase3 SEC]

必选参数:
  -i, --input              固件 rootfs 目录路径

可选参数:
  --case NUM               Case 编号（如 007），不指定则自动分配
  --start PHASE            起始阶段: 1, 2, 或 3（默认: 1）
  --end PHASE              结束阶段: 1, 2, 或 3（默认: 3）
  --max-time-phase1 SEC    Phase 1 最大探索时间（默认: 1000）
  --timeout-phase2 SEC     Phase 2 QEMU 超时（默认: 180）
  --timeout-phase3 SEC     Phase 3 干预超时（默认: 600）
```

## 工具集

FirmCure 提供 42+ 专业工具，分为 4 大类：

- **Radare2 工具**（12 个）：静态二进制分析、反汇编、交叉引用分析
- **GDB 工具**（7 个）：动态调试、断点链、寄存器修改
- **系统工具**（22 个）：虚拟机操作、文件管理、网络诊断
- **验证工具**（1 个）：三层网络栈验证

## 支持的固件

| 序号 | 厂商 | 设备 | 架构 | 内核 | 网络 | 端口 | 可交互 |
|-----|------|------|------|------|------|------|--------|
| 1 | Totolink | NR1800X | mipsel | ✅ | ✅ | ✅ | ✅ |
| 2 | Totolink | N150RT | mipsel | ✅ | ✅ | ✅ | ✅ |
| 3 | D-Link | DAP-1522 | mipsel | ✅ | ✅ | ✅ | ✅ |
| 4 | D-Link | dsp-w215 | mipsel | ✅ | ✅ | ✅ | ✅ |
| 5 | D-Link | DGL-5500 | mipsel | ✅ | ✅ | ✅ | ✅ |
| 6 | D-Link | DIR823X | arm64 | ✅ | ✅ | ✅ | ✅ |
| 7 | WAVLINK | NU516U1 | mipsel | ✅ | ✅ | ✅ | ✅ |
| 8 | WAVLINK | WN531P3 | mipsel | ✅ | ✅ | ✅ | ✅ |
| 9 | Tenda | AC15 | armhf | ✅ | ✅ | ✅ | ✅ |
| 10 | Tenda | AC18 | armhf | ✅ | ✅ | ✅ | ✅ |
| 11 | Tenda | AC500 | armhf | ✅ | ✅ | ✅ | ✅ |
| 12 | Tenda | AX1806 | armhf | ✅ | ✅ | ✅ | ✅ |
| 13 | Draytek | Vigor3900 | armel | ✅ | ✅ | ✅ | ✅ |
| 14 | Netgear | wn1000rp | mipsel | ✅ | ✅ | ✅ | ✅ |
| 15 | Netgear | XR500 | armhf | ✅ | ✅ | ✅ | ❌ |
| 16 | TRENDnet | TEW-711BR | mipseb | ✅ | ✅ | ✅ | ✅ |
| 17 | TRENDnet | TEW-813DRU | mipseb | ✅ | ✅ | ✅ | ✅ |
| 18 | TP-LINK | TL-IPC43AN | armhf | ✅ | ✅ | ✅ | ✅ |
| 19 | TP-LINK | RE580D | armel | ✅ | ✅ | ✅ | ✅ |
| 20 | Asus | FW_WL500gPv2_2015 | mipsel | ✅ | ✅ | ✅ | ✅ |
| 21 | XIAOMI | AX9000 | arm64 | ✅ | ✅ | ✅ | ❌ |



任何具有可提取 rootfs 和 HTTPD 二进制的固件均支持。

## 持续测试数据集

FirmCure 维护着一个持续更新的固件重托管实验数据集：

**[🔬 redtecher.cn/experiments-data](https://redtecher.cn/experiments-data/)**

该数据集包括：
- 实时固件分析测试结果
- 性能指标和成功率统计
- 详细日志和干预策略
- 跨厂商兼容性数据

这个数据集提供了 FirmCure 能力的透明度，并作为固件重托管研究的基准测试。

## 输出目录结构

FirmCure 运行后，所有结果会整理在 `scratch/{case_id}/` 目录中：

```
scratch/092/
├── README.md                  # Case 摘要和元数据
├── summary.json               # 整体执行统计
├── run.log                    # 完整执行日志（调试用）
│
├── phase1/                    # Phase 1: 固件分析
│   ├── phase1_analysis.json   # 完整分析报告
│   ├── httpd_info.json        # HTTPD 服务详细信息
│   ├── startup.sh             # 自动生成的启动脚本
│   ├── httpd_start.sh         # HTTPD 专用启动脚本
│   ├── architecture.txt       # 架构信息
│   ├── dependencies.json      # 共享库依赖
│   └── CONTEXT_SUMMARY.md     # 智能体推理总结
│
├── phase2/                    # Phase 2: 重托管环境构建
│   ├── rootfs.qcow2           # QEMU 磁盘镜像（可启动）
│   ├── run_qemu.sh            # QEMU 启动脚本
│   └── phase2_result.json    # 构建结果
│
└── phase3/                    # Phase 3: 运行时干预
    ├── phase3_summary.json    # 干预结果
    └── intervention_log.json   # 详细修复历史
```

### 关键文件说明

**summary.json** - 整体运行的快速概览：
```json
{
  "case_id": "092",
  "total": {
    "duration_minutes": 15.46,
    "token_usage": {
      "total_tokens": 3628622
    }
  },
  "phases": {
    "phase3": {
      "success": true,
      "iterations": 1
    }
  }
}
```

**phase1/phase1_analysis.json** - 固件分析结果：
- `architecture`: CPU 架构、位数、端序、libc 类型
- `httpd_service`: HTTPD 二进制、配置文件、端口
- `startup_sequence`: 启动脚本和 init 系统
- `dependencies`: 所需的库和守护进程

**phase2/rootfs.qcow2** - 可启动的 QEMU 磁盘镜像，可直接用于：
```bash
qemu-system-arm -M vexpress-a9 -kernel v3-armhf \
  -hda rootfs.qcow2 -nographic
```

**phase3/phase3_summary.json** - 干预结果：
- `success`: HTTPD 是否成功运行
- `iterations`: 修复尝试次数
- `token_usage`: LLM API 成本

## 项目结构

```
FirmCure/
├── main.py                    # CLI 入口
├── flow.py                    # 流水线编排
├── config.py                  # LLM 配置
├── agents/                    # 智能体定义
├── crews/                     # Crew 组装
├── tasks/                     # 任务提示词
├── tools/                     # 工具实现
│   ├── firmcure-tool/         # 虚拟机与文件系统操作
│   ├── radare2-tool/          # 二进制分析
│   ├── gdb-tool/              # 调试工具
│   └── validation-tool/       # 网络验证
├── knowledge/                 # 专家知识库
├── core/                      # 基础设施模块
├── resources/                 # 预编译内核和库
├── extrator/                  # 固件提取模块
├── config/                    # 配置文件
└── requirements.txt           # Python 依赖
```


## 开源协议

MIT License - 详见 LICENSE 文件
