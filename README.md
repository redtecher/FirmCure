<p align="center">
  <img src="pic/image.png" alt="FirmCure" width="400"/>
</p>

<h1 align="center">FirmCure</h1>

<p align="center">
  <strong>LLM-Powered Automated Firmware Rehosting & Vulnerability Analysis Platform</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue" />
  <img src="https://img.shields.io/badge/CrewAI-1.14.1-green" />
  <img src="https://img.shields.io/badge/QEMU-System_Emulation-orange" />
  <img src="https://img.shields.io/badge/License-MIT-yellow" />
</p>

---

## What is FirmCure?

FirmCure automates IoT firmware emulation using LLM-powered agents. Given an extracted firmware rootfs, it analyzes the firmware, builds a QEMU virtual machine, and fixes runtime crashes — achieving a fully interactive emulated web service with no manual intervention.

## Publication

**FIRMCURE: Towards Autonomous and Adaptive Rehosting of Linux-Based Firmware**

📄 [arXiv:2606.24549](https://arxiv.org/abs/2606.24549) | [PDF](https://arxiv.org/pdf/2606.24549)


## Features

- **Automated Analysis**: Deep firmware analysis including CPU architecture, HTTPD discovery, startup tracing, and dependency mapping
- **QEMU Environment Build**: Automatic kernel selection, disk image creation, and boot configuration
- **Runtime Intervention**: Multi-agent system that diagnoses and fixes runtime crashes using GDB, Radare2, and filesystem tools
- **Zero Manual Configuration**: No need to manually configure QEMU parameters or debug crashes
- **Interactive Shell**: Get a fully interactive QEMU shell after successful emulation

## Quick Start

### 1. Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y qemu-system-arm qemu-system-mips gdb-multiarch nmap \
  radare2 parted dosfstools rsync uml-utilities binwalk
```

**macOS:**
```bash
brew install qemu gdb nmap radare2 binwalk
```

**Python dependencies:**
```bash
pip install -r requirements.txt
```

### 2. Configure LLM API

```bash
cd config/
cp config.json.example config.json
cp config.yaml.example config.yaml
```

Edit `config.json` with your LLM API credentials:

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

**Supported providers:** OpenAI, DeepSeek, 阿里云通义千问, 智谱 AI, Anthropic (via proxy), or any OpenAI-compatible API.

Edit `config.yaml` with your sudo password:
```yaml
sudo_password: "your-sudo-password"
```

### 3. Extract Firmware

Use the included FirmDissector extractor:

```bash
python extrator/extractor.py firmware.bin
```

Or use binwalk/firmware-mod-kit:
```bash
binwalk -e firmware.bin
```

### 4. Run FirmCure

```bash
python main.py -i ./extracted_firmware/squashfs-root/
```

**Skip to specific phase:**
```bash
# Start from Phase 2 (skip analysis if already done)
python main.py -i ./rootfs/ --start 2 --case 007

# Only run Phase 1 analysis
python main.py -i ./rootfs/ --start 1 --end 1
```

### 5. Access Emulated Firmware

After successful emulation, you'll get an interactive QEMU shell:

```bash
~ # ps | grep httpd
~ # netstat -tlnp
~ # cat /etc/config/httpd
```

From your host machine:
```bash
curl http://10.10.10.2/
nmap -sV 10.10.10.2
```

## How It Works

### Phase 1 — Firmware Analysis

Analyzes the extracted firmware rootfs to identify:
- CPU architecture (ARM/MIPS, bit width, endianness)
- HTTPD binary location and type
- Boot scripts and startup sequence
- Dependencies (NVRAM, device nodes, daemons)

**Output:** Structured JSON report + auto-generated startup scripts

### Phase 2 — Rehosting Environment Build

Builds a bootable QEMU disk image:
- Selects appropriate kernel for detected architecture
- Creates partitioned disk with rootfs
- Injects startup scripts and network config
- Tests QEMU boot with auto-repair on failure

**Supported architectures:** armel, armhf, mips, mipsel

### Phase 3 — Runtime Intervention

Multi-agent team diagnoses and fixes runtime failures:
- **Manager** classifies fault types
- **Crash Expert** uses GDB breakpoint chains to fix crashes
- **File Expert** repairs missing files and permissions
- **Network Expert** resolves network configuration issues
- **Web Expert** fixes HTTPD-specific problems
- **Generic Expert** handles other issues

Up to 5 iterations until service runs successfully.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FirmCure Pipeline                         │
│                                                                  │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │ Phase 1  │───▶│   Phase 2    │───▶│      Phase 3         │   │
│  │ Analysis │    │  Rehosting   │    │   Intervention       │   │
│  └──────────┘    └──────────────┘    └──────────────────────┘   │
│       │                │                      │                 │
│       ▼                ▼                      ▼                 │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │ Analyst  │    │  Synthesis   │    │  Manager + Experts   │   │
│  │ Agent    │    │  Engineer    │    │  (Crash, File, Net,   │   │
│  └──────────┘    └──────────────┘    │   Web, Generic)      │   │
│                                     └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Command Line Options

```
usage: main.py -i ROOTFS [-h] [--case NUM] [--start PHASE] [--end PHASE]
                     [--max-time-phase1 SEC] [--timeout-phase2 SEC]
                     [--timeout-phase3 SEC]

required:
  -i, --input              Firmware rootfs directory path

options:
  --case NUM               Case number (e.g., 007), auto-assigned if omitted
  --start PHASE            Start phase: 1, 2, or 3 (default: 1)
  --end PHASE              End phase: 1, 2, or 3 (default: 3)
  --max-time-phase1 SEC    Phase 1 max exploration time (default: 1000)
  --timeout-phase2 SEC     Phase 2 QEMU timeout (default: 180)
  --timeout-phase3 SEC     Phase 3 intervention timeout (default: 600)
```

## Tools & Capabilities

FirmCure provides 42+ specialized tools across 4 categories:

- **Radare2 Tools** (12): Static binary analysis, disassembly, xref analysis
- **GDB Tools** (7): Dynamic debugging, breakpoint chains, register modification
- **System Tools** (22): VM operations, file management, network diagnostics
- **Validation Tools** (1): Three-layer network stack validation

## Supported Firmware

| No. | Vendor | Device | Architecture | Kernel | Network | Port | Interactive |
|-----|--------|--------|--------------|--------|---------|------|-------------|
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



Any firmware with an extractable rootfs and HTTPD binary is supported.

## Output Directory Structure

After running FirmCure, all results are organized in the `scratch/{case_id}/` directory:

```
scratch/092/
├── README.md                  # Case summary and metadata
├── summary.json               # Overall execution statistics
├── run.log                    # Complete execution log (debugging)
│
├── phase1/                    # Phase 1: Firmware Analysis
│   ├── phase1_analysis.json   # Complete analysis report
│   ├── httpd_info.json        # HTTPD service details
│   ├── startup.sh             # Auto-generated startup script
│   ├── httpd_start.sh         # HTTPD-specific launch script
│   ├── architecture.txt       # Architecture information
│   ├── dependencies.json      # Shared library dependencies
│   └── CONTEXT_SUMMARY.md     # Agent reasoning summary
│
├── phase2/                    # Phase 2: Rehosting Environment Build
│   ├── rootfs.qcow2           # QEMU disk image (bootable)
│   ├── run_qemu.sh            # QEMU launch script
│   └── phase2_result.json    # Build results
│
└── phase3/                    # Phase 3: Runtime Intervention
    ├── phase3_summary.json    # Intervention results
    └── intervention_log.json   # Detailed fix history
```

### Key Files Explained

**summary.json** - Quick overview of the entire run:
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

**phase1/phase1_analysis.json** - Firmware analysis results:
- `architecture`: CPU arch, bits, endian, libc
- `httpd_service`: HTTPD binary, config, ports
- `startup_sequence`: Boot scripts and init system
- `dependencies`: Required libraries and daemons

**phase2/rootfs.qcow2** - Bootable QEMU disk image that can be used with:
```bash
qemu-system-arm -M vexpress-a9 -kernel v3-armhf \
  -hda rootfs.qcow2 -nographic
```

**phase3/phase3_summary.json** - Intervention results:
- `success`: Whether HTTPD is now running
- `iterations`: Number of fix attempts
- `token_usage`: LLM API costs

## Project Structure

```
FirmCure/
├── main.py                    # CLI entry point
├── flow.py                    # Pipeline orchestration
├── config.py                  # LLM configuration
├── agents/                    # Agent definitions
├── crews/                     # Crew assembly
├── tasks/                     # Task prompts
├── tools/                     # Tool implementations
│   ├── firmcure-tool/         # VM & filesystem operations
│   ├── radare2-tool/          # Binary analysis
│   ├── gdb-tool/              # Debugging
│   └── validation-tool/       # Network validation
├── knowledge/                 # Expert knowledge base
├── core/                      # Infrastructure modules
├── resources/                 # Pre-built kernels & libraries
├── extrator/                  # Firmware extraction module
├── config/                    # Configuration files
└── requirements.txt           # Python dependencies
```


## License

MIT License - see LICENSE file for details.
