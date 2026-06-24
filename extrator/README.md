# FirmDissector

智能固件迭代解包工具 - 自动检测并递归提取多层嵌套的固件镜像，直到获得 rootfs 文件系统。

## 特性

- 🔍 **智能检测** - 自动识别 UBI/UBIFS/SquashFS 等多种固件格式
- 🔄 **递归解包** - 自动处理多层嵌套的固件结构
- 📋 **队列处理** - 自动提取所有嵌套文件，不会遗漏任何 UBIFS 文件
- 🎯 **精准定位** - 智能识别 rootfs 文件系统路径
- 🛠️ **多工具支持** - binwalk + ubi_extract_file + ubidump + ubireader + unsquashfs
- 📊 **详细日志** - 完整的提取链追踪和调试信息

## 核心功能

### 支持的文件格式

| 格式类型 | 文件扩展名 | 提取工具 | 说明 |
|---------|-----------|---------|------|
| **UBI 镜像** | `.ubi` | ubi_extract_file, ubidump, ubireader_extract_images | 闪存镜像格式 |
| **UBIFS 文件系统** | `.ubifs` | binwalk -Me | UBI 文件系统 |
| **SquashFS** | `.squashfs`, `.sfs` | unsquashfs | 只读压缩文件系统 |
| **通用归档** | `.zip`, `.tar`, `.chk` 等 | binwalk -Me | 递归提取所有内容 |

### 智能提取流程

```
固件文件 (firmware.chk)
       ↓
┌──────────────────────────────────────┐
│  第 1 轮: binwalk 递归提取           │
│  → 提取出 UBI 镜像文件               │
└──────────────────────────────────────┘
       ↓
┌──────────────────────────────────────┐
│  第 2 轮: UBI 镜像提取               │
│  → 发现 4 个 UBIFS 文件              │
│  → 全部加入处理队列                  │
└──────────────────────────────────────┘
       ↓
┌──────────────────────────────────────┐
│  第 3-N 轮: UBIFS 文件递归提取        │
│  → 逐个处理队列中的 UBIFS 文件       │
│  → 使用 binwalk -Me 递归解包         │
└──────────────────────────────────────┘
       ↓
┌──────────────────────────────────────┐
│  ✅ 找到 rootfs!                    │
│  → 包含 bin, etc, lib, usr...      │
└──────────────────────────────────────┘
```

### 提取策略优先级

**对于 UBI 镜像:**
1. `ubi_extract_file` - 系统命令（最可靠）
2. `ubidump.py` - 内置 Python 脚本（fallback）
3. `ubireader_extract_images` - 系统命令
4. `binwalk -Me` - 通用回退方案

**对于 UBIFS 文件系统:**
1. `binwalk -Me` - 递归提取（效果最好）

**对于 SquashFS:**
1. `unsquashfs` - 专用工具
2. `binwalk -Me` - 回退方案

**对于其他格式:**
1. `binwalk -Me` - 通用递归提取

## 安装

### 1. 安装系统依赖

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install binwalk
# 可选：安装 ubireader 以获得更好的 UBI 支持
sudo apt install ubireader
```

**Arch Linux:**
```bash
sudo pacman -S binwalk
# ubireader 从 AUR 安装
yay -S ubireader
```

**macOS:**
```bash
brew install binwalk
pip install ubi-reader
```

### 2. Python 依赖

```bash
# 无额外 Python 依赖，仅使用标准库
# 可选：安装 python-magic 以获得更准确的文件类型检测
pip install python-magic colorama
```

### 3. 克隆项目

```bash
git clone https://github.com/yourusername/FirmDissector.git
cd FirmDissector
```

## 使用方法

### 命令行使用

```bash
# 基本使用
python extractor.py firmware.bin

# 指定输出目录（默认为 extracted_固件名称）
python extractor.py firmware.bin -o /path/to/output

# 查看帮助
python extractor.py --help
```

### 作为 Python 库使用

```python
from extractor import FirmDissector

# 创建提取器实例
extractor = FirmDissector('firmware.chk')

# 执行智能提取
rootfs_path = extractor.extract()

# 打印结果
print(f"✅ 提取完成!")
print(f"🎯 RootFS 位置: {rootfs_path}")

# 查看提取摘要
print(extractor.get_extraction_summary())
```

### 完整示例

```python
from pathlib import Path
from extractor import FirmDissector

# 提取固件
firmware = Path('RAX50-V1.0.9.108_2.0.74.chk')
extractor = FirmDissector(str(firmware))

try:
    rootfs = extractor.extract()
    print(f"\n成功提取 RootFS 到: {rootfs}")

    # 访问文件系统
    etc_passwd = rootfs / 'etc' / 'passwd'
    if etc_passwd.exists():
        print("\n=== /etc/passwd ===")
        print(etc_passwd.read_text())

except Exception as e:
    print(f"提取失败: {e}")
```

## 输出结构

提取后的文件结构示例：

```
firmware/
├── RAX50-V1.0.9.108_2.0.74.chk
│
├── RAX50-V1.0.9.108_2.0.74.chk_extracted/
│   ├── 0.ubi
│   └── checksum.md5
│
├── 0_extracted/
│   ├── img-xxx_vol-rootfs_ubifs.ubifs
│   ├── img-xxx_vol-METADATA.ubifs
│   ├── img-xxx_vol-METADATACOPY.ubifs
│   └── img-xxx_vol-filestruct_full.bin.ubifs
│
├── img-xxx_vol-rootfs_ubifs.ubifs_extracted/
│   ├── bin/
│   ├── etc/
│   ├── lib/
│   ├── usr/
│   ├── var/
│   └── ...  ← ✅ 这里就是 rootfs!
│
└── img-xxx_vol-METADATA.ubifs_extracted/
    └── (元数据文件)
```

## 工作原理

### 1. 智能文件分析

对于每个目标文件，工具会：

- 检查文件扩展名（`.ubi`, `.ubifs`, `.squashfs` 等）
- 使用 `file` 命令进行类型识别
- 使用 `binwalk` 扫描内部结构
- 验证 Magic Bytes 确保准确识别

### 2. 提取结果处理

每次提取后：

- 查找所有嵌套的可提取文件（`.ubi`, `.ubifs`, `.img` 等）
- 自动将所有嵌套文件加入处理队列
- 从队列中逐个提取，确保不遗漏任何文件
- 每次提取后检查是否已找到 rootfs

### 3. Rootfs 识别

rootfs 判断标准（满足 3 个以上）：

- `bin/` - 可执行文件目录
- `etc/` - 配置文件目录
- `lib/` - 库文件目录
- `usr/` - 用户程序目录
- `var/` - 变量数据目录
- `root/` - root 用户目录
- `sbin/` - 系统二进制文件目录

## 项目结构

```
FirmDissector/
├── extractor.py           # 核心提取引擎
├── ubidump.py            # UBI 镜像解包工具（fallback）
├── cli.py                # 命令行接口
├── __init__.py           # 包初始化
├── test_setup.py         # 安装测试
├── requirements.txt      # 依赖说明
└── README.md            # 本文档
```

## 核心类和方法

### `FirmDissector`

主提取器类，实现智能固件解包。

**初始化参数:**
- `firmware_path` (str): 固件文件路径
- `output_dir` (str, optional): 输出目录，默认为 `extracted_固件名称`

**主要方法:**
- `extract() -> Path`: 执行智能循环提取，返回 rootfs 路径
- `get_extraction_summary() -> str`: 获取提取链摘要报告

### `ExtractionTool` 枚举

可用的提取工具类型：
- `BINWALK` - binwalk 递归提取
- `UBI_EXTRACT_FILE` - ubi_extract_file 工具
- `UBIDUMP` - ubidump.py 内置工具（当 ubi_extract_file 失败时使用）
- `UBIREADER_IMAGES` - ubireader_extract_images 工具
- `UBIREADER_FILES` - ubireader_extract_files 工具
- `UNSQUASHFS` - unsquashfs 工具

### `ExtractionResult` 数据类

存储单次提取结果：
- `success` (bool) - 是否成功
- `output_path` (Path) - 输出路径
- `tool` (ExtractionTool) - 使用的工具
- `details` (str) - 详细信息
- `extracted_files` (int) - 提取的文件数量
- `next_targets` (List[Path]) - 发现的嵌套文件列表

## 示例输出

```
======================================================================
📦 初始化智能固件提取器
   固件: /home/iot/Desktop/firmware/RAX50-V1.0.9.108_2.0.74.chk
   输出: /home/iot/Desktop/firmware/extracted_RAX50-V1.0.9.108_2.0.74
======================================================================

======================================================================
🔄 第 0 轮解包循环
   当前目标: /home/iot/Desktop/firmware/RAX50-V1.0.9.108_2.0.74.chk
======================================================================
📊 分析结果:
   类型: data
   是rootfs: ❌
   UBI镜像: ❌
   UBIFS: ❌
   SquashFS: ❌
   归档文件: ❌
🔧 使用 binwalk -Me 递归提取...
   ✅ 找到提取目录: .../RAX50-V1.0.9.108_2.0.74.chk_extracted
✅ 提取成功: binwalk递归提取完成
   ➤ 将 1 个目标加入队列

======================================================================
🔄 第 1 轮解包循环
   当前目标: 0.ubi
======================================================================
📊 分析结果:
   类型: UBI image
   是rootfs: ❌
   UBI镜像: ✅
🔧 提取UBI镜像...
   尝试 ubireader_extract_images...
   ✅ 找到提取目录: .../0_extracted
   ➤ 找到 4 个 UBIFS 文件
   ➤ 将 4 个目标加入队列
   ➤ 从队列中选择下一个目标: img-xxx_vol-rootfs_ubifs.ubifs (剩余: 3)

======================================================================
🔄 第 2 轮解包循环
   当前目标: img-xxx_vol-rootfs_ubifs.ubifs
======================================================================
🔧 提取UBIFS文件系统...
   使用 binwalk -Me 递归提取...
✅ 提取成功: binwalk递归提取完成

======================================================================
🎯 找到 rootfs: .../img-xxx_vol-rootfs_ubifs.ubifs_extracted
======================================================================

✅ 提取完成！
🎯 Rootfs路径: .../img-xxx_vol-rootfs_ubifs.ubifs_extracted
```

## 故障排除

### 1. binwalk 未安装

```bash
# 检查是否安装
which binwalk

# Ubuntu/Debian 安装
sudo apt install binwalk

# 验证安装
binwalk --help
```

### 2. 提取失败或找不到 rootfs

```bash
# 增加日志详细程度
export PYTHONUNBUFFERED=1
python extractor.py firmware.bin 2>&1 | tee extraction.log

# 检查日志中的错误信息
grep -i "error\|failed" extraction.log
```

### 3. UBIFS 文件未完全提取

工具会自动将所有 UBIFS 文件加入队列并逐个提取。如果某些文件被跳过：

```bash
# 手动检查未提取的文件
find . -name "*.ubifs" -exec sh -c 'echo "{}"; ls -l "{}_extracted" 2>/dev/null || echo "  未提取"' \;
```

### 4. 清理并重新提取

```bash
# 删除所有提取的目录
find . -type d -name "*_extracted" -exec rm -rf {} +

# 重新运行提取
python extractor.py firmware.bin
```

## 性能说明

- **内存占用**: 取决于固件大小，binwalk 可能占用 100-500MB
- **磁盘空间**: 通常需要固件大小 2-3 倍的临时空间
- **提取时间**:
  - 小型固件 (< 50MB): 1-5 分钟
  - 中型固件 (50-200MB): 5-15 分钟
  - 大型固件 (> 200MB): 15-60 分钟

## 常见问题

**Q: 为什么有些固件提取后找不到 rootfs?**

A: 可能原因：
- 固件使用了自定义格式，不是标准的 UBI/UBIFS
- rootfs 被压缩在自定义格式中（如 LZMA、XZ）
- 固件仅包含部分文件系统（如只有 kernel，没有 rootfs）

**Q: ubireader 是必需的吗？**

A: 不是必需的。如果没有 ubireader，工具会自动回退到 binwalk，功能完全可用。安装 ubireader 可以在某些情况下提供更好的提取效果。

**Q: 如何处理加密的固件？**

A: 本工具不支持解密。如果固件加密，需要：
1. 查找设备的解密密钥
2. 使用设备厂商提供的解密工具
3. 或者逆向分析解密算法

**Q: 提取后的文件可以直接刷入设备吗？**

A: 不建议。提取的文件仅用于分析：
- 查看文件系统结构
- 分析配置文件
- 提取固件中的二进制程序
- 安全审计和漏洞分析

## 贡献

欢迎提交 Issue 和 Pull Request！

主要改进方向：
- 支持更多固件格式
- 优化提取算法性能
- 增加文件系统完整性校验
- 添加更多分析功能

## 许可证

MIT License

## 致谢

本工具依赖于以下优秀的开源项目：
- [binwalk](https://github.com/ReFirmLabs/binwalk) - 固件分析工具
- [ubi_reader](https://github.com/jrspruitt/ubi_reader) - UBI/UBIFS 解包工具
