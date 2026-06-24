# ELF DYNAMIC Segment Patcher

针对 **LD_PRELOAD 被禁用** 的嵌入式固件（uClibc/musl），通过直接修改 ELF 二进制文件的 DYNAMIC 段注入 DT_NEEDED 条目，强制动态链接器加载指定的 hook 共享库。

经 TOTOLINK N150RT (MIPS BE, uClibc 0.9.33, 无 section header) 验证通过。

## 适用场景

- 固件的 uClibc/musl 编译时关闭了 LD_PRELOAD 支持
- 二进制文件被剥离了 section header，patchelf 无法使用
- QEMU 全系统仿真中需要 hook 硬件交互函数（apmib、nvram 等）

## 支持的 ELF 类型

| 特性 | 支持 |
|------|------|
| ELF32 / ELF64 | 均支持 |
| 大端 (MIPS BE, ARMEB) | 支持 |
| 小端 (MIPS LE, ARM, x86) | 支持 |
| 无 section header | 支持（仅需 segment 信息） |
| DYNAMIC p_filesz=0 | 自动回退到 LOAD 段定位 |

## 用法

### 查看依赖

```bash
python3 main.py ./boa --list
```

### 单文件修补

```bash
# 默认插入到 DT_NEEDED 首位（hook 场景必须用 first）
python3 main.py ./boa libhook.so -o boa_patched

# 追加到末尾（非 hook 场景，如添加额外依赖）
python3 main.py ./binary libextra.so --position last
```

### 批量修补

扫描目录下所有动态链接 ELF 可执行文件，自动注入 DT_NEEDED 并备份原文件为 `.bak`：

```bash
python3 main.py --batch ./squashfs-root libhook.so
```

## 工作原理

```
原始 ELF:                          修补后 ELF:
┌─────────────────┐                ┌─────────────────┐
│ DYNAMIC 段       │                │ DYNAMIC 段       │
│  DT_NEEDED libc  │                │  DT_NEEDED libhook│ ← 新增（首位）
│  DT_NEEDED libapm│                │  DT_NEEDED libc   │
│  DT_STRTAB ...   │                │  DT_NEEDED libapm │
│  ...             │                │  DT_STRTAB ...    │
│  DT_NULL         │                │  ...              │
│  [padding]       │                │  DT_NULL          │
├─────────────────┤                ├─────────────────┤
│ .dynstr "libc..."│                │ .dynstr "libc..." │
│                  │                │          "libhook"│ ← 新增
└─────────────────┘                └─────────────────┘
```

### 插入方式

| 方式 | 触发条件 | 说明 |
|------|----------|------|
| **shift** (默认) | `--position first` | 所有 DYNAMIC 条目后移一位，新条目插入首部。确保 hook 库在目标库之前加载，符号优先覆盖。 |
| **replace** | 有多个 DT_NULL 终止符时 | 替换多余的 DT_NULL。配合 `--position last` 使用。 |

### 为什么 hook 需要 position=first

ELF 动态链接器按 DT_NEEDED 列表顺序搜索符号，**第一个匹配的定义生效**。要 hook `libapmib.so` 中的 `apmib_get`，hook 库必须在 DT_NEEDED 列表中排在 `libapmib.so` 之前：

```
[0] libhook.so        ← apmib_get 定义在此，先被找到，hook 生效
[1] libapmib.so       ← 原始 apmib_get 被忽略
[2] libc.so.0
```

## 完整工作流：QEMU 全系统仿真 + 函数 Hook

以 TOTOLINK N150RT 为例：

### 1. 编译 hook 库

hook 库必须：
- 与目标固件相同架构（如 MIPS Big-Endian）
- 声明依赖固件的 libc（如 `libc.so.0` 而非 `libc.so.6`）
- 覆盖目标二进制从被 hook 库导入的**所有**符号

```bash
# 编译时避免 glibc 依赖
mips-linux-gnu-gcc -fPIC -shared -nostdlib \
  -Wl,--no-as-needed -Wl,-lc,--as-needed \
  -o libhook.so hook.c

# 如果链接了 libc.so.6，手动替换为 libc.so.0（等长可直接替换）
python3 -c "
data = open('libhook.so','rb').read()
data = data.replace(b'libc.so.6', b'libc.so.0')
open('libhook.so','wb').write(data)
"
```

### 2. 注入 DT_NEEDED

```bash
# 单个修补
python3 main.py ./squashfs-root/bin/boa libhook.so -o ./squashfs-root/bin/boa

# 或批量修补
python3 main.py --batch ./squashfs-root libhook.so
```

### 3. 部署到固件

```bash
cp libhook.so squashfs-root/lib/

# 确保环境完整
echo "root::0:0:root:/root:/bin/sh" >> squashfs-root/etc/passwd
echo "root::0:" >> squashfs-root/etc/group
mkdir -p squashfs-root/etc/boa
```

### 4. 重新打包 & 运行

```bash
# 打包 squashfs
mksquashfs squashfs-root firmware.img -comp xz

# QEMU 全系统仿真
qemu-system-mips -M malta -kernel vmlinux \
  -drive file=firmware.img,format=raw \
  -nographic
```

## 注意事项

1. **hook 库必须覆盖所有导入符号**：目标二进制可能从被 hook 库导入非标准名称的函数（如 boa 从 libapmib.so 导入 `BrMode`、`flash_read_raw_mib` 等）。用以下命令检查：
   ```bash
   mips-linux-gnu-objdump -T ./binary | grep "UND"
   ```

2. **hook 库的 libc 依赖**：编译 hook 库时如果依赖了 glibc（`libc.so.6`），固件的 ld-uClibc 无法加载。解决方案：
   - 用 `-nostdlib` 编译，依赖运行时从已加载的 libc.so.0 解析
   - 或编译后将 `libc.so.6` 字符串替换为 `libc.so.0`

3. **padding 空间限制**：工具利用 .dynstr 和 DYNAMIC 段后的 padding 写入数据。如果固件二进制非常紧凑，可能空间不足。

4. **不修改文件大小**：工具不改变二进制文件大小，仅利用现有 padding 区域（shift 方式时扩展 PT_DYNAMIC 的 p_filesz）。

## 参考

- [二进制固件函数劫持术-DYNAMIC](https://blog.csdn.net/Karka_/article/details/132021841)
- ELF(5) 手册 — Dynamic Section 相关定义
- 《揭秘家用路由器0day漏洞挖掘技术》
