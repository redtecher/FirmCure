"""
Phase 2 Tasks - QEMU启动故障诊断修复任务
"""

from crewai import Task, Agent


def create_boot_diagnosis_task(
    rootfs_path: str,
    boot_log: str,
    qemu_command: str,
    architecture: str,
    agent: Agent,
    repair_history: str = "",
    iteration: int = 1,
) -> Task:
    """创建QEMU启动故障诊断任务"""

    return Task(
        description=f"""分析QEMU启动失败日志，找出根因并修复。

## ⚠️ 核心原则（严格遵守）

**一次只修复一个关键问题，调整完立即输出结果，不要过度思考！**

- ✅ 找到第一个关键问题 → 修复 → 立即输出JSON
- ❌ 不要同时修复多个问题
- ❌ 不要反复调用工具确认同一件事
- ❌ 不要分析完一个继续找下一个问题
- ❌ 思考超过2轮就输出结果

## 当前环境信息
- 架构: {architecture}
- Rootfs: {rootfs_path}
- 当前QEMU命令: ```{qemu_command}```
- 修复轮次: 第{iteration}轮（最多3轮）

## 启动日志（完整）
```
{boot_log}
```

{repair_history}

## 诊断优先级
1. **Kernel panic** → 最关键，立即修复（CPU ISA、init路径、root device）
2. **Unable to mount root fs** → 修复root device或文件系统
3. **No init found** → 修复init路径
4. 其他问题按严重程度处理

## 输出格式（严格遵守）
```json
{{{{
  "diagnosis": "一句话诊断（说明发现的唯一关键问题）",
  "repairs_applied": ["本次修复的具体操作"],
  "qemu_adjustments": {{{{
    "cpu": "74Kf",
    "root_device": "/dev/sda1",
    "rootfstype": "ext4",
    "memory": "256M",
    "extra_append": "",
    "kernel_params": "",
    "reason": "调整原因"
  }}}} or null,
  "success": true
}}}}
```

**注意**:
- `qemu_adjustments`只填需要修改的字段
- `kernel_version`: 切换预编译内核版本（"v3", "v4", "v5"），用于解决 "Kernel too old" 错误。**必须先调用 `list_precompiled_kernels` 工具确认可用版本**
- `dtb`: DTB文件名（如 "vexpress-v2p-ca9.dtb"），armhf 使用 v4 内核时**必须**设置
- 如果不需要调整QEMU参数，设为 `null`
- 修复完一个问题就返回，让外层重新测试
""",
        expected_output="JSON格式的诊断和修复报告，包含diagnosis、repairs_applied、qemu_adjustments字段",
        agent=agent,
    )
