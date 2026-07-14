#!/usr/bin/env python3
"""
网络管理器 - 配置 tap0 网络接口
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, Optional

import os
import yaml

SUDO_PASSWORD = os.getenv("SUDO_PASSWORD", "")


def run_sudo_command(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    if SUDO_PASSWORD:
        return subprocess.run(
            f"echo '{SUDO_PASSWORD}' | sudo -S {cmd}",
            shell=True,
            check=check,
            capture_output=True,
            text=True
        )
    return subprocess.run(f"sudo {cmd}", shell=True, check=check, capture_output=True, text=True)


def setup_network(tap_name: str = "tap0", tap_ip: str = "10.10.10.1/24") -> bool:
    print(f"[*] 配置 {tap_name} 网络接口...")

    result = run_sudo_command(f"tunctl -t {tap_name} -u $(whoami)", check=False)
    if result.returncode != 0:
        result = run_sudo_command(f"ip tuntap add mode tap user $(whoami) name {tap_name}", check=False)

    check = subprocess.run(f"ip link show {tap_name}", shell=True, capture_output=True)
    if check.returncode != 0:
        print(f"[✗] 创建 {tap_name} 接口失败")
        return False

    check_ip = subprocess.run(f"ip addr show {tap_name} | grep -q '{tap_ip}'", shell=True, capture_output=True)
    if check_ip.returncode != 0:
        result = run_sudo_command(f"ip addr add {tap_ip} dev {tap_name}", check=False)
        if result.returncode != 0 and "File exists" not in result.stderr:
            print(f"[✗] 添加 IP 地址失败")
            return False

    run_sudo_command(f"ip link set dev {tap_name} up")

    subprocess.run(f"ip addr show {tap_name}", shell=True)
    print(f"[✓] {tap_name} 网络配置完成")
    return True


def setup_qemu_ifup() -> bool:
    print("[*] 配置 /etc/qemu-ifup...")

    run_sudo_command("mv /etc/qemu-ifup /etc/qemu-ifup.bak", check=False)

    # Phase 2/3 都显式创建并配置 tap0 了，这里只需要让 QEMU 的 ifup 钩子成功返回。
    # 使用 no-op 脚本比依赖历史 /etc/qemu-ifup.bak 更稳妥，避免 backup 缺失导致 QEMU 直接退出。
    qemu_ifup_content = """#!/bin/sh
exit 0
"""

    temp_file = "/tmp/qemu-ifup-temp"
    with open(temp_file, 'w') as f:
        f.write(qemu_ifup_content)

    run_sudo_command(f"mv {temp_file} /etc/qemu-ifup")
    run_sudo_command("chmod +x /etc/qemu-ifup")

    print("[✓] /etc/qemu-ifup 配置完成")
    return True


def restore_qemu_ifup():
    print("[*] 恢复 /etc/qemu-ifup...")
    backup_exists = subprocess.run(
        "test -f /etc/qemu-ifup.bak",
        shell=True,
        capture_output=True,
    ).returncode == 0
    if backup_exists:
        run_sudo_command("mv /etc/qemu-ifup.bak /etc/qemu-ifup", check=False)
    else:
        run_sudo_command("rm -f /etc/qemu-ifup", check=False)
    print("[✓] /etc/qemu-ifup 已恢复")


def cleanup_network(tap_name: str = "tap0"):
    print(f"[*] 清理网络接口 {tap_name}...")

    if subprocess.run(f"ip link show {tap_name}", shell=True, capture_output=True).returncode == 0:
        run_sudo_command(f"ip link set {tap_name} down", check=False)
        run_sudo_command(f"ip tuntap del mode tap name {tap_name}", check=False)

    print("[✓] 网络清理完成")
