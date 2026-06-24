#!/usr/bin/env python3
"""
FirmDissector 测试脚本 - 验证程序结构
"""
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

from extractor import FirmDissector, ExtractionResult

def test_imports():
    """测试导入是否正常"""
    print("=" * 60)
    print("测试 1: 导入模块")
    print("=" * 60)

    try:
        from extractor import FirmDissector, ExtractionResult
        print("✓ 成功导入 FirmDissector")
        print("✓ 成功导入 ExtractionResult")
        return True
    except Exception as e:
        print(f"✗ 导入失败: {e}")
        return False


def test_class_structure():
    """测试类结构"""
    print("\n" + "=" * 60)
    print("测试 2: 类结构")
    print("=" * 60)

    try:
        # 检查类方法
        methods = ['extract', '_analyze_target', '_extract_ubi',
                   '_extract_ubifs', '_find_rootfs']

        for method in methods:
            if hasattr(FirmDissector, method):
                print(f"✓ 方法存在: {method}")
            else:
                print(f"✗ 方法缺失: {method}")
                return False

        return True
    except Exception as e:
        print(f"✗ 测试失败: {e}")
        return False


def test_binwalk_available():
    """检查 binwalk 是否可用"""
    print("\n" + "=" * 60)
    print("测试 3: 依赖工具检查")
    print("=" * 60)

    import subprocess

    # 检查 binwalk
    try:
        result = subprocess.run(['which', 'binwalk'],
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ binwalk 已安装: {result.stdout.strip()}")
        else:
            print("✗ binwalk 未安装")
            print("  安装方法: sudo apt install binwalk")
    except Exception as e:
        print(f"✗ 检查 binwalk 失败: {e}")

    # 检查 ubireader
    try:
        result = subprocess.run(['which', 'ubireader_extract_images'],
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ ubireader 已安装: {result.stdout.strip()}")
        else:
            print("⚠ ubireader 未安装 (可选，会使用 binwalk 替代)")
            print("  安装方法: sudo apt install ubireader")
    except Exception as e:
        print(f"⚠ 检查 ubireader 失败: {e}")


def test_firmware_detection():
    """测试固件文件检测功能"""
    print("\n" + "=" * 60)
    print("测试 4: 文件检测功能")
    print("=" * 60)

    # 查找当前目录的固件文件
    current_dir = Path('.')
    firmware_files = []

    # 常见固件文件名
    patterns = ['*.bin', '*.trx', '*.img', '*.firmware']

    for pattern in patterns:
        matches = list(current_dir.glob(pattern))
        firmware_files.extend(matches)

    if firmware_files:
        print(f"找到 {len(firmware_files)} 个可能的固件文件:")
        for f in firmware_files[:5]:  # 只显示前5个
            size_mb = f.stat().st_size / (1024 * 1024)
            print(f"  - {f.name} ({size_mb:.2f} MB)")
    else:
        print("当前目录没有找到固件文件")
        print("\n你可以:")
        print("  1. 将固件文件复制到当前目录")
        print("  2. 使用完整路径运行:")
        print("     python example.py /path/to/firmware.bin")


def main():
    """运行所有测试"""
    print("\nFirmDissector 程序测试\n")

    results = []
    results.append(test_imports())
    results.append(test_class_structure())
    test_binwalk_available()
    test_firmware_detection()

    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)

    if all(results):
        print("✓ 程序结构正常，可以使用")
        print("\n下一步:")
        print("  1. 准备一个固件文件")
        print("  2. 运行: python cli.py <固件文件路径>")
        print("  3. 或: python example.py <固件文件路径>")
    else:
        print("✗ 程序存在问题，请检查")


if __name__ == '__main__':
    main()
