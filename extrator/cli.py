#!/usr/bin/env python3
"""
FirmDissector CLI - 命令行接口
"""
import argparse
import sys
import json
from pathlib import Path
from extractor import FirmDissector


def main():
    # Print ASCII art at the beginning

    parser = argparse.ArgumentParser(
        description='FirmDissector - 固件迭代解包工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s firmware.bin                           # 解包固件
  %(prog)s firmware.bin -o output                 # 指定输出目录
  %(prog)s firmware.bin --json                    # 输出JSON格式结果
  %(prog)s firmware.bin --max-depth 5             # 设置最大迭代深度
        """
    )

    parser.add_argument('firmware', help='固件文件路径')
    parser.add_argument('-o', '--output', help='输出目录 (默认: ./extracted)')
    parser.add_argument('--max-depth', type=int, default=10,
                        help='最大迭代深度 (默认: 10)')
    parser.add_argument('--json', action='store_true',
                        help='以JSON格式输出结果')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='详细输出模式')
    parser.add_argument('--dry-run', action='store_true',
                        help='仅分析不解包')

    args = parser.parse_args()

    # 检查文件存在
    firmware_path = Path(args.firmware)
    if not firmware_path.exists():
        print(f"错误: 固件文件不存在: {args.firmware}", file=sys.stderr)
        sys.exit(1)

    try:
        # 创建提取器
        dissector = FirmDissector(
            str(firmware_path),
            output_dir=args.output
        )
        dissector.max_depth = args.max_depth

        if args.dry_run:
            print("Dry run模式 - 仅分析文件")
            info = dissector._analyze_target(firmware_path)
            print(f"\n文件分析结果:")
            print(f"  UBI镜像: {info['is_ubi']}")
            print(f"  UBIFS文件系统: {info['is_ubifs']}")
            print(f"  Binwalk条目数: {len(info['binwalk_output'])}")
            return

        # 执行提取
        rootfs_path = dissector.extract()

        # 输出结果
        if args.json:
            result = {
                'success': True,
                'rootfs_path': str(rootfs_path),
                'firmware': str(firmware_path),
                'extraction_chain': [
                    {
                        'method': r.tool.value,
                        'path': str(r.output_path),
                        'details': r.details
                    }
                    for r in dissector.extraction_chain
                ]
            }
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print("\n" + "=" * 60)
            print("提取完成!")
            print(f"RootFS路径: {rootfs_path}")
            print("=" * 60)
            print(dissector.get_extraction_summary())

    except KeyboardInterrupt:
        print("\n\n提取被用户中断", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n错误: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
