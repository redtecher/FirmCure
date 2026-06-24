"""
FirmDissector - 固件迭代解包工具

支持自动检测和提取:
  - UBI 镜像
  - UBIFS 文件系统
  - 多层嵌套固件
  - 自动定位 rootfs

示例:
    from FirmDissector import FirmDissector

    dissector = FirmDissector('firmware.bin')
    rootfs = dissector.extract()
    print(f"RootFS: {rootfs}")
"""

from .extractor import FirmDissector, ExtractionResult

__version__ = '1.0.0'
__all__ = ['FirmDissector', 'ExtractionResult']
