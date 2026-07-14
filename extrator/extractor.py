"""
Firmware Extractor - Smart iterative extraction workflow
Implements: binwalk -Me → Analyze → UBI tools → Loop until rootfs
"""
import os
import subprocess
import logging
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class ExtractionTool(Enum):
    """可用的提取工具"""
    BINWALK = "binwalk"
    UBI_EXTRACT_FILE = "ubi_extract_file"
    UBIDUMP = "ubidump"
    UBIREADER_IMAGES = "ubireader_extract_images"
    UBIREADER_FILES = "ubireader_extract_files"
    UNSQUASHFS = "unsquashfs"


@dataclass
class ExtractionResult:
    """存储提取结果"""
    success: bool
    output_path: Optional[Path]
    tool: ExtractionTool
    details: str
    extracted_files: int = 0
    next_targets: List[Path] = None

    def __post_init__(self):
        if self.next_targets is None:
            self.next_targets = []


class FirmDissector:
    """智能固件提取器 - 循环解包工作流"""

    def __init__(self, firmware_path: str, output_dir: str = None):
        self.firmware_path = Path(firmware_path)
        # 默认输出目录为 extracted_固件名称
        self.output_dir = Path(output_dir) if output_dir else self.firmware_path.parent / f"extracted_{self.firmware_path.stem}"
        self.extraction_chain: List[ExtractionResult] = []
        self.current_depth = 0
        self.max_depth = 15
        self.visited_files = set()  # 避免重复处理
        self.target_queue = []  # 待处理的目标文件队列

        if not self.firmware_path.exists():
            raise FileNotFoundError(f"固件文件不存在: {firmware_path}")

        # 打印 ASCII 艺术字横幅
        self._print_banner()

        logger.info("=" * 70)
        logger.info(f"📦 初始化智能固件提取器")
        logger.info(f"   固件: {self.firmware_path}")
        logger.info(f"   输出: {self.output_dir}")
        logger.info("=" * 70)

    def extract(self) -> Path:
        """执行智能循环提取，直到获得rootfs"""
        current_target = self.firmware_path

        while self.current_depth < self.max_depth:
            logger.info("\n" + "=" * 70)
            logger.info(f"🔄 第 {self.current_depth} 轮解包循环")
            logger.info(f"   当前目标: {current_target}")
            logger.info("=" * 70)

            # 步骤1: 分析当前文件/目录
            analysis = self._analyze_target(current_target)
            self._log_analysis(analysis)

            # 步骤2: 检查是否已经是rootfs
            if analysis['is_rootfs']:
                logger.info("✅ 已找到rootfs，提取完成！")
                return current_target

            # 步骤3: 选择最佳提取策略并执行（不指定输出目录，让工具自行处理）
            result = self._extract_with_strategy(current_target, analysis)

            if not result.success:
                logger.warning(f"⚠️  提取失败: {result.details}")
                break

            self.extraction_chain.append(result)
            logger.info(f"✅ 提取成功: {result.details}")
            logger.info(f"   工具: {result.tool.value}")
            logger.info(f"   提取文件数: {result.extracted_files}")
            if result.output_path:
                logger.info(f"   输出路径: {result.output_path}")

            # 步骤4: 检查是否找到rootfs
            if result.output_path:
                rootfs_path = self._find_rootfs(result.output_path)
                if rootfs_path:
                    logger.info("=" * 70)
                    logger.info(f"🎯 找到 rootfs: {rootfs_path}")
                    logger.info("=" * 70)
                    return rootfs_path

            # 步骤5: 确定下一轮目标
            # 优先使用提取结果中的 next_targets（如 UBI 镜像中的 UBIFS 文件）
            if result.next_targets:
                # 将所有 next_targets 加入队列
                for target in result.next_targets:
                    if str(target) not in self.visited_files:
                        self.target_queue.append(target)
                        self.visited_files.add(str(target))
                logger.info(f"   ➤ 将 {len(result.next_targets)} 个目标加入队列")

            # 从队列中获取下一个目标
            if self.target_queue:
                next_target = self.target_queue.pop(0)
                logger.info(f"   ➤ 从队列中选择下一个目标: {next_target.name} (剩余: {len(self.target_queue)})")
            else:
                next_target = self._determine_next_target(result.output_path, analysis) if result.output_path else None

            if not next_target:
                logger.info("ℹ️  未找到可继续解包的目标，可能已到达底层文件系统")
                # 检查最后的结果是否可用
                if result.output_path and result.output_path.exists():
                    final_check = self._analyze_target(result.output_path)
                    if final_check['is_rootfs']:
                        return result.output_path
                break

            # 准备下一轮
            self.current_depth += 1
            current_target = next_target

        # 未找到明确rootfs，返回最佳结果
        if self.extraction_chain:
            last_result = self.extraction_chain[-1]
            logger.info(f"\n📁 返回最终提取目录: {last_result.output_path}")
            return last_result.output_path

        raise Exception("❌ 提取失败：无法解包固件")

    def _analyze_target(self, target: Path) -> Dict:
        """分析目标（文件或目录）的特征"""
        analysis = {
            'is_rootfs': False,
            'is_ubi': False,
            'is_ubifs': False,
            'is_squashfs': False,
            'is_cpio': False,
            'is_archive': False,
            'file_type': 'unknown',
            'contains_nested': False,
            'nested_files': [],
            'binwalk_output': []
        }

        if target.is_dir():
            # 分析目录
            analysis['is_rootfs'] = self._check_rootfs_indicators(target)
            analysis['nested_files'] = self._find_nested_archives(target)
            analysis['contains_nested'] = len(analysis['nested_files']) > 0
            analysis['file_type'] = 'directory'

        elif target.is_file():
            # 优先检查文件扩展名（更准确）
            suffix = target.suffix.lower()

            # UBIFS文件扩展名检查
            if suffix == '.ubifs':
                analysis['is_ubifs'] = True

            # UBI文件扩展名检查
            elif suffix == '.ubi':
                analysis['is_ubi'] = True

            # SquashFS文件扩展名检查
            elif suffix in ['.squashfs', '.sfs']:
                analysis['is_squashfs'] = True

            # 使用file命令和binwalk进行更深入的分析
            try:
                # 使用file命令
                result = subprocess.run(
                    ['file', str(target)],
                    capture_output=True, text=True, timeout=10
                )
                file_type = result.stdout.lower()
                analysis['file_type'] = file_type

                # 使用binwalk扫描
                binwalk_result = subprocess.run(
                    ['binwalk', str(target)],
                    capture_output=True, text=True, timeout=60
                )
                analysis['binwalk_output'] = binwalk_result.stdout.split('\n')

                # 如果扩展名没确定，用内容检测
                if not analysis['is_ubi'] and not analysis['is_ubifs']:
                    # 检测特定类型
                    analysis['is_ubi'] = any([
                        'ubi image' in file_type,
                        '0x2B4' in binwalk_result.stdout,
                        self._check_magic_bytes(target, b'UBI!')
                    ])

                    analysis['is_ubifs'] = any([
                        'ubifs' in file_type and 'ubi image' not in file_type,
                        'UBI#' in binwalk_result.stdout,
                        self._check_magic_bytes(target, [b'\x31\x18\x10\x06', b'UBI#'])
                    ])

                analysis['is_squashfs'] = analysis['is_squashfs'] or any([
                    'squashfs' in file_type,
                    'hsqs' in binwalk_result.stdout,
                    'sqsh' in binwalk_result.stdout
                ])

                analysis['is_cpio'] = 'cpio archive' in file_type
                analysis['is_archive'] = any([
                    'archive' in file_type,
                    'tar archive' in file_type,
                    analysis['is_cpio']
                ])

            except Exception as e:
                logger.warning(f"分析文件失败: {e}")

        return analysis

    def _log_analysis(self, analysis: Dict):
        """输出分析结果"""
        logger.info("📊 分析结果:")
        logger.info(f"   类型: {analysis['file_type']}")
        logger.info(f"   是rootfs: {'✅' if analysis['is_rootfs'] else '❌'}")
        logger.info(f"   UBI镜像: {'✅' if analysis['is_ubi'] else '❌'}")
        logger.info(f"   UBIFS: {'✅' if analysis['is_ubifs'] else '❌'}")
        logger.info(f"   SquashFS: {'✅' if analysis['is_squashfs'] else '❌'}")
        logger.info(f"   归档文件: {'✅' if analysis['is_archive'] else '❌'}")
        if analysis['nested_files']:
            logger.info(f"   嵌套文件: {len(analysis['nested_files'])} 个")
            for f in analysis['nested_files'][:5]:
                logger.info(f"      - {f.name}")

    def _extract_with_strategy(self, target: Path, analysis: Dict) -> ExtractionResult:
        """根据分析结果选择最佳提取策略"""

        # 策略1: UBI镜像 → 使用ubi_extract_file或ubireader
        if analysis['is_ubi']:
            return self._extract_ubi(target)

        # 策略2: UBIFS文件系统 → 使用binwalk
        if analysis['is_ubifs']:
            return self._extract_ubifs(target)

        # 策略3: SquashFS → 使用unsquashfs
        if analysis['is_squashfs']:
            return self._extract_squashfs(target)

        # 策略4: 目录中的嵌套文件 → 提取每一个
        if target.is_dir() and analysis['nested_files']:
            return self._extract_nested_files(target, analysis['nested_files'])

        # 策略5: 默认使用binwalk -Me（递归matryoshka模式）
        return self._extract_binwalk_me(target)

    def _extract_binwalk_me(self, target: Path) -> ExtractionResult:
        """使用binwalk -Me递归提取（首选方法）"""
        logger.info("🔧 使用 binwalk -Me 递归提取...")

        try:
            # 确保target是绝对路径
            target = target.resolve()

            # binwalk会在目标文件所在目录创建提取目录
            extract_dir = target.parent / f"{target.name}_extracted"

            logger.info(f"命令: binwalk -M -e {target.name}")
            logger.info(f"工作目录: {target.parent}")
            logger.info(f"预期提取目录: {extract_dir}")

            result = subprocess.run(
                ['binwalk', '-M', '-e', str(target)],
                capture_output=True,
                text=True,
                timeout=600,
                cwd=str(target.parent)
            )

            # 输出binwalk的详细信息用于调试
            if result.stdout:
                logger.debug(f"binwalk stdout: {result.stdout[:500]}")
            if result.stderr:
                logger.warning(f"binwalk stderr: {result.stderr[:500]}")

            # 等待一下确保文件系统同步
            import time
            time.sleep(2)

            # 策略1: 检查预期的提取目录
            if extract_dir.exists():
                logger.info(f"   ✅ 找到提取目录: {extract_dir}")
                file_count = sum(1 for _ in extract_dir.rglob('*') if _.is_file())
                return ExtractionResult(
                    success=True,
                    output_path=extract_dir,
                    tool=ExtractionTool.BINWALK,
                    details=f"binwalk递归提取完成",
                    extracted_files=file_count
                )

            # 策略2: 搜索可能的提取目录（带通配符）
            logger.info(f"   ⚠️  预期目录不存在，搜索可能的提取目录...")

            # binwalk可能创建的目录名模式
            possible_patterns = [
                f"_{target.name}*.extracted",
                f"_{target.name}.extracted*",
                f"_{target.stem}*.extracted",
                f"_{target.stem}.extracted*",
                f"{target.name}*.extracted",
                f"{target.stem}*.extracted",
                "*.extracted",
            ]

            for pattern in possible_patterns:
                extracted = list(target.parent.glob(pattern))
                if extracted:
                    # 按修改时间排序，选择最新的
                    extracted.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                    actual_dir = extracted[0]
                    logger.info(f"   ✅ 找到匹配目录: {actual_dir}")
                    file_count = sum(1 for _ in actual_dir.rglob('*') if _.is_file())
                    return ExtractionResult(
                        success=True,
                        output_path=actual_dir,
                        tool=ExtractionTool.BINWALK,
                        details=f"binwalk递归提取完成 (目录: {actual_dir.name})",
                        extracted_files=file_count
                    )

            # 策略3: 列出实际创建的文件/目录
            logger.info(f"   ⚠️  未找到标准提取目录，列出父目录内容:")
            try:
                parent_items = list(target.parent.iterdir())
                for item in parent_items[:20]:
                    logger.info(f"      - {item.name} {'(目录)' if item.is_dir() else '(文件)'}")
            except Exception as e:
                logger.warning(f"   无法列出目录: {e}")

            return ExtractionResult(
                success=False,
                output_path=None,
                tool=ExtractionTool.BINWALK,
                details="binwalk未创建预期的提取目录"
            )

        except subprocess.TimeoutExpired:
            return ExtractionResult(
                success=False,
                output_path=None,
                tool=ExtractionTool.BINWALK,
                details="binwalk执行超时"
            )
        except Exception as e:
            logger.error(f"   异常: {e}")
            return ExtractionResult(
                success=False,
                output_path=None,
                tool=ExtractionTool.BINWALK,
                details=f"binwalk执行失败: {e}"
            )

    def _extract_ubi(self, target: Path) -> ExtractionResult:
        """提取UBI镜像 - 尝试多种工具"""
        logger.info("🔧 提取UBI镜像...")

        # 创建基于目标的输出目录
        output_dir = target.parent / f"{target.stem}_extracted"

        # 方法1: ubi_extract_file (最常用)
        if shutil.which('ubi_extract_file'):
            logger.info("尝试 ubi_extract_file...")
            try:
                cmd = ['ubi_extract_file', str(target), str(output_dir)]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if output_dir.exists() and any(output_dir.iterdir()):
                    file_count = sum(1 for _ in output_dir.rglob('*') if _.is_file())
                    # 查找嵌套的 UBIFS 文件
                    nested_ubifs = list(output_dir.rglob('*.ubifs'))
                    return ExtractionResult(
                        success=True,
                        output_path=output_dir,
                        tool=ExtractionTool.UBI_EXTRACT_FILE,
                        details=f"ubi_extract_file提取成功",
                        extracted_files=file_count,
                        next_targets=nested_ubifs
                    )
            except Exception as e:
                logger.warning(f"   ubi_extract_file失败: {e}")

        # 方法2: ubidump.py (fallback when ubi_extract_file fails)
        ubidump_script = Path(__file__).parent / "ubidump.py"
        if ubidump_script.exists():
            logger.info("   尝试 ubidump.py...")
            try:
                cmd = ['python3', str(ubidump_script), '--savedir', str(output_dir), str(target)]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if output_dir.exists() and any(output_dir.iterdir()):
                    file_count = sum(1 for _ in output_dir.rglob('*') if _.is_file())
                    # 查找嵌套的 UBIFS 文件
                    nested_ubifs = list(output_dir.rglob('*.ubifs'))
                    logger.info(f"   找到 {len(nested_ubifs)} 个 UBIFS 文件")
                    return ExtractionResult(
                        success=True,
                        output_path=output_dir,
                        tool=ExtractionTool.UBIDUMP,
                        details=f"ubidump提取成功",
                        extracted_files=file_count,
                        next_targets=nested_ubifs
                    )
            except Exception as e:
                logger.warning(f"   ubidump失败: {e}")

        # 方法3: ubireader_extract_images (系统命令)
        if shutil.which('ubireader_extract_images'):
            logger.info("   尝试 ubireader_extract_images...")
            try:
                cmd = ['ubireader_extract_images', '-o', str(output_dir), str(target)]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if output_dir.exists() and any(output_dir.iterdir()):
                    file_count = sum(1 for _ in output_dir.rglob('*') if _.is_file())
                    # 查找嵌套的 UBIFS 文件
                    nested_ubifs = list(output_dir.rglob('*.ubifs'))
                    logger.info(f"   找到 {len(nested_ubifs)} 个 UBIFS 文件")
                    return ExtractionResult(
                        success=True,
                        output_path=output_dir,
                        tool=ExtractionTool.UBIREADER_IMAGES,
                        details=f"ubireader提取成功",
                        extracted_files=file_count,
                        next_targets=nested_ubifs
                    )
            except Exception as e:
                logger.warning(f"   ubireader_extract_images失败: {e}")

        # 方法4: binwalk -Me (fallback)
        logger.info("   回退到 binwalk -Me...")
        return self._extract_binwalk_me(target)

    def _extract_ubifs(self, target: Path) -> ExtractionResult:
        """提取UBIFS文件系统"""
        logger.info("🔧 提取UBIFS文件系统...")

        # 优先使用 binwalk -Me (对 UBIFS 效果更好)
        logger.info("   使用 binwalk -Me 递归提取...")
        return self._extract_binwalk_me(target)

    def _extract_squashfs(self, target: Path) -> ExtractionResult:
        """提取SquashFS文件系统"""
        logger.info("🔧 提取SquashFS文件系统...")

        # 创建基于目标的输出目录
        output_dir = target.parent / f"{target.stem}_extracted"

        if shutil.which('unsquashfs'):
            try:
                # unsquashfs会创建squashfs-root目录
                cmd = ['unsquashfs', '-f', '-d', str(output_dir), str(target)]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if output_dir.exists() and any(output_dir.iterdir()):
                    file_count = sum(1 for _ in output_dir.rglob('*') if _.is_file())
                    return ExtractionResult(
                        success=True,
                        output_path=output_dir,
                        tool=ExtractionTool.UNSQUASHFS,
                        details=f"SquashFS提取成功",
                        extracted_files=file_count
                    )
            except Exception as e:
                logger.warning(f"   unsquashfs失败: {e}")

        # 回退到binwalk
        return self._extract_binwalk_me(target)

    def _extract_nested_files(self, parent_dir: Path, nested_files: List[Path]) -> ExtractionResult:
        """提取目录中的多个嵌套文件"""
        logger.info(f"🔧 提取 {len(nested_files)} 个嵌套文件...")

        extracted_count = 0
        next_targets = []
        output_dir = parent_dir / "nested_extracted"
        output_dir.mkdir(parents=True, exist_ok=True)

        for i, nested_file in enumerate(nested_files[:10]):  # 限制处理数量
            logger.info(f"   [{i+1}/{len(nested_files)}] {nested_file.name}")

            analysis = self._analyze_target(nested_file)
            result = self._extract_with_strategy(nested_file, analysis)

            if result.success:
                extracted_count += result.extracted_files
                if result.next_targets:
                    next_targets.extend(result.next_targets)

        file_count = sum(1 for _ in output_dir.rglob('*') if _.is_file())

        return ExtractionResult(
            success=extracted_count > 0,
            output_path=output_dir,
            tool=ExtractionTool.BINWALK,
            details=f"提取了 {extracted_count} 个嵌套文件",
            extracted_files=file_count,
            next_targets=next_targets
        )

    def _determine_next_target(self, current_dir: Path, prev_analysis: Dict) -> Optional[Path]:
        """智能确定下一轮提取的目标"""
        if not current_dir or not current_dir.exists():
            return None

        # 优先级1: UBI/UBIFS镜像文件
        for pattern in ['*.ubi', '*.ubifs', '*.ubi.img', '*.ubifs.img']:
            matches = list(current_dir.rglob(pattern))
            if matches:
                target = matches[0]
                if str(target) not in self.visited_files:
                    self.visited_files.add(str(target))
                    logger.info(f"   ➤ 下一个目标: {target.name} (UBI镜像)")
                    return target

        # 优先级2: 大型二进制文件（可能是固件）
        files = [f for f in current_dir.rglob('*')
                if f.is_file() and not f.is_symlink()
                and str(f) not in self.visited_files]

        # 过滤掉已知的非固件文件
        excluded_exts = ['.txt', '.log', '.xml', '.html', '.json', '.md5', '.sha256']
        candidates = [f for f in files
                     if f.suffix.lower() not in excluded_exts
                     and f.stat().st_size > 1024 * 1024]  # > 1MB

        for candidate in sorted(candidates, key=lambda x: x.stat().st_size, reverse=True)[:5]:
            # 快速检查是否为二进制
            try:
                with open(candidate, 'rb') as f:
                    header = f.read(32)
                    # 排除ELF、压缩文件等
                    if not header.startswith(b'\x7fELF'):
                        self.visited_files.add(str(candidate))
                        logger.info(f"   ➤ 下一个目标: {candidate.name} ({candidate.stat().st_size // 1024}KB)")
                        return candidate
            except:
                continue

        # 优先级3: 检查是否有子目录包含可提取的内容
        for subdir in current_dir.iterdir():
            if subdir.is_dir() and not subdir.name.startswith('.') and subdir.name != '_extracted':
                nested = self._find_nested_archives(subdir)
                if nested:
                    logger.info(f"   ➤ 下一个目标: {nested[0].name} (目录中的嵌套文件)")
                    self.visited_files.add(str(nested[0]))
                    return nested[0]

        logger.info("   ℹ️  未找到下一轮提取目标")
        return None

    def _find_rootfs(self, directory: Path) -> Optional[Path]:
        """查找rootfs目录"""
        if not directory or not directory.exists():
            return None

        # 检查当前目录
        if self._check_rootfs_indicators(directory):
            return directory

        # 递归检查子目录（限制深度）
        for item in directory.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                result = self._find_rootfs(item)
                if result:
                    return result

        return None

    def _check_rootfs_indicators(self, directory: Path) -> bool:
        """检查目录是否为rootfs"""
        if not directory or not directory.is_dir():
            return False

        rootfs_indicators = ['bin', 'etc', 'lib', 'usr', 'sbin', 'var', 'root', 'home', 'proc', 'sys', 'dev']
        dirs = [d.name for d in directory.iterdir() if d.is_dir()]
        matches = sum(1 for ind in rootfs_indicators if ind in dirs)

        return matches >= 3

    def _find_nested_archives(self, directory: Path) -> List[Path]:
        """在目录中查找嵌套的归档文件"""
        if not directory or not directory.is_dir():
            return []

        patterns = [
            '*.ubi', '*.ubifs', '*.img', '*.bin',
            '*.tar', '*.tar.gz', '*.tgz', '*.tar.bz2',
            '*.cpio', '*.squashfs', '*.jffs2',
            '*.trx', '*.dlf', '*.wsp'
        ]

        nested = []
        for pattern in patterns:
            matches = list(directory.rglob(pattern))
            nested.extend(matches)

        # 去重并排序
        nested = list(set(nested))
        nested.sort(key=lambda x: x.stat().st_size, reverse=True)

        return nested[:20]  # 限制数量

    def _check_magic_bytes(self, file_path: Path, signatures) -> bool:
        """检查文件的magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)

                if isinstance(signatures, bytes):
                    signatures = [signatures]

                return any(header.startswith(sig) for sig in signatures)
        except:
            return False

    def _print_banner(self):
        """打印 ASCII 艺术字横幅"""
        banner = r"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ______ _                _____  _                   _               ║
║  |  ____(_)              |  __ \(_)                 | |              ║
║  | |__   _ _ __ _ __ ___ | |  | |_ ___ ___  ___  ___| |_ ___  _ __   ║
║  |  __| | | '__| '_ ` _ \| |  | | / __/ __|/ _ \/ __| __/ _ \| '__|  ║
║  | |    | | |  | | | | | | |__| | \__ \__ \  __/ (__| || (_) | |     ║
║  |_|    |_|_|  |_| |_| |_|_____/|_|___/___/\___|\___|\__\___/|_|     ║
║                                                                      ║
║             Firmware Dissector Tool v1.0 By Redtecher                ║
║                Smart Iterative Extraction Workflow                   ║
╚══════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

    def get_extraction_summary(self) -> str:
        """获取提取摘要报告"""
        if not self.extraction_chain:
            return "❌ 无提取记录"

        summary = ["\n" + "=" * 70]
        summary.append("📋 提取链摘要")
        summary.append("=" * 70)

        for i, result in enumerate(self.extraction_chain):
            summary.append(f"\n[{i}] 工具: {result.tool.value}")
            summary.append(f"    详情: {result.details}")
            summary.append(f"    文件数: {result.extracted_files}")
            summary.append(f"    路径: {result.output_path}")

        summary.append("\n" + "=" * 70)
        return "\n".join(summary)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python extractor.py <firmware_file> [output_dir]")
        sys.exit(1)

    firmware = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        extractor = FirmDissector(firmware, output)
        rootfs = extractor.extract()

        print("\n" + "=" * 70)
        print(f"✅ 提取完成！")
        print(f"🎯 Rootfs路径: {rootfs}")
        print(extractor.get_extraction_summary())

    except Exception as e:
        print(f"❌ 错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
