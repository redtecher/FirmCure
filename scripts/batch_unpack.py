#!/usr/bin/env python3
"""
batch_unpack.py - 批量固件解包工具 (FirmCure)

扫描目录中的固件文件, 依次:
  预处理容器 (zip/rar/7z/tar) → binwalk -Me 递归解包 → 定位 rootfs
失败时回退到 extrator/FirmDissector。支持并行、断点续跑、清单报告。

解包策略 (分层, 越往后越重):
  A) binwalk -Me <源文件>            # 主路径: binwalk 自带 zip/rar 识别 + matryoshka 递归
  B) 手动解容器 + binwalk -Me <镜像>  # 兜底1: 处理中文/空格内层文件名等坑
  C) FirmDissector (extrator/)       # 兜底2: UBI/UBIFS 等需要专用工具的固件

用法:
  python3 scripts/batch_unpack.py                            # 扫描 iots/ → iots/extracted/
  python3 scripts/batch_unpack.py -i iots/ -o iots/extracted/ -j 4
  python3 scripts/batch_unpack.py iots/foo.zip iots/bar.rar  # 显式文件列表
  python3 scripts/batch_unpack.py --limit 3                  # 先试 3 个
  python3 scripts/batch_unpack.py --force                    # 强制重新解包(忽略已完成)
  python3 scripts/batch_unpack.py --dry-run                  # 只列出将处理的文件

依赖: binwalk unzip unrar 7z tar file unsquashfs (缺失会在启动时告警, 不致命)
"""
import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_PRINT_LOCK = threading.Lock()   # 让多线程的日志输出不交错

# ────────────────────────────── 配置 ──────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent          # FirmCure/
EXTRATOR_DIR = REPO_ROOT / "extrator"                        # FirmDissector 所在

# 视为固件源文件的扩展名 (容器 + 裸镜像)
FIRMWARE_EXT = {
    ".zip", ".rar", ".7z",
    ".tar", ".gz", ".tgz", ".bz2", ".xz", ".tar.gz",
    ".bin", ".img", ".firm", ".fw",
    ".trx", ".dlf", ".wsp", ".sdk", ".pkgtb",
    ".cpio", ".jffs2", ".squashfs", ".sfs",
    ".ubi", ".ubifs",
}

CONTAINER_TOOL = {  # 扩展名 → (解包命令前缀, 备注)
    ".zip":  ("unzip",  ["unzip", "-o", "-q", "{src}", "-d", "{dst}"]),
    ".rar":  ("unrar",  ["unrar", "x", "-o+", "-y", "{src}", "{dst}/"]),
    ".7z":   ("7z",     ["7z", "x", "-y", "-o{dst}", "{src}"]),
    ".tar":  ("tar",    ["tar", "-xf", "{src}", "-C", "{dst}"]),
    ".tgz":  ("tar",    ["tar", "-xzf", "{src}", "-C", "{dst}"]),
    ".gz":   ("tar",    ["tar", "-xzf", "{src}", "-C", "{dst}"]),
    ".bz2":  ("tar",    ["tar", "-xjf", "{src}", "-C", "{dst}"]),
    ".xz":   ("tar",    ["tar", "-xJf", "{src}", "-C", "{dst}"]),
}

ROOTFS_DIRS = {"bin", "etc", "lib", "usr", "sbin", "var", "root", "home", "proc", "sys", "dev"}
ARCH_KEYWORDS = ["aarch64", "arm", "mips", "x86-64", "80386", "intel", "powerpc", "risc-v"]

BINWALK_TIMEOUT = 1800   # 单次 binwalk 超时 (秒)


# ────────────────────────────── 工具函数 ──────────────────────────────

def run(cmd, cwd=None, timeout=BINWALK_TIMEOUT):
    """运行命令, 返回 (returncode, stdout, stderr)。命令用 list 形式, 原生处理中文/空格路径。"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def is_container(p: Path) -> bool:
    s = p.name.lower()
    return any(s.endswith(ext) for ext in CONTAINER_TOOL) or s.endswith(".tar.gz")


def is_firmware_file(p: Path) -> bool:
    if not p.is_file():
        return False
    s = p.name.lower()
    if s.endswith(".tar.gz"):
        return True
    return p.suffix.lower() in FIRMWARE_EXT


def sanitize_stem(name: str) -> str:
    """把文件名(去扩展名)规整成纯 ASCII 安全目录名: 去掉中文/中文符号/空格等。
    注意: Python3 的 \\w 是 Unicode 感知(含 CJK), 不能用它, 必须显式 ASCII 字符集。"""
    s = name
    if s.lower().endswith(".tar.gz"):
        s = s[:-len(".tar.gz")]
    else:
        s = os.path.splitext(s)[0]
    s = re.sub(r"[^A-Za-z0-9._\-]+", "_", s).strip("._")
    return s or "firmware"


ROOTFS_NAMES = ("squashfs-root", "jffs2-root", "cramfs-root", "rootfs", "root")


def _rootfs_score(d: Path) -> int:
    """目录里命中 rootfs 指示目录 (bin/etc/lib/...) 的数量。"""
    try:
        names = {x.name for x in d.iterdir() if x.is_dir()}
    except Exception:
        return 0
    return len(names & ROOTFS_DIRS)


def locate_rootfs(directory: Path, depth: int = 0):
    """在 directory 下定位真正的固件 rootfs。

    优先级:
      1) unsquashfs 输出的 squashfs-root* —— 权威的文件系统根, 取文件最多的
         (主 rootfs 通常最大; 固件里 /opt/.../rootfs 之类的应用内嵌 rootfs 会被自然忽略)。
      2) 其它命名 rootfs (jffs2-root/rootfs), 取最浅的。
      3) 回退: binwalk -Me 误判时, 取最浅且指示目录>=3 的目录。
    """
    if not directory or not directory.is_dir():
        return None
    # 1) squashfs-root* 取最大
    sq = [(count_files(d), d) for d in directory.rglob("squashfs-root*") if d.is_dir()]
    sq = [(n, d) for n, d in sq if n > 0]
    if sq:
        sq.sort(key=lambda x: x[0], reverse=True)
        return sq[0][1]
    # 2) / 3) 命名 rootfs 或 indicator 命中, 最浅优先
    hits = []
    try:
        for d in directory.rglob("*"):
            if not d.is_dir() or d.is_symlink():
                continue
            score = _rootfs_score(d)
            if score < 3:
                continue
            low = d.name.lower()
            named = low in ROOTFS_NAMES or any(low.startswith(n + "-") for n in ROOTFS_NAMES)
            depth_n = len(d.relative_to(directory).parts)
            hits.append((depth_n, 0 if named else 1, d))   # 浅优先, 命名优先
    except Exception:
        pass
    if hits:
        hits.sort(key=lambda x: (x[0], x[1]))
        return hits[0][2]
    return None


def detect_arch(rootfs: Path) -> str:
    """用 file 命令探测 rootfs 里某个 ELF 的架构 (跟符号链接, busybox 一般是软链目标)。"""
    probes = ["bin/busybox", "bin/sh", "sbin/init", "usr/bin/httpd", "bin/login"]
    candidates = [rootfs / p for p in probes if (rootfs / p).exists()]
    for sub in ("bin", "sbin", "usr/bin", "usr/sbin"):
        d = rootfs / sub
        if not d.is_dir():
            continue
        for f in d.iterdir():
            if f.is_file():              # is_file 会跟随符号链接
                candidates.append(f)
            if len(candidates) > 40:     # 够多了, 不必扫全
                break
    seen = set()
    for f in candidates:
        if str(f) in seen:
            continue
        seen.add(str(f))
        rc, out, _ = run(["file", "-b", str(f)], timeout=15)
        low = out.lower()
        if "elf" in low:
            for kw in ARCH_KEYWORDS:
                if kw in low:
                    return kw.upper() if kw in ("arm", "mips") else kw
            return "elf-unknown"
    return "unknown"


def count_files(rootfs: Path) -> int:
    try:
        return sum(1 for _ in rootfs.rglob("*") if _.is_file())
    except Exception:
        return 0


def extract_container(src: Path, dst: Path, log):
    """手动解压容器到 dst。返回 (成功?, 文件列表)。"""
    dst.mkdir(parents=True, exist_ok=True)
    ext_key = ".tar.gz" if src.name.lower().endswith(".tar.gz") else src.suffix.lower()
    entry = CONTAINER_TOOL.get(ext_key)
    if not entry:
        return False, []
    tool_name, tmpl = entry
    if not shutil.which(tool_name):
        log(f"  缺少工具 {tool_name}, 跳过手动解容器")
        return False, []
    cmd = [c.replace("{src}", str(src)).replace("{dst}", str(dst)) for c in tmpl]
    rc, out, err = run(cmd, timeout=600)
    if rc != 0:
        log(f"  解容器失败({tool_name}): {err.strip()[:200]}")
        return False, []
    files = [p for p in dst.rglob("*") if p.is_file()]
    return True, files


def pick_firmware_image(files, log):
    """从解出来的文件里挑最可能是固件镜像的: 优先 binwalk 识别出文件系统的, 其次最大文件。"""
    candidates = [f for f in files if f.stat().st_size > 512 * 1024]  # >512KB
    if not candidates:
        candidates = files[:]
    scored = []
    for f in candidates[:15]:
        rc, out, _ = run(["binwalk", str(f)], timeout=60)
        low = out.lower()
        score = sum(k in low for k in ("squashfs", "jffs2", "cramfs", "ubifs",
                                       "filesystem", "uimage", "linux", "rootfs"))
        scored.append((score, f.stat().st_size, f))
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    if scored and scored[0][0] > 0:
        return scored[0][2]
    # 没有命中文件系统特征 → 取最大文件 (binwalk -M 会继续递归)
    return max(candidates, key=lambda f: f.stat().st_size) if candidates else None


# ────────────────────────────── 单个固件处理 ──────────────────────────────

def process_one(source: Path, out_root: Path, force: bool) -> dict:
    stem = sanitize_stem(source.name)
    workdir = out_root / stem
    result = {
        "source": str(source), "stem": stem, "status": "failed",
        "method": None, "rootfs": None, "arch": "unknown",
        "file_count": 0, "elapsed_sec": 0.0, "error": None,
    }
    t0 = time.time()
    rec = []

    def log(msg):
        rec.append(msg)
        with _PRINT_LOCK:
            print(msg, flush=True)

    # 断点续跑: 已完成则跳过
    rootfs_link = workdir / "rootfs"
    if rootfs_link.exists() and not force:
        target = rootfs_link.resolve()
        if target.exists() and len({d.name for d in target.iterdir() if d.is_dir()} & ROOTFS_DIRS) >= 3:
            result.update(status="skipped", rootfs=str(target),
                          arch=detect_arch(target), file_count=count_files(target),
                          elapsed_sec=round(time.time() - t0, 1))
            log(f"[SKIP] {source.name} (已完成, rootfs 已存在)")
            _write_log(workdir, rec)
            return result

    if force and workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    log(f"\n{'='*70}\n[UNPACK] {source.name}  ({source.stat().st_size//1024} KB)")

    # ── 容器: 解包取内层镜像 → 复制成 ASCII 名 image.bin 放进 workdir → binwalk ──
    # 关键: 复制成 image.bin 并用 cwd=workdir 运行 (不用 -C), 一次规避三类坑:
    #   1) 内层中文/空格文件名; 2) binwalk -C 对"输入恰在 -C 目录内"行为不稳定;
    #   3) staging 嵌套在 workdir 内时输出落到 staging 被误删
    if is_container(source):
        staging = Path(tempfile.mkdtemp(prefix=f"unpack_{stem}_"))
        try:
            ok, files = extract_container(source, staging, log)
            if ok and files:
                img = pick_firmware_image(files, log)
                if img:
                    local = workdir / "image.bin"
                    try:
                        shutil.copy2(img, local)
                        log(f"  内层镜像: {img.name} (→ {local.name})")
                        rootfs = _try_binwalk(local, workdir, log, use_cwd=True)
                        if rootfs:
                            method = "binwalk_staged"
                    except OSError as e:
                        log(f"  复制内层镜像失败: {e}")
        finally:
            if not os.environ.get("BATCH_UNPACK_DEBUG"):
                shutil.rmtree(staging, ignore_errors=True)
            else:
                log(f"  [DEBUG] 保留 staging: {staging}")

    # ── 裸镜像 / 容器 staged 未果: 直接 binwalk -Me -C workdir 源文件 ──
    if not rootfs:
        rootfs = _try_binwalk(source, workdir, log, use_cwd=False)
        if rootfs:
            method = "binwalk"

    # ── FirmDissector 兜底 (UBI/UBIFS 等需要专用工具的固件) ──
    if not rootfs:
        rootfs = _try_firmdissector(source, workdir, log)
        if rootfs:
            method = "firmdissector"

    if rootfs and rootfs.is_dir():
        # 建立 rootfs 软链, 便于后续 FirmCure 统一定位
        try:
            if rootfs_link.exists() or rootfs_link.is_symlink():
                rootfs_link.unlink()
            rootfs_link.symlink_to(rootfs)
        except OSError:
            shutil.copytree(rootfs, rootfs_link, symlinks=True, dirs_exist_ok=True)
        arch = detect_arch(rootfs)
        result.update(status="ok", method=method, rootfs=str(rootfs),
                      arch=arch, file_count=count_files(rootfs),
                      elapsed_sec=round(time.time() - t0, 1), error=None)
        log(f"[OK] {source.name}  method={method} arch={arch} "
            f"files={result['file_count']} ({result['elapsed_sec']}s)")
    else:
        result.update(status="failed", elapsed_sec=round(time.time() - t0, 1),
                      error="所有策略均未定位到 rootfs")
        log(f"[FAIL] {source.name}: 未找到 rootfs")

    _write_log(workdir, rec)
    return result


def _try_binwalk(target: Path, cwd: Path, log, use_cwd: bool = False) -> Path | None:
    """binwalk 解包, 返回定位到的 rootfs。

    先用 -e (不递归进 squashfs 内部文件, 输出干净); 没找到 rootfs 再 -Me 兜底。
      use_cwd=True  : target 已在 cwd 内 (staged 后的 image.bin), 用相对名 + cwd 运行,
                      规避 binwalk -C 对"输入位于 -C 目录内"的不稳定行为。
      use_cwd=False : 用 -C cwd 指定输出目录, target 在 cwd 之外 (裸镜像源文件)。
    """
    for flags, label in [(["-e"], "binwalk -e"), (["-M", "-e"], "binwalk -Me")]:
        if use_cwd:
            cmd = ["binwalk"] + flags + [target.name]
            log(f"  {label} {target.name} (cwd={cwd.name}) ...")
            rc, out, err = run(cmd, cwd=str(cwd))
        else:
            cmd = ["binwalk"] + flags + ["-C", str(cwd), str(target)]
            log(f"  {label} -C {cwd.name} {target.name} ...")
            rc, out, err = run(cmd)
        if os.environ.get("BATCH_UNPACK_DEBUG"):
            log(f"  [DEBUG] cmd={cmd} rc={rc} stderr(300)={err[:300]!r}")
        if err and err.strip() and "WARNING" not in err:
            log(f"  binwalk stderr: {err.strip()[:200]}")
        if rc != 0:
            log(f"  binwalk 返回码 {rc}")
        rootfs = locate_rootfs(cwd)
        if rootfs:
            return rootfs
        log(f"  {label} 未定位到 rootfs, 尝试下一策略")
    return None


def _try_firmdissector(source: Path, workdir: Path, log) -> Path | None:
    """回退: 调用 extrator/FirmDissector 迭代解包。"""
    if not EXTRATOR_DIR.exists():
        return None
    log("  FirmDissector 兜底 ...")
    # 把源文件放进独立子目录, 让 FirmDissector 的输出落在我们控制的位置
    fd_in = workdir / "fd_in"
    fd_in.mkdir(exist_ok=True)
    local_src = fd_in / source.name
    try:
        if not local_src.exists():
            shutil.copy2(source, local_src)
    except Exception as e:
        log(f"  复制源文件失败: {e}")
        return None
    fd_out = workdir / "fd_out"
    try:
        sys.path.insert(0, str(EXTRATOR_DIR))
        import importlib
        extractor = importlib.import_module("extractor")
        importlib.reload(extractor)
        fd = extractor.FirmDissector(str(local_src), output_dir=str(fd_out))
        root = fd.extract()
        return locate_rootfs(fd_out) or (root if root and root.is_dir() else None)
    except Exception as e:
        log(f"  FirmDissector 失败: {e}")
        return None


def _write_log(workdir: Path, lines):
    try:
        (workdir / "unpack.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass


# ────────────────────────────── 发现 / 主流程 ──────────────────────────────

def discover(inputs, recursive=True):
    files = []
    for inp in inputs:
        p = Path(inp)
        if p.is_file() and is_firmware_file(p):
            files.append(p.resolve())
        elif p.is_dir():
            for root, _, names in os.walk(p):
                if not recursive and Path(root) != p:
                    continue
                for n in names:
                    fp = Path(root) / n
                    if is_firmware_file(fp) and not _is_extracted_artifact(fp, p):
                        files.append(fp.resolve())
        else:
            print(f"[warn] 忽略非固件/不存在: {inp}", file=sys.stderr)
    # 去重, 保持顺序
    seen, uniq = set(), []
    for f in files:
        if f not in seen:
            seen.add(f)
            uniq.append(f)
    return uniq


def _is_extracted_artifact(fp: Path, scan_root: Path) -> bool:
    """跳过输出目录和已有解包中间产物, 避免重复扫描已解出来的 .bin/.zip。"""
    for part in fp.parts:
        low = part.lower()
        if low == "extracted":              # 输出目录 <input>/extracted
            return True
        if ".extracted" in low:             # binwalk: _foo.zip.extracted
            return True
        if low.endswith("_extracted"):      # FirmDissector: foo_extracted
            return True
        if low.endswith("_extract"):        # 手动: TL-xxx_extract
            return True
    return False


def check_tools():
    missing = []
    for tool in ("binwalk", "file", "unzip", "unrar", "7z", "tar", "unsquashfs"):
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        print(f"[warn] 缺少工具(部分容器/格式可能解不了): {', '.join(missing)}", file=sys.stderr)


def write_manifest(out_root: Path, results):
    out_root.mkdir(parents=True, exist_ok=True)
    (out_root / "manifest.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    with (out_root / "manifest.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()) if results else
                           ["source", "stem", "status", "method", "rootfs",
                            "arch", "file_count", "elapsed_sec", "error"])
        w.writeheader()
        for r in results:
            w.writerow(r)


def main():
    ap = argparse.ArgumentParser(
        description="批量固件解包 (binwalk -Me 为主, FirmDissector 兜底)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("inputs", nargs="*",
                    help="固件文件或目录 (默认: iots/)")
    ap.add_argument("-i", "--input", default=None, help="输入目录 (默认 iots/)")
    ap.add_argument("-o", "--output", default=None,
                    help="输出目录 (默认 <input>/extracted)")
    ap.add_argument("-j", "--jobs", type=int,
                    default=min(4, os.cpu_count() or 2), help="并行数 (默认 min(4,cpu))")
    ap.add_argument("--limit", type=int, default=0, help="只处理前 N 个 (调试用)")
    ap.add_argument("--force", action="store_true", help="强制重新解包, 忽略已完成")
    ap.add_argument("--dry-run", action="store_true", help="只列出待处理文件, 不解包")
    ap.add_argument("--no-recursive", action="store_true", help="不递归扫描输入目录")
    args = ap.parse_args()

    check_tools()

    # 解析输入
    in_targets = args.inputs or ([args.input] if args.input else [])
    if not in_targets:
        default_in = REPO_ROOT / "iots"
        if not default_in.exists():
            ap.error(f"默认输入目录不存在: {default_in}, 请用 -i 指定")
        in_targets = [str(default_in)]
    scan_recursive = not args.no_recursive

    files = discover(in_targets, recursive=scan_recursive)
    if args.limit > 0:
        files = files[:args.limit]

    if not files:
        print("未发现任何固件文件。")
        return

    # 输出目录: 显式 -o 优先, 否则取第一个输入目录下的 extracted/
    if args.output:
        out_root = Path(args.output).resolve()
    else:
        first = Path(in_targets[0]).resolve()
        base = first if first.is_dir() else first.parent
        out_root = base / "extracted"
    out_root.mkdir(parents=True, exist_ok=True)

    print(f"输入: {in_targets}")
    print(f"输出: {out_root}")
    print(f"发现 {len(files)} 个固件, 并行={args.jobs}, force={args.force}")

    if args.dry_run:
        for f in files:
            print(f"  - {f}")
        return

    results = []
    t_start = time.time()
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(process_one, f, out_root, args.force): f for f in files}
        # _noop_log 仅占位, 真正的日志在 process_one 内部 print; 这里按完成顺序收集
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                f = futures[fut]
                results.append({"source": str(f), "stem": sanitize_stem(f.name),
                                "status": "failed", "method": None, "rootfs": None,
                                "arch": "unknown", "file_count": 0, "elapsed_sec": 0,
                                "error": f"异常: {e}"})

    # 按 stem 排序输出稳定清单
    results.sort(key=lambda r: r["stem"])
    write_manifest(out_root, results)

    # 汇总
    ok = sum(1 for r in results if r["status"] == "ok")
    skip = sum(1 for r in results if r["status"] == "skipped")
    fail = sum(1 for r in results if r["status"] == "failed")
    print(f"\n{'='*70}")
    print(f"完成: {ok} ok / {skip} skipped / {fail} failed  (共 {len(results)}, "
          f"耗时 {round(time.time()-t_start,1)}s)")
    print(f"清单: {out_root/'manifest.json'}  (同目录还有 manifest.csv)")
    if fail:
        print(f"\n失败列表:")
        for r in results:
            if r["status"] == "failed":
                print(f"  - {r['source']}: {r['error']}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main() or 0)
