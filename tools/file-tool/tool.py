"""文件操作工具 - rootfs 文件系统读写、搜索、ELF 分析"""

import os
import json
import shutil
import subprocess
from pathlib import Path


class FileTool:
    """rootfs 文件操作后端

    所有路径自动拼接 ROOTFS_PATH 前缀，调用方只需传 rootfs 内的相对路径。
    """

    def __init__(self, rootfs_path: str = ""):
        self.rootfs_path = rootfs_path

    def _full(self, path: str) -> Path:
        """将 rootfs 相对路径转为宿主机绝对路径"""
        return Path(self.rootfs_path) / path.lstrip("/")

    # ─── 读 ───

    def read_file(self, path: str, encoding: str = "utf-8") -> str:
        """读取文本文件"""
        full = self._full(path)
        if not full.exists():
            return f"ERROR: File not found: {path}"
        try:
            return full.read_text(encoding=encoding, errors='replace')[:10000]
        except Exception as e:
            return f"ERROR: {e}"

    def read_json(self, path: str) -> str:
        """读取 JSON 文件并返回格式化字符串"""
        full = self._full(path)
        if not full.exists():
            return f"ERROR: File not found: {path}"
        try:
            content = json.loads(full.read_text(encoding='utf-8'))
            return json.dumps(content, ensure_ascii=False, indent=2)[:10000]
        except Exception as e:
            return f"ERROR: {e}"

    # ─── 写 / 删 / 创建 ───

    def write_file(self, path: str, content: str) -> str:
        """写入文本文件"""
        full = self._full(path)
        full.parent.mkdir(parents=True, exist_ok=True)
        try:
            full.write_text(content, encoding='utf-8')
            return f"Written {len(content)} bytes to {path}"
        except Exception as e:
            return f"ERROR: {e}"

    def remove(self, path: str) -> str:
        """删除文件、目录或符号链接"""
        full = self._full(path)
        if not full.exists() and not full.is_symlink():
            return f"ERROR: Not found: {path}"
        try:
            if full.is_symlink() or full.is_file():
                full.unlink()
            elif full.is_dir():
                shutil.rmtree(full)
            return f"Removed: {path}"
        except Exception as e:
            return f"ERROR: {e}"

    def mkdir(self, path: str) -> str:
        """创建目录（含父目录）"""
        full = self._full(path)
        full.mkdir(parents=True, exist_ok=True)
        return f"Created: {path}"

    def copy_to_rootfs(self, src: str, dst: str) -> str:
        """从主机复制文件到 rootfs"""
        full_dst = self._full(dst)
        full_dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, str(full_dst))
            return f"Copied {src} -> {full_dst}"
        except Exception as e:
            return f"ERROR: {e}"

    # ─── 搜索 / 列出 ───

    def list_dir(self, path: str, recursive: bool = False) -> str:
        """列出目录内容"""
        import glob as glob_mod

        full = self._full(path)
        if not full.exists():
            return f"ERROR: Directory not found: {path}"

        entries = []
        max_entries = 200
        try:
            if recursive:
                for p in sorted(full.rglob("*")):
                    prefix = "[D] " if p.is_dir() else "[F] "
                    entries.append(f"{prefix}{p.relative_to(full)}")
                    if len(entries) >= max_entries:
                        entries.append(f"... (truncated, {max_entries} entries max)")
                        break
            else:
                for p in sorted(full.iterdir()):
                    prefix = "[D] " if p.is_dir() else "[F] "
                    entries.append(f"{prefix}{p.name}")
                    if len(entries) >= max_entries:
                        break
        except Exception as e:
            return f"ERROR: {e}"
        return "\n".join(entries)

    def find_files(self, root: str, pattern: str, recursive: bool = True) -> str:
        """搜索文件（glob 模式匹配）

        Args:
            root: 搜索起始目录
            pattern: glob 模式，如 *.conf, etc/**/*.sh, httpd*
            recursive: 是否递归，默认 True
        """
        import glob as glob_mod

        base = self.rootfs_path.rstrip("/")
        search_root = f"{base}/{root.lstrip('/')}"
        if recursive:
            matches = glob_mod.glob(f"{search_root}/**/{pattern}", recursive=True)
        else:
            matches = glob_mod.glob(f"{search_root}/{pattern}")
        rel_paths = [m[len(base):] for m in matches[:100]]
        return json.dumps({"files": rel_paths, "count": len(rel_paths)}, ensure_ascii=False)

    def file_exists(self, path: str) -> str:
        """检查文件或目录是否存在"""
        full = self._full(path)
        if full.exists():
            info = {
                "exists": True,
                "is_dir": full.is_dir(),
                "is_file": full.is_file(),
                "is_symlink": full.is_symlink(),
                "size": full.stat().st_size if full.is_file() else 0,
            }
            return json.dumps(info)
        return json.dumps({"exists": False})

    def file_stat(self, path: str) -> str:
        """获取文件详细元信息：权限、大小、uid/gid、mtime、symlink 目标等"""
        full = self._full(path)
        if not full.exists() and not full.is_symlink():
            return json.dumps({"exists": False})

        try:
            st = full.lstat()
            info = {
                "exists": True,
                "path": path,
                "is_file": full.is_file(),
                "is_dir": full.is_dir(),
                "is_symlink": full.is_symlink(),
                "size": st.st_size,
                "mode_oct": oct(st.st_mode),
                "permissions": oct(st.st_mode & 0o777),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "mtime": st.st_mtime,
            }
            if full.is_symlink():
                try:
                    info["symlink_target"] = str(full.readlink())
                except Exception:
                    info["symlink_target"] = "(unreadable)"
            return json.dumps(info, ensure_ascii=False)
        except Exception as e:
            return f"ERROR: {e}"

    # ─── ELF / 二进制分析 ───

    def elf_info(self, path: str) -> str:
        """使用 file 命令获取 ELF 二进制信息"""
        full = self._full(path)
        if not full.exists():
            return f"ERROR: File not found: {path}"
        try:
            result = subprocess.run(
                ["file", "-b", str(full)], capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
        except Exception as e:
            return f"ERROR: {e}"

    def readelf_deps(self, path: str) -> str:
        """使用 readelf 查看共享库依赖"""
        full = self._full(path)
        if not full.exists():
            return f"ERROR: File not found: {path}"
        try:
            result = subprocess.run(
                ["readelf", "-d", str(full)], capture_output=True, text=True, timeout=10
            )
            lines = [l.strip() for l in result.stdout.split("\n") if "NEEDED" in l]
            return "\n".join(lines) if lines else result.stdout.strip()
        except Exception as e:
            return f"ERROR: {e}"

    def check_kernel(self, kernel_path: str) -> str:
        """检查内核架构信息（主机绝对路径）"""
        try:
            result = subprocess.run(
                ["file", kernel_path], capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
        except Exception as e:
            return f"ERROR: {e}"

    def list_lib_base(self) -> str:
        """列出 lib_base 中可用的替换库文件"""
        try:
            from config import get_lib_base_dir
            lib_base = get_lib_base_dir()
            if not lib_base.exists():
                return "lib_base目录不存在"
            entries = sorted(str(p.relative_to(lib_base)) for p in lib_base.rglob("*") if p.is_file())
            return json.dumps(entries, ensure_ascii=False)
        except Exception as e:
            return f"ERROR: {e}"
