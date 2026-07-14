"""网络诊断工具 — 宿主机网络操作"""

import json
import os
import socket
import subprocess
import tempfile


class NetworkTool:
    """宿主机网络操作后端"""

    def ping(self, host: str, count: int = 3, timeout: int = 2) -> str:
        """Ping 主机检查连通性"""
        try:
            result = subprocess.run(
                ["ping", "-c", str(count), "-W", str(timeout), host],
                capture_output=True, text=True, timeout=count * timeout + 5,
            )
            return result.stdout + result.stderr
        except Exception as e:
            return f"ERROR: {e}"

    def scan_ports(self, host: str, ports: str) -> str:
        """扫描指定端口是否开放"""
        results = []
        for port_str in ports.split(","):
            try:
                port = int(port_str.strip())
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                result = s.connect_ex((host, port))
                s.close()
                results.append({"port": port, "open": result == 0})
            except Exception as e:
                results.append({"port": port_str.strip(), "error": str(e)})
        return json.dumps(results, ensure_ascii=False)

    def http_request(self, url: str, method: str = "GET", timeout: int = 10) -> str:
        """发送 HTTP 请求，跟随重定向并携带 cookie，返回最终状态码"""
        cookie_jar = tempfile.mktemp(suffix=".cookies")
        try:
            cmd = [
                "curl", "-s", "-L", "-c", cookie_jar, "-b", cookie_jar,
                "-o", "/dev/null", "-w",
                "%{http_code} %{size_download} %{url_effective}",
                "-m", str(timeout), "-X", method, url,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            parts = result.stdout.strip().split()
            status_code = int(parts[0]) if parts else 0
            size_download = int(parts[1]) if len(parts) > 1 else 0
            final_url = parts[2] if len(parts) > 2 else ""
            return json.dumps({
                "url": url,
                "final_url": final_url,
                "status_code": status_code,
                "size": size_download,
            }, ensure_ascii=False)
        except Exception as e:
            return f"ERROR: {e}"
        finally:
            try:
                os.unlink(cookie_jar)
            except Exception:
                pass

    def http_get_body(self, url: str, timeout: int = 10) -> str:
        """发送 HTTP GET 请求，跟随重定向并携带 cookie，返回响应体内容"""
        cookie_jar = tempfile.mktemp(suffix=".cookies")
        try:
            cmd = [
                "curl", "-s", "-L", "-c", cookie_jar, "-b", cookie_jar,
                "-m", str(timeout), url,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            return result.stdout[:5000]
        except Exception as e:
            return f"ERROR: {e}"
        finally:
            try:
                os.unlink(cookie_jar)
            except Exception:
                pass

    def find_port_conflict(self, port: int) -> str:
        """检查端口是否被占用"""
        try:
            result = subprocess.run(
                ["ss", "-tlnp", f"sport = :{port}"],
                capture_output=True, text=True, timeout=5,
            )
            lines = [l for l in result.stdout.strip().split("\n") if "LISTEN" in l]
            return json.dumps({"port": port, "in_use": len(lines) > 0, "detail": lines}, ensure_ascii=False)
        except Exception as e:
            return f"ERROR: {e}"

    def get_network_config(self) -> str:
        """获取宿主机网络接口配置"""
        try:
            result = subprocess.run(
                ["ip", "addr", "show"], capture_output=True, text=True, timeout=5,
            )
            return result.stdout[:3000]
        except Exception as e:
            return f"ERROR: {e}"
