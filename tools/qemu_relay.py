"""
QemuRelay - Unix Socket Relay for MCP Server ↔ QemuShell 通信

在主进程中运行的线程，监听 Unix socket，接收 JSON 请求，
转发给 QemuShell.execute_command()，返回 JSON 响应。

协议:
  请求: {"command": "ps w", "timeout": 10, "monitor": true}
  响应: {"output": "...", "error": null}
"""

import json
import socket
import threading
import logging
import os

logger = logging.getLogger(__name__)


class QemuRelay:
    """Unix Socket Relay — 桥接 MCP 子进程与 QemuShell"""

    def __init__(self, shell, socket_path: str = "/tmp/firmcure-relay.sock"):
        self.shell = shell
        self.socket_path = socket_path
        self._server_socket = None
        self._thread = None
        self._running = False

    def start(self):
        """启动 relay 后台线程"""
        if self._running:
            return

        # 清理残留 socket 文件
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        logger.info(f"[QemuRelay] Started on {self.socket_path}")

    def stop(self):
        """停止 relay"""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except Exception:
                pass
        logger.info("[QemuRelay] Stopped")

    def _serve(self):
        """后台服务循环"""
        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(self.socket_path)
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)  # 每秒检查 _running 标志

        while self._running:
            try:
                conn, _ = self._server_socket.accept()
                conn.settimeout(60.0)
                self._handle_connection(conn)
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_connection(self, conn: socket.socket):
        """处理单个连接"""
        try:
            # 读取请求
            data = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                # 简单协议：以换行符结尾的 JSON
                if data.endswith(b"\n"):
                    break

            if not data:
                conn.sendall(json.dumps({"output": "", "error": "empty request"}).encode() + b"\n")
                return

            request = json.loads(data.decode().strip())
            command = request.get("command", "")
            timeout = request.get("timeout", 30)
            monitor = request.get("monitor", True)

            if not command:
                conn.sendall(json.dumps({"output": "", "error": "no command"}).encode() + b"\n")
                return

            # 执行命令
            output = self.shell.execute_command(command, timeout=float(timeout), monitor=monitor)
            response = {"output": output or "", "error": None}
            conn.sendall(json.dumps(response, ensure_ascii=False).encode() + b"\n")

        except json.JSONDecodeError as e:
            try:
                conn.sendall(json.dumps({"output": "", "error": f"JSON parse error: {e}"}).encode() + b"\n")
            except Exception:
                pass
        except Exception as e:
            try:
                conn.sendall(json.dumps({"output": "", "error": str(e)}).encode() + b"\n")
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
