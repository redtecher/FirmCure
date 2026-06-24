#!/usr/bin/env python3
"""
验证工具 - 三层网络验证（ping + nmap + curl）

【重要】此工具仅负责验证，不修改任何进程状态：
  ✅ 调用 ping/nmap/curl 检查当前服务状态
  ❌ 不杀进程、不重启服务、不修改 QEMU 状态

使用流程：
  1. 专家修复 → 调用此工具验证 → 返回验证结果
  2. Manager 接收结果 → 判定成功/失败
  3. 若失败需重诊 → Manager 才负责杀进程+重启+重新应用断点
"""

import os
import subprocess
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class NetworkValidator:
    """三层网络验证 - ping + nmap + curl（只验证，不修改进程）"""

    def __init__(self, guest_ip: str = "10.10.10.2", httpd_port: int = 80):
        self.guest_ip = guest_ip
        self.httpd_port = httpd_port
        self.timestamp = datetime.now().isoformat()

    def ping_check(self) -> Dict[str, Any]:
        """第1层：ICMP 连通性检查"""
        try:
            result = subprocess.run(
                ["ping", "-c", "2", "-W", "2", self.guest_ip],
                capture_output=True, text=True, timeout=10
            )
            success = result.returncode == 0
            return {
                "layer": "ping",
                "target": self.guest_ip,
                "success": success,
                "output": result.stdout if success else result.stderr,
                "rtt": self._extract_rtt(result.stdout) if success else None,
            }
        except Exception as e:
            logger.error(f"Ping check failed: {e}")
            return {
                "layer": "ping",
                "target": self.guest_ip,
                "success": False,
                "error": str(e),
            }

    def nmap_check(self) -> Dict[str, Any]:
        """第2层：端口扫描（使用 nmap 或 telnet 备选）"""
        try:
            # 尝试使用 nmap
            result = subprocess.run(
                ["nmap", "-p", str(self.httpd_port), self.guest_ip],
                capture_output=True, text=True, timeout=15
            )
            success = "open" in result.stdout.lower()
            return {
                "layer": "nmap",
                "target": f"{self.guest_ip}:{self.httpd_port}",
                "success": success,
                "port_state": self._extract_port_state(result.stdout),
                "output": result.stdout[:200],
            }
        except FileNotFoundError:
            logger.warning("nmap not found, using telnet fallback")
            # 备选：使用 telnet
            try:
                result = subprocess.run(
                    ["telnet", self.guest_ip, str(self.httpd_port)],
                    input=b"\r\n", capture_output=True, timeout=5
                )
                success = result.returncode == 0
                return {
                    "layer": "nmap (telnet fallback)",
                    "target": f"{self.guest_ip}:{self.httpd_port}",
                    "success": success,
                    "port_state": "open" if success else "closed",
                }
            except Exception as e:
                return {
                    "layer": "nmap",
                    "target": f"{self.guest_ip}:{self.httpd_port}",
                    "success": False,
                    "error": str(e),
                }
        except Exception as e:
            logger.error(f"Nmap check failed: {e}")
            return {
                "layer": "nmap",
                "target": f"{self.guest_ip}:{self.httpd_port}",
                "success": False,
                "error": str(e),
            }

    def curl_check(self) -> Dict[str, Any]:
        """第3层：HTTP 应用层检查（使用 cookie jar 处理认证重定向）"""
        import tempfile

        try:
            url = f"http://{self.guest_ip}:{self.httpd_port}/"
            # 使用 cookie jar 处理嵌入式 httpd 的认证重定向
            # Tenda 等路由器: / → 302(set-cookie) → /main.html → 302(with cookie) → 200
            cookie_jar = tempfile.mktemp(suffix=".cookies")
            result = subprocess.run(
                ["curl", "-s", "-D", "-", "-L", "-c", cookie_jar, "-b", cookie_jar, "-m", "8", url],
                capture_output=True, text=True, timeout=15
            )

            # 清理 cookie jar
            try:
                os.unlink(cookie_jar)
            except Exception:
                pass

            raw = result.stdout or ""
            # 提取所有 HTTP 状态码（-L 可能产生多次响应头）
            all_statuses = []
            for line in raw.split("\n"):
                line = line.strip()
                if line.startswith("HTTP/"):
                    parts = line.split()
                    if len(parts) >= 2:
                        all_statuses.append(parts[1])

            initial_status = all_statuses[0] if all_statuses else "unknown"
            final_status = all_statuses[-1] if all_statuses else "unknown"

            # 响应体（最后一个空行后的内容）
            if "\r\n\r\n" in raw:
                body = raw.rsplit("\r\n\r\n", 1)[-1]
            elif "\n\n" in raw:
                body = raw.rsplit("\n\n", 1)[-1]
            else:
                body = raw
            response_sample = body[:300] if body else ""
            redirect_followed = len(all_statuses) > 1
            response_length = len(body) if body else 0

            # 判断HTTP服务是否正常（以跟随重定向后的最终状态码为准）
            # 只有最终 20x 才算成功，30x/40x/50x 都不算
            if final_status.startswith("20"):
                logger.info(f"✅ HTTP成功响应：{url} → {final_status} (redirect_chain: {all_statuses})")
                success = True
            elif final_status.startswith(("4", "5")):
                logger.warning(f"❌ HTTP错误：{url} → {final_status} (redirect_chain: {all_statuses})")
                success = False
            elif final_status.startswith("30"):
                # 重定向后还是 30x（循环或无法跟随）→ 失败
                logger.warning(f"❌ HTTP重定向未解析：{url} → {final_status} (redirect_chain: {all_statuses})")
                success = False
            else:
                logger.warning(f"❌ HTTP响应异常：{url} (status: {final_status})")
                success = False

            return {
                "layer": "curl",
                "url": url,
                "success": success,
                "http_status": initial_status,
                "final_http_status": final_status,
                "all_http_statuses": all_statuses,
                "redirect_followed": redirect_followed,
                "response_length": len(body),
                "response_sample": response_sample,
            }
        except Exception as e:
            logger.error(f"Curl check failed: {e}")
            return {
                "layer": "curl",
                "url": f"http://{self.guest_ip}:{self.httpd_port}/",
                "success": False,
                "error": str(e),
            }

    def validate_full_stack(self) -> Dict[str, Any]:
        """执行三层验证，返回综合结果"""
        results = {
            "timestamp": self.timestamp,
            "guest_ip": self.guest_ip,
            "httpd_port": self.httpd_port,
            "layers": {},
            "summary": {},
        }

        # 第1层：网络连通
        ping_result = self.ping_check()
        results["layers"]["ping"] = ping_result
        ping_ok = ping_result.get("success", False)

        # 第2层：端口开放
        nmap_result = self.nmap_check()
        results["layers"]["nmap"] = nmap_result
        nmap_ok = nmap_result.get("success", False)

        # 第3层：HTTP 服务
        curl_result = self.curl_check()
        results["layers"]["curl"] = curl_result
        curl_ok = curl_result.get("success", False)

        # 综合判定
        # 综合判定
        logger.info(f"Validation Summary - ping: {ping_ok}, port: {nmap_ok}, curl: {curl_ok}")
        logger.info(f"Curl details - status: {curl_result.get('http_status')}, final: {curl_result.get('final_http_status')}, redirect: {curl_result.get('redirect_followed')}")

        results["summary"] = {
            "network_reachable": ping_ok,
            "port_open": nmap_ok,
            "http_responding": curl_ok,
            "overall_success": ping_ok and nmap_ok and curl_ok,
            "simulation_level": self._determine_simulation_level(ping_ok, nmap_ok, curl_ok),
        }
        logger.info(f"Overall validation result: {results['summary']}")

        return results

    @staticmethod
    def _extract_rtt(ping_output: str) -> Optional[str]:
        """从 ping 输出中提取 RTT"""
        for line in ping_output.split("\n"):
            if "min/avg/max" in line or "min/avg/max/stddev" in line:
                return line.strip()
        return None

    @staticmethod
    def _extract_port_state(nmap_output: str) -> str:
        """从 nmap 输出中提取端口状态"""
        for line in nmap_output.split("\n"):
            if "/tcp" in line:
                return line.strip()
        return "unknown"

    @staticmethod
    def _extract_http_status(curl_output: str) -> Optional[str]:
        """从 HTTP 响应头中提取状态码"""
        for line in curl_output.split("\n"):
            line = line.strip()
            if line.startswith("HTTP/"):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
        return None

    @staticmethod
    def _extract_location(headers: str) -> Optional[str]:
        """从 HTTP 响应头中提取 Location。"""
        for line in headers.split("\n"):
            if line.lower().startswith("location:"):
                return line.split(":", 1)[1].strip()
        return None

    @staticmethod
    def _split_headers_and_body(raw_response: str) -> tuple[str, str]:
        """拆分 curl -D - 输出的头和 body。"""
        if "\r\n\r\n" in raw_response:
            headers, body = raw_response.split("\r\n\r\n", 1)
            return headers, body
        if "\n\n" in raw_response:
            headers, body = raw_response.split("\n\n", 1)
            return headers, body
        return raw_response, ""

    @staticmethod
    def _determine_simulation_level(ping_ok: bool, nmap_ok: bool, curl_ok: bool) -> str:
        """根据验证结果判断仿真维度"""
        if ping_ok and nmap_ok and curl_ok:
            return "✅ 完全仿真（网络+端口+应用）"
        elif ping_ok and nmap_ok:
            return "⚠️  网络+端口可达，应用层故障"
        elif ping_ok:
            return "⚠️  网络可达，端口未开放"
        else:
            return "❌ 网络不可达"


def create_validation_tools(shell=None, **kwargs):
    """为 CrewAI 创建验证工具"""
    from crewai.tools import tool

    validator = NetworkValidator(
        guest_ip=kwargs.get("guest_ip", "10.10.10.2"),
        httpd_port=kwargs.get("httpd_port", 80),
    )

    @tool("validate_network_stack")
    def validate_network_stack_tool() -> str:
        """
        执行三层网络验证：ping + nmap + curl

        返回 JSON，包含：
        - layers: 各层验证结果（ping/nmap/curl）
        - summary: 网络可达性、端口状态、HTTP 响应、仿真维度判定
        """
        result = validator.validate_full_stack()
        logger.info(f"Network validation result: {result['summary']}")
        return json.dumps(result, ensure_ascii=False, indent=2)

    return [validate_network_stack_tool]
