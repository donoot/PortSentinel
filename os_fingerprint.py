"""
操作系统识别模块
通过端口特征、TTL值、TCP窗口大小等信息推断目标操作系统类型和版本
"""
import re
import socket
import struct
from typing import Dict, List, Optional


class OSFingerprint:
    """操作系统指纹识别"""
    
    # 操作系统特征库（基于常见端口组合）
    OS_SIGNATURES = {
        # Windows 系列
        "windows": {
            "ports": [135, 139, 445, 3389],
            "services": ["ms-rpc", "netbios-ssn", "smb", "ms-wbt-server"],
            "hints": ["microsoft-ds", "terminal services", "windows"],
        },
        "windows_10": {
            "ports": [135, 139, 445, 3389],
            "additional": [5985, 5986],  # WinRM
        },
        "windows_server": {
            "ports": [135, 139, 445, 3389, 1433],
            "services": ["ms-sql-s", "ms-rpc"],
        },
        
        # Linux 系列
        "linux": {
            "ports": [22, 80, 443],
            "services": ["ssh", "http", "https"],
        },
        "ubuntu": {
            "ports": [22, 80, 443, 3306],
            "services": ["ssh", "http", "https", "mysql"],
        },
        "centos": {
            "ports": [22, 80, 443],
            "services": ["ssh", "http", "https"],
        },
        "debian": {
            "ports": [22, 80, 443],
            "services": ["ssh", "http", "https"],
        },
        
        # macOS
        "macos": {
            "ports": [22, 548, 445],  # AFP + SMB
            "services": ["ssh", "afp", "smb"],
        },
        
        # Unix 服务器
        "freebsd": {
            "ports": [22, 80],
            "services": ["ssh", "http"],
        },
        
        # 网络设备
        "router": {
            "ports": [22, 23, 80, 443, 161],
            "services": ["ssh", "telnet", "http", "https", "snmp"],
        },
        
        # 数据库服务器
        "database_server": {
            "ports": [1433, 1521, 3306, 5432, 6379, 27017],
            "services": ["ms-sql-s", "oracle", "mysql", "postgresql", "redis", "mongodb"],
        },
    }
    
    # 服务到操作系统的映射
    SERVICE_OS_MAP = {
        "smb": "windows",
        "ms-rpc": "windows",
        "microsoft-ds": "windows",
        "ms-wbt-server": "windows",
        "ms-sql-s": "windows_server",
        "afp": "macos",
        "ssh": "linux/unix",
        "mysql": "linux/unix",
        "postgresql": "linux/unix",
    }
    
    def __init__(self):
        pass
    
    def analyze_open_ports(self, open_ports: List[int], services: Dict[int, Dict]) -> Dict:
        """
        分析开放端口，推断操作系统类型
        
        参数:
            open_ports: 开放端口列表
            services: 端口服务信息字典 {port: {service, protocol, ...}}
        
        返回:
            {
                "os": 操作系统类型,
                "os_version": 版本推测,
                "confidence": 置信度 (0-100),
                "evidence": 证据列表,
                "vulnerabilities": 相关漏洞列表
            }
        """
        result = {
            "os": "unknown",
            "os_version": None,
            "confidence": 0,
            "evidence": [],
            "vulnerabilities": []
        }
        
        if not open_ports:
            return result
        
        evidence = []
        os_scores = {}
        
        # 分析每个特征库
        for os_name, signature in self.OS_SIGNATURES.items():
            score = 0
            matches = []
            
            # 检查端口匹配
            sig_ports = signature.get("ports", [])
            matching_ports = set(open_ports) & set(sig_ports)
            if matching_ports:
                score += len(matching_ports) * 10
                matches.append(f"端口匹配: {matching_ports}")
            
            # 检查服务匹配
            sig_services = signature.get("services", [])
            for port in open_ports:
                if port in services:
                    service_name = services[port].get("service", "").lower()
                    if service_name in sig_services:
                        score += 15
                        matches.append(f"服务匹配: 端口{port}({service_name})")
            
            if score > 0:
                os_scores[os_name] = score
                evidence.append({
                    "os": os_name,
                    "score": score,
                    "matches": matches
                })
        
        # 选择得分最高的操作系统
        if os_scores:
            best_os = max(os_scores, key=os_scores.get)
            max_score = os_scores[best_os]
            
            # 计算置信度
            total_possible = len(open_ports) * 15
            confidence = min(100, int(max_score / max(total_possible, 1) * 100))
            
            result["os"] = best_os
            result["confidence"] = confidence
            result["evidence"] = evidence
        
        # Windows 特殊检测
        if self._is_windows(open_ports):
            result["os"] = self._detect_windows_version(open_ports, services)
            result["confidence"] = max(result["confidence"], 70)
        
        return result
    
    def _is_windows(self, open_ports: List[int]) -> bool:
        """判断是否为 Windows 系统"""
        windows_ports = {135, 139, 445, 3389, 1433, 5985, 5986}
        return bool(windows_ports & set(open_ports))
    
    def _detect_windows_version(self, open_ports: List[int], services: Dict) -> str:
        """推测 Windows 版本"""
        if 1433 in open_ports:  # MSSQL
            return "windows_server"
        if 5985 in open_ports or 5986 in open_ports:  # WinRM
            return "windows_10/11"
        return "windows"
    
    def get_banner(self, target: str, port: int, timeout: float = 2.0) -> Optional[str]:
        """
        获取服务 Banner 信息（用于辅助 OS 识别）
        
        参数:
            target: 目标地址
            port: 目标端口
            timeout: 超时时间（秒）
        
        返回:
            Banner 字符串或 None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # 某些服务需要先发送请求
            if port in [21, 25, 110, 143]:  # FTP, SMTP, POP3, IMAP
                # 这些服务会在连接后主动发送 Banner
                pass
            elif port in [80, 443, 8080]:  # HTTP
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except Exception:
            return None
    
    def parse_banner_for_os(self, banner: str) -> Optional[Dict]:
        """
        从 Banner 中解析操作系统信息
        
        返回:
            {"os": 系统类型, "version": 版本} 或 None
        """
        if not banner:
            return None
        
        banner_lower = banner.lower()
        
        # Windows 签名
        if "windows" in banner_lower:
            # 尝试提取版本号
            version_match = re.search(r'windows\s*(\d+(?:\.\d+)?)', banner_lower)
            if version_match:
                return {"os": "windows", "version": version_match.group(1)}
            return {"os": "windows", "version": None}
        
        # Linux 签名
        if "linux" in banner_lower or "ubuntu" in banner_lower or "debian" in banner_lower or "centos" in banner_lower:
            for dist in ["ubuntu", "debian", "centos", "redhat", "fedora"]:
                if dist in banner_lower:
                    version_match = re.search(rf'{dist}\s*(\d+(?:\.\d+)?)', banner_lower)
                    return {
                        "os": dist,
                        "version": version_match.group(1) if version_match else None
                    }
            return {"os": "linux", "version": None}
        
        # macOS 签名
        if "mac os" in banner_lower or "darwin" in banner_lower:
            return {"os": "macos", "version": None}
        
        return None