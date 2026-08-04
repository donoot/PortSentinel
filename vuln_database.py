"""
漏洞数据库模块
存储常见操作系统和服务的已知漏洞信息
提供漏洞查询和风险评估功能
"""
import json
from typing import Dict, List, Optional


class VulnerabilityDatabase:
    """漏洞数据库"""
    
    # Windows 漏洞库
    WINDOWS_VULNERABILITIES = {
        "smb": [
            {
                "cve": "CVE-2017-0144",
                "name": "永恒之蓝 (EternalBlue)",
                "affected": "Windows Vista, 7, 8.1, 10, Server 2008-2016",
                "severity": "critical",
                "description": "SMBv1 远程代码执行漏洞，被 WannaCry 勒索病毒利用",
                "mitigation": "安装 MS17-010 补丁，禁用 SMBv1，防火墙阻断445端口",
                "ports": [139, 445],
            },
            {
                "cve": "CVE-2020-0796",
                "name": "SMBGhost",
                "affected": "Windows 10 v1903, v1909, Server v1903, v1909",
                "severity": "critical",
                "description": "SMBv3 压缩协议远程代码执行漏洞",
                "mitigation": "安装2020年3月补丁，禁用SMBv3压缩",
                "ports": [445],
            },
        ],
        "rdp": [
            {
                "cve": "CVE-2019-0708",
                "name": "BlueKeep",
                "affected": "Windows XP, Vista, 7, Server 2003, 2008, 2008 R2",
                "severity": "critical",
                "description": "RDP 远程桌面服务远程代码执行漏洞，无需认证",
                "mitigation": "安装补丁，启用NLA，禁用RDP或限制访问IP",
                "ports": [3389],
            },
            {
                "cve": "CVE-2019-1181/1182",
                "name": "BlueGate",
                "affected": "Windows 8.1, 10, Server 2012-2019",
                "severity": "critical",
                "description": "RDP 远程代码执行漏洞",
                "mitigation": "安装2019年8月补丁",
                "ports": [3389],
            },
        ],
        "winrm": [
            {
                "cve": "Multiple",
                "name": "WinRM 凭据泄露",
                "affected": "Windows Server 2008+",
                "severity": "high",
                "description": "WinRM 配置不当可能导致凭据泄露或远程执行",
                "mitigation": "限制WinRM访问IP，使用HTTPS，强密码策略",
                "ports": [5985, 5986],
            },
        ],
        "mssql": [
            {
                "cve": "CVE-2020-0618",
                "name": "MSSQL 远程代码执行",
                "affected": "SQL Server 2012-2019",
                "severity": "high",
                "description": "SQL Server Reporting Services 远程代码执行",
                "mitigation": "安装2020年2月补丁，限制1433端口访问",
                "ports": [1433, 1434],
            },
        ],
        "iis": [
            {
                "cve": "CVE-2017-7269",
                "name": "IIS WebDAV 远程代码执行",
                "affected": "IIS 6.0 (Windows Server 2003)",
                "severity": "critical",
                "description": "WebDAV ScStoragePathFromUrl 缓冲区溢出",
                "mitigation": "禁用WebDAV，升级IIS版本",
                "ports": [80, 443],
            },
        ],
    }
    
    # Linux/Unix 漏洞库
    LINUX_VULNERABILITIES = {
        "ssh": [
            {
                "cve": "CVE-2024-6387",
                "name": "OpenSSH regreSSHion",
                "affected": "OpenSSH 8.5p1 - 9.7p1",
                "severity": "critical",
                "description": "OpenSSH 远程代码执行竞态条件漏洞",
                "mitigation": "升级到 OpenSSH 9.8+，或配置 LoginGraceTime 0",
                "ports": [22],
            },
            {
                "cve": "CVE-2021-28041",
                "name": "OpenSSH 双重释放漏洞",
                "affected": "OpenSSH 8.2p1 - 8.4p1",
                "severity": "high",
                "description": "ssh-agent 双重释放可能导致代码执行",
                "mitigation": "升级 OpenSSH 版本",
                "ports": [22],
            },
        ],
        "mysql": [
            {
                "cve": "CVE-2019-25128",
                "name": "MySQL 远程代码执行",
                "affected": "MySQL 5.7.x",
                "severity": "high",
                "description": "特定配置下的远程代码执行漏洞",
                "mitigation": "升级MySQL版本，限制3306端口访问",
                "ports": [3306],
            },
        ],
        "redis": [
            {
                "cve": "Multiple",
                "name": "Redis 未授权访问",
                "affected": "Redis < 6.0",
                "severity": "critical",
                "description": "默认无密码认证，可写入SSH公钥或crontab",
                "mitigation": "设置密码，绑定内网IP，禁用危险命令",
                "ports": [6379],
            },
        ],
        "mongodb": [
            {
                "cve": "Multiple",
                "name": "MongoDB 未授权访问",
                "affected": "MongoDB 所有版本（默认配置）",
                "severity": "critical",
                "description": "默认无认证，可读写数据库",
                "mitigation": "启用认证，绑定内网IP",
                "ports": [27017],
            },
        ],
    }
    
    # 通用服务漏洞
    COMMON_VULNERABILITIES = {
        "ftp": [
            {
                "cve": "Multiple",
                "name": "FTP 明文传输",
                "affected": "所有FTP服务",
                "severity": "high",
                "description": "FTP明文传输用户名密码和文件内容",
                "mitigation": "使用FTPS或SFTP替代",
                "ports": [20, 21],
            },
        ],
        "telnet": [
            {
                "cve": "Multiple",
                "name": "Telnet 明文传输",
                "affected": "所有Telnet服务",
                "severity": "critical",
                "description": "Telnet完全无加密，极度危险",
                "mitigation": "使用SSH替代，关闭Telnet服务",
                "ports": [23],
            },
        ],
        "snmp": [
            {
                "cve": "Multiple",
                "name": "SNMP 默认Community",
                "affected": "所有SNMP服务（默认配置）",
                "severity": "high",
                "description": "默认public/private community可泄露完整系统信息",
                "mitigation": "修改默认community字符串，使用SNMPv3",
                "ports": [161, 162],
            },
        ],
    }
    
    def __init__(self):
        self.all_vulns = {
            **self.WINDOWS_VULNERABILITIES,
            **self.LINUX_VULNERABILITIES,
            **self.COMMON_VULNERABILITIES
        }
    
    def get_vulnerabilities_for_port(self, port: int, service: str = None, os_type: str = None) -> List[Dict]:
        """
        获取指定端口相关的漏洞信息
        
        参数:
            port: 端口号
            service: 服务名称（可选）
            os_type: 操作系统类型（可选）
        
        返回:
            漏洞信息列表
        """
        vulnerabilities = []
        
        # 端口到服务类型的映射
        port_service_map = {
            139: "smb", 445: "smb",
            3389: "rdp",
            5985: "winrm", 5986: "winrm",
            1433: "mssql", 1434: "mssql",
            22: "ssh",
            3306: "mysql",
            6379: "redis",
            27017: "mongodb",
            20: "ftp", 21: "ftp",
            23: "telnet",
            161: "snmp", 162: "snmp",
        }
        
        service_key = port_service_map.get(port)
        if not service_key:
            return vulnerabilities
        
        # 根据OS类型和端口获取漏洞
        if os_type and "windows" in os_type.lower():
            if service_key in self.WINDOWS_VULNERABILITIES:
                vulnerabilities.extend(self.WINDOWS_VULNERABILITIES[service_key])
        elif os_type and "linux" in os_type.lower():
            if service_key in self.LINUX_VULNERABILITIES:
                vulnerabilities.extend(self.LINUX_VULNERABILITIES[service_key])
        else:
            # 没有OS信息时，返回所有相关漏洞
            if service_key in self.all_vulns:
                vulnerabilities.extend(self.all_vulns[service_key])
        
        return vulnerabilities
    
    def get_vulnerability_summary(self, os_type: str = None, open_ports: List[int] = None) -> Dict:
        """
        获取漏洞摘要报告
        
        返回:
            {
                "critical": 严重漏洞数量,
                "high": 高危漏洞数量,
                "total": 总漏洞数量,
                "vulnerabilities": 漏洞详情列表
            }
        """
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "total": 0,
            "vulnerabilities": []
        }
        
        checked_services = set()
        
        # 检查所有开放端口
        ports = open_ports or []
        for port in ports:
            vulns = self.get_vulnerabilities_for_port(port, os_type=os_type)
            for vuln in vulns:
                if vuln["name"] not in checked_services:
                    checked_services.add(vuln["name"])
                    summary["vulnerabilities"].append(vuln)
                    summary["total"] += 1
                    
                    severity = vuln.get("severity", "medium").lower()
                    if severity == "critical":
                        summary["critical"] += 1
                    elif severity == "high":
                        summary["high"] += 1
                    elif severity == "medium":
                        summary["medium"] += 1
        
        return summary
    
    def format_vulnerability_report(self, vuln: Dict) -> str:
        """格式化单个漏洞报告为文本"""
        report = []
        report.append(f"【{vuln.get('name', 'Unknown')}】")
        report.append(f"CVE: {vuln.get('cve', 'N/A')}")
        report.append(f"影响版本: {vuln.get('affected', 'N/A')}")
        report.append(f"严重等级: {vuln.get('severity', 'medium').upper()}")
        report.append(f"描述: {vuln.get('description', 'N/A')}")
        report.append(f"修复建议: {vuln.get('mitigation', 'N/A')}")
        return "\n".join(report)