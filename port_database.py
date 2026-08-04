"""
端口识别库管理模块
加载并查询端口数据库，识别端口风险等级和服务信息
"""
import json
import os


class PortDatabase:
    """端口识别库，从JSON文件加载端口信息并提供查询接口"""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "port_database.json")
        self.db_path = db_path
        self.ports = {}
        self.risk_levels = {}
        self.load()

    def load(self):
        """从JSON文件加载数据库"""
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.ports = data.get("ports", {})
            self.risk_levels = data.get("risk_levels", {})
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[警告] 端口数据库加载失败: {e}，使用空数据库")
            self.ports = {}
            self.risk_levels = {
                "safe": {"label": "正常", "color": "#27ae60", "priority": 0},
                "warning": {"label": "警告", "color": "#f39c12", "priority": 1},
                "danger": {"label": "危险", "color": "#e74c3c", "priority": 2},
                "unknown": {"label": "未知", "color": "#95a5a6", "priority": 3},
            }

    def reload(self):
        """重新加载数据库"""
        self.load()

    def lookup(self, port, protocol="tcp"):
        """
        查询端口信息
        返回: dict {service, protocol, risk, description, hazard}
        """
        key = str(port)
        info = self.ports.get(key)
        if info:
            return {
                "port": port,
                "service": info.get("service", "未知"),
                "protocol": info.get("protocol", protocol),
                "risk": info.get("risk", "unknown"),
                "description": info.get("description", ""),
                "hazard": info.get("hazard", ""),
            }
        return {
            "port": port,
            "service": "未知",
            "protocol": protocol,
            "risk": "unknown",
            "description": f"端口 {port} 不在已知识别库中",
            "hazard": "未知端口，建议人工确认其对应的服务和用途",
        }

    def get_risk_level(self, port):
        """获取端口风险等级"""
        return self.lookup(port)["risk"]

    def get_risk_label(self, risk):
        """获取风险等级的中文标签"""
        return self.risk_levels.get(risk, {}).get("label", "未知")

    def get_risk_color(self, risk):
        """获取风险等级对应的颜色"""
        return self.risk_levels.get(risk, {}).get("color", "#95a5a6")

    def get_all_known_ports(self):
        """返回所有已知端口列表"""
        return sorted(int(k) for k in self.ports.keys())

    def add_port(self, port, service, protocol="tcp", risk="unknown",
                 description="", hazard=""):
        """
        手动添加或更新端口信息到识别库
        如果端口已存在则覆盖更新

        参数:
            port: 端口号 (int 或 str)
            service: 服务名称
            protocol: 协议 (tcp/udp)
            risk: 风险等级 (safe/warning/danger/unknown)
            description: 功能描述
            hazard: 危害说明

        返回: (success: bool, message: str)
        """
        key = str(port)
        try:
            port_num = int(port)
            if port_num < 0 or port_num > 65535:
                return False, "端口号必须在 0-65535 范围内"
        except (ValueError, TypeError):
            return False, f"无效的端口号: {port}"

        if protocol not in ("tcp", "udp"):
            return False, "协议必须为 tcp 或 udp"

        if risk not in ("safe", "warning", "danger", "unknown"):
            return False, "风险等级必须为 safe/warning/danger/unknown"

        is_update = key in self.ports
        self.ports[key] = {
            "service": service,
            "protocol": protocol,
            "risk": risk,
            "description": description,
            "hazard": hazard,
        }

        success, msg = self._save()
        if success:
            action = "更新" if is_update else "添加"
            return True, f"端口 {port} ({service}) 已{action}到识别库"
        return False, msg

    def remove_port(self, port):
        """
        从识别库中删除端口信息

        返回: (success: bool, message: str)
        """
        key = str(port)
        if key not in self.ports:
            return False, f"端口 {port} 不在识别库中"

        del self.ports[key]
        success, msg = self._save()
        if success:
            return True, f"端口 {port} 已从识别库中删除"
        return False, msg

    def _save(self):
        """将识别库保存到JSON文件"""
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["ports"] = self.ports
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True, "保存成功"
        except Exception as e:
            return False, f"保存失败: {e}"
