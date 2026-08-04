"""
GUI增强功能模块
提供右键菜单、悬停提示、操作系统检测集成等高级功能
"""
import os
import subprocess
import webbrowser
import json

from PyQt5.QtWidgets import (
    QMenu, QAction, QToolTip, QMessageBox, QApplication,
    QDialog, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QLabel, QInputDialog,
    QFormLayout, QLineEdit, QComboBox, QSpinBox, QWidget
)
from PyQt5.QtCore import Qt, QTimer, QPoint
from PyQt5.QtGui import QCursor, QFont

from os_fingerprint import OSFingerprint
from vuln_database import VulnerabilityDatabase


def copy_to_clipboard(text):
    """
    使用 Qt 内置剪贴板 API 复制文本
    替代 pyperclip，避免额外依赖
    """
    app = QApplication.instance()
    if app is not None:
        clipboard = app.clipboard()
        clipboard.setText(str(text))
        return True
    return False


class ContextMenuHelper:
    """右键菜单辅助类"""

    @staticmethod
    def create_port_scan_context_menu(parent, table, row, col):
        """
        为端口扫描结果表格创建右键菜单

        参数:
            parent: 父窗口（MainWindow实例）
            table: QTableWidget
            row: 当前行
            col: 当前列
        """
        menu = QMenu(parent)

        # 获取选中行的端口信息
        port_item = table.item(row, 0)
        if not port_item:
            return menu

        port = port_item.data(Qt.DisplayRole)
        proto = table.item(row, 1).text() if table.item(row, 1) else "tcp"
        service = table.item(row, 2).text() if table.item(row, 2) else ""
        risk = table.item(row, 3).text() if table.item(row, 3) else ""
        description = table.item(row, 4).text() if table.item(row, 4) else ""
        hazard = table.item(row, 5).text() if table.item(row, 5) else ""

        # ── 复制功能 ──
        copy_port_action = QAction(f"复制端口: {port}", parent)
        copy_port_action.triggered.connect(lambda: copy_to_clipboard(str(port)))
        menu.addAction(copy_port_action)

        copy_all_action = QAction("复制完整信息", parent)
        info_text = f"端口: {port}\n协议: {proto}\n服务: {service}\n风险: {risk}\n描述: {description}\n危害: {hazard}"
        copy_all_action.triggered.connect(lambda: copy_to_clipboard(info_text))
        menu.addAction(copy_all_action)

        menu.addSeparator()

        # ── 本机扫描特有功能 ──
        target = parent.target_input.text().strip() if hasattr(parent, 'target_input') else "127.0.0.1"
        is_local = target in ("127.0.0.1", "localhost", "0.0.0.0", "::1")

        if is_local:
            # 查找该端口的服务项（找到哪个程序使用的端口）
            find_service_action = QAction("查找该端口的服务项", parent)
            find_service_action.triggered.connect(
                lambda: parent.find_port_service(port, proto)
            )
            menu.addAction(find_service_action)

            # 关闭/打开该端口（通过防火墙规则）
            block_port_action = QAction("通过防火墙关闭该端口", parent)
            block_port_action.triggered.connect(
                lambda: parent.toggle_port_firewall(port, proto, block=True)
            )
            menu.addAction(block_port_action)

            allow_port_action = QAction("通过防火墙打开该端口", parent)
            allow_port_action.triggered.connect(
                lambda: parent.toggle_port_firewall(port, proto, block=False)
            )
            menu.addAction(allow_port_action)

            menu.addSeparator()

        # ── 漏洞与安全分析 ──
        vuln_action = QAction("查看已知漏洞", parent)
        vuln_action.triggered.connect(lambda: parent.show_port_vulnerabilities(port, service))
        menu.addAction(vuln_action)

        # 全网络检索该端口的详细信息
        search_all_action = QAction("全网络检索该端口详细信息", parent)
        search_all_action.triggered.connect(lambda: parent.search_port_all_engines(port, service))
        menu.addAction(search_all_action)

        # 在线搜索此端口漏洞（CVE数据库）
        search_cve_action = QAction("在线搜索CVE漏洞", parent)
        search_cve_action.triggered.connect(lambda: parent.search_port_online(port))
        menu.addAction(search_cve_action)

        menu.addSeparator()

        # ── 添加到识别库 ──
        add_db_action = QAction("添加/更新到识别库", parent)
        add_db_action.triggered.connect(
            lambda: parent.add_port_to_database(port, proto, service, risk, description, hazard)
        )
        menu.addAction(add_db_action)

        # ── 大模型对话 ──
        ai_chat_action = QAction("大模型分析该端口", parent)
        ai_chat_action.triggered.connect(lambda: parent.ai_analyze_port(port, service, risk, description, hazard))
        menu.addAction(ai_chat_action)

        menu.addSeparator()

        # ── 扫描操作 ──
        quick_scan_action = QAction("快速扫描常用端口", parent)
        quick_scan_action.triggered.connect(parent.start_quick_scan)
        menu.addAction(quick_scan_action)

        return menu

    @staticmethod
    def create_connection_context_menu(parent, table, row, col):
        """
        为活动连接表格创建右键菜单

        参数:
            parent: 父窗口（MainWindow实例）
            table: QTableWidget
            row: 当前行
            col: 当前列
        """
        menu = QMenu(parent)

        # 获取连接信息
        proto_item = table.item(row, 0)
        if not proto_item:
            return menu

        proto = proto_item.text()
        local_addr = table.item(row, 1).text() if table.item(row, 1) else ""
        local_port = table.item(row, 2).data(Qt.DisplayRole) if table.item(row, 2) else 0
        remote_addr = table.item(row, 3).text() if table.item(row, 3) else ""
        remote_port = table.item(row, 4).data(Qt.DisplayRole) if table.item(row, 4) else 0
        state = table.item(row, 5).text() if table.item(row, 5) else ""
        process = table.item(row, 6).text() if table.item(row, 6) else ""

        # 提取PID
        pid_str = ""
        if '(' in process and ')' in process:
            pid_str = process.split('(')[-1].rstrip(')')
        elif process.isdigit():
            pid_str = process

        # ── 复制功能 ──
        copy_addr_action = QAction(f"复制地址: {local_addr}:{local_port}", parent)
        copy_addr_action.triggered.connect(lambda: copy_to_clipboard(f"{local_addr}:{local_port}"))
        menu.addAction(copy_addr_action)

        if remote_addr != "*" and remote_addr != "0.0.0.0":
            copy_remote_action = QAction(f"复制远程地址: {remote_addr}:{remote_port}", parent)
            copy_remote_action.triggered.connect(lambda: copy_to_clipboard(f"{remote_addr}:{remote_port}"))
            menu.addAction(copy_remote_action)

        menu.addSeparator()

        # ── 连接操作 ──
        # 关闭该连接（仅TCP）
        if proto == "TCP":
            close_action = QAction("关闭该连接", parent)
            close_action.triggered.connect(lambda: parent.close_selected_connection(row))
            menu.addAction(close_action)

        # ── 进程操作 ──
        if pid_str.isdigit():
            pid = int(pid_str)

            menu.addSeparator()

            # 打开该程序目录位置
            open_dir_action = QAction("打开程序所在目录", parent)
            open_dir_action.triggered.connect(lambda: parent.open_process_directory(pid))
            menu.addAction(open_dir_action)

            # 打开该进程的详细命令及参数
            show_cmd_action = QAction("查看进程命令及参数", parent)
            show_cmd_action.triggered.connect(lambda: parent.show_process_command(pid))
            menu.addAction(show_cmd_action)

            # 查看进程详情
            process_info_action = QAction("查看进程详情", parent)
            process_info_action.triggered.connect(lambda: parent.show_process_info(pid))
            menu.addAction(process_info_action)

            menu.addSeparator()

            # 结束进程
            kill_action = QAction(f"结束进程: {process}", parent)
            kill_action.triggered.connect(lambda: parent.kill_process(pid))
            menu.addAction(kill_action)

        menu.addSeparator()

        # ── 网络查询 ──
        if remote_addr != "*" and remote_addr != "0.0.0.0":
            whois_action = QAction(f"WHOIS查询: {remote_addr}", parent)
            whois_action.triggered.connect(lambda: parent.query_whois(remote_addr))
            menu.addAction(whois_action)

            ip_location_action = QAction(f"查询IP归属地: {remote_addr}", parent)
            ip_location_action.triggered.connect(lambda: parent.query_ip_location(remote_addr))
            menu.addAction(ip_location_action)

        return menu


class ToolTipHelper:
    """悬停提示辅助类"""

    @staticmethod
    def get_port_scan_tooltip(table, row):
        """获取端口扫描结果行的悬停提示"""
        if row < 0 or row >= table.rowCount():
            return ""

        port = table.item(row, 0).data(Qt.DisplayRole) if table.item(row, 0) else 0
        service = table.item(row, 2).text() if table.item(row, 2) else "未知"
        risk = table.item(row, 3).text() if table.item(row, 3) else "未知"
        description = table.item(row, 4).text() if table.item(row, 4) else ""
        hazard = table.item(row, 5).text() if table.item(row, 5) else ""

        tooltip = f"""<b>端口:</b> {port}<br>
<b>服务:</b> {service}<br>
<b>风险等级:</b> {risk}<br>
<b>描述:</b> {description}<br>
<b>危害:</b> {hazard}<br><br>
<i>右键可查看更多操作</i>"""

        return tooltip

    @staticmethod
    def get_connection_tooltip(table, row):
        """获取活动连接行的悬停提示"""
        if row < 0 or row >= table.rowCount():
            return ""

        proto = table.item(row, 0).text() if table.item(row, 0) else ""
        local_addr = table.item(row, 1).text() if table.item(row, 1) else ""
        local_port = table.item(row, 2).data(Qt.DisplayRole) if table.item(row, 2) else 0
        remote_addr = table.item(row, 3).text() if table.item(row, 3) else ""
        remote_port = table.item(row, 4).data(Qt.DisplayRole) if table.item(row, 4) else 0
        state = table.item(row, 5).text() if table.item(row, 5) else ""
        process = table.item(row, 6).text() if table.item(row, 6) else ""

        state_desc = {
            "ESTABLISHED": "已建立连接，正在传输数据",
            "LISTEN": "正在监听等待连接",
            "TIME_WAIT": "等待关闭，确保数据传输完毕",
            "CLOSE_WAIT": "等待应用层关闭",
            "SYN_SENT": "主动打开，等待对方确认",
            "SYN_RCVD": "收到连接请求，等待确认",
        }

        state_info = state_desc.get(state, state)

        tooltip = f"""<b>协议:</b> {proto}<br>
<b>本地地址:</b> {local_addr}:{local_port}<br>
<b>远程地址:</b> {remote_addr}:{remote_port}<br>
<b>状态:</b> {state} ({state_info})<br>
<b>进程:</b> {process}<br><br>
<i>右键可查看更多操作</i>"""

        return tooltip


class OSDetectionHelper:
    """操作系统检测辅助类"""

    def __init__(self):
        self.os_fingerprint = OSFingerprint()
        self.vuln_db = VulnerabilityDatabase()

    def analyze_scan_results(self, scan_results):
        """
        分析扫描结果，识别操作系统

        参数:
            scan_results: 扫描结果列表，每个元素是 {port, service, risk, ...}

        返回:
            {
                "os": 操作系统类型,
                "confidence": 置信度,
                "vulnerabilities": 漏洞列表
            }
        """
        open_ports = [r["port"] for r in scan_results if r.get("open", True)]
        services = {r["port"]: r for r in scan_results if r.get("open", True)}

        # 执行OS识别
        os_result = self.os_fingerprint.analyze_open_ports(open_ports, services)

        # 获取相关漏洞
        os_type = os_result.get("os", "unknown")
        vuln_summary = self.vuln_db.get_vulnerability_summary(os_type, open_ports)

        return {
            "os": os_result.get("os", "unknown"),
            "confidence": os_result.get("confidence", 0),
            "evidence": os_result.get("evidence", []),
            "vulnerabilities": vuln_summary
        }

    def format_os_report(self, os_result):
        """格式化操作系统检测报告"""
        lines = []
        lines.append("=== 操作系统识别报告 ===\n")

        os_type = os_result.get("os", "未知")
        confidence = os_result.get("confidence", 0)

        lines.append(f"识别结果: {os_type}")
        lines.append(f"置信度: {confidence}%\n")

        evidence = os_result.get("evidence", [])
        if evidence:
            lines.append("识别依据:")
            for ev in evidence:
                lines.append(f"  - {ev.get('os', 'unknown')}: {', '.join(ev.get('matches', []))}")

        vulns = os_result.get("vulnerabilities", {})
        if vulns.get("total", 0) > 0:
            lines.append(f"\n安全风险:")
            lines.append(f"  严重漏洞: {vulns.get('critical', 0)} 个")
            lines.append(f"  高危漏洞: {vulns.get('high', 0)} 个")
            lines.append(f"  中危漏洞: {vulns.get('medium', 0)} 个")
            lines.append(f"  总计: {vulns.get('total', 0)} 个")

        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════
#  对话框辅助类
# ═══════════════════════════════════════════════════════════

class ProcessCommandDialog(QDialog):
    """显示进程命令行及参数的对话框"""

    def __init__(self, pid, parent=None):
        super().__init__(parent)
        self.pid = pid
        self.setWindowTitle(f"进程命令及参数 - PID: {pid}")
        self.setMinimumSize(600, 400)
        self._init_ui()
        self._load_info()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # 信息标签
        info_label = QLabel(f"进程 ID: {self.pid}")
        info_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(info_label)

        # 命令行显示
        layout.addWidget(QLabel("命令行:"))
        self.cmd_edit = QTextEdit()
        self.cmd_edit.setFont(QFont("Consolas", 10))
        self.cmd_edit.setReadOnly(True)
        layout.addWidget(self.cmd_edit)

        # 参数列表
        layout.addWidget(QLabel("参数列表:"))
        self.args_edit = QTextEdit()
        self.args_edit.setFont(QFont("Consolas", 10))
        self.args_edit.setReadOnly(True)
        layout.addWidget(self.args_edit)

        # 按钮
        btn_layout = QHBoxLayout()
        copy_btn = QPushButton("复制命令行")
        copy_btn.clicked.connect(self._copy_command)
        btn_layout.addWidget(copy_btn)
        btn_layout.addStretch()
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

    def _load_info(self):
        """加载进程信息"""
        try:
            import psutil
            proc = psutil.Process(self.pid)

            # 获取命令行
            cmdline = proc.cmdline()
            exe = proc.exe()
            name = proc.name()
            cwd = proc.cwd() if hasattr(proc, 'cwd') else "N/A"

            cmd_text = f"进程名: {name}\n"
            cmd_text += f"可执行文件: {exe}\n"
            cmd_text += f"工作目录: {cwd}\n\n"
            cmd_text += f"完整命令行:\n{' '.join(cmdline)}"

            self.cmd_edit.setPlainText(cmd_text)

            # 参数列表
            if len(cmdline) > 1:
                args_text = ""
                for i, arg in enumerate(cmdline[1:], 1):
                    args_text += f"参数 {i}: {arg}\n"
                self.args_edit.setPlainText(args_text)
            else:
                self.args_edit.setPlainText("（无额外参数）")

        except psutil.NoSuchProcess:
            self.cmd_edit.setPlainText(f"错误: PID {self.pid} 的进程不存在")
            self.args_edit.setPlainText("")
        except psutil.AccessDenied:
            self.cmd_edit.setPlainText(f"错误: 无法访问 PID {self.pid} 的进程信息（权限不足）\n请以管理员身份运行程序")
            self.args_edit.setPlainText("")
        except Exception as e:
            self.cmd_edit.setPlainText(f"错误: {e}")
            self.args_edit.setPlainText("")

    def _copy_command(self):
        """复制命令行到剪贴板"""
        copy_to_clipboard(self.cmd_edit.toPlainText())
        QMessageBox.information(self, "已复制", "命令行已复制到剪贴板")


class PortServiceDialog(QDialog):
    """显示端口对应服务信息的对话框"""

    def __init__(self, port, proto, parent=None):
        super().__init__(parent)
        self.port = port
        self.proto = proto
        self.setWindowTitle(f"端口 {port} 服务信息")
        self.setMinimumSize(700, 500)
        self._init_ui()
        self._load_info()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # 标题
        title = QLabel(f"端口 {self.port} ({self.proto.upper()}) 的服务信息")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)

        # 信息显示
        self.info_edit = QTextEdit()
        self.info_edit.setFont(QFont("Consolas", 10))
        self.info_edit.setReadOnly(True)
        layout.addWidget(self.info_edit)

        # 按钮
        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self._load_info)
        btn_layout.addWidget(refresh_btn)
        btn_layout.addStretch()
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

    def _load_info(self):
        """加载端口服务信息"""
        try:
            import psutil
            import socket

            info_lines = [f"端口 {self.port} ({self.proto.upper()}) 服务信息", "=" * 50, ""]

            # 1. 查找占用该端口的进程
            found = False
            if self.proto.lower() == "tcp":
                connections = psutil.net_connections(kind='tcp')
            else:
                connections = psutil.net_connections(kind='udp')

            for conn in connections:
                if conn.laddr and conn.laddr.port == self.port:
                    found = True
                    try:
                        proc = psutil.Process(conn.pid)
                        info_lines.append(f"占用进程: {proc.name()} (PID: {conn.pid})")
                        info_lines.append(f"可执行文件: {proc.exe()}")
                        info_lines.append(f"命令行: {' '.join(proc.cmdline())}")
                        info_lines.append(f"连接状态: {conn.status}")
                        info_lines.append(f"本地地址: {conn.laddr}")
                        if conn.raddr:
                            info_lines.append(f"远程地址: {conn.raddr}")
                        info_lines.append("")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        info_lines.append(f"PID: {conn.pid} (无法获取详细信息)")
                        info_lines.append("")

            if not found:
                info_lines.append("当前没有进程监听此端口")
                info_lines.append("")

            # 2. Windows服务查询
            info_lines.append("─" * 50)
            info_lines.append("Windows 服务信息:")
            info_lines.append("")
            try:
                import subprocess
                result = subprocess.run(
                    ['netstat', '-ano'],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split('\n'):
                    if f':{self.port} ' in line or f':{self.port}\n' in line:
                        info_lines.append(line.strip())
            except Exception:
                pass

            # 3. 端口知识
            info_lines.append("")
            info_lines.append("─" * 50)
            info_lines.append("端口知识:")
            info_lines.append("")

            try:
                # 尝试通过socket获取服务名
                service_name = socket.getservbyport(self.port, self.proto.lower())
                info_lines.append(f"标准服务名: {service_name}")
            except OSError:
                info_lines.append("此端口无标准服务名定义")

            # 4. 防火墙规则
            info_lines.append("")
            info_lines.append("─" * 50)
            info_lines.append("防火墙规则:")
            info_lines.append("")
            try:
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule',
                     f'name=all', f'dir=in'],
                    capture_output=True, text=True, timeout=10
                )
                current_rule = []
                for line in result.stdout.split('\n'):
                    if line.strip().startswith('规则名称') or line.strip().startswith('Rule Name'):
                        if current_rule and any(f'{self.port}' in l for l in current_rule):
                            info_lines.extend(current_rule)
                            info_lines.append("")
                        current_rule = [line.strip()]
                    elif current_rule:
                        current_rule.append(line.strip())
            except Exception:
                info_lines.append("（无法获取防火墙规则）")

            self.info_edit.setPlainText("\n".join(info_lines))

        except Exception as e:
            self.info_edit.setPlainText(f"加载信息失败: {e}")


class AddPortDialog(QDialog):
    """添加/更新端口到识别库的对话框"""

    # 风险等级选项
    RISK_ITEMS = [
        ("safe", "正常 - 已知安全服务"),
        ("warning", "警告 - 需关注的风险服务"),
        ("danger", "危险 - 高危服务，建议关闭"),
        ("unknown", "未知 - 风险待评估"),
    ]

    def __init__(self, port_db, port=0, proto="tcp", service="", risk="unknown",
                 description="", hazard="", parent=None):
        """
        参数:
            port_db: PortDatabase 实例
            port: 预填端口号
            proto: 预填协议
            service: 预填服务名
            risk: 预填风险等级
            description: 预填描述
            hazard: 预填危害
        """
        super().__init__(parent)
        self.port_db = port_db
        self.result_data = None

        self.setWindowTitle("添加/更新端口识别信息")
        self.setMinimumWidth(450)
        self._init_ui(port, proto, service, risk, description, hazard)

    def _init_ui(self, port, proto, service, risk, description, hazard):
        layout = QVBoxLayout(self)

        # ── 说明文字 ──
        hint = QLabel(
            "填写端口信息并保存到本地识别库。\n"
            "已存在的端口将被覆盖更新。"
        )
        hint.setStyleSheet("color: #666; padding: 5px;")
        layout.addWidget(hint)

        # ── 表单 ──
        form = QFormLayout()

        # 端口号
        self.port_spin = QSpinBox()
        self.port_spin.setRange(0, 65535)
        self.port_spin.setValue(int(port) if port else 0)
        form.addRow("端口号 *:", self.port_spin)

        # 协议
        self.proto_combo = QComboBox()
        self.proto_combo.addItem("TCP", "tcp")
        self.proto_combo.addItem("UDP", "udp")
        idx = self.proto_combo.findData(proto.lower())
        if idx >= 0:
            self.proto_combo.setCurrentIndex(idx)
        form.addRow("协议 *:", self.proto_combo)

        # 服务名称
        self.service_edit = QLineEdit(service if service and service != "未知" else "")
        self.service_edit.setPlaceholderText("如: HTTP, SSH, SMB, 自定义服务名")
        form.addRow("服务名称 *:", self.service_edit)

        # 风险等级
        self.risk_combo = QComboBox()
        for value, label in self.RISK_ITEMS:
            self.risk_combo.addItem(label, value)
        idx = self.risk_combo.findData(risk)
        if idx >= 0:
            self.risk_combo.setCurrentIndex(idx)
        form.addRow("风险等级 *:", self.risk_combo)

        # 功能描述
        self.desc_edit = QLineEdit(description if description and not description.startswith("端口") else "")
        self.desc_edit.setPlaceholderText("该端口提供的服务功能描述")
        form.addRow("功能描述:", self.desc_edit)

        # 危害说明
        self.hazard_edit = QLineEdit(hazard if hazard and hazard != "未知端口，建议人工确认其对应的服务和用途" else "")
        self.hazard_edit.setPlaceholderText("该端口可能带来的安全风险和危害")
        form.addRow("危害说明:", self.hazard_edit)

        layout.addLayout(form)

        # ── 按钮 ──
        btn_layout = QHBoxLayout()

        save_btn = QPushButton("保存到识别库")
        save_btn.setStyleSheet("background-color: #27ae60; color: white; padding: 6px 20px; font-weight: bold;")
        save_btn.clicked.connect(self._save)
        btn_layout.addWidget(save_btn)

        btn_layout.addStretch()

        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.reject)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)

    def _save(self):
        """保存端口信息到识别库"""
        port = self.port_spin.value()
        proto = self.proto_combo.currentData()
        service = self.service_edit.text().strip()
        risk = self.risk_combo.currentData()
        description = self.desc_edit.text().strip()
        hazard = self.hazard_edit.text().strip()

        # 验证必填项
        if port == 0:
            QMessageBox.warning(self, "提示", "端口号不能为0")
            return
        if not service:
            QMessageBox.warning(self, "提示", "服务名称不能为空")
            return

        # 检查是否已存在
        is_update = str(port) in self.port_db.ports
        if is_update:
            reply = QMessageBox.question(
                self, "确认更新",
                f"端口 {port} 已存在于识别库中。\n"
                f"当前服务: {self.port_db.ports[str(port)].get('service', '?')}\n"
                f"是否覆盖更新？",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return

        # 调用 PortDatabase.add_port
        success, msg = self.port_db.add_port(
            port, service, proto, risk, description, hazard
        )

        if success:
            self.result_data = {
                "port": port, "protocol": proto, "service": service,
                "risk": risk, "description": description, "hazard": hazard,
            }
            QMessageBox.information(self, "成功", msg)
            self.accept()
        else:
            QMessageBox.warning(self, "失败", msg)