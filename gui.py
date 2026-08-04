"""
PyQt5 GUI界面模块
提供端口扫描参数设置、结果展示、活动连接管理、连接关闭等功能
使用QThread后台执行扫描，通过信号槽机制实时更新UI
"""
import csv

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QSpinBox, QDoubleSpinBox,
    QPushButton, QTableWidget, QTableWidgetItem, QTabWidget,
    QProgressBar, QHeaderView, QMessageBox, QAction, QFileDialog,
    QInputDialog, QDialog,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont

from port_database import PortDatabase
from connection_manager import ConnectionManager
from port_scanner import PortScanner
from gui_helpers import ContextMenuHelper, ToolTipHelper, OSDetectionHelper, ProcessCommandDialog, PortServiceDialog, AddPortDialog
from vuln_database import VulnerabilityDatabase
from app_logger import get_logger
from PyQt5.QtWidgets import QMenu, QToolTip
from PyQt5.QtGui import QCursor
import os
import subprocess
import webbrowser
from datetime import datetime


# ═══════════════════════════════════════════════════════════
#  后台线程
# ═══════════════════════════════════════════════════════════
class ScanWorker(QThread):
    """端口扫描后台线程"""
    result_found = pyqtSignal(dict)         # 发现开放端口
    progress_updated = pyqtSignal(int, int)  # (scanned, total)
    scan_finished = pyqtSignal(list)        # 所有开放端口列表
    scan_error = pyqtSignal(str)            # 错误信息

    def __init__(self, scanner, port_db, scan_known_only=False):
        super().__init__()
        self.scanner = scanner
        self.port_db = port_db
        self.scan_known_only = scan_known_only

    def run(self):
        try:
            if self.scan_known_only:
                results = self.scanner.scan_known_ports(
                    self.port_db,
                    on_result=self.result_found.emit,
                    on_progress=self.progress_updated.emit,
                )
            else:
                results = self.scanner.scan(
                    self.port_db,
                    on_result=self.result_found.emit,
                    on_progress=self.progress_updated.emit,
                )
            self.scan_finished.emit(results)
        except Exception as e:
            self.scan_error.emit(str(e))


class ConnectionWorker(QThread):
    """获取活动连接后台线程"""
    connections_ready = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, conn_mgr):
        super().__init__()
        self.conn_mgr = conn_mgr

    def run(self):
        try:
            conns = self.conn_mgr.get_all_connections()
            self.connections_ready.emit(conns)
        except Exception as e:
            self.error.emit(str(e))


# ═══════════════════════════════════════════════════════════
#  主窗口
# ═══════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.logger = get_logger()
        self.logger.info("正在初始化主窗口...")

        self.port_db = PortDatabase()
        self.conn_mgr = ConnectionManager()
        self.scan_worker = None
        self.conn_worker = None
        self.vuln_db = VulnerabilityDatabase()
        self.os_detector = OSDetectionHelper()
        self.last_scan_results = []
        self.scan_start_time = None

        self._init_ui()
        self._init_menu()
        self._setup_context_menus()
        self.logger.info("主窗口初始化完成")
        self.refresh_connections()

    # ─── UI 初始化 ───
    def _init_ui(self):
        self.setWindowTitle("PortSentinel v0.08 - 网络端口扫描与安全监控工具")
        self.setMinimumSize(1000, 700)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        main_layout.addWidget(self._create_param_section())
        main_layout.addWidget(self._create_tabs(), stretch=1)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")

    def _init_menu(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("文件(&F)")
        export_action = QAction("导出扫描结果", self)
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        file_menu.addSeparator()
        exit_action = QAction("退出", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        tool_menu = menubar.addMenu("工具(&T)")
        reload_db_action = QAction("重新加载端口识别库", self)
        reload_db_action.triggered.connect(self.reload_database)
        tool_menu.addAction(reload_db_action)
        refresh_conn_action = QAction("刷新活动连接", self)
        refresh_conn_action.triggered.connect(self.refresh_connections)
        tool_menu.addAction(refresh_conn_action)

        help_menu = menubar.addMenu("帮助(&H)")
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def _create_param_section(self):
        widget = QWidget()
        layout = QGridLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)

        layout.addWidget(QLabel("扫描目标:"), 0, 0)
        self.target_input = QLineEdit("127.0.0.1")
        layout.addWidget(self.target_input, 0, 1)

        layout.addWidget(QLabel("起始端口:"), 0, 2)
        self.start_port_spin = QSpinBox()
        self.start_port_spin.setRange(1, 65535)
        self.start_port_spin.setValue(1)
        layout.addWidget(self.start_port_spin, 0, 3)

        layout.addWidget(QLabel("结束端口:"), 0, 4)
        self.end_port_spin = QSpinBox()
        self.end_port_spin.setRange(1, 65535)
        self.end_port_spin.setValue(65535)
        layout.addWidget(self.end_port_spin, 0, 5)

        layout.addWidget(QLabel("线程数:"), 1, 0)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 1000)
        self.threads_spin.setValue(300)
        layout.addWidget(self.threads_spin, 1, 1)

        layout.addWidget(QLabel("超时(秒):"), 1, 2)
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.1, 10.0)
        self.timeout_spin.setValue(0.5)
        self.timeout_spin.setSingleStep(0.1)
        layout.addWidget(self.timeout_spin, 1, 3)

        self.scan_btn = QPushButton("开始扫描")
        self.scan_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_btn, 1, 4)

        self.scan_known_btn = QPushButton("仅扫描已知端口")
        self.scan_known_btn.clicked.connect(lambda: self.start_scan(known_only=True))
        layout.addWidget(self.scan_known_btn, 1, 5)

        self.cancel_btn = QPushButton("取消扫描")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_scan)
        layout.addWidget(self.cancel_btn, 0, 6)

        self.refresh_conn_btn = QPushButton("刷新活动连接")
        self.refresh_conn_btn.clicked.connect(self.refresh_connections)
        layout.addWidget(self.refresh_conn_btn, 1, 6)

        return widget

    def _create_tabs(self):
        self.tabs = QTabWidget()

        # Tab1: 端口扫描结果
        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)
        self.scan_table = QTableWidget(0, 6)
        self.scan_table.setHorizontalHeaderLabels(
            ["端口", "协议", "服务", "风险等级", "描述", "危害"]
        )
        header = self.scan_table.horizontalHeader()
        for i in range(4):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        self.scan_table.setAlternatingRowColors(True)
        self.scan_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.scan_table.setSortingEnabled(True)
        scan_layout.addWidget(self.scan_table)

        btn_layout = QHBoxLayout()
        self.export_btn = QPushButton("导出结果")
        self.export_btn.clicked.connect(self.export_results)
        btn_layout.addWidget(self.export_btn)
        self.scan_summary = QLabel("")
        self.scan_summary.setStyleSheet("color: #2c3e50; font-weight: bold;")
        btn_layout.addWidget(self.scan_summary)
        btn_layout.addStretch()
        scan_layout.addLayout(btn_layout)

        self.tabs.addTab(scan_tab, "端口扫描结果")

        # Tab2: 活动连接
        conn_tab = QWidget()
        conn_layout = QVBoxLayout(conn_tab)
        self.conn_table = QTableWidget(0, 7)
        self.conn_table.setHorizontalHeaderLabels(
            ["协议", "本地地址", "本地端口", "远程地址", "远程端口", "状态", "进程(PID)"]
        )
        header2 = self.conn_table.horizontalHeader()
        for i in range(6):
            header2.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        header2.setSectionResizeMode(6, QHeaderView.Stretch)
        self.conn_table.setAlternatingRowColors(True)
        self.conn_table.setSelectionBehavior(QTableWidget.SelectRows)
        conn_layout.addWidget(self.conn_table)

        conn_btn_layout = QHBoxLayout()
        self.close_conn_btn = QPushButton("关闭选中TCP连接")
        self.close_conn_btn.clicked.connect(self.close_connection)
        conn_btn_layout.addWidget(self.close_conn_btn)
        self.conn_count_label = QLabel("")
        self.conn_count_label.setStyleSheet("color: #2c3e50; font-weight: bold;")
        conn_btn_layout.addWidget(self.conn_count_label)
        conn_btn_layout.addStretch()
        conn_layout.addLayout(conn_btn_layout)

        self.tabs.addTab(conn_tab, "活动连接")

        return self.tabs

    # ─── 扫描逻辑 ───
    def start_scan(self, known_only=False):
        target = self.target_input.text().strip() or "127.0.0.1"
        start_port = self.start_port_spin.value()
        end_port = self.end_port_spin.value()
        threads = self.threads_spin.value()
        timeout = self.timeout_spin.value()

        if start_port > end_port:
            self.logger.warning(f"参数错误: 起始端口({start_port}) > 结束端口({end_port})")
            QMessageBox.warning(self, "参数错误", "起始端口不能大于结束端口")
            return

        # 记录扫描开始
        self.scan_start_time = datetime.now()
        self.logger.log_scan_start(target, start_port, end_port, threads, timeout, known_only)

        scanner = PortScanner(target, start_port, end_port, threads, timeout)
        self.scan_worker = ScanWorker(scanner, self.port_db, scan_known_only=known_only)

        self.scan_worker.result_found.connect(self._on_scan_result)
        self.scan_worker.progress_updated.connect(self._on_scan_progress)
        self.scan_worker.scan_finished.connect(self._on_scan_finished)
        self.scan_worker.scan_error.connect(self._on_scan_error)

        self.scan_table.setSortingEnabled(False)
        self.scan_table.setRowCount(0)
        self.scan_btn.setEnabled(False)
        self.scan_known_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.scan_summary.setText("扫描中...")

        self.scan_worker.start()
        self.status_bar.showMessage(f"正在扫描 {target}:{start_port}-{end_port} ...")

    def cancel_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.scanner.cancel()
            self.logger.log_scan_cancelled()
            self.status_bar.showMessage("正在取消扫描...")

    def _on_scan_result(self, result):
        row = self.scan_table.rowCount()
        self.scan_table.insertRow(row)

        risk = result.get("risk", "unknown")
        risk_label = self.port_db.get_risk_label(risk)
        risk_color = self.port_db.get_risk_color(risk)

        port_item = QTableWidgetItem()
        port_item.setData(Qt.DisplayRole, result["port"])
        port_item.setTextAlignment(Qt.AlignCenter)

        proto_item = QTableWidgetItem(result["protocol"])
        proto_item.setTextAlignment(Qt.AlignCenter)

        service_item = QTableWidgetItem(result["service"])

        risk_item = QTableWidgetItem(risk_label)
        risk_item.setForeground(QColor(risk_color))
        risk_item.setFont(QFont("Microsoft YaHei", weight=QFont.Bold))
        risk_item.setTextAlignment(Qt.AlignCenter)

        desc_item = QTableWidgetItem(result.get("description", ""))
        hazard_item = QTableWidgetItem(result.get("hazard", ""))

        self.scan_table.setItem(row, 0, port_item)
        self.scan_table.setItem(row, 1, proto_item)
        self.scan_table.setItem(row, 2, service_item)
        self.scan_table.setItem(row, 3, risk_item)
        self.scan_table.setItem(row, 4, desc_item)
        self.scan_table.setItem(row, 5, hazard_item)

        # 记录扫描结果到日志
        self.logger.log_scan_result(
            result["port"], result["protocol"], result["service"],
            risk_label, result.get("description", ""), result.get("hazard", "")
        )

    def _on_scan_progress(self, scanned, total):
        if total > 0:
            percent = int(scanned * 100 / total)
            self.progress_bar.setValue(percent)
            self.status_bar.showMessage(f"扫描进度: {scanned}/{total} ({percent}%)")
            # 记录进度到日志（自动按25%间隔记录）
            self.logger.log_scan_progress(scanned, total)

    def _on_scan_finished(self, results):
        self.scan_btn.setEnabled(True)
        self.scan_known_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.scan_table.setSortingEnabled(True)

        self.last_scan_results = results

        danger = sum(1 for r in results if r["risk"] == "danger")
        warning = sum(1 for r in results if r["risk"] == "warning")
        safe = sum(1 for r in results if r["risk"] == "safe")
        unknown = sum(1 for r in results if r["risk"] == "unknown")

        # 记录扫描完成
        elapsed = 0.0
        if self.scan_start_time:
            elapsed = (datetime.now() - self.scan_start_time).total_seconds()
        self.logger.log_scan_finished(results, elapsed)

        summary = (f"扫描完成: 共 {len(results)} 个开放端口 | "
                   f"正常: {safe}  警告: {warning}  "
                   f"危险: {danger}  未知: {unknown}")
        self.scan_summary.setText(summary)
        self.status_bar.showMessage(summary)

        if danger > 0:
            self.logger.warning(f"安全告警: 检测到 {danger} 个高危端口")
            QMessageBox.warning(
                self, "安全警告",
                f"检测到 {danger} 个高危端口开放！\n"
                f"请查看[端口扫描结果]中风险等级为[危险]的端口，\n"
                f"建议立即关闭对应服务或通过防火墙限制访问。"
            )

    def _on_scan_error(self, error_msg):
        self.scan_btn.setEnabled(True)
        self.scan_known_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.logger.log_scan_error(error_msg)
        QMessageBox.critical(self, "扫描错误", error_msg)
        self.status_bar.showMessage("扫描出错")

    # ─── 活动连接逻辑 ───
    def refresh_connections(self):
        self.conn_table.setRowCount(0)
        self.conn_count_label.setText("正在获取连接...")
        self.logger.info("正在刷新活动连接列表...")
        self.conn_worker = ConnectionWorker(self.conn_mgr)
        self.conn_worker.connections_ready.connect(self._on_connections_ready)
        self.conn_worker.error.connect(self._on_conn_error)
        self.conn_worker.start()

    def _on_connections_ready(self, connections):
        self.conn_table.setSortingEnabled(False)
        self.conn_table.setRowCount(0)

        for conn in connections:
            row = self.conn_table.rowCount()
            self.conn_table.insertRow(row)

            proto_item = QTableWidgetItem(conn["protocol"])
            proto_item.setTextAlignment(Qt.AlignCenter)

            local_addr_item = QTableWidgetItem(conn["local_addr"])

            local_port_item = QTableWidgetItem()
            local_port_item.setData(Qt.DisplayRole, conn["local_port"])
            local_port_item.setTextAlignment(Qt.AlignCenter)

            remote_addr_item = QTableWidgetItem(conn["remote_addr"])

            remote_port_item = QTableWidgetItem()
            remote_port_item.setData(Qt.DisplayRole, conn["remote_port"])
            remote_port_item.setTextAlignment(Qt.AlignCenter)

            state_item = QTableWidgetItem(conn["state"])
            state_item.setTextAlignment(Qt.AlignCenter)
            state = conn["state"]
            if state == "ESTABLISHED":
                state_item.setForeground(QColor("#2980b9"))
                state_item.setFont(QFont("Microsoft YaHei", weight=QFont.Bold))
            elif state == "LISTEN":
                state_item.setForeground(QColor("#27ae60"))
                state_item.setFont(QFont("Microsoft YaHei", weight=QFont.Bold))
            elif state in ("CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2"):
                state_item.setForeground(QColor("#f39c12"))

            proc_item = QTableWidgetItem(f"{conn['process']} ({conn['pid']})")

            self.conn_table.setItem(row, 0, proto_item)
            self.conn_table.setItem(row, 1, local_addr_item)
            self.conn_table.setItem(row, 2, local_port_item)
            self.conn_table.setItem(row, 3, remote_addr_item)
            self.conn_table.setItem(row, 4, remote_port_item)
            self.conn_table.setItem(row, 5, state_item)
            self.conn_table.setItem(row, 6, proc_item)

        self.conn_table.setSortingEnabled(True)
        self.conn_count_label.setText(f"共 {len(connections)} 个连接")
        self.status_bar.showMessage(f"已加载 {len(connections)} 个活动连接")
        # 记录连接信息到日志
        self.logger.log_connections(connections)

    def _on_conn_error(self, error_msg):
        self.conn_count_label.setText("获取连接失败")
        self.logger.error(f"获取活动连接失败: {error_msg}")
        QMessageBox.critical(self, "错误", f"获取活动连接失败:\n{error_msg}")

    def close_connection(self):
        rows = set(item.row() for item in self.conn_table.selectedItems())
        if not rows:
            QMessageBox.information(self, "提示", "请先在表格中选择要关闭的连接")
            return

        tcp_rows = []
        for row in rows:
            proto = self.conn_table.item(row, 0).text()
            if proto == "TCP":
                tcp_rows.append(row)

        if not tcp_rows:
            QMessageBox.information(self, "提示", "只能关闭TCP连接，选中的行中没有TCP连接")
            return

        reply = QMessageBox.question(
            self, "确认关闭",
            f"将关闭 {len(tcp_rows)} 个TCP连接，是否继续？",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        success_count = 0
        fail_messages = []

        for row in tcp_rows:
            local_addr = self.conn_table.item(row, 1).text()
            local_port = int(self.conn_table.item(row, 2).data(Qt.DisplayRole))
            remote_addr = self.conn_table.item(row, 3).text()
            remote_port = int(self.conn_table.item(row, 4).data(Qt.DisplayRole))

            success, msg = self.conn_mgr.close_tcp_connection(
                local_addr, local_port, remote_addr, remote_port
            )
            # 记录关闭连接操作
            self.logger.log_connection_closed(
                local_addr, local_port, remote_addr, remote_port, success, msg
            )
            if success:
                success_count += 1
            else:
                fail_messages.append(
                    f"{local_addr}:{local_port} -> {remote_addr}:{remote_port}: {msg}"
                )

        if fail_messages:
            QMessageBox.warning(
                self, "部分失败",
                f"成功关闭 {success_count} 个连接\n\n失败:\n" + "\n".join(fail_messages)
            )
        else:
            QMessageBox.information(self, "成功", f"成功关闭 {success_count} 个连接")

        self.refresh_connections()

    # ─── 工具功能 ───
    def export_results(self):
        if self.scan_table.rowCount() == 0:
            QMessageBox.information(self, "提示", "没有扫描结果可导出")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "导出扫描结果", "port_scan_results.csv", "CSV文件 (*.csv)"
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                headers = [
                    self.scan_table.horizontalHeaderItem(col).text()
                    for col in range(self.scan_table.columnCount())
                ]
                writer.writerow(headers)
                for row in range(self.scan_table.rowCount()):
                    row_data = []
                    for col in range(self.scan_table.columnCount()):
                        item = self.scan_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    writer.writerow(row_data)
            self.logger.log_action("导出扫描结果", f"保存到 {path}, {self.scan_table.rowCount()} 行")
            QMessageBox.information(self, "导出成功", f"结果已保存到:\n{path}")
        except Exception as e:
            self.logger.log_error("导出扫描结果", e)
            QMessageBox.critical(self, "导出失败", str(e))

    def reload_database(self):
        self.logger.log_action("重新加载端口识别库")
        self.port_db.reload()
        self.logger.info(f"端口识别库已重新加载，共 {len(self.port_db.ports)} 个端口")
        QMessageBox.information(self, "成功", "端口识别库已重新加载")

    # ─── 右键菜单设置 ───
    def _setup_context_menus(self):
        """为表格配置右键菜单和悬停提示"""
        # 端口扫描结果表格
        self.scan_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.scan_table.customContextMenuRequested.connect(self._show_scan_context_menu)
        self.scan_table.setMouseTracking(True)
        self.scan_table.cellEntered.connect(self._on_scan_cell_entered)

        # 活动连接表格
        self.conn_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.conn_table.customContextMenuRequested.connect(self._show_conn_context_menu)
        self.conn_table.setMouseTracking(True)
        self.conn_table.cellEntered.connect(self._on_conn_cell_entered)

    def _show_scan_context_menu(self, position):
        """端口扫描结果右键菜单"""
        row = self.scan_table.rowAt(position.y())
        if row < 0:
            return
        menu = ContextMenuHelper.create_port_scan_context_menu(
            self, self.scan_table, row, 0
        )
        menu.exec_(self.scan_table.viewport().mapToGlobal(position))

    def _show_conn_context_menu(self, position):
        """活动连接右键菜单"""
        row = self.conn_table.rowAt(position.y())
        if row < 0:
            return
        menu = ContextMenuHelper.create_connection_context_menu(
            self, self.conn_table, row, 0
        )
        menu.exec_(self.conn_table.viewport().mapToGlobal(position))

    def _on_scan_cell_entered(self, row, col):
        """端口扫描结果悬停提示"""
        tooltip = ToolTipHelper.get_port_scan_tooltip(self.scan_table, row)
        if tooltip:
            QToolTip.showText(QCursor.pos(), tooltip, self.scan_table)

    def _on_conn_cell_entered(self, row, col):
        """活动连接悬停提示"""
        tooltip = ToolTipHelper.get_connection_tooltip(self.conn_table, row)
        if tooltip:
            QToolTip.showText(QCursor.pos(), tooltip, self.conn_table)

    # ─── 端口扫描右键功能实现 ───
    def find_port_service(self, port, proto):
        """查找该端口的服务项（哪个程序使用的端口）"""
        dialog = PortServiceDialog(port, proto, self)
        dialog.exec_()

    def toggle_port_firewall(self, port, proto, block=True):
        """通过Windows防火墙关闭/打开该端口"""
        action = "关闭" if block else "打开"
        self.logger.log_action(f"防火墙{action}端口", f"端口: {port}/{proto}")
        reply = QMessageBox.question(
            self, f"防火墙{action}端口",
            f"确认通过Windows防火墙{action}端口 {port} ({proto.upper()})？\n"
            f"此操作需要管理员权限。",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        try:
            if block:
                cmd = (
                    f'netsh advfirewall firewall add rule '
                    f'name="PortSentinel Block {port} {proto}" '
                    f'dir=in action=block protocol={proto.upper()} '
                    f'localport={port}'
                )
            else:
                cmd = (
                    f'netsh advfirewall firewall delete rule '
                    f'name="PortSentinel Block {port} {proto}"'
                )

            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                self.logger.info(f"防火墙规则操作成功: {action}端口 {port}/{proto}")
                QMessageBox.information(
                    self, "成功",
                    f"已{action}端口 {port} ({proto.upper()})\n\n"
                    f"防火墙规则已{'添加' if block else '删除'}"
                )
            else:
                self.logger.error(f"防火墙规则操作失败: {result.stderr}")
                QMessageBox.warning(
                    self, "失败",
                    f"{action}端口失败:\n{result.stderr}\n\n"
                    f"请以管理员身份运行程序"
                )
        except Exception as e:
            self.logger.log_error(f"防火墙{action}端口", e)
            QMessageBox.critical(self, "错误", f"执行失败: {e}")

    def show_port_vulnerabilities(self, port, service):
        """显示端口相关漏洞"""
        vulns = self.vuln_db.get_vulnerabilities_for_port(port, service)
        if not vulns:
            QMessageBox.information(self, "提示", f"端口 {port} 暂无已知漏洞信息")
            return

        details = []
        for vuln in vulns:
            details.append(self.vuln_db.format_vulnerability_report(vuln))
            details.append("\n" + "─" * 50 + "\n")

        QMessageBox.information(self, f"端口 {port} 已知漏洞", "\n".join(details))

    def search_port_online(self, port):
        """在线搜索CVE漏洞"""
        url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=port+{port}"
        webbrowser.open(url)
        self.status_bar.showMessage(f"已打开浏览器搜索端口 {port} 的CVE漏洞")

    def search_port_all_engines(self, port, service):
        """全网络检索该端口的详细信息"""
        search_term = f"port {port} {service}" if service else f"port {port}"
        engines = [
            ("Google", f"https://www.google.com/search?q={search_term}+vulnerability+security"),
            ("Bing", f"https://www.bing.com/search?q={search_term}+vulnerability+security"),
            ("百度", f"https://www.baidu.com/s?wd={search_term}+漏洞+安全"),
            ("CVE Details", f"https://www.cvedetails.com/google-search-results.php?q=port+{port}"),
            ("Exploit DB", f"https://www.exploit-db.com/search?q={port}"),
        ]

        items = [f"{name}" for name, _ in engines]
        from PyQt5.QtWidgets import QInputDialog
        choice, ok = QInputDialog.getItem(
            self, "全网络检索", "选择搜索引擎:", items, 0, False
        )
        if ok and choice:
            for name, url in engines:
                if name == choice:
                    webbrowser.open(url)
                    self.status_bar.showMessage(f"已通过 {name} 检索端口 {port}")
                    break

    def add_port_to_database(self, port, proto, service, risk_label, description, hazard):
        """添加/更新端口信息到识别库"""
        self.logger.log_action("添加端口到识别库", f"端口: {port}/{proto}")

        # 将中文风险标签转换为英文key
        risk_map = {"正常": "safe", "警告": "warning", "危险": "danger", "未知": "unknown"}
        risk_key = risk_map.get(risk_label, "unknown")

        dialog = AddPortDialog(
            self.port_db, port, proto, service, risk_key, description, hazard, self
        )
        if dialog.exec_() == QDialog.Accepted and dialog.result_data:
            data = dialog.result_data
            self.logger.info(
                f"端口已保存到识别库: {data['port']}/{data['protocol']} "
                f"服务={data['service']} 风险={data['risk']}"
            )
            self.status_bar.showMessage(
                f"端口 {data['port']} ({data['service']}) 已保存到识别库"
            )

    def ai_analyze_port(self, port, service, risk, description, hazard):
        """大模型分析该端口 - 打开AI对话页面"""
        prompt = (
            f"请分析以下网络端口的安全信息：\n\n"
            f"端口: {port}\n"
            f"服务: {service}\n"
            f"风险等级: {risk}\n"
            f"描述: {description}\n"
            f"危害: {hazard}\n\n"
            f"请从以下方面分析：\n"
            f"1. 该端口的用途和常见服务\n"
            f"2. 存在的安全风险\n"
            f"3. 已知漏洞和攻击方式\n"
            f"4. 加固建议和防护措施\n"
            f"5. 是否应该关闭该端口"
        )

        # 复制提示词到剪贴板（使用 Qt 内置 API，无需 pyperclip）
        from gui_helpers import copy_to_clipboard
        copy_to_clipboard(prompt)

        # 提供多个AI平台选择
        ai_platforms = [
            ("ChatGPT", "https://chat.openai.com/"),
            ("Claude", "https://claude.ai/"),
            ("通义千问", "https://tongyi.aliyun.com/"),
            ("文心一言", "https://yiyan.baidu.com/"),
            ("Kimi", "https://kimi.moonshot.cn/"),
            ("DeepSeek", "https://chat.deepseek.com/"),
            ("Google Gemini", "https://gemini.google.com/"),
        ]

        items = [name for name, _ in ai_platforms]
        choice, ok = QInputDialog.getItem(
            self, "大模型分析", "选择AI平台（提示词已复制到剪贴板）:", items, 0, False
        )
        if ok and choice:
            for name, url in ai_platforms:
                if name == choice:
                    webbrowser.open(url)
                    self.status_bar.showMessage(
                        f"已打开 {name}，请粘贴提示词进行分析（已复制到剪贴板）"
                    )
                    QMessageBox.information(
                        self, "提示词已复制",
                        f"分析提示词已复制到剪贴板。\n\n"
                        f"请在打开的 {name} 页面中粘贴（Ctrl+V）并发送。\n\n"
                        f"提示词内容：\n{prompt[:200]}..."
                    )
                    break

    def start_quick_scan(self):
        """快速扫描常用端口"""
        self.start_scan(known_only=True)

    # ─── 活动连接右键功能实现 ───
    def close_selected_connection(self, row):
        """关闭选中的TCP连接"""
        proto = self.conn_table.item(row, 0).text()
        if proto != "TCP":
            QMessageBox.warning(self, "提示", "只能关闭TCP连接")
            return

        local_addr = self.conn_table.item(row, 1).text()
        local_port = int(self.conn_table.item(row, 2).data(Qt.DisplayRole))
        remote_addr = self.conn_table.item(row, 3).text()
        remote_port = int(self.conn_table.item(row, 4).data(Qt.DisplayRole))

        reply = QMessageBox.question(
            self, "确认关闭",
            f"确认关闭连接：\n{local_addr}:{local_port} -> {remote_addr}:{remote_port}?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        success, msg = self.conn_mgr.close_tcp_connection(
            local_addr, local_port, remote_addr, remote_port
        )
        self.logger.log_connection_closed(
            local_addr, local_port, remote_addr, remote_port, success, msg
        )
        if success:
            QMessageBox.information(self, "成功", msg)
            self.refresh_connections()
        else:
            QMessageBox.warning(self, "失败", msg)

    def open_process_directory(self, pid):
        """打开程序所在目录"""
        self.logger.log_action("打开程序目录", f"PID: {pid}")
        try:
            import psutil
            proc = psutil.Process(pid)
            exe_path = proc.exe()

            if not exe_path or not os.path.exists(exe_path):
                QMessageBox.warning(self, "提示", f"无法获取进程 {pid} 的可执行文件路径")
                return

            # 在文件资源管理器中选中该文件
            subprocess.Popen(f'explorer /select,"{exe_path}"', shell=True)
            self.logger.info(f"已打开进程目录: PID={pid}, 路径={exe_path}")
            self.status_bar.showMessage(f"已打开: {os.path.dirname(exe_path)}")
        except psutil.NoSuchProcess:
            self.logger.error(f"进程不存在: PID={pid}")
            QMessageBox.warning(self, "错误", f"进程 {pid} 不存在")
        except psutil.AccessDenied:
            self.logger.error(f"权限不足，无法访问进程: PID={pid}")
            QMessageBox.warning(self, "权限不足", f"无法访问进程 {pid} 的信息，请以管理员身份运行")
        except Exception as e:
            self.logger.log_error("打开程序目录", e)
            QMessageBox.critical(self, "错误", f"打开目录失败: {e}")

    def show_process_command(self, pid):
        """显示进程的详细命令及参数"""
        dialog = ProcessCommandDialog(pid, self)
        dialog.exec_()

    def show_process_info(self, pid):
        """显示进程详细信息"""
        try:
            import psutil
            proc = psutil.Process(pid)
            import datetime

            info = f"""进程信息 (PID: {pid})
{'=' * 50}

进程名: {proc.name()}
可执行文件: {proc.exe()}
工作目录: {proc.cwd()}

命令行: {' '.join(proc.cmdline())}

状态: {proc.status()}
CPU使用率: {proc.cpu_percent(interval=0.1)}%
内存使用: {proc.memory_info().rss / 1024 / 1024:.2f} MB
线程数: {proc.num_threads()}

创建时间: {datetime.datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')}

网络连接:"""

            connections = proc.net_connections()
            for conn in connections[:20]:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "*"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "*"
                info += f"\n  {conn.type} {laddr} -> {raddr} ({conn.status})"

            if len(connections) > 20:
                info += f"\n  ... 还有 {len(connections) - 20} 个连接"

            QMessageBox.information(self, f"进程信息 (PID: {pid})", info)
        except psutil.NoSuchProcess:
            QMessageBox.warning(self, "错误", f"进程 {pid} 不存在")
        except psutil.AccessDenied:
            QMessageBox.warning(self, "权限不足", f"无法访问进程 {pid}，请以管理员身份运行")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"获取进程信息失败: {e}")

    def kill_process(self, pid):
        """结束进程"""
        reply = QMessageBox.question(
            self, "确认",
            f"确认结束进程 PID: {pid}？\n\n"
            f"警告: 结束进程可能影响系统稳定性！",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        self.logger.log_action("结束进程", f"PID: {pid}")
        try:
            import psutil
            psutil.Process(pid).terminate()
            self.logger.info(f"进程已结束: PID={pid}")
            QMessageBox.information(self, "成功", f"进程 {pid} 已结束")
            self.refresh_connections()
        except psutil.NoSuchProcess:
            self.logger.warning(f"进程不存在: PID={pid}")
            QMessageBox.warning(self, "提示", f"进程 {pid} 已不存在")
        except psutil.AccessDenied:
            self.logger.error(f"权限不足，无法结束进程: PID={pid}")
            QMessageBox.warning(self, "权限不足", f"无法结束进程 {pid}，请以管理员身份运行")
        except Exception as e:
            self.logger.log_error("结束进程", e)
            QMessageBox.critical(self, "失败", f"结束进程失败: {e}")

    def query_whois(self, ip):
        """WHOIS查询"""
        self.logger.log_action("WHOIS查询", f"IP: {ip}")
        webbrowser.open(f"https://ipinfo.io/{ip}")
        self.status_bar.showMessage(f"正在查询 {ip} 的WHOIS信息")

    def query_ip_location(self, ip):
        """查询IP归属地"""
        self.logger.log_action("查询IP归属地", f"IP: {ip}")
        webbrowser.open(f"https://www.ip138.com/iplookup.asp?ip={ip}&action=2")
        self.status_bar.showMessage(f"正在查询 {ip} 的归属地")

    def show_about(self):
        QMessageBox.about(
            self, "关于 PortSentinel",
            "<h3>PortSentinel v0.08</h3>"
            "<p>Windows 网络端口扫描与安全监控工具</p>"
            "<p>基于 Windows 底层 API (iphlpapi.dll) 实现</p>"
            "<hr>"
            "<p><b>功能特性:</b></p>"
            "<ul>"
            "<li>多线程 TCP 端口扫描</li>"
            "<li>端口识别与风险评级 (107+ 端口)</li>"
            "<li>活动连接实时监控</li>"
            "<li>TCP 连接强制关闭 (SetTcpEntry)</li>"
            "</ul>"
            "<p><b>注意:</b> 关闭连接功能需要管理员权限</p>"
            "<hr>"
            "<p><b>作者:</b> donoot</p>"
            "<p><b>版本:</b> v0.08</p>"
            "<p><b>日期:</b> 2026-08-04</p>"
            "<p><b>许可:</b> GPL v3</p>"
        )

    # ─── 窗口关闭 ───
    def closeEvent(self, event):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.scanner.cancel()
            self.scan_worker.wait(3000)
        if self.conn_worker and self.conn_worker.isRunning():
            self.conn_worker.wait(3000)
        event.accept()
