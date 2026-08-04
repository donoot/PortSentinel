"""
PortSentinel v0.08 - Windows 网络端口扫描与安全监控工具
基于 Windows 底层 API (iphlpapi.dll) 实现，使用 PyQt5 构建 GUI 界面

功能:
  1. 多线程 TCP 端口扫描（可配置范围、线程数、超时）
  2. 端口识别库自动匹配服务名、风险等级和危害描述
  3. 活动 TCP/UDP 连接实时监控（含进程信息）
  4. 强制关闭指定 TCP 连接（SetTcpEntry，需管理员权限）
  5. 扫描结果导出 CSV

作者: donoot
许可: GNU General Public License v3
"""
import sys
import os
import ctypes

# 确保项目目录在 sys.path 中
_base_dir = os.path.dirname(os.path.abspath(__file__))
if _base_dir not in sys.path:
    sys.path.insert(0, _base_dir)

from PyQt5.QtWidgets import QApplication, QMessageBox

from gui import MainWindow
from app_logger import init_logger, get_logger


def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def main():
    # 初始化日志系统（在 QApplication 之前，确保所有操作都被记录）
    logger = init_logger(_base_dir)
    logger.info("正在初始化 QApplication...")

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # 提示管理员权限
    if not is_admin():
        logger.warning("当前以非管理员权限运行，关闭连接功能将受限")
        QMessageBox.warning(
            None, "权限提示",
            "当前未以管理员身份运行。\n\n"
            "端口扫描和连接查看功能可正常使用，\n"
            "但[关闭TCP连接]功能需要管理员权限。\n\n"
            "如需使用关闭连接功能，请右键 -> 以管理员身份运行。"
        )
    else:
        logger.info("当前以管理员权限运行")

    try:
        window = MainWindow()
        window.show()
        logger.info("主窗口已显示，进入事件循环")
        exit_code = app.exec_()
        logger.info(f"事件循环结束，退出码: {exit_code}")
        logger.log_shutdown()
        sys.exit(exit_code)
    except Exception as e:
        logger.exception(f"程序发生未捕获异常: {e}")
        logger.log_shutdown()
        raise


if __name__ == "__main__":
    main()
