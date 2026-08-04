"""
PortSentinel 日志系统模块
记录设备信息、网络信息、使用时间、扫描细节、报错信息等
日志文件以 netinfo_YYYYMMDD_HHMMSS_主机名.log 格式保存在 log 目录下
"""
import os
import sys
import socket
import platform
import logging
import traceback
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None


class AppLogger:
    """应用日志管理器"""

    def __init__(self, base_dir=None):
        """
        初始化日志系统

        参数:
            base_dir: 项目根目录，日志将保存在其下的 log/ 子目录
        """
        if base_dir is None:
            # 默认为当前文件所在目录
            base_dir = os.path.dirname(os.path.abspath(__file__))

        self.base_dir = base_dir
        self.log_dir = os.path.join(base_dir, "log")

        # 创建日志目录
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir, exist_ok=True)

        # 生成日志文件名: netinfo_YYYYMMDD_HHMMSS_主机名.log
        hostname = socket.gethostname()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_filename = f"netinfo_{timestamp}_{hostname}.log"
        self.log_path = os.path.join(self.log_dir, self.log_filename)

        # 配置 Python logging
        self.logger = logging.getLogger("PortSentinel")
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers = []  # 清除已有 handler

        # 文件 handler - 记录所有级别
        file_handler = logging.FileHandler(self.log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        self.logger.addHandler(file_handler)

        # 控制台 handler - 仅记录 WARNING 及以上
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(logging.Formatter(
            "[%(levelname)s] %(message)s"
        ))
        self.logger.addHandler(console_handler)

        self.start_time = datetime.now()
        self._log_system_info()

    def _log_system_info(self):
        """记录系统基本信息"""
        self.logger.info("=" * 60)
        self.logger.info("PortSentinel 启动")
        self.logger.info("=" * 60)
        self.logger.info(f"启动时间: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        # ── 设备信息 ──
        self.logger.info("─" * 40)
        self.logger.info("【设备信息】")
        hostname = socket.gethostname()
        self.logger.info(f"  主机名: {hostname}")
        self.logger.info(f"  操作系统: {platform.system()} {platform.release()}")
        self.logger.info(f"  系统版本: {platform.version()}")
        self.logger.info(f"  系统架构: {platform.machine()}")
        self.logger.info(f"  处理器: {platform.processor()}")

        if psutil:
            try:
                mem = psutil.virtual_memory()
                self.logger.info(f"  总内存: {mem.total / (1024**3):.2f} GB")
                self.logger.info(f"  可用内存: {mem.available / (1024**3):.2f} GB")
                self.logger.info(f"  内存使用率: {mem.percent}%")
                self.logger.info(f"  CPU核心数: {psutil.cpu_count(logical=True)}")
                self.logger.info(f"  CPU物理核心: {psutil.cpu_count(logical=False)}")
            except Exception as e:
                self.logger.warning(f"  获取硬件信息失败: {e}")

        # ── 网络设备信息 ──
        self.logger.info("─" * 40)
        self.logger.info("【网络设备信息】")
        self._log_network_info()

        # ── Python 环境信息 ──
        self.logger.info("─" * 40)
        self.logger.info("【运行环境】")
        self.logger.info(f"  Python版本: {platform.python_version()}")
        self.logger.info(f"  Python路径: {sys.executable}")
        self.logger.info(f"  工作目录: {os.getcwd()}")

        # ── 权限信息 ──
        self.logger.info("─" * 40)
        self.logger.info("【权限信息】")
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            self.logger.info(f"  管理员权限: {'是' if is_admin else '否'}")
        except Exception:
            self.logger.info("  管理员权限: 未知")

        self.logger.info("=" * 60)

    def _log_network_info(self):
        """记录网络接口和MAC地址信息"""
        if psutil:
            try:
                # 获取本机所有IP地址
                hostname = socket.gethostname()
                try:
                    local_ip = socket.gethostbyname(hostname)
                    self.logger.info(f"  主机IP: {local_ip}")
                except Exception:
                    pass

                # 获取所有网络接口信息
                addrs = psutil.net_if_addrs()
                stats = psutil.net_if_stats()

                for iface_name, iface_addrs in addrs.items():
                    is_up = stats.get(iface_name)
                    up_status = "启用" if (is_up and is_up.isup) else "禁用"
                    self.logger.info(f"  网卡: {iface_name} [{up_status}]")

                    for addr in iface_addrs:
                        family = addr.family
                        address = addr.address

                        # IPv4
                        if family == socket.AF_INET:
                            self.logger.info(f"    IPv4: {address}")
                            if addr.netmask:
                                self.logger.info(f"    子网掩码: {addr.netmask}")
                            if addr.broadcast:
                                self.logger.info(f"    广播地址: {addr.broadcast}")
                        # IPv6
                        elif family == socket.AF_INET6:
                            self.logger.info(f"    IPv6: {address}")
                        # MAC地址 (Windows: family=-1, psutil.AF_LINK; Linux: socket.AF_PACKET)
                        else:
                            # 通过地址格式判断是否为MAC地址 (XX-XX-XX-XX-XX-XX 或 XX:XX:XX:XX:XX:XX)
                            if (':' in address or '-' in address) and len(address) >= 12:
                                self.logger.info(f"    MAC地址: {address}")
                            else:
                                self.logger.info(f"    其他地址: {address}")

                # 网络统计
                net_io = psutil.net_io_counters()
                self.logger.info(f"  网络统计:")
                self.logger.info(f"    发送字节: {net_io.bytes_sent / (1024**2):.2f} MB")
                self.logger.info(f"    接收字节: {net_io.bytes_recv / (1024**2):.2f} MB")
                self.logger.info(f"    发送包数: {net_io.packets_sent}")
                self.logger.info(f"    接收包数: {net_io.packets_recv}")
                self.logger.info(f"    发送错误: {net_io.errout}")
                self.logger.info(f"    接收错误: {net_io.errin}")

            except Exception as e:
                self.logger.error(f"获取网络信息失败: {e}")
                self.logger.debug(traceback.format_exc())
        else:
            self.logger.warning("  psutil未安装，无法获取详细网络信息")

    # ═══════════════════════════════════════════════════════════
    #  日志记录方法
    # ═══════════════════════════════════════════════════════════

    def info(self, msg):
        """记录一般信息"""
        self.logger.info(msg)

    def warning(self, msg):
        """记录警告信息"""
        self.logger.warning(msg)

    def error(self, msg):
        """记录错误信息"""
        self.logger.error(msg)

    def debug(self, msg):
        """记录调试信息"""
        self.logger.debug(msg)

    def exception(self, msg):
        """记录异常信息（含堆栈）"""
        self.logger.error(msg)
        self.logger.debug(traceback.format_exc())

    def log_scan_start(self, target, start_port, end_port, threads, timeout, known_only=False):
        """记录扫描开始"""
        mode = "已知端口扫描" if known_only else "全范围扫描"
        self.logger.info("=" * 60)
        self.logger.info("【开始端口扫描】")
        self.logger.info(f"  扫描模式: {mode}")
        self.logger.info(f"  扫描目标: {target}")
        self.logger.info(f"  端口范围: {start_port} - {end_port}")
        self.logger.info(f"  线程数: {threads}")
        self.logger.info(f"  超时时间: {timeout}秒")
        self.logger.info(f"  开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info("-" * 40)

    def log_scan_result(self, port, protocol, service, risk, description, hazard):
        """记录单个扫描结果"""
        self.logger.info(
            f"  [发现开放端口] {port}/{protocol} | 服务: {service} | "
            f"风险: {risk} | 描述: {description} | 危害: {hazard}"
        )

    def log_scan_progress(self, scanned, total):
        """记录扫描进度（仅在每25%时记录，避免日志过大）"""
        if total > 0:
            percent = int(scanned * 100 / total)
            if percent % 25 == 0 and percent > 0:
                self.logger.debug(f"  扫描进度: {scanned}/{total} ({percent}%)")

    def log_scan_finished(self, results, elapsed_seconds):
        """记录扫描完成"""
        danger = sum(1 for r in results if r.get("risk") == "danger")
        warning = sum(1 for r in results if r.get("risk") == "warning")
        safe = sum(1 for r in results if r.get("risk") == "safe")
        unknown = sum(1 for r in results if r.get("risk") == "unknown")

        self.logger.info("-" * 40)
        self.logger.info("【扫描完成】")
        self.logger.info(f"  结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info(f"  耗时: {elapsed_seconds:.2f} 秒")
        self.logger.info(f"  开放端口总数: {len(results)}")
        self.logger.info(f"  正常: {safe} | 警告: {warning} | 危险: {danger} | 未知: {unknown}")
        self.logger.info(f"  扫描速率: {len(results) / max(elapsed_seconds, 0.01):.1f} 端口/秒")

        if danger > 0:
            self.logger.warning(f"  ⚠ 检测到 {danger} 个高危端口！")
            for r in results:
                if r.get("risk") == "danger":
                    self.logger.warning(
                        f"    高危: {r['port']}/{r['protocol']} - {r['service']} - {r.get('hazard', '')}"
                    )

        self.logger.info("=" * 60)

    def log_scan_error(self, error_msg):
        """记录扫描错误"""
        self.logger.error("【扫描错误】")
        self.logger.error(f"  错误信息: {error_msg}")
        self.logger.error(f"  发生时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.debug(traceback.format_exc())

    def log_scan_cancelled(self):
        """记录扫描取消"""
        self.logger.warning("【扫描已取消】")
        self.logger.warning(f"  取消时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def log_connections(self, connections):
        """记录活动连接信息"""
        self.logger.info("─" * 40)
        self.logger.info("【活动连接列表】")
        self.logger.info(f"  获取时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info(f"  连接总数: {len(connections)}")

        tcp_count = sum(1 for c in connections if c.get("protocol") == "TCP")
        udp_count = sum(1 for c in connections if c.get("protocol") == "UDP")
        established = sum(1 for c in connections if c.get("state") == "ESTABLISHED")
        listen = sum(1 for c in connections if c.get("state") == "LISTEN")

        self.logger.info(f"  TCP: {tcp_count} | UDP: {udp_count}")
        self.logger.info(f"  已建立: {established} | 监听: {listen}")

        # 记录所有连接详情
        for conn in connections:
            proto = conn.get("protocol", "?")
            local = f"{conn.get('local_addr', '?')}:{conn.get('local_port', '?')}"
            remote = f"{conn.get('remote_addr', '?')}:{conn.get('remote_port', '?')}"
            state = conn.get("state", "?")
            pid = conn.get("pid", "?")
            process = conn.get("process", "?")
            self.logger.debug(f"  {proto} {local} -> {remote} [{state}] PID:{pid} ({process})")

        self.logger.info("─" * 40)

    def log_connection_closed(self, local_addr, local_port, remote_addr, remote_port, success, msg):
        """记录关闭连接操作"""
        if success:
            self.logger.info(f"【关闭连接成功】 {local_addr}:{local_port} -> {remote_addr}:{remote_port}")
        else:
            self.logger.warning(
                f"【关闭连接失败】 {local_addr}:{local_port} -> {remote_addr}:{remote_port} - {msg}"
            )

    def log_action(self, action, details=""):
        """记录用户操作"""
        self.logger.info(f"【用户操作】 {action}" + (f" - {details}" if details else ""))

    def log_error(self, context, error):
        """记录通用错误"""
        self.logger.error(f"【错误】{context}: {error}")
        self.logger.debug(traceback.format_exc())

    def log_shutdown(self):
        """记录程序关闭"""
        end_time = datetime.now()
        duration = end_time - self.start_time
        self.logger.info("=" * 60)
        self.logger.info("【PortSentinel 关闭】")
        self.logger.info(f"  关闭时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info(f"  运行时长: {duration}")
        self.logger.info(f"  日志文件: {self.log_path}")
        self.logger.info("=" * 60)

    def get_log_path(self):
        """获取当前日志文件路径"""
        return self.log_path

    def get_log_dir(self):
        """获取日志目录路径"""
        return self.log_dir


# ═══════════════════════════════════════════════════════════
#  全局日志实例（单例模式）
# ═══════════════════════════════════════════════════════════

_global_logger = None


def get_logger(base_dir=None):
    """
    获取全局日志实例
    首次调用时初始化，后续调用返回同一实例
    """
    global _global_logger
    if _global_logger is None:
        _global_logger = AppLogger(base_dir)
    return _global_logger


def init_logger(base_dir=None):
    """初始化全局日志实例"""
    global _global_logger
    _global_logger = AppLogger(base_dir)
    return _global_logger