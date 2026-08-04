"""
多线程端口扫描模块
使用 concurrent.futures.ThreadPoolExecutor 进行高效TCP connect扫描
支持自定义扫描范围、线程数、超时时间，支持取消操作和进度回调
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner:
    """多线程端口扫描器"""

    def __init__(self, target="127.0.0.1", start_port=1, end_port=65535,
                 threads=200, timeout=0.5):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = max(1, min(threads, 1000))
        self.timeout = max(0.1, timeout)
        self._cancelled = False

    def cancel(self):
        """取消扫描"""
        self._cancelled = True

    def scan_port(self, port):
        """扫描单个TCP端口，返回是否开放"""
        if self._cancelled:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def scan(self, port_database=None, on_result=None, on_progress=None):
        """
        执行端口扫描

        参数:
            port_database: PortDatabase实例，用于查询端口识别信息
            on_result:     回调，每发现一个开放端口时调用 on_result(result_dict)
            on_progress:   回调，进度更新 on_progress(scanned, total)

        返回: 所有开放端口结果列表
        """
        self._cancelled = False
        open_ports = []
        total = self.end_port - self.start_port + 1
        scanned = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port): port
                for port in range(self.start_port, self.end_port + 1)
            }

            for future in as_completed(future_to_port):
                if self._cancelled:
                    break

                port = future_to_port[future]
                scanned += 1

                if on_progress and scanned % 50 == 0:
                    on_progress(scanned, total)

                try:
                    is_open = future.result()
                except Exception:
                    is_open = False

                if is_open:
                    info = {}
                    if port_database:
                        info = port_database.lookup(port)

                    result = {
                        "port": port,
                        "protocol": "tcp",
                        "open": True,
                        "service": info.get("service", "未知"),
                        "risk": info.get("risk", "unknown"),
                        "description": info.get("description", ""),
                        "hazard": info.get("hazard", ""),
                    }
                    open_ports.append(result)
                    if on_result:
                        on_result(result)

            if on_progress:
                on_progress(total, total)

        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    def scan_known_ports(self, port_database, on_result=None, on_progress=None):
        """
        快速扫描识别库中所有已知端口
        适用于快速安全检查场景
        """
        self._cancelled = False
        known_ports = port_database.get_all_known_ports()
        total = len(known_ports)
        scanned = 0
        open_ports = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port): port
                for port in known_ports
            }

            for future in as_completed(future_to_port):
                if self._cancelled:
                    break

                port = future_to_port[future]
                scanned += 1

                if on_progress:
                    on_progress(scanned, total)

                try:
                    is_open = future.result()
                except Exception:
                    is_open = False

                if is_open:
                    info = port_database.lookup(port)
                    result = {
                        "port": port,
                        "protocol": "tcp",
                        "open": True,
                        "service": info.get("service", "未知"),
                        "risk": info.get("risk", "unknown"),
                        "description": info.get("description", ""),
                        "hazard": info.get("hazard", ""),
                    }
                    open_ports.append(result)
                    if on_result:
                        on_result(result)

        open_ports.sort(key=lambda x: x["port"])
        return open_ports
