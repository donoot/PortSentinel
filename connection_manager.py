"""
Windows底层网络连接管理模块
使用ctypes调用iphlpapi.dll的API:
  - GetExtendedTcpTable: 获取所有TCP连接（含PID）
  - GetExtendedUdpTable: 获取所有UDP监听（含PID）
  - SetTcpEntry: 关闭指定TCP连接（设置状态为DELETE_TCB）
"""
import ctypes
import socket
import struct
from ctypes import wintypes

# ─── 加载Windows DLL ───
iphlpapi = ctypes.WinDLL('iphlpapi.dll')

# ─── 常量定义 ───
AF_INET = 2
AF_INET6 = 23

# TCP表查询类型（含PID）
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

# TCP连接状态码
MIB_TCP_STATE_DELETE_TCB = 12

TCP_STATE_MAP = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD",
    5: "ESTABLISHED", 6: "FIN_WAIT1", 7: "FIN_WAIT2",
    8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
    11: "TIME_WAIT", 12: "DELETE_TCB",
}

# SetTcpEntry 返回码
NO_ERROR = 0
ERROR_ACCESS_DENIED = 5
ERROR_NOT_FOUND = 1168
ERROR_INVALID_PARAMETER = 87


# ─── 结构体定义 ───
class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", wintypes.DWORD),
        ("table", MIB_TCPROW_OWNER_PID * 1),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_UDPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", wintypes.DWORD),
        ("table", MIB_UDPROW_OWNER_PID * 1),
    ]


class MIB_TCPROW(ctypes.Structure):
    """SetTcpEntry所需的结构体"""
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
    ]


# ─── 编解码辅助函数 ───
def _dw_to_ip(dw_addr):
    """DWORD地址 -> IP字符串 (dw_addr在小端机器上是主机字节序的值)"""
    return socket.inet_ntoa(struct.pack('<I', dw_addr))


def _dw_to_port(dw_port):
    """DWORD端口 -> 端口号 (端口以网络字节序存储在低16位)"""
    return socket.ntohs(dw_port & 0xFFFF)


def _port_to_dw(port):
    """端口号 -> DWORD编码 (用于SetTcpEntry)"""
    return socket.htons(port)


def _ip_to_dw(ip_str):
    """IP字符串 -> DWORD值"""
    return struct.unpack('<I', socket.inet_aton(ip_str))[0]


class ConnectionManager:
    """Windows网络连接管理器，获取和关闭本机网络连接"""

    def __init__(self):
        self._process_cache = {}
        self._refresh_process_cache()

    def _refresh_process_cache(self):
        """刷新进程名缓存"""
        self._process_cache = {}
        self._process_cache[0] = "System Idle Process"
        self._process_cache[4] = "System"
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                self._process_cache[proc.info['pid']] = proc.info['name'] or "Unknown"
        except Exception:
            pass

    def get_process_name(self, pid):
        """获取进程名"""
        if pid in self._process_cache:
            return self._process_cache[pid]
        try:
            import psutil
            name = psutil.Process(pid).name()
            self._process_cache[pid] = name
            return name
        except Exception:
            return f"PID:{pid}"

    def get_tcp_connections(self):
        """获取所有TCP连接（含PID和进程名）"""
        size = wintypes.DWORD(0)
        # 第一次调用获取所需缓冲区大小
        iphlpapi.GetExtendedTcpTable(
            None, ctypes.byref(size), False,
            AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
        )
        buf = (ctypes.c_byte * size.value)()
        ret = iphlpapi.GetExtendedTcpTable(
            buf, ctypes.byref(size), False,
            AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
        )
        if ret != NO_ERROR:
            return []

        table = ctypes.cast(buf, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
        num = table.dwNumEntries
        # 通过指针访问变长数组元素
        row_ptr = ctypes.pointer(table.table[0])
        connections = []
        for i in range(num):
            row = row_ptr[i]
            conn = {
                "protocol": "TCP",
                "local_addr": _dw_to_ip(row.dwLocalAddr),
                "local_port": _dw_to_port(row.dwLocalPort),
                "remote_addr": _dw_to_ip(row.dwRemoteAddr),
                "remote_port": _dw_to_port(row.dwRemotePort),
                "state": TCP_STATE_MAP.get(row.dwState, "UNKNOWN"),
                "pid": row.dwOwningPid,
                "process": self.get_process_name(row.dwOwningPid),
            }
            connections.append(conn)
        return connections

    def get_udp_connections(self):
        """获取所有UDP监听（含PID和进程名）"""
        size = wintypes.DWORD(0)
        iphlpapi.GetExtendedUdpTable(
            None, ctypes.byref(size), False,
            AF_INET, UDP_TABLE_OWNER_PID, 0
        )
        buf = (ctypes.c_byte * size.value)()
        ret = iphlpapi.GetExtendedUdpTable(
            buf, ctypes.byref(size), False,
            AF_INET, UDP_TABLE_OWNER_PID, 0
        )
        if ret != NO_ERROR:
            return []

        table = ctypes.cast(buf, ctypes.POINTER(MIB_UDPTABLE_OWNER_PID)).contents
        num = table.dwNumEntries
        row_ptr = ctypes.pointer(table.table[0])
        connections = []
        for i in range(num):
            row = row_ptr[i]
            conn = {
                "protocol": "UDP",
                "local_addr": _dw_to_ip(row.dwLocalAddr),
                "local_port": _dw_to_port(row.dwLocalPort),
                "remote_addr": "*",
                "remote_port": 0,
                "state": "UDP",
                "pid": row.dwOwningPid,
                "process": self.get_process_name(row.dwOwningPid),
            }
            connections.append(conn)
        return connections

    def get_all_connections(self):
        """获取所有TCP和UDP连接"""
        return self.get_tcp_connections() + self.get_udp_connections()

    def get_listening_ports(self):
        """获取所有监听中的端口（TCP LISTEN + UDP）"""
        tcp = [c for c in self.get_tcp_connections() if c["state"] == "LISTEN"]
        udp = self.get_udp_connections()
        return tcp + udp

    def close_tcp_connection(self, local_addr, local_port, remote_addr, remote_port):
        """
        关闭指定TCP连接（通过SetTcpEntry设置状态为DELETE_TCB）
        需要管理员权限。
        返回: (success: bool, message: str)
        """
        row = MIB_TCPROW()
        row.dwState = MIB_TCP_STATE_DELETE_TCB
        row.dwLocalAddr = _ip_to_dw(local_addr)
        row.dwLocalPort = _port_to_dw(local_port)
        row.dwRemoteAddr = _ip_to_dw(remote_addr)
        row.dwRemotePort = _port_to_dw(remote_port)

        ret = iphlpapi.SetTcpEntry(ctypes.byref(row))

        if ret == NO_ERROR:
            return True, "连接已成功关闭"
        elif ret == ERROR_ACCESS_DENIED:
            return False, "权限不足，请以管理员身份运行程序"
        elif ret == ERROR_NOT_FOUND:
            return False, "未找到指定连接（可能已自行关闭）"
        elif ret == ERROR_INVALID_PARAMETER:
            return False, "参数无效"
        else:
            return False, f"关闭失败，错误码: {ret}"
