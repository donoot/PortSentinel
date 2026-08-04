# PortSentinel v0.08 技术手册

> **Windows 网络端口扫描与安全监控工具技术文档**
>
> - **版本：** v0.08
> - **作者：** donoot
> - **日期：** 2026-08-04
> - **许可：** GNU General Public License v3 (GPL v3)

---

## 目录

1. [系统架构](#1-系统架构)
2. [模块详解](#2-模块详解)
3. [Windows 底层技术](#3-windows-底层技术)
4. [多线程技术](#4-多线程技术)
5. [日志系统设计](#5-日志系统设计)
6. [安全检测机制](#6-安全检测机制)
7. [右键菜单功能实现](#7-右键菜单功能实现)
8. [数据流](#8-数据流)
9. [性能优化](#9-性能优化)

---

## 1. 系统架构

PortSentinel 采用清晰的 **三层架构**，将用户界面、业务逻辑与系统接口分离，保证模块独立可测、易于维护。

### 1.1 三层架构总览

```
┌──────────────────────────────────────────────────────────────────┐
│                     GUI 层 (PyQt5)                                │
│  MainWindow · ScanWorker(QThread) · ConnectionWorker(QThread)    │
│  ContextMenuHelper · ToolTipHelper · ProcessCommandDialog        │
│  PortServiceDialog · 各类 QDialog                                │
└───────────────────────────────┬──────────────────────────────────┘
                                │  信号槽 / 函数调用
┌───────────────────────────────▼──────────────────────────────────┐
│                     核心业务层                                    │
│  PortScanner       ConnectionManager    PortDatabase             │
│  OSFingerprint     VulnerabilityDatabase  AppLogger              │
└───────────────────────────────┬──────────────────────────────────┘
                                │  ctypes / psutil / socket / subprocess
┌───────────────────────────────▼──────────────────────────────────┐
│                     系统接口层                                    │
│  iphlpapi.dll (GetExtendedTcpTable/SetTcpEntry)                  │
│  psutil (进程信息) · socket (TCP connect) · subprocess (netsh)   │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 各层职责

| 层次 | 组件 | 职责 |
|------|------|------|
| **GUI 层** | `MainWindow`、`ScanWorker`、`ConnectionWorker`、`ContextMenuHelper`、`ToolTipHelper`、各 `Dialog` | 用户交互、参数采集、结果展示、右键菜单与悬停提示 |
| **核心业务层** | `PortScanner`、`ConnectionManager`、`PortDatabase`、`OSFingerprint`、`VulnerabilityDatabase`、`AppLogger` | 扫描调度、连接管理、端口识别、OS 推断、漏洞匹配、日志记录 |
| **系统接口层** | `ctypes + iphlpapi.dll`、`psutil`、`socket`、`subprocess` | 直接调用 Windows API 与系统命令，屏蔽底层差异 |

### 1.3 模块依赖关系

```
main.py                       # 程序入口
  ├── app_logger.py            # 日志系统（单例）
  └── gui.py                   # 主界面
        ├── port_scanner.py    # 多线程端口扫描
        ├── connection_manager.py  # Windows 连接管理 (iphlpapi.dll)
        ├── port_database.py       # 端口识别库
        │     └── port_database.json
        ├── gui_helpers.py         # GUI 辅助（菜单/提示/对话框）
        │     ├── os_fingerprint.py    # OS 指纹识别
        │     └── vuln_database.py     # 漏洞数据库
        └── vuln_database.py      # 漏洞数据库（直接引用）
```

> `main.py` 在加载任何业务模块前先将项目根目录写入 `sys.path`，确保子模块导入在任意工作目录下都正确。

---

## 2. 模块详解

### 2.1 main.py — 程序入口

入口模块负责 **日志初始化 → QApplication 创建 → 主窗口显示 → 事件循环 → 优雅退出** 的完整生命周期。

#### 2.1.1 管理员权限检测

```python
def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False
```

通过 `shell32.IsUserAnAdmin()` 判断当前进程是否具备管理员令牌。非管理员时仅警告，不阻断启动——端口扫描与连接查看仍可用，仅 `SetTcpEntry` 关闭连接、防火墙规则操作等需要提权。

#### 2.1.2 main() 启动流程

```python
def main():
    logger = init_logger(_base_dir)        # 1. 日志先行
    logger.info("正在初始化 QApplication...")

    app = QApplication(sys.argv)
    app.setStyle("Fusion")                 # 2. 统一跨平台外观

    if not is_admin():                     # 3. 权限提示
        logger.warning("当前以非管理员权限运行，关闭连接功能将受限")
        QMessageBox.warning(None, "权限提示", ...)
    else:
        logger.info("当前以管理员权限运行")

    try:
        window = MainWindow()
        window.show()
        exit_code = app.exec_()            # 4. 进入 Qt 事件循环
        logger.info(f"事件循环结束，退出码: {exit_code}")
        logger.log_shutdown()              # 5. 记录关闭与运行时长
        sys.exit(exit_code)
    except Exception as e:
        logger.exception(f"程序发生未捕获异常: {e}")
        logger.log_shutdown()
        raise
```

**关键设计：**

- **日志先行**：`init_logger` 在 `QApplication` 之前调用，确保后续所有操作（包括 Qt 初始化、窗口构造）都有日志记录。
- **异常兜底**：`try/except` 捕获主流程未处理异常，`logger.exception` 同时输出错误消息和完整堆栈（堆栈在 DEBUG 级别），随后调用 `log_shutdown` 保证日志尾部完整。
- **路径自举**：模块顶部将 `_base_dir` 插入 `sys.path`，避免从快捷方式或非项目目录启动时找不到子模块。

---

### 2.2 port_scanner.py — 端口扫描模块

基于 **TCP connect 扫描**（全连接扫描）实现，使用 `concurrent.futures.ThreadPoolExecutor` 调度多线程。

#### 2.2.1 PortScanner 类定义

```python
class PortScanner:
    def __init__(self, target="127.0.0.1", start_port=1, end_port=65535,
                 threads=200, timeout=0.5):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = max(1, min(threads, 1000))   # 钳制到 1~1000
        self.timeout = max(0.1, timeout)            # 下限 0.1s
        self._cancelled = False
```

参数钳制逻辑保证线程数与超时时间始终在合理区间，避免极端输入导致资源耗尽。

#### 2.2.2 单端口扫描 scan_port()

```python
def scan_port(self, port):
    if self._cancelled:                  # 取消检查点
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        result = sock.connect_ex((self.target, port))   # 非抛异常式连接
        sock.close()
        return result == 0               # 0 表示成功
    except Exception:
        return False
```

- 使用 `connect_ex` 而非 `connect`：前者在连接失败时返回错误码而非抛异常，避免大量异常对象创建开销。
- 每次 `socket` 使用后立即 `close()`，防止文件描述符泄漏。

#### 2.2.3 全范围扫描 scan()

```python
def scan(self, port_database=None, on_result=None, on_progress=None):
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

            if on_progress and scanned % 50 == 0:    # 每 50 个回调一次
                on_progress(scanned, total)

            try:
                is_open = future.result()
            except Exception:
                is_open = False

            if is_open:
                info = port_database.lookup(port) if port_database else {}
                result = {
                    "port": port, "protocol": "tcp", "open": True,
                    "service": info.get("service", "未知"),
                    "risk": info.get("risk", "unknown"),
                    "description": info.get("description", ""),
                    "hazard": info.get("hazard", ""),
                }
                open_ports.append(result)
                if on_result:
                    on_result(result)             # 实时回调 UI

        if on_progress:
            on_progress(total, total)             # 强制 100% 收尾

    open_ports.sort(key=lambda x: x["port"])
    return open_ports
```

**关键算法：**

- **任务一次性提交**：所有端口通过字典推导一次性 `submit` 到线程池，线程池内部排队调度，避免逐个提交的调度开销。
- **as_completed 实时消费**：`as_completed` 返回已完成 future 的迭代器，每完成一个立即处理，配合 `on_result` 回调实现 **边扫边显示**。
- **进度节流**：`scanned % 50 == 0` 每 50 个端口才触发一次进度回调，避免高频信号淹没 Qt 事件循环。
- **取消传播**：`_cancelled` 标志在 `as_completed` 循环顶部检查，已提交但未开始的任务仍会执行 `scan_port`，但 `scan_port` 内部第一行也会检查该标志并快速返回 `False`。

#### 2.2.4 已知端口快速扫描 scan_known_ports()

```python
def scan_known_ports(self, port_database, on_result=None, on_progress=None):
    known_ports = port_database.get_all_known_ports()   # 仅数据库中的端口
    total = len(known_ports)
    ...
    with ThreadPoolExecutor(max_workers=self.threads) as executor:
        future_to_port = {
            executor.submit(self.scan_port, port): port
            for port in known_ports
        }
        ...
```

与 `scan()` 共享线程池与回调机制，区别仅在于 **任务集合来自数据库**而非连续区间，适用于快速安全体检（通常 < 200 个端口，秒级完成）。

#### 2.2.5 取消机制 cancel()

```python
def cancel(self):
    self._cancelled = True
```

通过实例标志位实现 **协作式取消**。由于 Python 的 GIL 与线程池特性，无法强杀工作线程，因此在两个层级插入检查点：

1. `scan_port` 入口：未开始的任务快速返回。
2. `as_completed` 循环顶部：已完成的任务不再处理，跳出循环。

> 注意：当前实现使用普通 `bool` 标志而非 `threading.Event`。在 CPython GIL 下对单个布尔赋值是原子的，足以满足需求；如需更严格的内存可见性语义可替换为 `threading.Event`。

---

### 2.3 connection_manager.py — 连接管理模块

通过 `ctypes` 直接调用 `iphlpapi.dll` 的 Windows IP Helper API，获取和操作本机网络连接表。

#### 2.3.1 DLL 加载与常量

```python
iphlpapi = ctypes.WinDLL('iphlpapi.dll')

AF_INET = 2
AF_INET6 = 23

TCP_TABLE_OWNER_PID_ALL = 5     # 取所有 TCP 连接 + PID
UDP_TABLE_OWNER_PID = 1         # 取所有 UDP 监听 + PID

MIB_TCP_STATE_DELETE_TCB = 12   # SetTcpEntry 删除连接用

# SetTcpEntry 返回码
NO_ERROR = 0
ERROR_ACCESS_DENIED = 5
ERROR_NOT_FOUND = 1168
ERROR_INVALID_PARAMETER = 87

TCP_STATE_MAP = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD",
    5: "ESTABLISHED", 6: "FIN_WAIT1", 7: "FIN_WAIT2",
    8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
    11: "TIME_WAIT", 12: "DELETE_TCB",
}
```

#### 2.3.2 结构体定义

```python
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
        ("table", MIB_TCPROW_OWNER_PID * 1),   # 变长数组占位
    ]

class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]

class MIB_TCPROW(ctypes.Structure):   # SetTcpEntry 专用（无 PID）
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
    ]
```

> `table` 字段声明为长度 1 的数组仅作占位，实际访问通过指针偏移完成（见 2.3.4）。

#### 2.3.3 字节序编解码辅助

```python
def _dw_to_ip(dw_addr):
    """DWORD -> IP 字符串（小端主机序）"""
    return socket.inet_ntoa(struct.pack('<I', dw_addr))

def _dw_to_port(dw_port):
    """DWORD -> 端口号（端口以网络字节序存储在低 16 位）"""
    return socket.ntohs(dw_port & 0xFFFF)

def _port_to_dw(port):
    """端口号 -> DWORD 编码（用于 SetTcpEntry）"""
    return socket.htons(port)

def _ip_to_dw(ip_str):
    """IP 字符串 -> DWORD"""
    return struct.unpack('<I', socket.inet_aton(ip_str))[0]
```

**关键细节：** API 返回的端口存储在 DWORD 的 **低 16 位** 且为网络字节序，因此解码必须 `ntohs(dw & 0xFFFF)`，先掩码再转主机序；而地址是主机序的 32 位值，用 `struct.pack('<I', ...)` 还原。

#### 2.3.4 get_tcp_connections() — 两阶段查询

```python
def get_tcp_connections(self):
    size = wintypes.DWORD(0)
    # 第一次调用：传入 None 获取所需缓冲区大小
    iphlpapi.GetExtendedTcpTable(
        None, ctypes.byref(size), False,
        AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
    )
    buf = (ctypes.c_byte * size.value)()       # 按需分配
    ret = iphlpapi.GetExtendedTcpTable(
        buf, ctypes.byref(size), False,
        AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
    )
    if ret != NO_ERROR:
        return []

    table = ctypes.cast(buf, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
    num = table.dwNumEntries
    row_ptr = ctypes.pointer(table.table[0])    # 通过指针遍历变长数组
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
```

**两阶段查询模式** 是 Windows API 的惯用法：第一次以空缓冲区调用获取 `size`，第二次以正确大小缓冲区获取真实数据。`get_udp_connections()` 采用完全相同的模式，仅替换为 `GetExtendedUdpTable` + `UDP_TABLE_OWNER_PID`。

#### 2.3.5 get_all_connections() 与 get_listening_ports()

```python
def get_all_connections(self):
    return self.get_tcp_connections() + self.get_udp_connections()

def get_listening_ports(self):
    tcp = [c for c in self.get_tcp_connections() if c["state"] == "LISTEN"]
    udp = self.get_udp_connections()
    return tcp + udp
```

UDP 连接的 `remote_addr` 统一为 `"*"`、`remote_port` 为 `0`、`state` 为 `"UDP"`，使表格列结构一致。

#### 2.3.6 进程名解析与缓存

```python
def _refresh_process_cache(self):
    self._process_cache = {0: "System Idle Process", 4: "System"}
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name']):
            self._process_cache[proc.info['pid']] = proc.info['name'] or "Unknown"
    except Exception:
        pass

def get_process_name(self, pid):
    if pid in self._process_cache:
        return self._process_cache[pid]
    try:
        import psutil
        name = psutil.Process(pid).name()
        self._process_cache[pid] = name
        return name
    except Exception:
        return f"PID:{pid}"
```

构造时批量预取所有进程名构建缓存，避免每个连接都调用一次 `psutil.Process(pid).name()`（数百连接 × 系统调用会造成显著延迟）。未命中时再单次查询并回填缓存。

#### 2.3.7 close_tcp_connection() — 强制关闭

```python
def close_tcp_connection(self, local_addr, local_port, remote_addr, remote_port):
    row = MIB_TCPROW()
    row.dwState = MIB_TCP_STATE_DELETE_TCB            # 12 = 删除该 TCB
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
```

返回 `(success: bool, message: str)` 元组，调用方据 `success` 决定后续 UI 行为，`message` 直接展示给用户。四个常见返回码分别映射到中文提示，未覆盖的错误码以数字形式返回便于排查。

---

### 2.4 port_database.py + port_database.json — 端口识别库

#### 2.4.1 JSON 数据结构

```json
{
  "ports": {
    "445": {
      "service": "SMB",
      "protocol": "tcp",
      "risk": "danger",
      "description": "Windows文件共享",
      "hazard": "勒索病毒(WannaCry)主要传播通道，永恒之蓝(MS17-010)利用此端口，应限制外部访问"
    },
    "22": { "service": "SSH", "protocol": "tcp", "risk": "safe", ... }
  },
  "risk_levels": {
    "safe":    {"label": "正常", "color": "#27ae60", "priority": 0},
    "warning": {"label": "警告", "color": "#f39c12", "priority": 1},
    "danger":  {"label": "危险", "color": "#e74c3c", "priority": 2},
    "unknown": {"label": "未知", "color": "#95a5a6", "priority": 3}
  }
}
```

当前数据库收录 **107 个已知端口**，覆盖常见服务、数据库、远程管理、文件共享、工业协议等。每个端口含 5 个字段：`service`（服务名）、`protocol`（tcp/udp）、`risk`（四级风险）、`description`（用途描述）、`hazard`（潜在危害）。

#### 2.4.2 PortDatabase 类

```python
class PortDatabase:
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "port_database.json")
        self.db_path = db_path
        self.ports = {}
        self.risk_levels = {}
        self.load()
```

`load()` 读取 JSON；若文件缺失或格式错误，回退到空端口表 + 默认四级风险配置（保证程序可用）：

```python
def load(self):
    try:
        with open(self.db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.ports = data.get("ports", {})
        self.risk_levels = data.get("risk_levels", {})
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[警告] 端口数据库加载失败: {e}，使用空数据库")
        self.ports = {}
        self.risk_levels = {
            "safe":    {"label": "正常", "color": "#27ae60", "priority": 0},
            "warning": {"label": "警告", "color": "#f39c12", "priority": 1},
            "danger":  {"label": "危险", "color": "#e74c3c", "priority": 2},
            "unknown": {"label": "未知", "color": "#95a5a6", "priority": 3},
        }
```

#### 2.4.3 查询接口 lookup()

```python
def lookup(self, port, protocol="tcp"):
    key = str(port)                  # JSON 键为字符串
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
    # 未知端口返回默认提示
    return {
        "port": port, "service": "未知", "protocol": protocol, "risk": "unknown",
        "description": f"端口 {port} 不在已知识别库中",
        "hazard": "未知端口，建议人工确认其对应的服务和用途",
    }
```

#### 2.4.4 GUI 显示辅助

```python
def get_risk_label(self, risk):
    return self.risk_levels.get(risk, {}).get("label", "未知")

def get_risk_color(self, risk):
    return self.risk_levels.get(risk, {}).get("color", "#95a5a6")

def get_all_known_ports(self):
    """返回所有已知端口列表（已排序）"""
    return sorted(int(k) for k in self.ports.keys())
```

`get_risk_label` / `get_risk_color` 供 `MainWindow._on_scan_result` 为风险等级单元格设置粗体与前景色（绿/黄/红/灰）。`get_all_known_ports` 供 `scan_known_ports()` 构造任务集合。

#### 2.4.5 热重载 reload()

```python
def reload(self):
    self.load()
```

GUI 的「工具 → 重新加载端口识别库」菜单触发，无需重启程序即可应用 JSON 编辑结果。

---

### 2.5 os_fingerprint.py — 操作系统指纹识别

#### 2.5.1 特征库 OS_SIGNATURES

通过 **端口组合 + 服务名** 双维度匹配，覆盖 Windows / Linux / macOS / FreeBSD / 路由器 / 数据库服务器等典型场景：

```python
OS_SIGNATURES = {
    "windows": {
        "ports": [135, 139, 445, 3389],
        "services": ["ms-rpc", "netbios-ssn", "smb", "ms-wbt-server"],
        "hints": ["microsoft-ds", "terminal services", "windows"],
    },
    "windows_10":     {"ports": [135, 139, 445, 3389], "additional": [5985, 5986]},
    "windows_server": {"ports": [135, 139, 445, 3389, 1433], "services": ["ms-sql-s", "ms-rpc"]},
    "linux":   {"ports": [22, 80, 443], "services": ["ssh", "http", "https"]},
    "ubuntu":  {"ports": [22, 80, 443, 3306], "services": ["ssh", "http", "https", "mysql"]},
    "macos":   {"ports": [22, 548, 445], "services": ["ssh", "afp", "smb"]},
    "freebsd": {"ports": [22, 80], "services": ["ssh", "http"]},
    "router":  {"ports": [22, 23, 80, 443, 161], "services": ["ssh", "telnet", "http", "https", "snmp"]},
    "database_server": {"ports": [1433, 1521, 3306, 5432, 6379, 27017], ...},
}
```

**Windows 指示端口：** 135 (MS-RPC)、139 (NetBIOS-SSN)、445 (SMB)、3389 (RDP)
**Linux 指示端口：** 22 (SSH)、111 (rpcbind)、3306/5432/6379/27017 (数据库族)
**macOS 指示端口：** 548 (AFP)、631 (CUPS)

#### 2.5.2 评分算法 analyze_open_ports()

```python
def analyze_open_ports(self, open_ports, services):
    result = {"os": "unknown", "os_version": None, "confidence": 0,
              "evidence": [], "vulnerabilities": []}
    if not open_ports:
        return result

    evidence = []
    os_scores = {}

    for os_name, signature in self.OS_SIGNATURES.items():
        score = 0
        matches = []

        # 端口匹配：每个匹配 +10
        sig_ports = signature.get("ports", [])
        matching_ports = set(open_ports) & set(sig_ports)
        if matching_ports:
            score += len(matching_ports) * 10
            matches.append(f"端口匹配: {matching_ports}")

        # 服务匹配：每个匹配 +15
        sig_services = signature.get("services", [])
        for port in open_ports:
            if port in services:
                service_name = services[port].get("service", "").lower()
                if service_name in sig_services:
                    score += 15
                    matches.append(f"服务匹配: 端口{port}({service_name})")

        if score > 0:
            os_scores[os_name] = score
            evidence.append({"os": os_name, "score": score, "matches": matches})

    if os_scores:
        best_os = max(os_scores, key=os_scores.get)
        max_score = os_scores[best_os]
        total_possible = len(open_ports) * 15
        confidence = min(100, int(max_score / max(total_possible, 1) * 100))
        result["os"] = best_os
        result["confidence"] = confidence
        result["evidence"] = evidence

    # Windows 特殊路径：覆盖置信度下限 70%
    if self._is_windows(open_ports):
        result["os"] = self._detect_windows_version(open_ports, services)
        result["confidence"] = max(result["confidence"], 70)

    return result
```

**算法要点：**

- **加权评分**：端口匹配权重 10，服务名匹配权重 15（服务名更可靠，故权重更高）。
- **置信度归一化**：`score / (open_ports * 15) * 100`，并钳制到 `[0, 100]`。
- **Windows 优先**：一旦命中 Windows 特征端口集合，强制置信度不低于 70%，并进一步细分版本（含 MSSQL → `windows_server`；含 WinRM 5985/5986 → `windows_10/11`）。

返回结构：`{ "os", "os_version", "confidence", "evidence", "vulnerabilities" }`，`evidence` 是各候选 OS 的得分与匹配证据列表，便于生成可解释的报告。

#### 2.5.3 Banner Grabbing（辅助手段）

`get_banner()` 主动连接目标端口并按服务类型发送探测：FTP/SMTP/POP3/IMAP 连接后服务会主动发 Banner；HTTP 端口发送 `HEAD / HTTP/1.0\r\n\r\n`；其他端口发送 `\r\n`。`parse_banner_for_os()` 用正则从 Banner 文本中提取 `windows`、`ubuntu`、`debian`、`centos`、`darwin` 等关键字及版本号，作为端口分析的补充证据。

---

### 2.6 vuln_database.py — 漏洞数据库

#### 2.6.1 数据组织

漏洞按 **服务类别** 分组，横跨三大类：

| 类别 | 字典 | 典型漏洞 |
|------|------|----------|
| Windows 漏洞 | `WINDOWS_VULNERABILITIES` | SMB（永恒之蓝 MS17-010、SMBGhost）、RDP（BlueKeep、BlueGate）、WinRM、MSSQL、IIS WebDAV |
| Linux/Unix 漏洞 | `LINUX_VULNERABILITIES` | SSH（regreSSHion CVE-2024-6387、双重释放）、MySQL、Redis 未授权、MongoDB 未授权 |
| 通用服务漏洞 | `COMMON_VULNERABILITIES` | FTP 明文、Telnet 明文、SNMP 默认 community |

每个漏洞条目结构：

```python
{
    "cve": "CVE-2017-0144",
    "name": "永恒之蓝 (EternalBlue)",
    "affected": "Windows Vista, 7, 8.1, 10, Server 2008-2016",
    "severity": "critical",            # critical / high / medium
    "description": "SMBv1 远程代码执行漏洞，被 WannaCry 勒索病毒利用",
    "mitigation": "安装 MS17-010 补丁，禁用 SMBv1，防火墙阻断445端口",
    "ports": [139, 445],
}
```

数据库共收录 **20+ 已知漏洞**，覆盖近年高危 CVE。构造时合并三表：

```python
def __init__(self):
    self.all_vulns = {
        **self.WINDOWS_VULNERABILITIES,
        **self.LINUX_VULNERABILITIES,
        **self.COMMON_VULNERABILITIES,
    }
```

#### 2.6.2 端口到服务的映射

```python
port_service_map = {
    139: "smb", 445: "smb",
    3389: "rdp",
    5985: "winrm", 5986: "winrm",
    1433: "mssql", 1434: "mssql",
    22: "ssh",
    3306: "mysql", 6379: "redis", 27017: "mongodb",
    20: "ftp", 21: "ftp",
    23: "telnet",
    161: "snmp", 162: "snmp",
}
```

#### 2.6.3 get_vulnerabilities_for_port()

```python
def get_vulnerabilities_for_port(self, port, service=None, os_type=None):
    service_key = port_service_map.get(port)
    if not service_key:
        return []

    if os_type and "windows" in os_type.lower():
        if service_key in self.WINDOWS_VULNERABILITIES:
            return list(self.WINDOWS_VULNERABILITIES[service_key])
    elif os_type and "linux" in os_type.lower():
        if service_key in self.LINUX_VULNERABILITIES:
            return list(self.LINUX_VULNERABILITIES[service_key])
    else:
        # 无 OS 信息时返回所有相关漏洞（跨平台）
        if service_key in self.all_vulns:
            return list(self.all_vulns[service_key])
    return []
```

**匹配逻辑：** 端口 → 服务类别 → 按 OS 过滤。若已识别出 OS 类型，仅返回该 OS 的漏洞；未识别时返回跨平台全集，保证不漏报。

#### 2.6.4 get_vulnerability_summary()

```python
def get_vulnerability_summary(self, os_type=None, open_ports=None):
    summary = {"critical": 0, "high": 0, "medium": 0, "total": 0, "vulnerabilities": []}
    checked_services = set()

    for port in (open_ports or []):
        vulns = self.get_vulnerabilities_for_port(port, os_type=os_type)
        for vuln in vulns:
            if vuln["name"] not in checked_services:   # 按漏洞名去重
                checked_services.add(vuln["name"])
                summary["vulnerabilities"].append(vuln)
                summary["total"] += 1
                severity = vuln.get("severity", "medium").lower()
                if severity == "critical":   summary["critical"] += 1
                elif severity == "high":     summary["high"] += 1
                elif severity == "medium":   summary["medium"] += 1
    return summary
```

按漏洞 `name` 去重（同一服务可能因多个端口重复命中），并按 `severity` 统计各级数量，供报告生成。

#### 2.6.5 format_vulnerability_report()

```python
def format_vulnerability_report(self, vuln):
    report = []
    report.append(f"【{vuln.get('name', 'Unknown')}】")
    report.append(f"CVE: {vuln.get('cve', 'N/A')}")
    report.append(f"影响版本: {vuln.get('affected', 'N/A')}")
    report.append(f"严重等级: {vuln.get('severity', 'medium').upper()}")
    report.append(f"描述: {vuln.get('description', 'N/A')}")
    report.append(f"修复建议: {vuln.get('mitigation', 'N/A')}")
    return "\n".join(report)
```

供右键菜单「查看已知漏洞」直接以 `QMessageBox` 展示。

---

### 2.7 gui.py — GUI 主界面

#### 2.7.1 ScanWorker(QThread) — 扫描后台线程

```python
class ScanWorker(QThread):
    result_found = pyqtSignal(dict)          # 每发现一个开放端口
    progress_updated = pyqtSignal(int, int)  # (scanned, total)
    scan_finished = pyqtSignal(list)         # 全部完成，开放端口列表
    scan_error = pyqtSignal(str)             # 异常消息

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
                    on_result=self.result_found.emit,      # 回调即信号发射
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
```

**设计精髓：** `PortScanner` 的回调 `on_result` / `on_progress` 直接绑定到 `pyqtSignal.emit`，将扫描器完全解耦于 UI——扫描器只管调用回调，回调恰好是 Qt 信号发射，由 Qt 跨线程信号槽机制安全地投递到主线程。

#### 2.7.2 ConnectionWorker(QThread) — 连接获取后台线程

```python
class ConnectionWorker(QThread):
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
```

`GetExtendedTcpTable` + `psutil` 进程名解析在连接数多时会阻塞数十毫秒，放入 QThread 避免界面卡顿。

#### 2.7.3 MainWindow(QMainWindow)

**初始化：**

```python
def __init__(self):
    super().__init__()
    self.logger = get_logger()
    self.port_db = PortDatabase()
    self.conn_mgr = ConnectionManager()
    self.vuln_db = VulnerabilityDatabase()
    self.os_detector = OSDetectionHelper()
    self.scan_worker = None
    self.conn_worker = None
    self.last_scan_results = []
    self.scan_start_time = None

    self._init_ui()
    self._init_menu()
    self._setup_context_menus()
    self.refresh_connections()       # 启动即拉取一次连接
```

**参数区 (`_create_param_section`)**：扫描目标、起始/结束端口（1-65535）、线程数（1-1000，默认 300）、超时（0.1-10.0s，默认 0.5）、开始扫描/仅扫描已知端口/取消扫描/刷新活动连接按钮。

**Tab 组件 (`_create_tabs`)**：

| Tab | 表格 | 列数 | 列定义 |
|-----|------|------|--------|
| 端口扫描结果 | `scan_table` | 6 | 端口、协议、服务、风险等级、描述、危害 |
| 活动连接 | `conn_table` | 7 | 协议、本地地址、本地端口、远程地址、远程端口、状态、进程(PID) |

两个表格均开启 `setAlternatingRowColors`、`SelectRows` 选择行为；扫描表启用 `setSortingEnabled`（按端口列点击排序）。

**扫描主流程方法：**

| 方法 | 职责 |
|------|------|
| `start_scan(known_only=False)` | 校验参数、记录 `log_scan_start`、创建 `PortScanner` + `ScanWorker`、连接信号、启动线程 |
| `cancel_scan()` | 调用 `scanner.cancel()` + `log_scan_cancelled` |
| `_on_scan_result(result)` | 向 `scan_table` 追加一行，按风险等级着色，记录 `log_scan_result` |
| `_on_scan_progress(scanned, total)` | 更新进度条与状态栏，调用 `log_scan_progress`（内部按 25% 节流） |
| `_on_scan_finished(results)` | 恢复按钮状态、统计各级风险数量、`log_scan_finished`（含耗时与扫描速率）、高危时弹窗告警 |
| `_on_scan_error(error_msg)` | `log_scan_error` + 错误弹窗 |

**连接主流程方法：**

| 方法 | 职责 |
|------|------|
| `refresh_connections()` | 创建 `ConnectionWorker` 并启动，重置表格 |
| `_on_connections_ready(connections)` | 填充 `conn_table`，按状态着色（ESTABLISHED 蓝、LISTEN 绿、WAIT 系列橙），`log_connections` |
| `close_connection()` | 批量关闭选中 TCP 连接，逐条 `log_connection_closed`，完成后刷新 |
| `_on_conn_error(error_msg)` | 错误日志 + 弹窗 |

**右键菜单功能方法（端口扫描表）：**

| 方法 | 功能 |
|------|------|
| `find_port_service(port, proto)` | 弹出 `PortServiceDialog`，显示占用该端口的进程、netstat、防火墙规则 |
| `toggle_port_firewall(port, proto, block=True)` | 通过 `netsh advfirewall firewall` 添加/删除阻断规则 |
| `show_port_vulnerabilities(port, service)` | 查询漏洞库并以 `QMessageBox` 展示 |
| `search_port_all_engines(port, service)` | 选择 Google/Bing/百度/CVE Details/Exploit DB 在线检索 |
| `ai_analyze_port(...)` | 生成分析提示词复制到剪贴板，选择 AI 平台（ChatGPT/Claude/通义/文心/Kimi/DeepSeek/Gemini）打开 |

**右键菜单功能方法（活动连接表）：**

| 方法 | 功能 |
|------|------|
| `close_selected_connection(row)` | 单条 TCP 连接关闭 |
| `open_process_directory(pid)` | `explorer /select` 打开进程可执行文件所在目录 |
| `show_process_command(pid)` | 弹出 `ProcessCommandDialog` 显示命令行与参数 |
| `show_process_info(pid)` | 弹窗显示进程名/exe/cwd/状态/CPU/内存/线程/创建时间/网络连接 |
| `kill_process(pid)` | `psutil.Process.terminate()` 结束进程 |
| `query_whois(ip)` | 打开 `ipinfo.io` 查询 WHOIS |
| `query_ip_location(ip)` | 打开 `ip138.com` 查询归属地 |

**右键菜单与悬停提示装配：**

```python
def _setup_context_menus(self):
    self.scan_table.setContextMenuPolicy(Qt.CustomContextMenu)
    self.scan_table.customContextMenuRequested.connect(self._show_scan_context_menu)
    self.scan_table.setMouseTracking(True)
    self.scan_table.cellEntered.connect(self._on_scan_cell_entered)

    self.conn_table.setContextMenuPolicy(Qt.CustomContextMenu)
    self.conn_table.customContextMenuRequested.connect(self._show_conn_context_menu)
    self.conn_table.setMouseTracking(True)
    self.conn_table.cellEntered.connect(self._on_conn_cell_entered)
```

`_show_scan_context_menu` / `_show_conn_context_menu` 将构造委托给 `ContextMenuHelper`；`_on_scan_cell_entered` / `_on_conn_cell_entered` 委托给 `ToolTipHelper` 并调用 `QToolTip.showText`。

**窗口关闭 `closeEvent`**：若后台线程仍在运行，先 `cancel()` 再 `wait(3000)` 等待退出，避免线程访问已销毁的 Qt 对象。

---

### 2.8 gui_helpers.py — GUI 辅助模块

#### 2.8.1 copy_to_clipboard()

```python
def copy_to_clipboard(text):
    """使用 Qt 内置剪贴板 API 复制文本（替代 pyperclip）"""
    app = QApplication.instance()
    if app is not None:
        clipboard = app.clipboard()
        clipboard.setText(str(text))
        return True
    return False
```

v0.08 移除了 `pyperclip` 依赖，统一使用 `QApplication.clipboard()`，消除了「pyperclip 缺失导致启动失败」的遗留问题。

#### 2.8.2 ContextMenuHelper

两个静态方法 `create_port_scan_context_menu` / `create_connection_context_menu` 接收 `(parent, table, row, col)`，从表格单元格读取数据后构造 `QMenu`：

- **端口扫描菜单**：复制端口 / 复制完整信息 →（本机扫描时）查找端口服务项、防火墙开关端口 → 查看已知漏洞、全网络检索、在线 CVE 搜索 → 大模型分析 → 快速扫描常用端口。
- **活动连接菜单**：复制本地/远程地址 →（TCP 时）关闭该连接 →（PID 可解析时）打开程序目录、查看进程命令及参数、查看进程详情、结束进程 →（有远程地址时）WHOIS 查询、IP 归属地查询。

菜单项通过 `lambda` 闭包绑定到 `parent`（即 `MainWindow`）的对应方法，`parent` 提供 `target_input` 属性用于判断是否本机扫描。

#### 2.8.3 ToolTipHelper

`get_port_scan_tooltip` / `get_connection_tooltip` 从表格行读取字段，拼装为 HTML 富文本（`<b>` 加粗、`<br>` 换行），并附带「右键可查看更多操作」提示。连接表的状态字段额外映射为中文说明（如 `ESTABLISHED` → 「已建立连接，正在传输数据」）。

#### 2.8.4 OSDetectionHelper

```python
class OSDetectionHelper:
    def __init__(self):
        self.os_fingerprint = OSFingerprint()
        self.vuln_db = VulnerabilityDatabase()

    def analyze_scan_results(self, scan_results):
        open_ports = [r["port"] for r in scan_results if r.get("open", True)]
        services = {r["port"]: r for r in scan_results if r.get("open", True)}
        os_result = self.os_fingerprint.analyze_open_ports(open_ports, services)
        os_type = os_result.get("os", "unknown")
        vuln_summary = self.vuln_db.get_vulnerability_summary(os_type, open_ports)
        return {
            "os": os_result.get("os", "unknown"),
            "confidence": os_result.get("confidence", 0),
            "evidence": os_result.get("evidence", []),
            "vulnerabilities": vuln_summary,
        }

    def format_os_report(self, os_result):
        # 生成包含识别结果、置信度、识别依据、安全风险统计的文本报告
        ...
```

将 `OSFingerprint` 与 `VulnerabilityDatabase` 组合，对外提供「扫描结果 → OS + 漏洞摘要」的一站式接口。

#### 2.8.5 ProcessCommandDialog

`QDialog` 子类，展示进程的命令行与参数列表：

- 通过 `psutil.Process(pid)` 获取 `cmdline()`、`exe()`、`name()`、`cwd()`。
- 命令行整体显示在上方 `QTextEdit`（Consolas 等宽字体），参数逐条编号显示在下方。
- 「复制命令行」按钮调用 `copy_to_clipboard`。
- 对 `NoSuchProcess` / `AccessDenied` 分别给出友好提示。

#### 2.8.6 PortServiceDialog

`QDialog` 子类，展示端口对应的服务信息，分四块：

1. **占用进程**：通过 `psutil.net_connections(kind='tcp'/'udp')` 查找监听该端口的进程，显示进程名、可执行文件、命令行、连接状态、本地/远程地址。
2. **Windows 服务信息**：执行 `netstat -ano` 并过滤含该端口的行。
3. **端口知识**：`socket.getservbyport(port, proto)` 查询标准服务名。
4. **防火墙规则**：`netsh advfirewall firewall show rule name=all dir=in` 并过滤含该端口的规则块。

「刷新」按钮可重新加载信息。

---

### 2.9 app_logger.py — 日志系统

#### 2.9.1 AppLogger 类

基于 Python 标准库 `logging`，单例模式管理。

**文件命名与目录：**

```python
self.log_dir = os.path.join(base_dir, "log")
if not os.path.exists(self.log_dir):
    os.makedirs(self.log_dir, exist_ok=True)

hostname = socket.gethostname()
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
self.log_filename = f"netinfo_{timestamp}_{hostname}.log"
self.log_path = os.path.join(self.log_dir, self.log_filename)
```

文件名格式：`netinfo_YYYYMMDD_HHMMSS_主机名.log`，每次启动生成新文件，便于按次审计。

**Handler 配置：**

```python
self.logger = logging.getLogger("PortSentinel")
self.logger.setLevel(logging.DEBUG)
self.logger.handlers = []   # 清除已有 handler，避免重复

# 文件 handler：DEBUG 及以上全记录
file_handler = logging.FileHandler(self.log_path, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
))
self.logger.addHandler(file_handler)

# 控制台 handler：仅 WARNING 及以上
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.WARNING)
console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
self.logger.addHandler(console_handler)
```

| Handler | 级别 | 用途 |
|---------|------|------|
| FileHandler | DEBUG+ | 完整审计日志，UTF-8 编码 |
| StreamHandler | WARNING+ | 控制台仅显示告警与错误，避免噪音 |

#### 2.9.2 启动期信息记录 `_log_system_info()`

启动时自动记录四大类信息：

1. **设备信息**：主机名、OS（`platform.system/release/version`）、架构、处理器、内存（总量/可用/使用率）、CPU 逻辑/物理核心数。
2. **网络设备信息**（`_log_network_info`）：本机 IP、所有网卡的启用状态、IPv4/IPv6/MAC 地址、子网掩码、广播地址、网络 IO 统计（收发字节、包数、错误数）。
3. **运行环境**：Python 版本、解释器路径、工作目录。
4. **权限信息**：`IsUserAnAdmin()` 结果。

> MAC 地址识别兼容 Windows（`family == -1` 或 `psutil.AF_LINK`）与 Linux（`socket.AF_PACKET`），通过地址格式（含 `:` 或 `-` 且长度 ≥ 12）二次判断，避免 v0.06 在 Windows 下因 `socket.AF_PACKET` 不存在而报错的问题。

#### 2.9.3 扫描日志方法

| 方法 | 触发时机 | 记录内容 |
|------|----------|----------|
| `log_scan_start(target, start_port, end_port, threads, timeout, known_only)` | `start_scan` | 扫描模式（全范围/已知端口）、目标、端口范围、线程数、超时、开始时间 |
| `log_scan_result(port, protocol, service, risk, description, hazard)` | 每发现开放端口 | 单行端口/服务/风险/描述/危害 |
| `log_scan_progress(scanned, total)` | 进度回调 | **仅每 25% 记录一次**，避免日志膨胀 |
| `log_scan_finished(results, elapsed_seconds)` | 扫描完成 | 结束时间、耗时、开放端口总数、各级风险统计、扫描速率（端口/秒）、高危端口明细 |
| `log_scan_error(error_msg)` | 扫描异常 | 错误信息 + 时间 + 完整堆栈（DEBUG） |
| `log_scan_cancelled()` | 用户取消 | 取消时间 |

**进度节流实现：**

```python
def log_scan_progress(self, scanned, total):
    if total > 0:
        percent = int(scanned * 100 / total)
        if percent % 25 == 0 and percent > 0:
            self.logger.debug(f"  扫描进度: {scanned}/{total} ({percent}%)")
```

全范围扫描 65535 个端口时，进度日志最多 4 条（25%/50%/75%/100%），而非数万条。

#### 2.9.4 连接日志方法

- `log_connections(connections)`：记录获取时间、连接总数、TCP/UDP 计数、ESTABLISHED/LISTEN 计数，所有连接详情在 DEBUG 级别逐条记录。
- `log_connection_closed(local_addr, local_port, remote_addr, remote_port, success, msg)`：成功记 INFO，失败记 WARNING。

#### 2.9.5 操作与错误日志

- `log_action(action, details="")`：用户操作（导出、防火墙开关、结束进程、WHOIS 查询等）记 INFO。
- `log_error(context, error)`：通用错误记 ERROR + 堆栈（DEBUG）。
- `exception(msg)`：异常记 ERROR 消息 + DEBUG 堆栈。

#### 2.9.6 生命周期与单例

```python
def log_shutdown(self):
    end_time = datetime.now()
    duration = end_time - self.start_time
    self.logger.info("=" * 60)
    self.logger.info("【PortSentinel 关闭】")
    self.logger.info(f"  关闭时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    self.logger.info(f"  运行时长: {duration}")
    self.logger.info(f"  日志文件: {self.log_path}")
    self.logger.info("=" * 60)

# 模块级单例
_global_logger = None

def get_logger(base_dir=None):
    global _global_logger
    if _global_logger is None:
        _global_logger = AppLogger(base_dir)
    return _global_logger

def init_logger(base_dir=None):
    global _global_logger
    _global_logger = AppLogger(base_dir)
    return _global_logger
```

`init_logger` 在 `main()` 入口强制创建；`get_logger` 在任意模块按需获取同一实例。`start_time` 在构造时记录，`log_shutdown` 计算并输出运行时长，并打印日志文件路径方便定位。

---

## 3. Windows 底层技术

### 3.1 iphlpapi.dll API 调用

通过 `ctypes.WinDLL('iphlpapi.dll')` 加载 IP Helper API，使用三个核心函数：

| API | 作用 | 关键参数 |
|-----|------|----------|
| `GetExtendedTcpTable` | 获取 TCP 连接表（含 PID） | `TCP_TABLE_OWNER_PID_ALL = 5` |
| `GetExtendedUdpTable` | 获取 UDP 监听表（含 PID） | `UDP_TABLE_OWNER_PID = 1` |
| `SetTcpEntry` | 修改 TCP 条目状态（用于关闭连接） | `MIB_TCP_STATE_DELETE_TCB = 12` |

#### 3.1.1 GetExtendedTcpTable 函数签名

```c
DWORD GetExtendedTcpTable(
    PVOID           pTcpTable,     // 输出缓冲区，NULL 时返回所需大小
    PDWORD          pdwSize,       // 输入/输出缓冲区大小
    BOOL            bOrder,        // 是否排序
    ULONG           ulAf,          // 地址族：AF_INET=2 / AF_INET6=23
    TCP_TABLE_CLASS TableClass,    // 表类型：TCP_TABLE_OWNER_PID_ALL=5
    ULONG           Reserved       // 保留，必须为 0
);
```

PortSentinel 仅处理 IPv4（`AF_INET = 2`），两次调用：第一次传 `None` 获取 `size`，第二次分配缓冲区取数据。

#### 3.1.2 结构体与变长数组访问

`MIB_TCPTABLE_OWNER_PID.table` 声明为长度 1 的数组仅占位，实际条目数由 `dwNumEntries` 决定。通过指针偏移访问变长部分：

```python
table = ctypes.cast(buf, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
num = table.dwNumEntries
row_ptr = ctypes.pointer(table.table[0])   # 取首元素指针
for i in range(num):
    row = row_ptr[i]                        # 指针下标访问，绕过长度 1 限制
    ...
```

#### 3.1.3 字节序关键点

| 字段 | 存储形式 | 解码 |
|------|----------|------|
| `dwLocalAddr` / `dwRemoteAddr` | 主机序 32 位 | `socket.inet_ntoa(struct.pack('<I', dw))` |
| `dwLocalPort` / `dwRemotePort` | 网络字节序，存于 DWORD 低 16 位 | `socket.ntohs(dw & 0xFFFF)` |

`SetTcpEntry` 写入时端口需反向编码：`socket.htons(port)`。

### 3.2 SetTcpEntry 与 DELETE_TCB 机制

`SetTcpEntry` 接收一个 `MIB_TCPROW` 指针，将其 `dwState` 设置为目标状态。将状态设为 `MIB_TCP_STATE_DELETE_TCB (12)` 即通知 TCP/IP 驱动删除该传输控制块（TCB），强制中断连接：

```python
row = MIB_TCPROW()
row.dwState = MIB_TCP_STATE_DELETE_TCB
row.dwLocalAddr  = _ip_to_dw(local_addr)
row.dwLocalPort  = _port_to_dw(local_port)
row.dwRemoteAddr = _ip_to_dw(remote_addr)
row.dwRemotePort = _port_to_dw(remote_port)
ret = iphlpapi.SetTcpEntry(ctypes.byref(row))
```

返回码映射：

| 返回码 | 含义 | 用户提示 |
|--------|------|----------|
| `NO_ERROR (0)` | 成功 | 连接已成功关闭 |
| `ERROR_ACCESS_DENIED (5)` | 权限不足 | 请以管理员身份运行 |
| `ERROR_NOT_FOUND (1168)` | 连接已不存在 | 可能已自行关闭 |
| `ERROR_INVALID_PARAMETER (87)` | 参数无效 | 参数无效 |

### 3.3 netsh advfirewall 防火墙命令

`toggle_port_firewall` 通过 `subprocess.run(..., shell=True)` 调用 `netsh`：

**阻断端口（添加入站规则）：**

```python
cmd = (
    f'netsh advfirewall firewall add rule '
    f'name="PortSentinel Block {port} {proto}" '
    f'dir=in action=block protocol={proto.upper()} '
    f'localport={port}'
)
```

**放行端口（删除规则）：**

```python
cmd = (
    f'netsh advfirewall firewall delete rule '
    f'name="PortSentinel Block {port} {proto}"'
)
```

规则名以 `PortSentinel Block` 前缀统一命名，便于后续删除时精确匹配。`returncode == 0` 视为成功，否则将 `stderr` 展示给用户并提示「请以管理员身份运行」。

---

## 4. 多线程技术

### 4.1 ThreadPoolExecutor 端口扫描

`PortScanner` 使用 `concurrent.futures.ThreadPoolExecutor` 调度 TCP connect 扫描：

- **一次性提交**：所有端口任务通过字典推导一次性 `submit`，线程池内部队列排队执行。
- **as_completed 实时消费**：`as_completed` 返回按完成顺序排列的 future 迭代器，配合 `on_result` 回调实现「边扫边显示」。
- **线程数钳制**：`max(1, min(threads, 1000))`，默认 300，GUI 允许用户在 1-1000 范围调整。

> TCP connect 扫描是 IO 密集型操作（`connect_ex` 在等待对端响应时阻塞），线程数远超 CPU 核数是合理的——线程大部分时间在等待超时。

### 4.2 QThread 后台操作

`ScanWorker` 与 `ConnectionWorker` 继承 `QThread`，重写 `run()` 在后台线程执行耗时操作：

| Worker | 后台任务 | 信号 |
|--------|----------|------|
| `ScanWorker` | 调用 `PortScanner.scan` / `scan_known_ports` | `result_found(dict)`、`progress_updated(int,int)`、`scan_finished(list)`、`scan_error(str)` |
| `ConnectionWorker` | 调用 `ConnectionManager.get_all_connections` | `connections_ready(list)`、`error(str)` |

### 4.3 信号槽机制（线程安全 UI 更新）

Qt 的信号槽在跨线程连接时自动使用 `Qt.QueuedConnection`：信号发射仅将参数副本投递到接收线程（主线程）的事件队列，槽函数在主线程事件循环中执行，从而安全地操作 UI 控件。

PortSentinel 的精妙之处在于 **将扫描器回调直接绑定为信号发射**：

```python
self.scanner.scan(
    self.port_db,
    on_result=self.result_found.emit,      # 回调即 emit
    on_progress=self.progress_updated.emit,
)
```

`PortScanner` 完全不感知 Qt，只调用普通 Python 可调用对象；而该可调用对象恰好是 `pyqtSignal.emit`，由 Qt 完成跨线程投递。扫描器与 UI 之间零耦合。

### 4.4 取消机制

扫描取消采用 **协作式标志位**：

```python
# PortScanner
self._cancelled = False

def cancel(self):
    self._cancelled = True

def scan_port(self, port):
    if self._cancelled:          # 检查点 1：任务入口
        return False
    ...

def scan(self, ...):
    for future in as_completed(future_to_port):
        if self._cancelled:      # 检查点 2：结果消费循环顶部
            break
        ...
```

`MainWindow.cancel_scan` 调用 `scanner.cancel()` 设置标志，正在运行的扫描在下一次检查点退出。窗口关闭时 `closeEvent` 也会先 `cancel()` 再 `wait(3000)` 等待线程结束，防止线程访问已销毁的 Qt 对象。

> 任务说明中提及 `threading.Event`：当前代码使用普通 `bool`（在 CPython GIL 下单布尔赋值原子，足以保证可见性）。如需更严格的语义可替换为 `threading.Event`，对外接口 `cancel()` 调用 `self._event.set()`，检查点调用 `self._event.is_set()`。

---

## 5. 日志系统设计

### 5.1 日志格式与文件命名

- **文件名**：`netinfo_YYYYMMDD_HHMMSS_主机名.log`
- **目录**：项目根目录下的 `log/`，启动时自动创建
- **文件格式**：UTF-8 编码纯文本
- **行格式**：`%(asctime)s [%(levelname)s] %(message)s`，时间精确到秒（`%Y-%m-%d %H:%M:%S`）
- **控制台格式**：`[%(levelname)s] %(message)s`（仅 WARNING 及以上输出）

### 5.2 日志级别

| 级别 | 文件 | 控制台 | 使用场景 |
|------|------|--------|----------|
| DEBUG | ✅ | ❌ | 扫描进度（25% 节流）、连接详情、异常堆栈 |
| INFO | ✅ | ❌ | 启动、扫描开始/完成、用户操作、关闭连接成功 |
| WARNING | ✅ | ✅ | 非管理员运行、扫描取消、关闭连接失败、高危端口告警 |
| ERROR | ✅ | ✅ | 扫描错误、获取连接失败、导出失败、进程操作失败 |

### 5.3 各阶段记录内容

| 阶段 | 记录内容 |
|------|----------|
| **启动** | 设备信息（主机名/OS/CPU/内存）、网络设备信息（网卡/IP/MAC/统计）、Python 环境、管理员权限 |
| **扫描开始** | 模式、目标、端口范围、线程数、超时、开始时间 |
| **扫描进行** | 每个开放端口的端口/协议/服务/风险/描述/危害；进度按 25% 间隔记录 |
| **扫描完成** | 结束时间、耗时、开放端口总数、各级风险统计、扫描速率、高危端口明细 |
| **扫描取消** | 取消时间 |
| **扫描错误** | 错误信息、时间、堆栈 |
| **连接刷新** | 获取时间、连接总数、TCP/UDP 计数、已建立/监听计数、每条连接详情（DEBUG） |
| **关闭连接** | 本地/远程地址端口、成功/失败、失败原因 |
| **用户操作** | 导出、防火墙开关、结束进程、WHOIS 查询等动作及详情 |
| **关闭** | 关闭时间、运行时长、日志文件路径 |

### 5.4 目录结构

```
PortSentinel/
├── log/
│   ├── netinfo_20260804_194850_CMCC.log     # 每次启动一个文件
│   └── netinfo_20260804_201230_CMCC.log
├── app_logger.py
├── ...
```

按次启动分文件，便于按时间定位某次运行的全部行为；文件名含主机名，便于多机环境归档。

---

## 6. 安全检测机制

### 6.1 端口风险分类算法

**四级分类**（`port_database.json` 的 `risk_levels`）：

| 等级 | 标签 | 颜色 | 含义 | 典型端口 |
|------|------|------|------|----------|
| `safe` | 正常 | `#27ae60` 绿 | 标准服务，通常安全 | 22 SSH、80 HTTP、443 HTTPS |
| `warning` | 警告 | `#f39c12` 橙 | 需注意配置 | 21 FTP、25 SMTP、161 SNMP |
| `danger` | 危险 | `#e74c3c` 红 | 高风险，应限制访问 | 23 Telnet、445 SMB、3389 RDP、6379 Redis |
| `unknown` | 未知 | `#95a5a6` 灰 | 不在识别库 | - |

**分类流程：**

1. 扫描发现开放端口 → `PortDatabase.lookup(port)` 查询 JSON。
2. 命中则返回数据库中的 `risk`；未命中返回 `unknown` 并附带「建议人工确认」提示。
3. GUI 的 `_on_scan_result` 调用 `get_risk_label` / `get_risk_color` 为风险等级单元格设置粗体与前景色。
4. 扫描完成后 `log_scan_finished` 统计各级数量；若有 `danger` 端口，弹窗告警并在日志中逐条列出。

### 6.2 OS 指纹匹配逻辑

详见 [2.5](#25-os_fingerprintpy--操作系统指纹识别)。核心是 **端口 + 服务双维度加权评分**：

- 端口匹配：每个 +10
- 服务名匹配：每个 +15
- 置信度 = `最高分 / (开放端口数 × 15) × 100`，钳制到 `[0, 100]`
- Windows 命中时置信度下限 70%，并按附加端口细分版本

返回 `{ os, confidence, evidence }`，`evidence` 含所有候选 OS 的得分与匹配证据，保证结果可解释。

### 6.3 漏洞匹配逻辑

详见 [2.6](#26-vuln_databasepy--漏洞数据库)。三步匹配：

1. **端口 → 服务类别**：通过 `port_service_map` 将端口号映射到 `smb`/`rdp`/`ssh`/`mysql` 等服务键。
2. **OS 过滤**：若已识别 OS，仅返回该 OS 对应的漏洞子库（Windows/Linux）；未识别时返回跨平台全集，保证不漏报。
3. **去重与统计**：`get_vulnerability_summary` 按漏洞 `name` 去重，按 `severity` 统计 critical/high/medium 数量。

### 6.4 防火墙规则管理

通过 `netsh advfirewall firewall` 命令动态添加/删除入站阻断规则（详见 [3.3](#33-netsh-advfirewall-防火墙命令)）。规则名以 `PortSentinel Block {port} {proto}` 统一命名，便于：

- 删除时按名称精确匹配，不影响用户其他规则。
- 在 `PortServiceDialog` 中可通过 `netsh show rule name=all` 列出与该端口相关的所有规则。

---

## 7. 右键菜单功能实现

### 7.1 ContextMenuPolicy.CustomContextMenu

两个表格均设置 `Qt.CustomContextMenu` 策略，并连接 `customContextMenuRequested` 信号：

```python
self.scan_table.setContextMenuPolicy(Qt.CustomContextMenu)
self.scan_table.customContextMenuRequested.connect(self._show_scan_context_menu)
```

右键按下时 Qt 发射 `customContextMenuRequested(QPoint)`，参数 `position` 是相对表格 viewport 的坐标。

### 7.2 菜单创建与动作连接

`_show_scan_context_menu` / `_show_conn_context_menu` 将构造委托给 `ContextMenuHelper`：

```python
def _show_scan_context_menu(self, position):
    row = self.scan_table.rowAt(position.y())   # 坐标 → 行号
    if row < 0:
        return
    menu = ContextMenuHelper.create_port_scan_context_menu(
        self, self.scan_table, row, 0
    )
    menu.exec_(self.scan_table.viewport().mapToGlobal(position))
```

`rowAt(position.y())` 将视口坐标转为行号；`mapToGlobal` 将视口坐标转为屏幕坐标供 `QMenu.exec_` 定位。

`ContextMenuHelper` 从表格单元格读取数据，用 `lambda` 闭包绑定动作：

```python
block_port_action = QAction("通过防火墙关闭该端口", parent)
block_port_action.triggered.connect(
    lambda: parent.toggle_port_firewall(port, proto, block=True)
)
menu.addAction(block_port_action)
```

### 7.3 端口扫描表右键功能全集

| 菜单项 | 触发条件 | 实现 |
|--------|----------|------|
| 复制端口 | 始终 | `copy_to_clipboard(str(port))` |
| 复制完整信息 | 始终 | 拼装多行文本复制 |
| 查找该端口的服务项 | 仅本机扫描 | `PortServiceDialog` |
| 通过防火墙关闭该端口 | 仅本机扫描 | `netsh add rule ... action=block` |
| 通过防火墙打开该端口 | 仅本机扫描 | `netsh delete rule ...` |
| 查看已知漏洞 | 始终 | `vuln_db.get_vulnerabilities_for_port` + `QMessageBox` |
| 全网络检索该端口详细信息 | 始终 | 选择引擎后 `webbrowser.open` |
| 在线搜索CVE漏洞 | 始终 | 打开 `cve.mitre.org` |
| 大模型分析该端口 | 始终 | 生成提示词复制到剪贴板，选择 AI 平台打开 |
| 快速扫描常用端口 | 始终 | `start_scan(known_only=True)` |

> 「本机扫描」判定：`target in ("127.0.0.1", "localhost", "0.0.0.0", "::1")`，仅本机扫描时显示防火墙与服务项操作（这些操作只对本地有意义）。

### 7.4 活动连接表右键功能全集

| 菜单项 | 触发条件 | 实现 |
|--------|----------|------|
| 复制地址: 本地 | 始终 | `copy_to_clipboard` |
| 复制远程地址 | 远程地址非 `*`/`0.0.0.0` | `copy_to_clipboard` |
| 关闭该连接 | 仅 TCP | `close_selected_connection(row)` |
| 打开程序所在目录 | PID 可解析 | `explorer /select,"exe_path"` |
| 查看进程命令及参数 | PID 可解析 | `ProcessCommandDialog` |
| 查看进程详情 | PID 可解析 | 弹窗显示进程全部信息 |
| 结束进程 | PID 可解析 | `psutil.Process.terminate()` |
| WHOIS查询 | 有远程地址 | 打开 `ipinfo.io` |
| 查询IP归属地 | 有远程地址 | 打开 `ip138.com` |

PID 从「进程(PID)」单元格文本中解析：优先匹配括号内数字，否则按纯数字处理。

---

## 8. 数据流

### 8.1 扫描数据流

```
用户输入(目标/端口范围/线程/超时)
        │
        ▼
MainWindow.start_scan()
        │  记录 log_scan_start
        ▼
ScanWorker(QThread).start()
        │
        ▼
PortScanner.scan(port_db, on_result, on_progress)
        │
        ▼
ThreadPoolExecutor.submit(scan_port, port) × N
        │
        ▼
socket.connect_ex((target, port))   ← 系统接口层
        │
        ▼
as_completed 循环:
  ├─ on_progress(scanned, total) → progress_updated 信号 → UI 进度条 + log_scan_progress
  └─ on_result(result_dict)      → result_found 信号  → UI 表格追加行 + log_scan_result
        │
        ▼
scan_finished 信号 → _on_scan_finished → 统计/告警/log_scan_finished
```

### 8.2 连接数据流

```
用户点击「刷新活动连接」 / 启动时自动触发
        │
        ▼
MainWindow.refresh_connections()
        │
        ▼
ConnectionWorker(QThread).start()
        │
        ▼
ConnectionManager.get_all_connections()
        │
        ▼
GetExtendedTcpTable / GetExtendedUdpTable   ← iphlpapi.dll
        │
        ▼
psutil 进程名解析（缓存优先）
        │
        ▼
connections_ready 信号 → _on_connections_ready → 填充表格 + log_connections
```

### 8.3 关闭连接数据流

```
用户选中行 → 右键「关闭该连接」/「关闭选中TCP连接」按钮
        │
        ▼
MainWindow.close_selected_connection(row) / close_connection()
        │  确认对话框
        ▼
ConnectionManager.close_tcp_connection(local_addr, local_port, remote_addr, remote_port)
        │
        ▼
MIB_TCPROW(dwState=DELETE_TCB) → SetTcpEntry   ← iphlpapi.dll
        │
        ▼
返回 (success, message)
        │
        ▼
log_connection_closed(...)
        │
        ▼
成功 → refresh_connections() 重新拉取连接表
失败 → QMessageBox 展示 message
```

---

## 9. 性能优化

### 9.1 线程池规模

- 默认 300 线程，GUI 允许 1-1000 调整。
- TCP connect 是 IO 密集型，线程数远超 CPU 核数合理——线程大部分时间在 `connect_ex` 等待超时。
- 全范围 65535 端口、300 线程、0.5s 超时下，最坏情况约 `65535 / 300 × 0.5 ≈ 109` 秒；实际因多数端口快速拒绝，通常远低于此。

### 9.2 进度日志 25% 节流

```python
def log_scan_progress(self, scanned, total):
    if total > 0:
        percent = int(scanned * 100 / total)
        if percent % 25 == 0 and percent > 0:
            self.logger.debug(...)
```

全范围扫描最多 4 条进度日志（25%/50%/75%/100%），而非每端口一条（65535 条），避免日志文件膨胀影响写入性能与可读性。

UI 进度回调则每 50 个端口触发一次（`scanned % 50 == 0`），平衡刷新频率与事件循环负载。

### 9.3 QThread 避免 UI 阻塞

扫描与连接获取均在 QThread 中执行，主线程仅处理信号槽回调（追加表格行、更新进度条）。即便后台扫描数万端口，UI 仍可响应（取消按钮、窗口拖动、Tab 切换）。

### 9.4 进程名缓存

`ConnectionManager._refresh_process_cache` 在构造时批量预取所有进程名，`get_process_name` 优先查缓存。数百连接共享同一份进程名映射，避免逐个 `psutil.Process(pid).name()` 的系统调用开销。

### 9.5 Qt 剪贴板替代 pyperclip

`copy_to_clipboard` 使用 `QApplication.clipboard().setText()`，无需额外第三方依赖。消除了 v0.06 中「pyperclip 缺失导致程序无法启动」的遗留问题，同时减少了打包体积与跨平台兼容性问题。

### 9.6 取消机制降低无效开销

用户取消后，`_cancelled` 标志在 `scan_port` 入口与 `as_completed` 循环顶部双重检查，已提交但未开始的任务快速返回 `False`，不再触发 `on_result` 与日志记录，最大限度减少取消后的 CPU 与 IO 消耗。

### 9.7 排序延迟启用

扫描期间 `setSortingEnabled(False)`，避免每插入一行都触发排序（O(n²) 退化）；扫描完成后 `setSortingEnabled(True)` 再启用，用户点击表头排序。这是 QTableWidget 大数据量插入的标准优化手法。

---

## 附录

### A. 关键 CVE 漏洞速查

| CVE | 名称 | 端口 | 严重等级 | 影响系统 |
|-----|------|------|----------|----------|
| CVE-2017-0144 | 永恒之蓝 (MS17-010) | 139/445 SMB | Critical | Windows Vista-2016 |
| CVE-2020-0796 | SMBGhost | 445 SMBv3 | Critical | Win10 1903/1909 |
| CVE-2019-0708 | BlueKeep | 3389 RDP | Critical | Windows XP-7 / Server 2003-2008 R2 |
| CVE-2019-1181/1182 | BlueGate | 3389 RDP | Critical | Win8.1-10 / Server 2012-2019 |
| CVE-2024-6387 | regreSSHion | 22 SSH | Critical | OpenSSH 8.5p1-9.7p1 |
| CVE-2020-0618 | MSSQL RCE | 1433/1434 | High | SQL Server 2012-2019 |
| CVE-2017-7269 | IIS WebDAV RCE | 80/443 | Critical | IIS 6.0 (Win Server 2003) |
| - | Redis 未授权访问 | 6379 | Critical | Redis < 6.0 |
| - | MongoDB 未授权访问 | 27017 | Critical | 所有版本（默认配置） |

### B. 运行依赖

- Python 3.8+
- PyQt5
- psutil
- Windows 操作系统（依赖 iphlpapi.dll 与 netsh）

### C. 文件清单

| 文件 | 职责 |
|------|------|
| `main.py` | 程序入口、权限检测、生命周期管理 |
| `port_scanner.py` | 多线程 TCP 端口扫描 |
| `connection_manager.py` | Windows 连接管理（iphlpapi.dll） |
| `port_database.py` / `port_database.json` | 端口识别库（107 端口） |
| `os_fingerprint.py` | 操作系统指纹识别 |
| `vuln_database.py` | 漏洞数据库（20+ CVE） |
| `gui.py` | PyQt5 主界面与后台线程 |
| `gui_helpers.py` | 右键菜单、悬停提示、对话框、OS 检测集成 |
| `app_logger.py` | 日志系统（单例） |

---

**文档版本：** v0.08
**最后更新：** 2026-08-04
**作者：** donoot
**许可：** GNU General Public License v3
