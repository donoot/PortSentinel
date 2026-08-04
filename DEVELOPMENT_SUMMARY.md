# PortSentinel 开发过程总结

> **版本**：v0.08
> **作者**：donoot
> **日期**：2026-08-04
> **许可证**：GPL v3

---

## 1. 项目概述

PortSentinel 是一款 Windows 平台网络端口扫描与安全监控工具。项目基于 Python + PyQt5 构建，通过 ctypes 调用 Windows 原生 API（iphlpapi.dll），实现对网络端口的深度扫描、活动连接监控、异常连接关闭以及漏洞风险识别等功能。

项目以 GPL v3 协议开源，遵循 GitHub 标准项目结构，旨在为个人用户与安全研究人员提供一款轻量、可扩展、可视化的本机网络安全审计工具。

---

## 2. 项目目标与需求

### 2.1 原始需求

1. Windows 本机网络端口扫描并展示状态
2. 自主发现开放端口
3. 构造识别库，检测端口正常/异常，识别危害
4. 关闭异常连接
5. 使用最新 Windows 底层技术
6. 多线程提高效率
7. GUI 界面可设置参数

### 2.2 后续增强需求

1. GitHub 标准化项目整理
2. GPL v3 许可证
3. 鼠标右键功能（活动连接表 + 端口扫描表）
4. 网络安全检测和监测功能
5. 操作系统识别及已知漏洞检测
6. 悬停弹出式详细说明
7. 日志系统（设备信息/网络信息/MAC 地址/使用时间/扫描细节/报错信息）
8. 管理员权限自动提升

---

## 3. 开发过程

### 3.1 v0.04 - 基础架构搭建

本阶段完成项目核心骨架与基础功能：

- **项目架构设计**：采用三层架构（GUI 层 / 核心业务层 / 系统接口层），各层职责清晰、解耦明确
- **核心扫描引擎**：`PortScanner` 使用 `ThreadPoolExecutor` 实现并发端口扫描
- **Windows API 封装**：`ConnectionManager` 通过 ctypes + iphlpapi.dll 获取/操作 TCP、UDP 连接
- **端口识别库**：基于 JSON 格式构建包含 107+ 端口的数据库，附带服务、风险等级与危害描述
- **基础 GUI 界面**：基于 PyQt5 `QMainWindow` 实现多 Tab 页布局

### 3.2 v0.06 - 功能完善与 GitHub 标准化

本阶段完善核心功能并完成开源化改造：

- **完善多线程扫描**：支持 1-1000 线程动态配置，提供全范围（1-65535）/已知端口两种扫描模式
- **活动连接监控**：实时获取 TCP/UDP 连接信息，包含 PID、进程名、本地/远程地址、连接状态
- **强制关闭 TCP 连接**：调用 `SetTcpEntry` 以 `DELETE_TCB` 方式断开异常连接
- **CSV 导出功能**：支持扫描结果与连接列表导出
- **GitHub 标准项目结构**：补充 README、LICENSE（GPL v3）、.gitignore、CHANGELOG
- **技术文档与使用说明**：新增技术手册与用户指南

### 3.3 v0.08 - 高级功能与安全增强

本阶段为重大增强版本，集中交付安全分析与可用性提升功能：

#### 操作系统指纹识别

- 通过端口组合分析推断目标操作系统
- 规则示例：Windows → 135/139/445/3389；Linux → 22/111；macOS → 548/631
- 实现置信度评估算法，根据命中端口数量给出概率性结论

#### 漏洞数据库

- 收录 20+ 知名 CVE 漏洞条目
- 典型漏洞：永恒之蓝（MS17-010）、BlueKeep（CVE-2019-0708）、SMBGhost（CVE-2020-0796）等
- 根据识别到的操作系统与开放端口自动匹配潜在漏洞
- 每条漏洞提供 CVE 编号、影响版本、修复建议

#### GUI 右键菜单

- **活动连接表（7 项功能）**：关闭连接、打开程序目录、查看进程命令及参数、查看进程详情、结束进程、WHOIS 查询、IP 归属地查询
- **端口扫描表（6 项功能）**：查找端口服务项、防火墙开关端口、查看漏洞、全网络检索、大模型分析
- 实现方式：Qt `CustomContextMenu` 信号 + `QMenu` 弹出菜单

#### 悬停提示

- 鼠标移至表格行时显示详细信息
- 端口信息：端口 / 服务 / 风险 / 描述 / 危害
- 连接信息：协议 / 地址 / 状态说明 / 进程
- 基于 `QToolTip` 实现

#### 日志系统

- 文件命名格式：`netinfo_YYYYMMDD_HHMMSS_主机名.log`
- 保存位置：`log/` 目录
- 记录内容：设备信息、网络设备信息、MAC 地址、使用时间、状态报告、扫描细节、报错信息
- 集成到所有关键操作，确保操作可追溯

#### 管理员权限

- `PortSentinel.bat` 启动时自动请求 UAC 权限
- 通过 `IsUserAnAdmin` 检测当前权限状态，权限不足时自动提升

---

## 4. 技术难点与解决方案

### 4.1 pyperclip 依赖问题

- **问题**：pyperclip 未安装导致程序启动崩溃
- **分析**：硬依赖在模块顶层 `import`，缺失即崩溃，影响可用性
- **解决**：移除 pyperclip，改用 Qt 内置 `QApplication.clipboard()`，实现零额外依赖的剪贴板操作

### 4.2 Windows socket.AF_PACKET 兼容性

- **问题**：日志模块在 Windows 上报错 `socket has no attribute 'AF_PACKET'`
- **分析**：`AF_PACKET` 是 Linux 专有常量，Windows 平台不存在
- **解决**：改用地址格式判断 MAC 地址（检查 `:` 或 `-` 分隔符及长度），跨平台兼容

### 4.3 IDE 运行按钮 `&` 符号错误

- **问题**：IDE 在 CMD 终端中使用 PowerShell 的 `&` 调用操作符
- **分析**：`&` 是 PowerShell 专用操作符，CMD 不支持
- **解决**：提供多种启动方式（bat 脚本 / 直接 python 命令），建议用户将 IDE 默认终端改为 PowerShell

### 4.4 多线程扫描与 UI 更新

- **问题**：直接在主线程执行扫描会导致 UI 冻结
- **解决**：使用 `QThread` 包装扫描逻辑，通过 `pyqtSignal` 信号槽机制安全更新 UI，实现扫描与渲染解耦

### 4.5 Windows API 调用

- **问题**：需要获取和关闭 TCP 连接，但 Python 标准库不直接支持
- **解决**：通过 ctypes 调用 iphlpapi.dll 的 `GetExtendedTcpTable` / `GetExtendedUdpTable` / `SetTcpEntry`，定义完整的 C 结构体映射

---

## 5. 目标达成情况

| 目标 | 状态 | 说明 |
|------|------|------|
| 端口扫描并展示状态 | ✅ 完成 | 多线程 TCP 扫描，实时显示开放端口 |
| 自主发现开放端口 | ✅ 完成 | 全范围 1-65535 扫描，实时反馈 |
| 构造识别库检测端口 | ✅ 完成 | 107+ 端口 JSON 数据库，三级风险分类 |
| 识别危害 | ✅ 完成 | 每个端口附带危害描述 |
| 关闭异常连接 | ✅ 完成 | SetTcpEntry DELETE_TCB |
| Windows 底层技术 | ✅ 完成 | iphlpapi.dll via ctypes |
| 多线程提高效率 | ✅ 完成 | ThreadPoolExecutor 1-1000 线程 |
| GUI 参数设置 | ✅ 完成 | PyQt5 界面，可设目标/范围/线程/超时 |
| GitHub 标准化 | ✅ 完成 | README/LICENSE/.gitignore/CHANGELOG |
| 鼠标右键功能 | ✅ 完成 | 两表共 13 项右键功能 |
| 网络安全检测 | ✅ 完成 | 漏洞库+OS 识别+防火墙管理 |
| 操作系统识别 | ✅ 完成 | 端口组合分析，置信度评估 |
| 悬停弹出说明 | ✅ 完成 | QToolTip 显示详细信息 |
| 日志系统 | ✅ 完成 | 完整日志记录，netinfo 格式 |
| 管理员权限 | ✅ 完成 | UAC 自动提升+权限检测 |

**总体达成率：15/15 = 100%**

---

## 6. 技术栈总结

| 技术 | 用途 |
|------|------|
| Python 3.8+ | 开发语言 |
| PyQt5 | GUI 框架 |
| ctypes | Windows API 调用 |
| iphlpapi.dll | TCP/UDP 连接管理 |
| ThreadPoolExecutor | 多线程端口扫描 |
| QThread + pyqtSignal | 后台任务+UI 更新 |
| psutil | 进程信息查询 |
| Python logging | 日志系统 |
| JSON | 端口识别库存储 |
| Qt clipboard | 剪贴板操作 |

---

## 7. 项目文件结构（最终版 v0.08）

```
PortSentinel/
├── main.py                  # 程序入口，sys.path 配置与启动逻辑
├── gui.py                   # PyQt5 主窗口与界面布局
├── gui_helpers.py           # GUI 辅助：右键菜单、悬停提示、对话框
├── port_scanner.py          # 多线程端口扫描引擎
├── connection_manager.py    # Windows API 封装（TCP/UDP 连接管理）
├── port_database.py         # 端口识别库加载与查询接口
├── port_database.json       # 端口识别库数据（107+ 端口）
├── os_fingerprint.py        # 操作系统指纹识别模块
├── vuln_database.py         # 漏洞数据库模块（20+ CVE）
├── app_logger.py            # 日志系统模块
├── requirements.txt         # Python 依赖清单
├── PortSentinel.bat         # UAC 自动提升启动脚本
├── run_port_sentinel.bat    # 备用启动脚本
├── README.md                # 项目说明
├── TECHNICAL_MANUAL.md      # 技术手册
├── USER_GUIDE.md            # 用户指南
├── CHANGELOG.md             # 更新日志
├── LICENSE                  # GPL v3 许可证
├── .gitignore               # Git 忽略规则
└── log/                     # 日志输出目录
    └── netinfo_YYYYMMDD_HHMMSS_主机名.log
```

---

## 8. 未来展望

- **端口 Banner Grabbing**：通过抓取服务 Banner 增强 OS 与服务识别精度
- **实时网络流量监控**：基于流量统计 API 实现可视化带宽监测
- **自动端口封锁策略**：根据风险等级自动触发防火墙规则
- **远程主机扫描支持**：扩展扫描引擎以支持局域网/远程目标
- **插件系统架构**：提供标准插件接口，支持第三方扩展功能模块

---

## 9. 结语

PortSentinel v0.08 完成了从基础端口扫描工具到综合性网络安全审计平台的演进。项目始终坚持「Windows 底层技术 + 零额外依赖 + 标准化开源」三大原则，所有原始需求与增强需求均已 100% 达成。

感谢开源社区与所有关注本项目的开发者，欢迎在 GPL v3 协议下自由使用、修改与分发。

— donoot，2026-08-04
