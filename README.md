# PortSentinel

> Windows 网络端口扫描与安全监控工具

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![PyQt5](https://img.shields.io/badge/PyQt5-5.15+-green.svg)](https://www.riverbankcomputing.com/software/pyqt/)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-v0.08-orange.svg)](CHANGELOG.md)
[![CVE](https://img.shields.io/badge/Vuln%20DB-20%2B-red.svg)](vuln_database.py)
[![Ports](https://img.shields.io/badge/Port%20DB-107%2B-brightgreen.svg)](port_database.json)

PortSentinel 是一款基于 Windows 底层 API 的本机网络端口扫描与安全监控工具。它能够自主发现开放端口，通过内置识别库检测端口服务的合法性、风险等级与潜在危害，结合操作系统指纹识别与漏洞数据库进行深度安全评估，并支持强制关闭异常 TCP 连接。采用多线程技术提升扫描效率，提供直观的 PyQt5 图形界面，内置完整的日志系统记录设备与网络状态。

- **作者**：donoot
- **版本**：v0.08
- **日期**：2026-08-04
- **许可证**：GPL v3

---

## 目录

- [功能特性](#功能特性)
- [技术架构](#技术架构)
- [项目结构](#项目结构)
- [环境要求](#环境要求)
- [安装](#安装)
- [使用方法](#使用方法)
- [右键菜单功能](#右键菜单功能)
- [端口识别库](#端口识别库)
- [漏洞数据库](#漏洞数据库)
- [日志系统](#日志系统)
- [技术栈](#技术栈)
- [常见问题](#常见问题)
- [贡献](#贡献)
- [版本历史](#版本历史)
- [许可证](#许可证)

---

## 功能特性

### 1. 多线程 TCP 端口扫描

基于 `concurrent.futures.ThreadPoolExecutor` 实现高效并发扫描。

- **线程可配置**：1-1000 线程并发，根据机器性能自由调整
- **两种扫描模式**：
  - 🔍 **全范围扫描**：覆盖 1-65535 全端口
  - ⚡ **快速扫描模式**：仅扫描识别库中已知端口，秒级完成安全检查
- **实时进度反馈**：扫描进度条实时更新，发现开放端口即刻显示
- **可取消操作**：扫描过程中支持随时取消
- **超时可配置**：自定义 socket 连接超时时间，适应不同网络环境

### 2. 端口识别库

内置 **107+ 常见端口识别库**（`port_database.json`），可热加载扩展。

- **三级风险分类**：
  - 🟢 **正常 (safe)**：如 HTTP(80)、HTTPS(443)、SSH(22) 等标准服务
  - 🟡 **警告 (warning)**：如 FTP(21)、SNMP(161) 等需注意配置的服务
  - 🔴 **危险 (danger)**：如 Telnet(23)、SMB(445)、RDP(3389)、Redis(6379) 等高风险端口
- **危害详情**：每个端口附带具体的安全风险描述和攻击场景说明
- **高危端口告警**：扫描完成后自动弹窗提示危险端口数量

### 3. 操作系统指纹识别

通过开放端口组合推断目标操作系统类型（`os_fingerprint.py`）。

- **端口特征匹配**：基于常见 OS 默认开放端口组合推断
- **置信度评估**：输出识别置信度，便于人工判断
- **多系统支持**：识别 Windows / Linux / macOS / 网络设备等

### 4. 漏洞风险评估

内置 **20+ CVE 漏洞数据库**（`vuln_database.py`），自动匹配开放端口对应漏洞。

- **知名漏洞覆盖**：
  - 🔴 **永恒之蓝** (MS17-010 / CVE-2017-0144) — SMB 端口 445
  - 🔴 **BlueKeep** (CVE-2019-0708) — RDP 端口 3389
  - 🔴 **SMBGhost** (CVE-2020-0796) — SMBv3 端口 445
  - 及更多高危 CVE 漏洞
- **自动匹配**：扫描结束后自动关联端口与漏洞条目
- **可视化提示**：漏洞信息通过右键菜单「查看漏洞」查看

### 5. 活动连接实时监控

- **实时连接列表**：获取本机所有 TCP/UDP 连接（含 PID 和进程名）
- **连接状态展示**：ESTABLISHED、LISTEN、TIME_WAIT 等状态彩色标注
- **进程关联**：每个连接关联到具体进程，便于追踪
- **自动刷新**：支持定时刷新保持连接列表最新

### 6. 强制关闭 TCP 连接

通过 Windows API `SetTcpEntry` 实现底层连接关闭。

- **底层 API 调用**：将连接状态设为 `DELETE_TCB` 强制移除
- **批量操作**：支持选中多个连接一次性关闭
- **权限检测**：自动检测管理员权限并提示（需管理员权限）

### 7. GUI 右键菜单功能

丰富的右键上下文菜单，覆盖日常安全运维需求（详见 [右键菜单功能](#右键菜单功能)）。

### 8. 悬停提示

鼠标移至表格行时自动显示详细信息提示框，无需点击即可查看完整内容，避免长文本截断。

### 9. 日志系统

完整的日志记录机制（`app_logger.py`）。

- **文件命名**：`netinfo_时间_主机名.log`
- **记录内容**：
  - 设备信息（主机名、系统版本等）
  - 网络信息（IP、MAC 地址）
  - 扫描细节（开放端口、识别结果）
  - 报错信息（异常堆栈、API 调用失败）
- **自动归档**：日志文件统一存放在 `log/` 目录

### 10. CSV 导出

扫描结果可导出为 CSV 文件，包含端口、协议、服务、风险等级、描述、危害等全部字段，便于后续分析或归档。

### 11. 高危端口告警

扫描完成后自动统计危险端口数量并弹窗告警，确保高风险端口不被忽略。

---

## 技术架构

```
┌─────────────────────────────────────────────────────────────┐
│                       GUI 层 (PyQt5)                         │
│  ┌───────────┐  ┌───────────┐  ┌─────────────┐              │
│  │ 参数设置   │  │ 扫描结果   │  │ 活动连接     │              │
│  │ Panel     │  │ TableView │  │ TableView   │              │
│  └─────┬─────┘  └─────▲─────┘  └──────▲──────┘              │
│        │              │               │                      │
│        ▼              │               │                      │
│  ┌───────────┐  ┌─────┴─────┐  ┌──────┴──────┐               │
│  │ ScanWorker│  │ConnWorker │  │ 右键菜单/    │              │
│  │ (QThread) │  │ (QThread) │  │ 悬停提示     │              │
│  └─────┬─────┘  └─────┬─────┘  └──────┬──────┘               │
│        │  信号槽机制    │               │                     │
└────────┼──────────────┼───────────────┼──────────────────────┘
         │              │               │
┌────────▼──────────────▼───────────────▼──────────────────────┐
│                          核心层                               │
│  ┌──────────────┐  ┌──────────────────┐  ┌────────────────┐  │
│  │ PortScanner  │  │ConnectionManager │  │  OsFingerprint │  │
│  │ (多线程扫描) │  │ (Win API 封装)   │  │  (OS 指纹识别) │  │
│  └──────────────┘  └──────────────────┘  └────────────────┘  │
│  ┌──────────────┐  ┌──────────────────┐                      │
│  │ PortDatabase │  │  VulnDatabase    │                      │
│  │ (识别库查询) │  │  (漏洞库匹配)    │                      │
│  └──────┬───────┘  └──────────────────┘                      │
└─────────┼────────────────────────────────────────────────────┘
          │
┌─────────▼───────────┐     ┌────────────────────────────────┐
│  Python socket      │     │     Windows iphlpapi.dll       │
│  (TCP connect 扫描) │     │  GetExtendedTcpTable            │
│                     │     │  GetExtendedUdpTable            │
│                     │     │  SetTcpEntry (DELETE_TCB)       │
└─────────────────────┘     └────────────────────────────────┘
          │
┌─────────▼───────────────────────────────────────────────────┐
│                      数据层 (JSON)                           │
│   port_database.json (107+ 端口)   vuln_database (20+ CVE)   │
└──────────────────────────────────────────────────────────────┘
```

### 使用的 Windows 底层技术

| API                   | 功能          | 说明                                                |
| --------------------- | ------------- | --------------------------------------------------- |
| `GetExtendedTcpTable` | 获取 TCP 连接 | 返回所有 TCP 连接表，含本地/远程地址端口、状态、PID |
| `GetExtendedUdpTable` | 获取 UDP 监听 | 返回所有 UDP 监听端点，含地址端口、PID              |
| `SetTcpEntry`         | 关闭 TCP 连接 | 将指定 TCP 连接状态设为 `DELETE_TCB` 实现强制关闭   |
| `IsUserAnAdmin`       | 权限检测      | 检测当前进程是否以管理员身份运行                    |

所有 API 通过 Python `ctypes` 直接调用，无需第三方网络库。

---

## 项目结构

```
PortSentinel/
├── main.py                  # 程序入口，管理员权限检测，日志系统初始化
├── gui.py                   # PyQt5 GUI 界面（QThread + 信号槽 + 右键菜单）
├── port_scanner.py          # 多线程端口扫描模块（ThreadPoolExecutor）
├── connection_manager.py    # Windows 底层连接管理（iphlpapi.dll via ctypes）
├── port_database.py         # 端口识别库管理模块
├── port_database.json       # 端口识别数据库（107+ 端口）
├── os_fingerprint.py        # 操作系统指纹识别模块
├── vuln_database.py         # 漏洞数据库模块（20+ CVE漏洞）
├── gui_helpers.py           # GUI辅助功能（右键菜单、悬停提示、对话框）
├── app_logger.py            # 日志系统模块
├── PortSentinel.bat         # 一键启动脚本（自动请求UAC权限）
├── requirements.txt         # Python 依赖
├── README.md                # 项目说明文档
├── CHANGELOG.md             # 版本更新记录
├── TECHNICAL_MANUAL.md      # 技术手册
├── DEVELOPMENT_SUMMARY.md   # 开发过程总结
├── LICENSE                  # GPL v3 开源许可证
└── .gitignore               # Git 忽略规则
```

---

## 环境要求

- **操作系统**：Windows 7 及以上
- **Python**：3.8 及以上
- **依赖库**：
  - PyQt5 >= 5.15（GUI 界面）
  - psutil >= 5.9（进程信息查询）
  - requests >= 2.28（网络查询功能，如 IP 归属地、WHOIS）

---

## 安装

### 1. 克隆仓库

```bash
git clone https://github.com/donoot/PortSentinel.git
cd PortSentinel
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

> 建议使用虚拟环境隔离依赖：`python -m venv venv && venv\Scripts\activate`

---

## 使用方法

### 方式一：一键启动脚本（推荐）

双击 `PortSentinel.bat`，脚本会自动请求 UAC 管理员权限并启动程序：

```bat
PortSentinel.bat
```

### 方式二：命令行运行

#### 普通模式

```bash
python main.py
```

此模式下可使用端口扫描和连接查看功能，但「关闭 TCP 连接」功能受限。

#### 管理员模式（推荐）

以管理员身份运行可额外使用 **关闭 TCP 连接** 功能：

- 右键 `main.py` → 以管理员身份运行
- 或在管理员 PowerShell 中执行：

```powershell
python main.py
```

### 界面操作指南

1. **设置参数**：在顶部参数栏设置扫描目标、端口范围、线程数、超时时间
2. **开始扫描**：点击「开始扫描」进行全范围扫描，或「仅扫描已知端口」进行快速安全检查
3. **查看结果**：在「端口扫描结果」标签页查看开放端口及其风险等级
4. **悬停查看**：鼠标移至表格行显示详细信息提示
5. **右键操作**：在结果行上右键，调用右键菜单功能（详见下节）
6. **监控连接**：切换到「活动连接」标签页查看当前所有网络连接
7. **关闭连接**：选中异常 TCP 连接后点击「关闭选中TCP连接」
8. **导出数据**：点击「导出结果」将扫描结果保存为 CSV 文件

---

## 右键菜单功能

PortSentinel 提供丰富的上下文右键菜单，按场景分为两类。

### 活动连接表（右键菜单）

| 菜单项               | 功能说明                                 |
| -------------------- | ---------------------------------------- |
| 🔌 关闭连接           | 强制关闭选中的 TCP 连接（SetTcpEntry）   |
| 📁 打开程序目录       | 在资源管理器中定位进程可执行文件所在目录 |
| 💻 查看进程命令及参数 | 显示进程启动命令行及参数                 |
| 📋 查看进程详情       | 显示进程 PID、路径、父进程等详细信息     |
| ❌ 结束进程           | 终止指定进程（需管理员权限）             |
| 🌐 WHOIS 查询         | 在线查询远端 IP 的 WHOIS 注册信息        |
| 📍 IP 归属地查询      | 查询远端 IP 的地理位置与运营商           |

### 端口扫描表（本机，右键菜单）

| 菜单项           | 功能说明                             |
| ---------------- | ------------------------------------ |
| 🔎 查找端口服务项 | 在端口识别库中定位该端口条目         |
| 🛡️ 防火墙开关端口 | 调用 Windows 防火墙规则开启/关闭端口 |
| 🐞 查看漏洞       | 显示该端口关联的 CVE 漏洞详情        |
| 🔗 全网络检索     | 在浏览器中检索该端口服务信息         |
| 📌 CVE 搜索       | 在 CVE 数据库中检索相关漏洞          |
| 🤖 大模型分析     | 调用大模型对该端口进行安全分析       |

---

## 端口识别库

端口识别数据库位于 `port_database.json`，采用 JSON 格式，结构清晰，易于扩展：

```json
{
  "ports": {
    "445": {
      "service": "SMB",
      "protocol": "tcp",
      "risk": "danger",
      "description": "Windows文件共享",
      "hazard": "勒索病毒(WannaCry)主要传播通道，永恒之蓝(MS17-010)利用此端口"
    }
  },
  "risk_levels": {
    "safe":    { "label": "正常", "color": "#27ae60" },
    "warning": { "label": "警告", "color": "#f39c12" },
    "danger":  { "label": "危险", "color": "#e74c3c" },
    "unknown": { "label": "未知", "color": "#95a5a6" }
  }
}
```

可通过菜单「工具」→「重新加载端口识别库」在运行时热加载更新后的数据库。

---

## 漏洞数据库

漏洞数据库（`vuln_database.py`）内置 20+ 知名 CVE 漏洞条目，覆盖近年来影响最广的 Windows 网络服务漏洞：

| 漏洞名称               | CVE 编号      | 影响端口    | 风险等级 |
| ---------------------- | ------------- | ----------- | -------- |
| 永恒之蓝 (EternalBlue) | CVE-2017-0144 | 445 (SMB)   | 🔴 严重   |
| BlueKeep               | CVE-2019-0708 | 3389 (RDP)  | 🔴 严重   |
| SMBGhost               | CVE-2020-0796 | 445 (SMBv3) | 🔴 严重   |
| ...                    | ...           | ...         | ...      |

扫描完成后，系统自动将开放端口与漏洞库匹配，可通过右键菜单「查看漏洞」查看详情。

---

## 日志系统

PortSentinel 内置完整日志系统（`app_logger.py`），自动记录运行全过程。

- **日志位置**：`log/` 目录
- **命名格式**：`netinfo_YYYYMMDD_HHMMSS_主机名.log`
- **记录内容**：

| 类别     | 内容                                   |
| -------- | -------------------------------------- |
| 设备信息 | 主机名、操作系统版本、CPU 架构         |
| 网络信息 | 本机 IP、MAC 地址、网卡列表            |
| 扫描细节 | 扫描参数、开放端口、识别结果、风险等级 |
| 报错信息 | API 调用失败、异常堆栈、用户操作错误   |
| 运行状态 | 程序启动、权限检测、事件循环、退出码   |

日志文件可用于事后审计、问题排查和安全事件追溯。

---

## 技术栈

| 组件        | 技术                  | 用途                         |
| ----------- | --------------------- | ---------------------------- |
| GUI 框架    | PyQt5 >= 5.15         | 窗口界面、表格展示、事件处理 |
| 多线程扫描  | ThreadPoolExecutor    | 1-1000 线程并发端口扫描      |
| UI 异步     | QThread + 信号槽      | 后台扫描不阻塞 UI            |
| Windows API | ctypes + iphlpapi.dll | 连接获取与关闭               |
| 进程信息    | psutil >= 5.9         | PID 到进程名映射             |
| 端口扫描    | Python socket         | TCP connect 扫描             |
| 数据格式    | JSON                  | 端口识别库与漏洞库存储       |
| 剪贴板      | Qt 内置剪贴板         | 替代 pyperclip，减少依赖     |
| 网络查询    | requests >= 2.28      | IP 归属地、WHOIS 等在线查询  |

---

## 常见问题

### Q1：关闭 TCP 连接功能不可用？

「关闭 TCP 连接」依赖 `SetTcpEntry` API，需要管理员权限。请使用 `PortSentinel.bat` 启动或以管理员身份运行 `main.py`。

### Q2：扫描速度慢？

- 适当增加线程数（建议 100-500）
- 降低 socket 超时时间（建议 0.5-1 秒）
- 使用「仅扫描已知端口」快速模式

### Q3：扫描时程序卡顿？

扫描任务运行在 QThread 中，理论上不会阻塞 UI。若仍卡顿，请降低线程数以减少系统资源占用。

### Q4：如何更新端口识别库？

直接编辑 `port_database.json`，然后在程序中通过「工具」→「重新加载端口识别库」热加载，无需重启。

### Q5：日志文件在哪里？

日志文件位于程序目录下的 `log/` 子目录，文件名格式为 `netinfo_时间_主机名.log`。

---

## 贡献

欢迎提交 Issue 和 Pull Request。

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

---

## 版本历史

详见 [CHANGELOG.md](CHANGELOG.md)。

技术细节请参考 [TECHNICAL_MANUAL.md](TECHNICAL_MANUAL.md)，开发过程详见 [DEVELOPMENT_SUMMARY.md](DEVELOPMENT_SUMMARY.md)。

---

## 许可证

本项目基于 [GNU General Public License v3](LICENSE) 开源。

---

## 作者

**donoot**

- GitHub: [@donoot](https://github.com/donoot)

---

*最后更新: 2026-08-04 · v0.08*
