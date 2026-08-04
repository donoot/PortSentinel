# 更新日志

所有版本的变更记录。

## v0.08 - 2026-08-04

### 新增
- 日志系统模块（app_logger.py）：以 netinfo_YYYYMMDD_HHMMSS_主机名.log 格式保存到 log/ 目录
- 日志记录设备信息（主机名/OS版本/CPU/内存）、网络设备信息（网卡/IP/MAC地址/网络统计）、使用时间、扫描细节、报错信息
- 端口扫描结果右键菜单：查找端口服务项、防火墙开关端口、全网络检索、大模型分析
- 活动连接右键菜单：打开程序目录、查看进程命令及参数、查看进程详情、结束进程、WHOIS查询、IP归属地查询
- 悬停提示功能：鼠标移至表格行显示详细信息
- 操作系统指纹识别模块（os_fingerprint.py）
- 漏洞数据库模块（vuln_database.py）：20+ CVE漏洞，含永恒之蓝/BlueKeep/SMBGhost
- GUI辅助模块（gui_helpers.py）：右键菜单、悬停提示、对话框

### 优化
- 移除 pyperclip 依赖，改用 Qt 内置剪贴板 API（QApplication.clipboard）
- 程序启动入口增加 sys.path 自动配置，确保模块导入正确
- 日志系统集成到所有关键操作：扫描/连接/右键操作/错误处理
- 启动脚本 PortSentinel.bat 优化：自动检测虚拟环境/系统Python

### 修复
- 修复 pyperclip 模块缺失导致程序无法启动的问题
- 修复 Windows 下 socket.AF_PACKET 不存在导致的日志记录错误
- 修复 IDE 运行按钮在 CMD 终端中使用 & 符号报错的问题

### 移除
- 移除 uac_admin.py（未使用的模块）
- 移除 test_modules.py（测试脚本）
- 移除 run.py（临时包装脚本）
- 移除 GUI_INTEGRATION_GUIDE.md、PROJECT_SUMMARY.md（冗余文档）
- 移除 pyperclip 依赖

## v0.06 - 2026-08-04

### 新增
- 多线程 TCP 端口扫描（ThreadPoolExecutor，1-1000线程）
- 端口识别库（107+端口，三级风险分类）
- 活动 TCP/UDP 连接实时监控
- 强制关闭 TCP 连接（SetTcpEntry API）
- CSV 导出功能
- GPL v3 开源许可证
- GitHub 标准项目结构

## v0.04 - 2026-08-04

### 初始版本
- 项目架构设计
- 核心扫描引擎实现
- 基础 GUI 界面
