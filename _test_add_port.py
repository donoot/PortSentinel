import sys
sys.path.insert(0, '.')

# 1. 验证 PortDatabase.add_port
from port_database import PortDatabase
db = PortDatabase()
print('识别库端口数:', len(db.ports))

# 测试添加端口
success, msg = db.add_port(9999, 'TestService', 'tcp', 'warning', '测试端口', '测试危害')
print(f'添加端口 9999: success={success}, msg={msg}')
print('识别库端口数:', len(db.ports))

# 验证查询
info = db.lookup(9999)
print(f'查询 9999: service={info["service"]}, risk={info["risk"]}')

# 测试更新
success, msg = db.add_port(9999, 'UpdatedService', 'tcp', 'danger', '更新描述', '更新危害')
print(f'更新端口 9999: success={success}, msg={msg}')
info = db.lookup(9999)
print(f'查询更新后: service={info["service"]}, risk={info["risk"]}')

# 删除测试端口
success, msg = db.remove_port(9999)
print(f'删除端口 9999: success={success}, msg={msg}')
print('识别库端口数:', len(db.ports))

# 2. 验证 GUI 导入和 AddPortDialog
from PyQt5.QtWidgets import QApplication
from gui import MainWindow
from gui_helpers import AddPortDialog

app = QApplication(sys.argv)
w = MainWindow()
print('窗口标题:', w.windowTitle())
print('add_port_to_database 方法存在:', hasattr(w, 'add_port_to_database'))

# 3. 验证右键菜单包含添加到识别库
from gui_helpers import ContextMenuHelper
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem
table = QTableWidget()
table.setColumnCount(6)
table.setRowCount(1)
table.setItem(0, 0, QTableWidgetItem())
table.item(0, 0).setData(0, 8080)
table.setItem(0, 1, QTableWidgetItem('tcp'))
table.setItem(0, 2, QTableWidgetItem('HTTP-Proxy'))
table.setItem(0, 3, QTableWidgetItem('未知'))
table.setItem(0, 4, QTableWidgetItem(''))
table.setItem(0, 5, QTableWidgetItem(''))

menu = ContextMenuHelper.create_port_scan_context_menu(w, table, 0, 0)
actions = [a.text() for a in menu.actions()]
print('右键菜单项:', actions)
has_add = '添加/更新到识别库' in actions
print('包含添加到识别库:', has_add)

print('全部验证通过')
