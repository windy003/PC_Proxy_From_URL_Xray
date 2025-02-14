import base64
import sys
import json
import requests
import subprocess
import os
from urllib.parse import unquote, urlparse, parse_qs
from PyQt5.QtWidgets import (QApplication, QSystemTrayIcon, QMenu, QWidget, 
                           QTextBrowser, QLineEdit, QPushButton, QComboBox,
                           QLabel, QVBoxLayout, QHBoxLayout, QMessageBox,
                           QStyle, QGroupBox)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
import threading
import time
import socket
import urllib3
from PyQt5.QtWidgets import QShortcut
from PyQt5.QtGui import QKeySequence
import winreg
import ctypes

class FetchThread(QThread):
    finished = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, url, max_retries=3):
        super().__init__()
        self.url = url
        self.max_retries = max_retries
        self.nodes = []
        self._is_running = True

    def stop(self):
        self._is_running = False

    def get_node_location(self, ip):
        # 直接返回未知位置，不进行网络请求
        return "未知位置"
        # 如果��要查询位置，可方式或缓存机制

    def parse_nodes(self, content):
        """解析节点信息"""
        try:
            nodes = []
            lines = content.splitlines()
            
            for line in lines:
                try:
                    if line.startswith('trojan://'):
                        # 解析trojan链接
                        # 格式: trojan://password@host:port?sni=xxx#remark
                        uri = line[9:]  # 去掉 'trojan://'
                        if '#' in uri:
                            uri, remark = uri.split('#', 1)
                            remark = unquote(remark)  # URL解码
                        else:
                            remark = '未命名节点'
                            
                        if '@' in uri:
                            password, address = uri.split('@', 1)
                            if '?' in address:
                                host_port, params = address.split('?', 1)
                            else:
                                host_port = address
                                params = ''
                                
                            if ':' in host_port:
                                host, port = host_port.split(':', 1)
                                
                                # 解sni参数
                                sni = 'baidu.com'  # 默认值
                                if 'sni=' in params:
                                    for param in params.split('&'):
                                        if param.startswith('sni='):
                                            sni = param[4:]
                                            break
                                
                                nodes.append({
                                    'host': host,
                                    'port': port,
                                    'password': password,
                                    'remark': remark,
                                    'sni': sni
                                })
                                
                    elif line.startswith('vmess://'):
                        # 保留原有的vmess解析逻辑
                        vmess_data = base64.b64decode(line[8:]).decode('utf-8')
                        node = json.loads(vmess_data)
                        nodes.append({
                            'host': node.get('add', ''),
                            'port': str(node.get('port', '')),
                            'password': node.get('id', ''),
                            'remark': node.get('ps', '未命名节点'),
                            'sni': node.get('sni', 'baidu.com')
                        })
                        
                except Exception as e:
                    print(f"解析节点失败: {e}, 链接: {line[:30]}...")  # 只打印前30个字符
                    continue
            
            print(f"成功解析 {len(nodes)} 个节点")  # 调试信息
            return nodes
            
        except Exception as e:
            print(f"解析节点时出错: {e}")
            return []

    def run(self):
        try:
            # 禁用 SSL 警告
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # 设置请求头
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # 添加重试机制
            for attempt in range(self.max_retries):
                try:
                    # 发送请求时headers
                    response = requests.get(
                        self.url, 
                        headers=headers,
                        verify=False, 
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        # 解析订阅内容
                        content = response.text.strip()
                        if content:
                            try:
                                decoded_content = base64.b64decode(content).decode('utf-8')
                                self.nodes = self.parse_nodes(decoded_content)
                                if self.nodes:
                                    self.finished.emit("节点获取成功")
                                    return
                            except Exception as e:
                                self.progress.emit(f"解析内容失败: {str(e)}")
                        
                        if attempt < self.max_retries - 1:
                            self.progress.emit(f"未获取到有效节点，正在重试... ({attempt + 1}/{self.max_retries})")
                            time.sleep(2)
                            continue
                        else:
                            self.finished.emit("未能获取到效点")
                    else:
                        if attempt < self.max_retries - 1:
                            self.progress.emit(f"请求失败，状态码: {response.status_code}，正在重试... ({attempt + 1}/{self.max_retries})")
                            time.sleep(2)
                            continue
                        else:
                            self.finished.emit(f"请求失败，状态码: {response.status_code}")
                            
                except requests.exceptions.RequestException as e:
                    if attempt < self.max_retries - 1:
                        self.progress.emit(f"网络请求错误: {str(e)}，正在重试... ({attempt + 1}/{self.max_retries})")
                        time.sleep(2)
                        continue
                    else:
                        self.finished.emit(f"网络请求错误: {str(e)}")
                        
        except Exception as e:
            self.finished.emit(f"发生错误: {str(e)}")

class ProxyThread(QThread):
    status_update = pyqtSignal(str)

    def __init__(self, server, port, password, sni=None):
        super().__init__()
        self.server = server
        self.port = port
        self.password = password
        self.sni = sni
        self._is_running = True
        self.process = None
        
        # 初始化配置目录
        self.app_data_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'ProxyByUrl')
        if not os.path.exists(self.app_data_dir):
            os.makedirs(self.app_data_dir)

    def run(self):
        try:
            if not self._is_running:
                return

            self.status_update.emit("开始配置代理服务...")
            
            # 获取正确的xray路径
            if getattr(sys, 'frozen', False):
                # 如果是打包后的exe运行
                base_path = sys._MEIPASS
            else:
                # 如果是直接运行python脚本
                base_path = os.path.dirname(os.path.abspath(__file__))
                
            xray_path = os.path.join(base_path, 'xray.exe')
            
            if not os.path.exists(xray_path):
                self.status_update.emit("错误: 找不到xray.exe，请确保xray.exe与程序在同一目录")
                return
            
            # 使用用户目录的xray配置文件
            config_path = os.path.join(self.app_data_dir, 'xray_config.json')
            
            # Xray 配置
            config = {
                "inbounds": [
                    {
                        "port": 10808,
                        "protocol": "socks",
                        "settings": {
                            "udp": True
                        }
                    },
                    {
                        "port": 10809,
                        "protocol": "http"
                    }
                ],
                "outbounds": [
                    {
                        "protocol": "trojan",
                        "settings": {
                            "servers": [
                                {
                                    "address": self.server,
                                    "port": int(self.port),
                                    "password": self.password
                                }
                            ]
                        },
                        "streamSettings": {
                            "network": "tcp",
                            "security": "tls",
                            "tlsSettings": {
                                "allowInsecure": True,
                                "serverName": self.sni if self.sni else self.server
                            }
                        }
                    }
                ],
                "log": {
                    "loglevel": "info"
                }
            }
            
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            
            self.status_update.emit("配置文件已生成")

            try:
                self.status_update.emit("正在启动Xray进程...")
                self.process = subprocess.Popen(
                    [xray_path, "run", "-c", config_path],  # 使用新的配置路径
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # 添加实时日志读取
                def log_reader(pipe, is_error=False):
                    while self._is_running:
                        line = pipe.readline()
                        if not line:
                            break
                        try:
                            decoded_line = line.decode('utf-8').strip()
                            if decoded_line:
                                prefix = "[警告]" if is_error else "[信息]"
                                self.status_update.emit(f"{prefix} {decoded_line}")
                        except Exception as e:
                            self.status_update.emit(f"[日志解码错误] {str(e)}")

                stdout_thread = threading.Thread(target=log_reader, args=(self.process.stdout,))
                stderr_thread = threading.Thread(target=log_reader, args=(self.process.stderr, True))
                stdout_thread.daemon = True
                stderr_thread.daemon = True
                stdout_thread.start()
                stderr_thread.start()

                self.status_update.emit("代理服务已启动，正在等待连接...")
                
                while self._is_running:
                    if self.process.poll() is not None:
                        self.status_update.emit(f"Xray进程意外退出，退出码：{self.process.poll()}")
                        break
                    time.sleep(1)

            except Exception as e:
                self.status_update.emit(f"启动代理服务失败: {str(e)}")
                if self.process:
                    self.process.terminate()

        except Exception as e:
            self.status_update.emit(f"代理线程错误: {str(e)}")

    def stop(self):
        self._is_running = False
        if self.process:
            try:
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(self.process.pid)], 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE)
            except Exception as e:
                print(f"停止进程时出错: {e}")
            self.process = None
            
        try:
            subprocess.run(['taskkill', '/F', '/IM', 'xray.exe'], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE)
        except Exception as e:
            print(f"清理残留程时出错: {e}")

class TrojanUrlViewer(QWidget):
    def __init__(self):
        super().__init__()
        # 基本属性初始化
        self.fetch_thread = None
        self.proxy_thread = None
        self.nodes = []
        self.auto_start = False  # 移到最前面初始化
        
        # 配置目录初始化
        self.app_data_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'ProxyByUrl')
        if not os.path.exists(self.app_data_dir):
            os.makedirs(self.app_data_dir)
        
        # 配置文件路径
        self.app_config_file = os.path.join(self.app_data_dir, 'app_config.json')
        print(f"应用配置文件路径: {self.app_config_file}")
        
        # 初始化顺序
        self.initUI()                  
        self.setup_autostart()         
        self.setupSystemTray()         
        self.setup_firewall_rules()    
        self.load_saved_config()       
        
        # 默认隐藏窗口
        self.hide()  # 添加这行
        
        # 如果有节点则自动连接
        if self.nodes:
            QTimer.singleShot(1000, self.auto_connect)

        # 获取资源文件路径
        if getattr(sys, 'frozen', False):
            application_path = sys._MEIPASS
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
            
        # 图标文件路径
        icon_path = os.path.join(application_path, 'icon.png')
        
        # 创建图标对象
        app_icon = QIcon(icon_path)
        
        # 设置窗口图标
        self.setWindowIcon(app_icon)
        
        # 设置系统托盘图标
        self.tray_icon.setIcon(app_icon)
        
        # 设置应用程序图标
        app = QApplication.instance()
        if app is not None:
            app.setWindowIcon(app_icon)

    def load_saved_config(self):
        try:
            if os.path.exists(self.app_config_file):
                with open(self.app_config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    print("加载的应用配置文件内容:", config)
                    
                    # 恢复所有点信息
                    if 'all_nodes' in config and config['all_nodes']:
                        print("找到已保存的所有节点��息")
                        self.nodes = config['all_nodes']
                        self.node_combo.clear()
                        for node in self.nodes:
                            self.node_combo.addItem(f"{node['remark']}")
                        
                        # 设置上次选择的节点
                        if 'last_node_index' in config:
                            last_index = config['last_node_index']
                            if 0 <= last_index < len(self.nodes):
                                self.node_combo.setCurrentIndex(last_index)

        except Exception as e:
            print(f"加载应用配置时出错: {e}")

    def clear_invalid_config(self):
        """清除无效的配置"""
        try:
            # 不要立即删除配置文件，而是保留最后一次的有效配置
            self.browser.setText("获取新节点列表失败，使用上次的配置")
            # 如果有保存的节点，继续使用
            if hasattr(self, 'nodes') and self.nodes:
                return
            
            # 只有在完全没有节点的情况下才清除配置
            if os.path.exists(self.app_config_file):
                os.remove(self.app_config_file)
            self.input_box.clear()
            self.node_combo.clear()
            self.browser.setText("请输入新的订阅链接")
            
        except Exception as e:
            print(f"清除应用配置时出错: {e}")

    def save_config(self, save_url=True):
        try:
            current_index = self.node_combo.currentIndex()
            if current_index >= 0 and self.nodes and current_index < len(self.nodes):
                if not os.path.exists(self.app_data_dir):
                    os.makedirs(self.app_data_dir)

                selected_node = self.nodes[current_index]
                config = {
                    'last_node_index': current_index,
                    'last_node_info': selected_node,
                    'all_nodes': self.nodes,
                    'auto_connect': True
                }
                
                if save_url:
                    config['last_url'] = self.input_box.text()
                
                # 使用临时文件确保安全写入
                temp_file = self.app_config_file + '.tmp'
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                
                if os.path.exists(temp_file):
                    if os.path.exists(self.app_config_file):
                        os.remove(self.app_config_file)
                    os.rename(temp_file, self.app_config_file)
                    print(f"配置已成功保存到: {self.app_config_file}")
        except Exception as e:
            print(f"保存应用配置时出错: {e}")

    def closeEvent(self, event):
        """重写关闭事件"""
        # 点击关闭按钮时只最小化到托盘
        event.ignore()  # 略关闭事件
        self.hide()     # 隐藏窗口
        self.tray_icon.showMessage(
            '提示',
            '程序已最小化到系统托盘，双击图标可以重新打开窗口',
            QSystemTrayIcon.Information,
            2000
        )

    def on_parse_click(self):
        try:
            url = self.input_box.text().strip()
            if not url:
                self.browser.setText('请输入URL')
                return
                
            if not url.startswith(('http://', 'https://')):
                self.browser.setText("请输入有效的HTTP/HTTPS URL")
                return
            
            # 如果有正在运行的线程，先停止它
            if self.fetch_thread and self.fetch_thread.isRunning():
                self.fetch_thread.stop()
                self.fetch_thread.wait()
            
            # 禁用按钮
            self.parse_button.setEnabled(False)
            self.browser.setText("正在获取节点信息...")
            
            # 创建新线程，添加重试机制
            self.fetch_thread = FetchThread(url, max_retries=3)  # 最多重试3次
            self.fetch_thread.finished.connect(self.on_fetch_finished)
            self.fetch_thread.progress.connect(self.on_fetch_progress)
            self.fetch_thread.start()
            
        except Exception as e:
            self.browser.setText(f"发生错误: {str(e)}")
            self.parse_button.setEnabled(True)

    def on_fetch_finished(self, result):
        try:
            self.browser.setText(result)
            self.parse_button.setEnabled(True)
            
            # 更新节点下拉框
            if hasattr(self.fetch_thread, 'nodes') and self.fetch_thread.nodes:
                self.nodes = self.fetch_thread.nodes
                print(f"成功获取到 {len(self.nodes)} 个节点")
                self.node_combo.clear()
                for node in self.nodes:
                    self.node_combo.addItem(f"{node['remark']}")
                
                # 清空URL输入框
                self.input_box.clear()
                
                # 保存配置但不保存URL
                self.save_config(save_url=False)  # 需要修改save_config方法接受参数
                
            else:
                print("���获取到新节点，保留现有节点")
                if not self.nodes:
                    self.nodes = []
                    self.node_combo.clear()
                    self.browser.setText("获取节点失败，请检查订阅链接是否有效")
                
        except Exception as e:
            print(f"处理结果时发生错误: {str(e)}")
        finally:
            self.parse_button.setEnabled(True)

    def on_fetch_progress(self, message):
        try:
            self.browser.append(message)
        except Exception as e:
            print(f"更新进度时发生错误: {str(e)}")

    def initUI(self):
        self.setWindowTitle('ProxyByUrl')
        # 移除全屏显示
        # self.showFullScreen()  # 删除这行
        
        # 设置窗口大小和位置
        desktop = QApplication.desktop()
        screen_rect = desktop.screenGeometry()
        window_width = int(screen_rect.width() * 0.8)  # 窗口宽度为幕的80%
        window_height = int(screen_rect.height() * 0.8)  # 窗口高度为屏幕的80%
        
        # 计算窗口位置，使其居中示
        x = (screen_rect.width() - window_width) // 2
        y = (screen_rect.height() - window_height) // 2
        
        # 设置窗口大小和位置
        self.setGeometry(x, y, window_width, window_height)
        
        # 使用垂直布局
        layout = QVBoxLayout()
        
        # URL输入区域
        url_layout = QHBoxLayout()
        self.input_box = QLineEdit()
        self.input_box.setPlaceholderText('请输入订阅URL...')
        self.input_box.returnPressed.connect(self.on_parse_click)
        
        # 使用 QShortcut 为输入框添加 Alt+D 快捷键
        shortcut = QShortcut(QKeySequence("Alt+D"), self)
        shortcut.activated.connect(lambda: self.input_box.setFocus())
        
        self.parse_button = QPushButton('获取节点(&G)')  # 添加Alt+G快捷键
        self.parse_button.clicked.connect(self.on_parse_click)
        url_layout.addWidget(self.input_box)
        url_layout.addWidget(self.parse_button)
        layout.addLayout(url_layout)
        
        # 节点选择区域
        node_layout = QHBoxLayout()
        node_label = QLabel('节点选择(&N)：')  # 添加带快捷键的标签
        self.node_combo = QComboBox()
        self.node_combo.setMinimumWidth(200)
        self.node_combo.currentIndexChanged.connect(self.on_node_changed)
        node_label.setBuddy(self.node_combo)  # 将标签与下拉框关联
        node_layout.addWidget(node_label)
        node_layout.addWidget(self.node_combo)
        layout.addLayout(node_layout)
        
        # 代理控制按���
        proxy_layout = QHBoxLayout()
        self.start_button = QPushButton('启动代理(&S)')  # 添加Alt+S快捷键
        self.stop_button = QPushButton('停止代理(&T)')   # 加Alt+T快捷键
        self.start_button.clicked.connect(self.start_proxy)
        self.stop_button.clicked.connect(self.stop_proxy)
        self.stop_button.setEnabled(False)
        proxy_layout.addWidget(self.start_button)
        proxy_layout.addWidget(self.stop_button)
        layout.addLayout(proxy_layout)
        
        # 状态显示区域 (移到按钮下方)
        status_group = QGroupBox("代理状态")
        status_layout = QVBoxLayout()
        self.status_label = QLabel('代理状态：未运行')
        self.status_browser = QTextBrowser()
        self.status_browser.setMaximumHeight(150)
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.status_browser)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # 节点信息显示区域
        self.browser = QTextBrowser()
        layout.addWidget(self.browser)
        
        self.setLayout(layout)

    def setupSystemTray(self):
        # 获取资源文件路径
        if getattr(sys, 'frozen', False):
            # 如果是打包后的exe
            application_path = sys._MEIPASS
        else:
            # 如果是直接运行python脚本
            application_path = os.path.dirname(os.path.abspath(__file__))
            
        # 图标文路径
        icon_path = os.path.join(application_path, 'icon.png')
        
        # 创建系统托盘图标
        self.tray_icon = QSystemTrayIcon(self)
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        else:
            print(f"找不到图标文件: {icon_path}")
        
        # 创建托盘菜单
        tray_menu = QMenu()
        
        # 添加"显示/隐藏"菜单项
        self.show_action = tray_menu.addAction('显示主窗口')
        self.show_action.triggered.connect(self.toggle_window)
        
        # 添加分隔线
        tray_menu.addSeparator()
        
        # 添加退出菜单项
        quit_action = tray_menu.addAction('退出程序')
        quit_action.triggered.connect(self.quit_app)
        
        # 添加自启动菜单项
        self.autostart_action = tray_menu.addAction('开机自启动')
        self.autostart_action.setCheckable(True)
        self.autostart_action.setChecked(self.auto_start)
        self.autostart_action.triggered.connect(self.toggle_autostart)
        
        tray_menu.addSeparator()
        
        # 修改托盘图标的提示信息
        self.tray_icon.setToolTip('ProxyByUrl (运行中)')
        
        # 添加状态显示到托盘菜单
        self.status_action = tray_menu.addAction('状态: 未连接')
        self.status_action.setEnabled(False)
        
        tray_menu.addSeparator()
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        
        # 添加托盘图标双击事件
        self.tray_icon.activated.connect(self.tray_icon_activated)

    def toggle_window(self):
        """切换窗口显示状态"""
        if self.isVisible():
            self.hide()
            self.show_action.setText('显示主窗口')
        else:
            self.show()
            self.activateWindow()
            self.show_action.setText('隐藏主窗口')

    def tray_icon_activated(self, reason):
        """处理托盘图标的点击事件"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.toggle_window()

    def quit_app(self):
        """完全退出程序"""
        try:
            # 保存配置
            self.save_config()
            
            # 停止代理
            if hasattr(self, 'proxy_thread') and self.proxy_thread and self.proxy_thread.isRunning():
                self.proxy_thread.stop()
                self.proxy_thread.wait()
            
            # 结束xray进程
            try:
                subprocess.run(['taskkill', '/F', '/IM', 'xray.exe'], 
                             stdout=subprocess.PIPE, 
                             stderr=subprocess.PIPE,
                             creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception as e:
                print(f"结束xray进程时出错: {e}")
            
            # 移除托盘图标
            if hasattr(self, 'tray_icon'):
                self.tray_icon.setVisible(False)
            
            # 退出程序
            QApplication.instance().quit()
            
        except Exception as e:
            print(f"退出程序时出错: {e}")
            QApplication.instance().quit()

    def start_proxy(self):
        try:
            # 先强制结束有已存在的 xray 进程
            subprocess.run(['taskkill', '/F', '/IM', 'xray.exe'], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE,
                         creationflags=subprocess.CREATE_NO_WINDOW)
            
            # 等待一小段时间确保进程完全结束
            time.sleep(1)
            
            # 检查端口是否被占用
            ports_to_check = [10808, 10809]
            for port in ports_to_check:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                if result == 0:
                    self.status_browser.append(f"���误端口 {port} 已被占用，请先关闭占用该端口的程序")
                    return

            current_index = self.node_combo.currentIndex()
            if current_index < 0 or not self.nodes:
                self.status_browser.append("请先选择节点")
                return
            
            node_info = self.nodes[current_index]
            
            # 停止现有代理
            self.stop_proxy()
            
            # 启动新代理
            self.proxy_thread = ProxyThread(node_info['host'], node_info['port'], node_info['password'], node_info.get('sni'))
            self.proxy_thread.status_update.connect(self.update_proxy_status)
            self.proxy_thread.start()
            
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            
            # 更新状态标显示代理信息
            status_text = (
                f"代理状态：运行中\n"
                f"SOCKS5: 127.0.0.1:10808\n"
                f"HTTP: 127.0.0.1:10809\n"
                f"节点: {node_info['remark']}"
            )
            self.status_label.setText(status_text)
            
            # 保存当前配置
            self.save_config()
            
        except Exception as e:
            self.status_browser.append(f"动代理时发生错误: {str(e)}")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def stop_proxy(self):
        try:
            if self.proxy_thread:
                self.proxy_thread.stop()
                self.proxy_thread.wait()
                self.proxy_thread = None
            
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_label.setText("代理状态：未运行")
            
        except Exception as e:
            self.browser.setText(f"止代理时发生错误: {str(e)}")

    def update_proxy_status(self, message):
        try:
            if "错误" in message:
                message = f'<span style="color: red;">{message}</span>'
                self.status_action.setText('状态: 连接错误')
            elif "成功" in message or "已启动" in message:
                message = f'<span style="color: green;">{message}</span>'
                self.status_action.setText('状态: 已连接')
            elif "警告" in message:
                message = f'<span style="color: orange;">{message}</span>'
            
            self.status_browser.append(message)
            self.status_browser.verticalScrollBar().setValue(
                self.status_browser.verticalScrollBar().maximum()
            )
        except Exception as e:
            print(f"更新状态时发生错误: {e}")

    def on_node_changed(self, index):
        # 当节点选择改变时保存配置
        self.save_config()

    def on_parse_click_with_callback(self, config):
        """获取节点，根据保存的节点信息选择正确的节点"""
        def select_saved_node():
            try:
                if 'last_node_info' in config and config['last_node_info']:
                    saved_node = config['last_node_info']
                    print("尝试恢复的节点信息:", saved_node)  # 调试信息
                    print("当前用节点列表:", [(i, node['remark']) for i, node in enumerate(self.nodes)])  # 调试信息
                    
                    # 查找匹配的节点
                    for i, node in enumerate(self.nodes):
                        if (node['host'] == saved_node['host'] and 
                            node['port'] == saved_node['port'] and 
                            node['remark'] == saved_node['remark']):
                            print(f"找到匹配节点，索引为: {i}")  # 调试信息
                            self.node_combo.setCurrentIndex(i)
                            if config.get('auto_connect', False):
                                QTimer.singleShot(500, self.start_proxy)
                            break
            except Exception as e:
                print(f"选择保存的节点时出错: {e}")

        # 先执行原有的获取节点操作
        print("开始获取节点...")  # 调试信息
        self.on_parse_click()
        # 增加延时时间，确保节点完全加载
        QTimer.singleShot(2000, select_saved_node)  # 延长等待时间到2

    def setup_autostart(self):
        """配置开机自启动"""
        try:
            startup_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            app_path = sys.executable
            
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, startup_path, 0, 
                              winreg.KEY_ALL_ACCESS) as key:
                try:
                    winreg.QueryValueEx(key, "ProxyByUrl")
                    self.auto_start = True
                except:
                    self.auto_start = False
        except Exception as e:
            print(f"检查自启动状态时出错: {e}")

    def toggle_autostart(self):
        """切换开机自启动状态"""
        try:
            startup_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            app_path = sys.executable
            
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, startup_path, 0, 
                              winreg.KEY_ALL_ACCESS) as key:
                if self.auto_start:
                    winreg.DeleteValue(key, "ProxyByUrl")
                    self.auto_start = False
                else:
                    winreg.SetValueEx(key, "ProxyByUrl", 0, winreg.REG_SZ, app_path)
                    self.auto_start = True
        except Exception as e:
            print(f"设置自启动时出错: {e}")

    def setup_firewall_rules(self):
        """配置防火墙规则"""
        try:
            # 检查是否以管理员权限运行
            if not self.is_admin():
                return
                
            # 获取xray路径
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(os.path.abspath(__file__))
            xray_path = os.path.join(base_path, 'xray.exe')
            
            # 删除已存在的规则（入站和出站）
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name=ProxyByUrl-In'
            ], capture_output=True)
            
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name=ProxyByUrl-Out'
            ], capture_output=True)
            
            # 添加新的入站规则
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=ProxyByUrl-In',
                'dir=in',
                'action=allow',
                'program=' + xray_path,
                'enable=yes',
                'profile=any',
                'protocol=TCP'
            ], capture_output=True)
            
            # 添加新的出站规则
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=ProxyByUrl-Out',
                'dir=out',
                'action=allow',
                'program=' + xray_path,
                'enable=yes',
                'profile=any',
                'protocol=TCP'
            ], capture_output=True)
            
            print("防火墙规则配置成功")
            
        except Exception as e:
            print(f"设置防火墙规则时出错: {e}")

    def is_admin(self):
        """检查是否具有管理员权限"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def auto_connect(self):
        """自动连接到上次使用的节点"""
        try:
            if self.nodes and self.node_combo.count() > 0:
                self.start_proxy()
        except Exception as e:
            print(f"自动连接时出错: {e}")

def main():
    try:
        # 检查是否已经运行
        socket_name = "ProxyByUrlSingleInstance"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('localhost', 12345))  # 使用特定端口检查
        except socket.error:
            print("程序已经在运行")
            sys.exit(0)
            
        # 检查管理员权限
        if not ctypes.windll.shell32.IsUserAnAdmin():
            # 使用 CREATE_NO_WINDOW 标志启动新进程
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            subprocess.Popen([
                'powershell.exe', 
                'Start-Process', 
                sys.executable,
                '-ArgumentList', ' '.join(sys.argv),
                '-Verb', 'RunAs',
                '-WindowStyle', 'Hidden'
            ], startupinfo=startupinfo)
            sys.exit()
            
        app = QApplication(sys.argv)
        
        if not QSystemTrayIcon.isSystemTrayAvailable():
            sys.exit(1)
            
        app.setQuitOnLastWindowClosed(False)
        
        viewer = TrojanUrlViewer()
        # 移除 viewer.show()
        
        sys.exit(app.exec_())
        
    except Exception as e:
        print(f"程序运行错误: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
