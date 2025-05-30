#  pyinstaller --noconfirm --onefile --windowed --icon=icon.ico --add-data "icon.ico;."   --add-data "icon.png;." --add-data "xray.exe;."   1.py   --name  "proxyByUrl"

# ------------------------------------------------
# self.app_config_file = os.path.join(self.app_data_dir, 'app_config.json')

            

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
import random

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
            
            # 添加更强大的重试机制
            for attempt in range(self.max_retries):
                try:
                    # 设置更长的超时时间
                    response = requests.get(
                        self.url, 
                        headers=headers,
                        verify=False, 
                        timeout=30,  # 增加超时时间到30秒
                        allow_redirects=True  # 允许重定向
                    )
                    
                    if response.status_code == 200:
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
                            wait_time = (attempt + 1) * 2  # 递增等待时间
                            self.progress.emit(f"未获取到有效节点，{wait_time}秒后重试... ({attempt + 1}/{self.max_retries})")
                            time.sleep(wait_time)
                            continue
                        else:
                            self.finished.emit("未能获取到有效节点")
                    else:
                        if attempt < self.max_retries - 1:
                            wait_time = (attempt + 1) * 2
                            self.progress.emit(f"请求失败(状态码: {response.status_code})，{wait_time}秒后重试... ({attempt + 1}/{self.max_retries})")
                            time.sleep(wait_time)
                            continue
                        else:
                            self.finished.emit(f"请求失败，状态码: {response.status_code}")
                            
                except requests.exceptions.ProxyError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = (attempt + 1) * 2
                        self.progress.emit(f"代理连接错误，{wait_time}秒后重试... ({attempt + 1}/{self.max_retries})")
                        time.sleep(wait_time)
                        continue
                    else:
                        self.finished.emit("代理连接失败，请检查网络设置或关闭系统代理后重试")
                        
                except requests.exceptions.RequestException as e:
                    if attempt < self.max_retries - 1:
                        wait_time = (attempt + 1) * 2
                        self.progress.emit(f"网络请求错误: {str(e)}，{wait_time}秒后重试... ({attempt + 1}/{self.max_retries})")
                        time.sleep(wait_time)
                        continue
                    else:
                        self.finished.emit(f"网络请求失败，请检查网络连接")
                        
        except Exception as e:
            self.finished.emit(f"发生未知错误: {str(e)}")

class ProxyThread(QThread):
    status_update = pyqtSignal(str)

    def __init__(self, server, port, password, sni=None, http_port=None):
        super().__init__()
        self.server = server
        self.port = port
        self.password = password
        self.sni = sni
        # 如果没有指定端口，选择一个随机高端口
        self.http_port = http_port if http_port else self.get_random_port()
        self._is_running = True
        self.process = None
        
        # 初始化配置目录
        self.app_data_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'ProxyByUrl')
        if not os.path.exists(self.app_data_dir):
            os.makedirs(self.app_data_dir)

    def get_random_port(self):
        """获取一个随机的可用高端口"""
        # 尝试最多10次找到一个可用端口
        for _ in range(10):
            # 选择一个20000-65000之间的随机端口
            random_port = random.randint(20000, 65000)
            
            # 检查端口是否可用
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('0.0.0.0', random_port))
            sock.close()
            
            # 如果端口可用 (connect_ex返回非零结果表示连接失败，即端口可能未被使用)
            if result != 0:
                return random_port
                
        # 如果没有找到可用端口，返回一个常规的高端口
        return 20809

    def run(self):
        try:
            if not self._is_running:
                return

            self.status_update.emit("开始配置代理服务...")
            self.status_update.emit(f"将使用HTTP代理端口: {self.http_port}")
            
            # 改为使用固定目录中的xray.exe
            xray_dest_path = os.path.join(self.app_data_dir, 'xray.exe')
            
            # 获取原始xray路径
            if getattr(sys, 'frozen', False):
                # 如果是打包后的exe运行
                base_path = sys._MEIPASS
            else:
                # 如果是直接运行python脚本
                base_path = os.path.dirname(os.path.abspath(__file__))
            
            xray_src_path = os.path.join(base_path, 'xray.exe')
            
            # 如果固定目录中不存在xray.exe，则复制一份
            if not os.path.exists(xray_dest_path):
                if os.path.exists(xray_src_path):
                    import shutil
                    shutil.copy2(xray_src_path, xray_dest_path)
                    self.status_update.emit("已将xray.exe复制到固定目录")
                else:
                    self.status_update.emit("错误: 找不到xray.exe，请确保xray.exe与程序在同一目录")
                    return
            
            # 使用固定目录中的xray.exe
            if not os.path.exists(xray_dest_path):
                self.status_update.emit("错误: 找不到xray.exe，请确保xray.exe与程序在同一目录")
                return
            
            # 其余代码保持不变，只需将xray_path替换为xray_dest_path
            xray_path = xray_dest_path
            
            # 使用用户目录的xray配置文件
            config_path = os.path.join(self.app_data_dir, 'xray_config.json')
            
            # Xray 配置 - 只使用HTTP代理
            config = {
                "inbounds": [
                    {
                        "port": self.http_port,
                        "listen": "0.0.0.0",  # 仅监听本地地址
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
                subprocess.run(['taskkill', '/F', '/PID', str(self.process.pid)], 
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
        
        # 配置目录初始化
        self.app_data_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'ProxyByUrl')
        if not os.path.exists(self.app_data_dir):
            os.makedirs(self.app_data_dir)
        
        # 配置文件路径
        self.app_config_file = os.path.join(self.app_data_dir, 'app_config.json')
        print(f"应用配置文件路径: {self.app_config_file}")
        
        # 初始化顺序
        self.initUI()                  
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
                        print("找到已保存的所有节点信息")
                        self.nodes = config['all_nodes']
                        self.node_combo.clear()
                        for node in self.nodes:
                            self.node_combo.addItem(f"{node['remark']}")
                        
                        # 设置上次选择的节点
                        if 'last_node_index' in config:
                            last_index = config['last_node_index']
                            if 0 <= last_index < len(self.nodes):
                                self.node_combo.setCurrentIndex(last_index)

                    # 恢复HTTP端口设置
                    if 'http_port' in config and hasattr(self, 'port_input'):
                        self.port_input.setText(config['http_port'])

        except Exception as e:
            print(f"加载应用配置时出错: {e}")

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
                
                # 保存HTTP端口设置
                if hasattr(self, 'port_input'):
                    config['http_port'] = self.port_input.text().strip()
                
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
                print("没有获取到新节点，保留现有节点")
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
        self.setWindowTitle('ProxyByUrl - 2025/5/30-02')  # 修改这行，添加版本信息
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
        
        # 添加HTTP端口输入区域
        port_layout = QHBoxLayout()
        port_label = QLabel('HTTP端口(&P)：')
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText('留空使用随机端口')
        self.port_input.setText('')  # 默认为空
        self.port_input.setMaximumWidth(150)
        port_label.setBuddy(self.port_input)
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_input)
        port_layout.addStretch()  # 添加弹性空间
        layout.addLayout(port_layout)
        
        # 代理控制按钮
        proxy_layout = QHBoxLayout()
        self.start_button = QPushButton('启动代理(&S)')  # 添加Alt+S快捷键
        self.stop_button = QPushButton('停止代理(&T)')   # 加Alt+T快捷键
        self.restart_button = QPushButton('重启连接(&R)')  # 添加重启按钮，带Alt+R快捷键
        self.start_button.clicked.connect(self.start_proxy)
        self.stop_button.clicked.connect(self.stop_proxy)
        self.restart_button.clicked.connect(self.restart_proxy)  # 连接重启功能
        self.stop_button.setEnabled(False)
        self.restart_button.setEnabled(False)  # 初始时禁用重启按钮

        proxy_layout.addWidget(self.start_button)
        proxy_layout.addWidget(self.stop_button)
        proxy_layout.addWidget(self.restart_button)  # 添加到布局
        layout.addLayout(proxy_layout)
        
        # 状态显示区域 (移到按钮下方)
        status_group = QGroupBox("代理状态")
        status_layout = QVBoxLayout()
        self.status_label = QLabel('代理状态：未运行')
        self.status_browser = QTextBrowser()
        self.status_browser.setMaximumHeight(150)
        
        # 添加状态区域的全屏切换按钮
        status_header_layout = QHBoxLayout()
        status_header_layout.addWidget(self.status_label)
        status_fullscreen_button = QPushButton("全屏(&Z)")
        status_fullscreen_button.clicked.connect(self.toggle_status_fullscreen)
        status_header_layout.addWidget(status_fullscreen_button)
        
        status_layout.addLayout(status_header_layout)
        status_layout.addWidget(self.status_browser)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # 保存状态区域原始大小的引用
        self.status_browser_original_height = self.status_browser.maximumHeight()
        self.status_group = status_group
        self.status_fullscreen_button = status_fullscreen_button
        
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
            
        # 图标文件路径
        icon_path = os.path.join(application_path, 'icon.png')
        
        # 创建系统托盘图标
        self.tray_icon = QSystemTrayIcon(self)
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        else:
            print(f"找不到图标文件: {icon_path}")
        
        # 创建托盘菜单
        tray_menu = QMenu()
        
        
        # 添加分隔线
        tray_menu.addSeparator()
        
        # 添加重启代理菜单项
        restart_action = tray_menu.addAction('重启代理(&R)')
        restart_action.triggered.connect(self.restart_proxy)
        
        # 添加退出菜单项（带快捷键X）
        quit_action = tray_menu.addAction('退出程序(&X)')
        quit_action.triggered.connect(self.quit_app)
        
        tray_menu.addSeparator()
        
        
        # 添加状态显示到托盘菜单
        self.status_action = tray_menu.addAction('状态: 未连接')
        self.status_action.setEnabled(False)
        
        tray_menu.addSeparator()
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        
        # 添加托盘图标双击事件
        self.tray_icon.activated.connect(self.tray_icon_activated)
        
        # 添加定时器来检查托盘图标状态
        self.tray_check_timer = QTimer()
        self.tray_check_timer.timeout.connect(self.check_tray_status)
        self.tray_check_timer.start(5000)  # 每5秒检查一次

    def tray_icon_activated(self, reason):
        """处理托盘图标的点击事件"""
        try:
            if reason == QSystemTrayIcon.DoubleClick:
                # 改进的窗口唤醒逻辑
                if not self.isVisible() or self.isMinimized():
                    # 强制显示并激活窗口
                    self.setWindowState(self.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)
                    self.show()
                    self.activateWindow()
                    self.raise_()
                    
                    # Windows特定的窗口激活方法
                    if sys.platform == 'win32':
                        try:
                            import ctypes
                            from ctypes import wintypes
                            
                            # 获取窗口句柄
                            hwnd = int(self.winId())
                            
                            # 强制将窗口带到前台
                            ctypes.windll.user32.SetForegroundWindow(hwnd)
                            ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                            ctypes.windll.user32.SetActiveWindow(hwnd)
                            
                        except Exception as e:
                            print(f"Windows特定激活失败: {e}")
                    
                    self.show_action.setText('隐藏主窗口')
                else:
                    self.hide()
                    self.show_action.setText('显示主窗口')
                
        except Exception as e:
            print(f"处理托盘图标点击事件时出错: {e}")
            # 发生错误时的备用方案
            try:
                self.setWindowState(Qt.WindowNoState)
                self.show()
                self.activateWindow()
                self.raise_()
                if sys.platform == 'win32':
                    import ctypes
                    hwnd = int(self.winId())
                    ctypes.windll.user32.SetForegroundWindow(hwnd)
            except:
                pass

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
            
            current_index = self.node_combo.currentIndex()
            if current_index < 0 or not self.nodes:
                self.status_browser.append("请先选择节点")
                return
            
            node_info = self.nodes[current_index]
            
            # 停止现有代理
            self.stop_proxy()
            
            # 获取用户输入的端口
            http_port = None
            if hasattr(self, 'port_input') and self.port_input.text().strip():
                try:
                    port_text = self.port_input.text().strip()
                    port_num = int(port_text)
                    if 1024 <= port_num <= 65535:  # 有效端口范围检查
                        http_port = port_num
                    else:
                        self.status_browser.append(f"端口 {port_num} 超出有效范围(1024-65535)，将使用随机端口")
                except ValueError:
                    self.status_browser.append("端口格式无效，将使用随机端口")
            
            if http_port:
                self.status_browser.append(f"尝试使用指定端口 {http_port} 启动代理...")
            else:
                self.status_browser.append("尝试使用随机高端口启动代理...")
            
            # 启动新代理，根据用户输入决定是否使用指定端口
            self.proxy_thread = ProxyThread(
                node_info['host'], 
                node_info['port'], 
                node_info['password'], 
                node_info.get('sni'),
                http_port  # 传入用户指定的端口，如果为None则使用随机端口
            )
            self.proxy_thread.status_update.connect(self.update_proxy_status)
            self.proxy_thread.start()
            
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.restart_button.setEnabled(True)  # 启用重启按钮
            
            # 稍微延迟一下更新状态，等待端口确定
            QTimer.singleShot(500, lambda: self.update_proxy_port_status())
            
            # 保存当前配置
            self.save_config()
            
        except Exception as e:
            self.status_browser.append(f"启动代理时发生错误: {str(e)}")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.restart_button.setEnabled(False)  # 禁用重启按钮

    def update_proxy_port_status(self):
        """更新代理端口状态信息"""
        try:
            if self.proxy_thread and hasattr(self.proxy_thread, 'http_port'):
                http_port = self.proxy_thread.http_port
                node_index = self.node_combo.currentIndex()
                if node_index >= 0 and self.nodes:
                    node_info = self.nodes[node_index]
                    # 更新状态标签显示代理信息
                    status_text = (
                        f"代理状态：运行中\n"
                        f"HTTP: 0.0.0.0:{http_port}\n"
                        f"节点: {node_info['remark']}"
                    )
                    self.status_label.setText(status_text)
                    self.status_browser.append(f"HTTP代理已启动在端口: {http_port}")
        except Exception as e:
            print(f"更新代理端口状态时出错: {e}")

    def stop_proxy(self):
        try:
            if self.proxy_thread:
                self.proxy_thread.stop()
                self.proxy_thread.wait()
                self.proxy_thread = None
            
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.restart_button.setEnabled(False)  # 禁用重启按钮
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

    def auto_connect(self):
        """自动连接到上次使用的节点"""
        try:
            if self.nodes and self.node_combo.count() > 0:
                self.start_proxy()
        except Exception as e:
            print(f"自动连接时出错: {e}")

    def toggle_fullscreen(self):
        """切换全屏与非全屏状态"""
        try:
            if self.isFullScreen():
                self.showNormal()
            else:
                self.showFullScreen()
        except Exception as e:
            print(f"切换全屏状态时出错: {e}")

    def toggle_status_fullscreen(self):
        """切换状态区域的全屏显示"""
        try:
            if self.status_browser.maximumHeight() == 16777215:  # 这是Qt的QWIDGETSIZE_MAX
                # 恢复正常大小
                self.status_browser.setMaximumHeight(self.status_browser_original_height)
                self.browser.show()  # 显示节点信息区域
                self.status_fullscreen_button.setText("全屏(&Z)")
            else:
                # 设置为全屏大小
                self.status_browser.setMaximumHeight(16777215)  # QWIDGETSIZE_MAX
                self.browser.hide()  # 隐藏节点信息区域以腾出更多空间
                self.status_fullscreen_button.setText("还原(&Z)")
            
            # 刷新界面布局
            self.layout().activate()
            
        except Exception as e:
            print(f"切换状态区域全屏显示时出错: {e}")

    def restart_proxy(self):
        """重启代理连接"""
        try:
            self.status_browser.append("正在重启代理连接...")
            
            # 保存当前节点索引和端口
            current_index = self.node_combo.currentIndex()
            current_port = None
            if hasattr(self, 'port_input') and self.port_input.text().strip():
                current_port = self.port_input.text().strip()
            
            # 先停止代理
            self.stop_proxy()
            
            # 等待一小段时间确保进程完全结束
            time.sleep(1)
            
            # 恢复之前的节点选择
            if current_index >= 0 and current_index < self.node_combo.count():
                self.node_combo.setCurrentIndex(current_index)
            
            # 恢复之前的端口设置
            if current_port and hasattr(self, 'port_input'):
                self.port_input.setText(current_port)
            
            # 重新启动代理
            self.start_proxy()
            
        except Exception as e:
            self.status_browser.append(f"重启代理时发生错误: {str(e)}")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.restart_button.setEnabled(False)

    def check_tray_status(self):
        """检查托盘图标状态，确保它始终可见"""
        try:
            if hasattr(self, 'tray_icon') and not self.tray_icon.isVisible():
                self.tray_icon.show()
        except Exception as e:
            print(f"检查托盘状态时出错: {e}")

def main():
    try:
        # 检查是否以管理员权限运行
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
        
        # 添加全局样式表设置
        app.setStyleSheet("""
            QWidget {
                font-size: 12pt;
            }
            QTextBrowser {
                font-size: 11pt;
            }
            QComboBox {
                font-size: 11pt;
            }
            QLineEdit {
                font-size: 11pt;
            }
            QPushButton {
                font-size: 11pt;
            }
        """)
        
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
