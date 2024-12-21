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
        # 如果后续需要查询位置，可以使用异步方式或缓存机制

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
                                
                                # 解析sni参数
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
                    # 发送请求时添加headers
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
                            self.finished.emit("未能获取到有效节点")
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

    def run(self):
        try:
            if not self._is_running:
                return

            self.status_update.emit("开始配置代理服务...")
            
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
            
            self.status_update.emit(f"当前配置信息：")
            self.status_update.emit(f"SOCKS5代理：127.0.0.1:10808")
            self.status_update.emit(f"HTTP代理：127.0.0.1:10809")
            self.status_update.emit(f"远程服务器：{self.server}:{self.port}")
            
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            
            self.status_update.emit("配置文件已生成")

            xray_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'xray.exe')
            if not os.path.exists(xray_path):
                self.status_update.emit("错误: 找不到xray.exe，请下载并放置在程序目录")
                return

            try:
                self.status_update.emit("正在启动Xray进程...")
                self.process = subprocess.Popen(
                    [xray_path, "run", "-c", config_path],
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
            print(f"清理残留进程时出错: {e}")

class TrojanUrlViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.fetch_thread = None
        self.proxy_thread = None
        self.nodes = []
        # 使用用户目录来保存配置
        user_home = os.path.expanduser('~')  # 获取用户主目录
        app_data_dir = os.path.join(user_home, 'AppData', 'Local', 'ProxyByUrl')
        if not os.path.exists(app_data_dir):
            os.makedirs(app_data_dir)
        
        self.config_file = os.path.join(app_data_dir, 'app_config.json')
        print(f"配置文件路径: {self.config_file}")  # 调试信息
        self.initUI()
        self.setupSystemTray()
        self.load_saved_config()  # 加载存的配置

    def load_saved_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    print("加载的配置文件内容:", config)
                    
                # 恢复上次的URL
                if 'last_url' in config:
                    self.input_box.setText(config['last_url'])
                    print(f"正在恢复URL: {config['last_url']}")
                    
                    # 如果有保存的节点信息，先恢复它
                    if 'last_node_info' in config and config['last_node_info']:
                        self.nodes = [config['last_node_info']]  # 先保存上次的节点
                        self.node_combo.clear()
                        self.node_combo.addItem(config['last_node_info']['remark'])
                        self.node_combo.setCurrentIndex(0)
                    
                    # 然后尝试获取新的节点列表
                    QTimer.singleShot(500, lambda: self.on_parse_click_with_callback(config))

        except Exception as e:
            print(f"加载配置时出错: {e}")

    def clear_invalid_config(self):
        """清除无效的配置"""
        try:
            # 不要立即删除配置文件，而是保留最后一次的有效配置
            self.browser.setText("获取新节点列表失败，使用上次的配置")
            # 如果有保存的节点，继续使用
            if hasattr(self, 'nodes') and self.nodes:
                return
            
            # 只有在完全没有节点的情况下才清除配置
            if os.path.exists(self.config_file):
                os.remove(self.config_file)
            self.input_box.clear()
            self.node_combo.clear()
            self.browser.setText("请输入新的订阅链接")
            
        except Exception as e:
            print(f"清除配置时出错: {e}")

    def save_config(self):
        try:
            current_index = self.node_combo.currentIndex()
            # 只在有效的节点选择时才保存配置
            if current_index >= 0 and self.nodes and current_index < len(self.nodes):
                config_dir = os.path.dirname(self.config_file)
                if not os.path.exists(config_dir):
                    os.makedirs(config_dir)

                selected_node = self.nodes[current_index]
                print(f"正在保存节点配置，选中的节点: {selected_node['remark']}")

                config = {
                    'last_url': self.input_box.text(),
                    'last_node_index': current_index,
                    'last_node_info': selected_node,
                    'auto_connect': True
                }
                
                print("即将保存的配置:", config)
                
                temp_file = self.config_file + '.tmp'
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                
                if os.path.exists(temp_file):
                    if os.path.exists(self.config_file):
                        os.remove(self.config_file)
                    os.rename(temp_file, self.config_file)
                    print(f"配置已成功保存到: {self.config_file}")
        except Exception as e:
            print(f"保存配置时出错: {e}")

    def closeEvent(self, event):
        """重写关闭事件"""
        if self.tray_icon.isVisible():
            self.hide()  # 隐藏主窗口
            self.tray_icon.showMessage(
                '提示',
                '程序已最小化到系统托盘，双击图标可以重新打开窗口',
                QSystemTrayIcon.Information,
                2000
            )
            event.ignore()  # 忽略关闭事件
        else:
            self.quit_app()
            event.accept()

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
                self.node_combo.clear()
                for node in self.nodes:
                    self.node_combo.addItem(f"{node['remark']}")
                
                # 如果有保存的配置，尝试恢复选择的节点
                try:
                    if os.path.exists(self.config_file):
                        with open(self.config_file, 'r', encoding='utf-8') as f:
                            config = json.load(f)
                            if 'last_node_info' in config and config['last_node_info']:
                                saved_node = config['last_node_info']
                                for i, node in enumerate(self.nodes):
                                    if (node['host'] == saved_node['host'] and 
                                        node['port'] == saved_node['port'] and 
                                        node['remark'] == saved_node['remark']):
                                        self.node_combo.setCurrentIndex(i)
                                        break
                except Exception as e:
                    print(f"恢复节点选择时出错: {e}")
            else:
                # 如果获取新节点失败，但有保存的节点，继续使用旧节点
                if hasattr(self, 'nodes') and self.nodes:
                    self.browser.setText("使用已保存的节点配置")
                else:
                    self.browser.setText("获取节点失败，请检查订阅链接是否有效")
            
        except Exception as e:
            self.browser.setText(f"处理结果时发生错误: {str(e)}")
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
        
        # 计算窗口位置，使其居中显示
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
        self.parse_button = QPushButton('获取节点')
        self.parse_button.clicked.connect(self.on_parse_click)
        url_layout.addWidget(self.input_box)
        url_layout.addWidget(self.parse_button)
        layout.addLayout(url_layout)
        
        # 节点选择下拉框
        self.node_combo = QComboBox()
        self.node_combo.setMinimumWidth(200)
        self.node_combo.currentIndexChanged.connect(self.on_node_changed)
        layout.addWidget(self.node_combo)
        
        # 代理控制按钮
        proxy_layout = QHBoxLayout()
        self.start_button = QPushButton('启动代理')
        self.stop_button = QPushButton('停止代理')
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
        show_action = tray_menu.addAction('显示主窗口')
        show_action.triggered.connect(self.show)
        quit_action = tray_menu.addAction('退出程序')
        quit_action.triggered.connect(self.quit_app)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        
        # 添加托盘图标双击事件
        self.tray_icon.activated.connect(self.tray_icon_activated)

    def tray_icon_activated(self, reason):
        """处理托盘图标的点击事件"""
        if reason == QSystemTrayIcon.DoubleClick:
            if self.isVisible():
                self.hide()
            else:
                self.show()
                self.activateWindow()  # 激活窗口

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
            subprocess.run(['taskkill', '/F', '/IM', 'xray.exe'], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE,
                         creationflags=subprocess.CREATE_NO_WINDOW)
            
            # 移除托盘图标
            self.tray_icon.hide()
            
            # 退出程序
            QApplication.quit()
            
        except Exception as e:
            print(f"退出程序时出错: {e}")
            QApplication.quit()

    def start_proxy(self):
        try:
            # 先强制结束所有已存在的 xray 进程
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
                    self.status_browser.append(f"错误：端口 {port} 已被占用，请先关闭占用该端口的程序")
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
            
            # 更新状态标签显示代理信息
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
            self.status_browser.append(f"启动代理时发生错误: {str(e)}")
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
            self.browser.setText(f"停止代理时发生错误: {str(e)}")

    def update_proxy_status(self, message):
        try:
            if "错误" in message:
                message = f'<span style="color: red;">{message}</span>'
            elif "成功" in message or "已启动" in message:
                message = f'<span style="color: green;">{message}</span>'
            elif "警告" in message:
                message = f'<span style="color: orange;">{message}</span>'
            
            self.status_browser.append(message)
            self.status_browser.verticalScrollBar().setValue(
                self.status_browser.verticalScrollBar().maximum()
            )
        except Exception as e:
            print(f"更新状态时发生错误: {str(e)}")

    def on_node_changed(self, index):
        # 当节点选择改变时保存配置
        self.save_config()

    def on_parse_click_with_callback(self, config):
        """获取节点后，根据保存的节点信息选择正确的节点"""
        def select_saved_node():
            try:
                if 'last_node_info' in config and config['last_node_info']:
                    saved_node = config['last_node_info']
                    print("尝试恢复的节点信息:", saved_node)  # 调试信息
                    print("当前可用节点列表:", [(i, node['remark']) for i, node in enumerate(self.nodes)])  # 调试信息
                    
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

def main():
    try:
        global app
        app = QApplication(sys.argv)
        
        # 检查系统是否支持系统托盘
        if not QSystemTrayIcon.isSystemTrayAvailable():
            QMessageBox.critical(None, '系统托盘', '系统托盘不可用')
            return
        
        # 设置退出时不自动关闭
        QApplication.setQuitOnLastWindowClosed(False)
        
        viewer = TrojanUrlViewer()
        viewer.show()
        
        sys.exit(app.exec_())
    except Exception as e:
        print(f"程序运行错误: {str(e)}")
        input("按回车键退出...")  # 添加这行以便查看错误信息

if __name__ == '__main__':
    main()
