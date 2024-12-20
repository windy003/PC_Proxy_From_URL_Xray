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
                           QStyle)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import threading
import time
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import select
import struct

class FetchThread(QThread):
    finished = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url
        self.nodes = []
        self._is_running = True

    def stop(self):
        self._is_running = False

    def get_node_location(self, ip):
        # 直接返回未知位置，不进行网络请求
        return "未知位置"
        # 如果后续需要查询位置，可以使用异步方式或缓存机制

    def parse_nodes(self, base64_content):
        try:
            decoded = base64.b64decode(base64_content).decode('utf-8')
            urls = decoded.split('\n')
            
            result = ""
            self.nodes = []
            
            for url in urls:
                if not self._is_running:
                    return "操作已取消"

                url = url.strip()
                if not url or not url.startswith('trojan://'):
                    continue
                    
                try:
                    # 解析URL
                    parsed = urlparse(url)
                    userinfo, server = parsed.netloc.split('@')
                    host, port = server.split(':')
                    
                    # 获取备注名称
                    remark = unquote(parsed.fragment) if parsed.fragment else "未命名节点"
                    
                    # 获取其他参数
                    query_params = parse_qs(parsed.query)
                    sni = query_params.get('sni', [''])[0]
                    
                    node_info = {
                        'host': host,
                        'port': port,
                        'password': userinfo,
                        'remark': remark,
                        'sni': sni
                    }
                    self.nodes.append(node_info)
                    
                    # 更新进度
                    self.progress.emit(f"正在处理: {remark}")
                    
                    # 构建显示信息
                    result += f"节点名称: {remark}\n"
                    result += f"服务器: {host}\n"
                    result += f"端口: {port}\n"
                    if sni:
                        result += f"SNI: {sni}\n"
                    result += "-" * 30 + "\n"
                
                except Exception as e:
                    continue
            
            return result if result else "未找到有效的trojan链接"
            
        except Exception as e:
            return f"解析错误: {str(e)}"

    def run(self):
        try:
            self.progress.emit("正在获取节点数据...")
            
            # 设置较短的超时时间
            response = requests.get(
                self.url, 
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=5,
                proxies={'http': None, 'https': None},
                verify=False
            )
            
            if response.status_code != 200:
                self.finished.emit(f"获取URL内容失败: HTTP {response.status_code}")
                return
                
            base64_content = response.text.strip()
            result = self.parse_nodes(base64_content)
            self.finished.emit(result)
            
        except requests.exceptions.Timeout:
            self.finished.emit("获取节点超时，请检查网络连接")
        except Exception as e:
            self.finished.emit(f"发生错误: {str(e)}")

class HttpToSocks5(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        try:
            host, port = self.path.split(':')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('127.0.0.1', 10808))  # 连接到 SOCKS5 代理
            
            # SOCKS5 握手
            sock.send(b'\x05\x01\x00')
            sock.recv(2)
            
            # 发送连接请求
            addr = host.encode()
            port = int(port)
            req = b'\x05\x01\x00\x03' + bytes([len(addr)]) + addr + struct.pack('>H', port)
            sock.send(req)
            sock.recv(10)
            
            self.send_response(200)
            self.end_headers()
            
            conns = [self.connection, sock]
            while True:
                r, w, e = select.select(conns, [], [])
                for s in r:
                    data = s.recv(4096)
                    if not data:
                        return
                    other = conns[1] if s is conns[0] else conns[0]
                    other.send(data)
        except Exception as e:
            self.send_error(500, str(e))
            return
    
    def do_GET(self):
        self.handle_request('GET')
    
    def do_POST(self):
        self.handle_request('POST')
    
    def handle_request(self, method):
        try:
            url = self.path
            headers = {k: v for k, v in self.headers.items()}
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('127.0.0.1', 10808))
            
            # SOCKS5 握手
            sock.send(b'\x05\x01\x00')
            sock.recv(2)
            
            # 解析目标地址
            if url.startswith('http://'):
                url = url[7:]
            host = url.split('/')[0]
            if ':' in host:
                host, port = host.split(':')
                port = int(port)
            else:
                port = 80
                
            # 发送连接请求
            addr = host.encode()
            req = b'\x05\x01\x00\x03' + bytes([len(addr)]) + addr + struct.pack('>H', port)
            sock.send(req)
            sock.recv(10)
            
            # 发送 HTTP 请求
            request = f'{method} {url} HTTP/1.1\r\n'
            for k, v in headers.items():
                request += f'{k}: {v}\r\n'
            request += '\r\n'
            
            sock.send(request.encode())
            
            # 接收响应
            response = sock.recv(4096)
            self.connection.send(response)
            
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                self.connection.send(data)
                
        except Exception as e:
            self.send_error(500, str(e))
            return

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
        self.initUI()
        self.setupSystemTray()

    def closeEvent(self, event):
        if self.tray_icon.isVisible():
            event.ignore()  # 忽略关闭事件
            self.hide()     # 隐藏窗口
            self.tray_icon.showMessage(
                "ProxyByUrl",
                "应用程序已最小化到系统托盘，双击图标可以重新打开窗口。",
                QSystemTrayIcon.Information,
                2000
            )
            print("窗口已最小化到系统托盘")  # 调试信息

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
            
            # 建新线程
            self.fetch_thread = FetchThread(url)
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
            self.node_combo.clear()
            if hasattr(self.fetch_thread, 'nodes'):
                for node in self.fetch_thread.nodes:
                    self.node_combo.addItem(f"{node['remark']}")
                self.nodes = self.fetch_thread.nodes
            
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
        self.setGeometry(300, 300, 600, 500)
        self.showMaximized()
        
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
        
        # 状态显示
        self.status_label = QLabel('代理状态：未运行')
        layout.addWidget(self.status_label)
        
        # 日志显示区域
        self.browser = QTextBrowser()
        layout.addWidget(self.browser)
        
        self.setLayout(layout)

    def setupSystemTray(self):
        # 创建系统托盘图标
        self.tray_icon = QSystemTrayIcon(self)
        
        # 使用更可靠的图标设置方式
        icon = QIcon()
        try:
            # 首先尝试加载自定义图标
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon.png')
            if os.path.exists(icon_path):
                icon = QIcon(icon_path)
            else:
                # 如果找不到自定义图标，使用系统图标
                icon = QIcon(self.style().standardPixmap(QStyle.SP_ComputerIcon))
            
            self.tray_icon.setIcon(icon)
            print(f"标已设置，路径: {icon_path}")  # 调试信息
        except Exception as e:
            print(f"设置图标时出错: {str(e)}")  # 调试信息
            

        # 确保托盘图标显示
        self.tray_icon.show()
        print("系统托盘图标应已显示")  # 调试信息
        
        # 创建托盘菜单
        tray_menu = QMenu()
        show_action = tray_menu.addAction('显示窗口')
        hide_action = tray_menu.addAction('最小化到托盘')
        quit_action = tray_menu.addAction('退出')
        
        # 绑定动作
        show_action.triggered.connect(self.showNormal)
        hide_action.triggered.connect(self.hide)
        quit_action.triggered.connect(self.on_quit)
        
        # 设置托盘图标提示文字
        self.tray_icon.setToolTip('ProxyByUrl')
        
        # 托盘图标的双击事件
        self.tray_icon.activated.connect(self.on_tray_icon_activated)
        
        # 设置右键菜单
        self.tray_icon.setContextMenu(tray_menu)

    def on_tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            if self.isHidden():
                self.showNormal()
            else:
                self.hide()

    def on_quit(self):
        # 清理资源并退出
        if self.proxy_thread and self.proxy_thread.isRunning():
            self.proxy_thread.stop()
            self.proxy_thread.wait()
        
        if self.fetch_thread and self.fetch_thread.isRunning():
            self.fetch_thread.stop()
            self.fetch_thread.wait()
        
        self.tray_icon.hide()
        QApplication.quit()

    def start_proxy(self):
        try:
            current_index = self.node_combo.currentIndex()
            if current_index < 0 or not self.nodes:
                self.browser.setText("请先选择节点")
                return
                
            node_info = self.nodes[current_index]
            
            # 停止现有代理
            self.stop_proxy()
            
            # 动新代理
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
            
        except Exception as e:
            self.browser.setText(f"启动代理时发生错误: {str(e)}")
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
            self.browser.append(message)
        except Exception as e:
            print(f"更新状态时发生错误: {str(e)}")

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
