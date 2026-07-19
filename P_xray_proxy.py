# & "D:\files\using\Python\PC_Proxy_From_URL_Xray\.venv\Scripts\python.exe" -m   PyInstaller --noconfirm --onefile --windowed --icon=256x256.ico --add-data "256x256.ico;."   --add-data "icon.png;." --add-data "xray.exe;."   --add-binary "tun2socks.exe;."  --add-binary "wintun.dll;." P_xray_proxy.py   --name  "proxyByUrl"

# ------------------------------------------------
# self.app_config_file = os.path.join(self.app_data_dir, 'app_config.json')

# ________________________________________________________            


# 这个项目会把程序目录下的xray.exe复制到固定目录下，然后使用固定目录下的xray.exe

import base64
import sys
import json
import requests
import subprocess
import os
from urllib.parse import unquote, quote, urlparse, parse_qs
from PyQt5.QtWidgets import (QApplication, QSystemTrayIcon, QMenu, QWidget,
                           QTextBrowser, QLineEdit, QPushButton, QComboBox,
                           QLabel, QVBoxLayout, QHBoxLayout, QMessageBox,
                           QStyle, QGroupBox, QStyledItemDelegate, QCheckBox)
from PyQt5.QtGui import QIcon, QColor
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QEvent, QRect
import threading
import time
import socket
import urllib3
from PyQt5.QtWidgets import QShortcut
from PyQt5.QtGui import QKeySequence
import winreg
import ctypes
import random
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

# 版本(日期)号，显示在窗口标题
APP_VERSION = '2026/7/19-1'


def get_resource_path(name):
    """获取资源文件路径(兼容 PyInstaller 打包与源码运行)"""
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, name)


def get_app_icon_path():
    """返回程序图标路径，优先使用 256x256.ico"""
    for name in ('256x256.ico', 'icon.ico', 'icon.png'):
        path = get_resource_path(name)
        if os.path.exists(path):
            return path
    return get_resource_path('256x256.ico')


def is_admin():
    """判断当前进程是否拥有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def relaunch_as_admin():
    """以管理员权限重新启动本程序，成功则返回 True(调用方应随后退出)"""
    try:
        if getattr(sys, 'frozen', False):
            # 打包后的 exe
            executable = sys.executable
            params = ''
        else:
            # 源码运行：用 python 解释器带上脚本路径
            executable = sys.executable
            params = f'"{os.path.abspath(__file__)}"'
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, params, None, 1
        )
        # ShellExecuteW 返回值 > 32 表示成功
        return ret > 32
    except Exception as e:
        print(f"提权重启失败: {e}")
        return False


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

    def _b64decode(self, s):
        """容错的 base64 解码，兼容 url-safe 变体与缺失的填充字符"""
        s = s.strip()
        s = s.replace('-', '+').replace('_', '/')
        missing = len(s) % 4
        if missing:
            s += '=' * (4 - missing)
        return base64.b64decode(s).decode('utf-8')

    def parse_ss(self, line):
        """解析 shadowsocks (ss://) 链接，返回节点字典或 None"""
        try:
            uri = line[5:]  # 去掉 'ss://'

            # 提取备注
            remark = '未命名节点'
            if '#' in uri:
                uri, remark = uri.split('#', 1)
                remark = unquote(remark)

            method = password = host = port = None

            if '@' in uri:
                # SIP002 格式: userinfo@host:port?plugin
                userinfo, hostpart = uri.rsplit('@', 1)
                userinfo = unquote(userinfo)
                try:
                    method, password = self._b64decode(userinfo).split(':', 1)
                except Exception:
                    # 少数链接 userinfo 未做 base64 编码
                    if ':' in userinfo:
                        method, password = userinfo.split(':', 1)
                # 去掉 plugin 等查询参数
                if '?' in hostpart:
                    hostpart = hostpart.split('?', 1)[0]
                if ':' in hostpart:
                    host, port = hostpart.rsplit(':', 1)
            else:
                # 旧格式: 整体 base64(method:password@host:port)
                if '?' in uri:
                    uri = uri.split('?', 1)[0]
                decoded = self._b64decode(uri)
                creds, hostpart = decoded.rsplit('@', 1)
                method, password = creds.split(':', 1)
                host, port = hostpart.rsplit(':', 1)

            if host and port and method and password:
                return {
                    'type': 'shadowsocks',
                    'host': host,
                    'port': port,
                    'password': password,
                    'method': method,
                    'remark': remark,
                    'sni': ''
                }
        except Exception as e:
            print(f"解析ss节点失败: {e}, 链接: {line[:30]}...")
        return None

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
                                    'type': 'trojan',
                                    'host': host,
                                    'port': port,
                                    'password': password,
                                    'remark': remark,
                                    'sni': sni
                                })

                    elif line.startswith('ss://'):
                        # 解析 shadowsocks 链接
                        # 支持两种格式:
                        #   SIP002:  ss://base64(method:password)@host:port?plugin#remark
                        #   旧格式:  ss://base64(method:password@host:port)#remark
                        node = self.parse_ss(line)
                        if node:
                            nodes.append(node)

                    elif line.startswith('vmess://'):
                        # 保留原有的vmess解析逻辑
                        vmess_data = base64.b64decode(line[8:]).decode('utf-8')
                        node = json.loads(vmess_data)
                        nodes.append({
                            'type': 'vmess',
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
                        allow_redirects=True,  # 允许重定向
                        proxies={'http': None, 'https': None}  # 禁用代理
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

    def __init__(self, server, port, password, sni=None, http_port=None, node_type='trojan', method=None, allow_lan=False):
        super().__init__()
        self.server = server
        self.port = port
        self.password = password
        self.sni = sni
        self.node_type = node_type      # trojan / shadowsocks
        self.method = method            # shadowsocks 加密方式
        self.allow_lan = allow_lan      # 是否允许局域网设备连接(HTTP 入站)
        # 如果没有指定端口，选择一个随机高端口
        self.http_port = http_port if http_port else self.get_random_port()
        # 供 TUN(tun2socks) 使用的 SOCKS5 入站端口，确保与 http 端口不同
        self.socks_port = self.get_random_port()
        while self.socks_port == self.http_port:
            self.socks_port = self.get_random_port()
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
            
            # 根据协议类型构建 outbound
            if self.node_type == 'shadowsocks':
                outbound = {
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [
                            {
                                "address": self.server,
                                "port": int(self.port),
                                "method": self.method,
                                "password": self.password
                            }
                        ]
                    }
                }
            else:
                # 默认按 trojan 处理
                outbound = {
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

            # HTTP 入站监听地址：允许局域网则绑 0.0.0.0，否则仅本机
            http_listen = "0.0.0.0" if self.allow_lan else "127.0.0.1"

            # Xray 配置 - HTTP 入站(普通/系统代理) + SOCKS 入站(供 TUN 使用)
            config = {
                "inbounds": [
                    {
                        "tag": "http-in",
                        "port": self.http_port,
                        "listen": http_listen,
                        "protocol": "http"
                    },
                    {
                        "tag": "socks-in",
                        "port": self.socks_port,
                        "listen": "127.0.0.1",
                        "protocol": "socks",
                        "settings": {"udp": True}
                    }
                ],
                "outbounds": [outbound],
                "log": {
                    "loglevel": "warning"
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


def build_test_outbound(node):
    """根据节点字典构建 xray outbound(与 ProxyThread.run 中逻辑保持一致)"""
    node_type = node.get('type', 'trojan')
    server = node.get('host', '')
    port = int(node.get('port', 0))
    if node_type == 'shadowsocks':
        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": server,
                    "port": port,
                    "method": node.get('method'),
                    "password": node.get('password')
                }]
            }
        }
    elif node_type == 'vmess':
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": server,
                    "port": port,
                    "users": [{
                        "id": node.get('password'),
                        "alterId": 0,
                        "security": "auto"
                    }]
                }]
            }
        }
    else:
        # 默认按 trojan 处理
        sni = node.get('sni') or server
        return {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": server,
                    "port": port,
                    "password": node.get('password')
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "allowInsecure": True,
                    "serverName": sni
                }
            }
        }


def get_free_port():
    """让操作系统分配一个空闲的本地端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class SpeedTestThread(QThread):
    """并发测试当前订阅下所有节点的真实延迟(毫秒)

    对每个节点单独启动一个仅含本地 HTTP 入站 + 该节点出站的 xray 实例，
    通过该本地代理请求测速 URL 并测量往返耗时。
    latency 语义: >=0 为毫秒数; -1 表示超时/连接失败; -2 表示启动/配置失败。
    """
    result = pyqtSignal(int, int)   # (节点索引, 延迟毫秒 / 负数错误码)
    progress = pyqtSignal(str)      # 进度文本
    test_finished = pyqtSignal()    # 全部测试结束

    TEST_URL = 'http://www.gstatic.com/generate_204'

    def __init__(self, nodes, xray_path, app_data_dir,
                 timeout=5, concurrency=5):
        super().__init__()
        self.nodes = nodes
        self.xray_path = xray_path
        self.app_data_dir = app_data_dir
        self.timeout = timeout
        self.concurrency = concurrency
        self._stop = False
        self._done = 0
        self._total = len(nodes)

    def stop(self):
        self._stop = True

    def _wait_port_ready(self, port, deadline):
        """等待本地端口开始监听，成功返回 True"""
        while time.time() < deadline:
            if self._stop:
                return False
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def _test_one(self, index, node):
        if self._stop:
            return index, -2
        port = get_free_port()
        cfg_path = os.path.join(self.app_data_dir, f'speedtest_{index}_{port}.json')
        proc = None
        try:
            config = {
                "inbounds": [{
                    "tag": "http-in",
                    "port": port,
                    "listen": "127.0.0.1",
                    "protocol": "http"
                }],
                "outbounds": [build_test_outbound(node)],
                "log": {"loglevel": "none"}
            }
            with open(cfg_path, 'w', encoding='utf-8') as f:
                json.dump(config, f)

            proc = subprocess.Popen(
                [self.xray_path, "run", "-c", cfg_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # 等待 xray 本地入站端口就绪(最多 4 秒)
            if not self._wait_port_ready(port, time.time() + 4):
                return index, -2

            if self._stop:
                return index, -2

            proxies = {
                'http': f'http://127.0.0.1:{port}',
                'https': f'http://127.0.0.1:{port}'
            }
            start = time.perf_counter()
            resp = requests.get(
                self.TEST_URL,
                proxies=proxies,
                timeout=self.timeout,
                verify=False
            )
            latency = int((time.perf_counter() - start) * 1000)
            if resp.status_code in (200, 204):
                return index, latency
            return index, -1
        except requests.exceptions.RequestException:
            return index, -1
        except Exception as e:
            print(f"测试节点 {index} 出错: {e}")
            return index, -2
        finally:
            if proc is not None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            try:
                if os.path.exists(cfg_path):
                    os.remove(cfg_path)
            except Exception:
                pass

    def run(self):
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                futures = {
                    executor.submit(self._test_one, i, node): i
                    for i, node in enumerate(self.nodes)
                }
                for future in as_completed(futures):
                    if self._stop:
                        break
                    try:
                        index, latency = future.result()
                    except Exception:
                        index, latency = futures[future], -2
                    self._done += 1
                    self.result.emit(index, latency)
                    self.progress.emit(f"测试进度: {self._done}/{self._total}")
        except Exception as e:
            self.progress.emit(f"测速线程错误: {str(e)}")
        finally:
            self.test_finished.emit()


class NodeDeleteDelegate(QStyledItemDelegate):
    """为下拉列表每一项在右侧绘制一个删除按钮 ✕"""
    BUTTON_WIDTH = 30

    def paint(self, painter, option, index):
        # 先绘制默认的项(文本、选中高亮等)
        super().paint(painter, option, index)
        # 在右侧绘制 ✕
        rect = option.rect
        btn_rect = QRect(
            rect.right() - self.BUTTON_WIDTH, rect.top(),
            self.BUTTON_WIDTH, rect.height()
        )
        painter.save()
        painter.setPen(QColor('#c0392b'))
        painter.drawText(btn_rect, Qt.AlignCenter, '✕')
        painter.restore()

    def sizeHint(self, option, index):
        size = super().sizeHint(option, index)
        size.setWidth(size.width() + self.BUTTON_WIDTH)
        return size


class TrojanUrlViewer(QWidget):
    def __init__(self):
        super().__init__()
        # 基本属性初始化
        self.fetch_thread = None
        self.proxy_thread = None
        self.speedtest_thread = None   # 延迟测试线程
        self.speed_results = {}        # {节点索引: 延迟毫秒/错误码}
        self.nodes = []
        # 多订阅支持
        self.subscriptions = []      # [{'name','url','nodes':[...],'node_index':int}]
        self.current_sub_index = 0   # 当前显示/使用的订阅索引
        # 全局系统代理状态：是否已由本程序写入系统代理设置
        self.system_proxy_active = False
        # TUN 模式状态
        self.tun_process = None       # tun2socks 子进程
        self.tun_active = False       # 是否已建立 TUN 及路由
        self.tun_routes = []          # 已添加、需要在关闭时删除的路由(目标网络)
        self.saved_gateway = None     # 启用 TUN 前的物理默认网关
        
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

        # 图标文件路径(优先 256x256.ico)
        icon_path = get_app_icon_path()

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

                    # 恢复订阅列表（新格式）
                    if 'subscriptions' in config and config['subscriptions']:
                        self.subscriptions = config['subscriptions']
                    # 向后兼容：把旧的单一 all_nodes 迁移成一个"默认订阅"
                    elif 'all_nodes' in config and config['all_nodes']:
                        print("检测到旧版配置，迁移为默认订阅")
                        self.subscriptions = [{
                            'name': '默认订阅',
                            'url': config.get('last_url', ''),
                            'nodes': config['all_nodes'],
                            'node_index': config.get('last_node_index', 0)
                        }]

                    # 恢复当前订阅索引
                    self.current_sub_index = config.get('current_sub_index', 0)
                    if not (0 <= self.current_sub_index < len(self.subscriptions)):
                        self.current_sub_index = 0

                    # 填充订阅下拉框
                    self.refresh_sub_combo()
                    # 填充当前订阅的节点
                    self.load_current_subscription_nodes()

                    # 恢复HTTP端口设置
                    if 'http_port' in config and hasattr(self, 'port_input'):
                        self.port_input.setText(config['http_port'])

                    # 恢复全局系统代理开关(不触发信号，避免加载时误操作)
                    if 'system_proxy' in config and hasattr(self, 'system_proxy_checkbox'):
                        self.system_proxy_checkbox.blockSignals(True)
                        self.system_proxy_checkbox.setChecked(bool(config['system_proxy']))
                        self.system_proxy_checkbox.blockSignals(False)

                    # 恢复 TUN 开关(不触发信号)
                    if 'tun_mode' in config and hasattr(self, 'tun_checkbox'):
                        self.tun_checkbox.blockSignals(True)
                        self.tun_checkbox.setChecked(bool(config['tun_mode']))
                        self.tun_checkbox.blockSignals(False)

                    # 恢复局域网访问开关(不触发信号)
                    if 'allow_lan' in config and hasattr(self, 'lan_checkbox'):
                        self.lan_checkbox.blockSignals(True)
                        self.lan_checkbox.setChecked(bool(config['allow_lan']))
                        self.lan_checkbox.blockSignals(False)

        except Exception as e:
            print(f"加载应用配置时出错: {e}")

    def current_subscription(self):
        """返回当前选中的订阅字典，没有则返回 None"""
        if 0 <= self.current_sub_index < len(self.subscriptions):
            return self.subscriptions[self.current_sub_index]
        return None

    def refresh_sub_combo(self):
        """根据 self.subscriptions 刷新订阅下拉框"""
        self.sub_combo.blockSignals(True)
        self.sub_combo.clear()
        for sub in self.subscriptions:
            self.sub_combo.addItem(sub.get('name', '未命名订阅'))
        if 0 <= self.current_sub_index < len(self.subscriptions):
            self.sub_combo.setCurrentIndex(self.current_sub_index)
        self.sub_combo.blockSignals(False)

    def load_current_subscription_nodes(self):
        """把当前订阅的节点加载到节点下拉框"""
        sub = self.current_subscription()
        self.node_combo.blockSignals(True)
        self.node_combo.clear()
        if sub is not None:
            self.nodes = sub.get('nodes', [])
            for node in self.nodes:
                self.node_combo.addItem(f"{node['remark']}")
            idx = sub.get('node_index', 0)
            if 0 <= idx < len(self.nodes):
                self.node_combo.setCurrentIndex(idx)
        else:
            self.nodes = []
        self.node_combo.blockSignals(False)

    def on_sub_changed(self, index):
        """切换订阅时更新显示的节点"""
        if 0 <= index < len(self.subscriptions):
            # 切换订阅会使正在进行的延迟测试节点索引失效，先停止它
            if self.speedtest_thread and self.speedtest_thread.isRunning():
                self.speedtest_thread.stop()
                self.speedtest_thread.wait()
            self.speed_results = {}
            self.current_sub_index = index
            self.load_current_subscription_nodes()
            self.save_config()

    def generate_sub_name(self, url):
        """为新订阅生成一个默认且唯一的名称"""
        existing_names = {s.get('name', '') for s in self.subscriptions}
        n = len(self.subscriptions) + 1
        name = f"订阅{n}"
        while name in existing_names:
            n += 1
            name = f"订阅{n}"
        return name

    def delete_subscription(self):
        """删除当前选中的订阅"""
        try:
            sub = self.current_subscription()
            if sub is None:
                return
            name = sub.get('name', '未命名订阅')
            reply = QMessageBox.question(
                self, '删除订阅', f'确定要删除订阅"{name}"吗？',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return
            del self.subscriptions[self.current_sub_index]
            if self.current_sub_index >= len(self.subscriptions):
                self.current_sub_index = max(0, len(self.subscriptions) - 1)
            self.refresh_sub_combo()
            self.load_current_subscription_nodes()
            self.save_config()
        except Exception as e:
            print(f"删除订阅时出错: {e}")

    def save_config(self, save_url=True):
        try:
            if not os.path.exists(self.app_data_dir):
                os.makedirs(self.app_data_dir)

            # 把当前节点选择记录到对应订阅里
            sub = self.current_subscription()
            if sub is not None:
                node_index = self.node_combo.currentIndex()
                if node_index >= 0:
                    sub['node_index'] = node_index

            config = {
                'subscriptions': self.subscriptions,
                'current_sub_index': self.current_sub_index,
                'auto_connect': True
            }

            # 保存HTTP端口设置
            if hasattr(self, 'port_input'):
                config['http_port'] = self.port_input.text().strip()

            # 保存全局系统代理开关状态
            if hasattr(self, 'system_proxy_checkbox'):
                config['system_proxy'] = self.system_proxy_checkbox.isChecked()

            # 保存 TUN 开关状态
            if hasattr(self, 'tun_checkbox'):
                config['tun_mode'] = self.tun_checkbox.isChecked()

            # 保存局域网访问开关状态
            if hasattr(self, 'lan_checkbox'):
                config['allow_lan'] = self.lan_checkbox.isChecked()

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
            
            # 把获取到的节点保存为一个订阅
            if hasattr(self.fetch_thread, 'nodes') and self.fetch_thread.nodes:
                nodes = self.fetch_thread.nodes
                url = getattr(self.fetch_thread, 'url', '')
                print(f"成功获取到 {len(nodes)} 个节点")

                # 订阅名称：优先用用户输入，否则自动生成
                name = self.name_input.text().strip()

                # 若已存在相同 URL 的订阅则更新，否则新增
                existing_index = None
                for i, s in enumerate(self.subscriptions):
                    if s.get('url') and s.get('url') == url:
                        existing_index = i
                        break

                if existing_index is not None:
                    sub = self.subscriptions[existing_index]
                    sub['nodes'] = nodes
                    sub['node_index'] = 0
                    if name:
                        sub['name'] = name
                    self.current_sub_index = existing_index
                else:
                    if not name:
                        name = self.generate_sub_name(url)
                    self.subscriptions.append({
                        'name': name,
                        'url': url,
                        'nodes': nodes,
                        'node_index': 0
                    })
                    self.current_sub_index = len(self.subscriptions) - 1

                # 刷新界面
                self.refresh_sub_combo()
                self.load_current_subscription_nodes()

                # 清空输入框
                self.input_box.clear()
                self.name_input.clear()

                # 保存配置
                self.save_config()

            else:
                print("没有获取到新节点，保留现有订阅")
                if not self.nodes:
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
        self.setWindowTitle(f'ProxyByUrl - {APP_VERSION}')  # 版本号见文件开头的 APP_VERSION
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
        
        # 订阅切换区域
        sub_layout = QHBoxLayout()
        sub_label = QLabel('订阅(&U)：')
        self.sub_combo = QComboBox()
        self.sub_combo.setMinimumWidth(200)
        self.sub_combo.currentIndexChanged.connect(self.on_sub_changed)
        sub_label.setBuddy(self.sub_combo)
        self.delete_sub_button = QPushButton('删除订阅(&E)')
        self.delete_sub_button.clicked.connect(self.delete_subscription)
        sub_layout.addWidget(sub_label)
        sub_layout.addWidget(self.sub_combo)
        sub_layout.addWidget(self.delete_sub_button)
        sub_layout.addStretch()
        layout.addLayout(sub_layout)

        # URL输入区域
        url_layout = QHBoxLayout()
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText('订阅名称(可留空)')
        self.name_input.setMaximumWidth(160)
        self.input_box = QLineEdit()
        self.input_box.setPlaceholderText('请输入订阅URL...')
        self.input_box.returnPressed.connect(self.on_parse_click)

        # 使用 QShortcut 为输入框添加 Alt+D 快捷键
        shortcut = QShortcut(QKeySequence("Alt+D"), self)
        shortcut.activated.connect(lambda: self.input_box.setFocus())

        self.parse_button = QPushButton('添加/更新订阅(&G)')  # 添加Alt+G快捷键
        self.parse_button.clicked.connect(self.on_parse_click)
        url_layout.addWidget(self.name_input)
        url_layout.addWidget(self.input_box)
        url_layout.addWidget(self.parse_button)
        layout.addLayout(url_layout)
        
        # 节点选择区域
        node_layout = QHBoxLayout()
        node_label = QLabel('节点选择(&N)：')  # 添加带快捷键的标签
        self.node_combo = QComboBox()
        self.node_combo.setMinimumWidth(200)
        self.node_combo.currentIndexChanged.connect(self.on_node_changed)
        # 给下拉列表每项加删除按钮 ✕
        self.node_combo.setItemDelegate(NodeDeleteDelegate(self.node_combo))
        self.node_combo.view().viewport().installEventFilter(self)
        node_label.setBuddy(self.node_combo)  # 将标签与下拉框关联
        self.share_button = QPushButton('分享节点(&C)')      # 复制当前节点链接到剪贴板
        self.share_button.clicked.connect(self.share_to_clipboard)
        self.import_button = QPushButton('从剪贴板导入(&I)')  # 从剪贴板解析链接导入节点
        self.import_button.clicked.connect(self.import_from_clipboard)
        self.speedtest_button = QPushButton('测试延迟(&M)')   # 测试当前订阅所有节点的延迟
        self.speedtest_button.setToolTip('依次为每个节点启动临时代理并测量真实往返毫秒数')
        self.speedtest_button.clicked.connect(self.start_speed_test)
        node_layout.addWidget(node_label)
        node_layout.addWidget(self.node_combo)
        node_layout.addWidget(self.share_button)
        node_layout.addWidget(self.import_button)
        node_layout.addWidget(self.speedtest_button)
        node_layout.addStretch()
        layout.addLayout(node_layout)
        
        # 添加HTTP端口输入区域
        port_layout = QHBoxLayout()
        port_label = QLabel('HTTP端口(&P)：')
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText('留空使用随机端口')
        self.port_input.setText('')  # 默认为空
        self.port_input.setMaximumWidth(150)
        port_label.setBuddy(self.port_input)
        # 全局系统代理开关
        self.system_proxy_checkbox = QCheckBox('全局系统代理(&Y)')
        self.system_proxy_checkbox.setToolTip('开启后所有应用自动走此代理，无需单独配置端口')
        self.system_proxy_checkbox.stateChanged.connect(self.on_system_proxy_toggled)
        # TUN 模式(虚拟网卡)开关
        self.tun_checkbox = QCheckBox('TUN模式(&U)')
        self.tun_checkbox.setToolTip('创建虚拟网卡接管全部流量(需要管理员权限及 tun2socks.exe / wintun.dll)')
        self.tun_checkbox.stateChanged.connect(self.on_tun_toggled)
        # 允许局域网访问开关
        self.lan_checkbox = QCheckBox('允许局域网访问(&L)')
        self.lan_checkbox.setToolTip('开启后同一局域网的其它设备可用「本机IP:端口」连接此HTTP代理')
        self.lan_checkbox.stateChanged.connect(self.on_lan_toggled)
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_input)
        port_layout.addSpacing(20)
        port_layout.addWidget(self.system_proxy_checkbox)
        port_layout.addSpacing(10)
        port_layout.addWidget(self.tun_checkbox)
        port_layout.addSpacing(10)
        port_layout.addWidget(self.lan_checkbox)
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
        # 限制日志文本上限，避免长时间运行时文档无限增长拖垮界面(导致托盘无法唤出)
        self.status_browser.document().setMaximumBlockCount(500)

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
        # 图标文件路径(优先 256x256.ico)
        icon_path = get_app_icon_path()

        # 创建系统托盘图标
        self.tray_icon = QSystemTrayIcon(self)
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        else:
            print(f"找不到图标文件: {icon_path}")

        # 创建托盘菜单
        tray_menu = QMenu()

        # 添加显示/隐藏主窗口菜单项
        self.show_action = tray_menu.addAction('显示主窗口(&S)')
        self.show_action.triggered.connect(self.toggle_window)

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

    def toggle_window(self):
        """切换窗口显示/隐藏状态"""
        try:
            if not self.isVisible() or self.isMinimized():
                # Windows特定的窗口激活方法 - 使用 AttachThreadInput 技巧绕过权限限制
                if sys.platform == 'win32':
                    try:
                        hwnd = int(self.winId())

                        # 获取前台窗口的线程ID
                        foreground_hwnd = ctypes.windll.user32.GetForegroundWindow()
                        foreground_thread_id = ctypes.windll.user32.GetWindowThreadProcessId(foreground_hwnd, None)
                        current_thread_id = ctypes.windll.kernel32.GetCurrentThreadId()

                        # 附加到前台线程（关键步骤）
                        attached = False
                        if foreground_thread_id != current_thread_id:
                            attached = ctypes.windll.user32.AttachThreadInput(foreground_thread_id, current_thread_id, True)

                        # 先恢复窗口状态
                        self.setWindowState(self.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)
                        self.show()

                        # 多种方法确保窗口到前台
                        ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                        ctypes.windll.user32.BringWindowToTop(hwnd)
                        ctypes.windll.user32.SetForegroundWindow(hwnd)
                        ctypes.windll.user32.SetActiveWindow(hwnd)

                        # 分离线程
                        if attached:
                            ctypes.windll.user32.AttachThreadInput(foreground_thread_id, current_thread_id, False)

                    except Exception as e:
                        print(f"Windows特定激活失败: {e}")
                        self.setWindowState(self.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)
                        self.show()
                else:
                    self.setWindowState(self.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)
                    self.show()

                self.activateWindow()
                self.raise_()

                if hasattr(self, 'show_action'):
                    self.show_action.setText('隐藏主窗口(&S)')
            else:
                self.hide()
                if hasattr(self, 'show_action'):
                    self.show_action.setText('显示主窗口(&S)')

        except Exception as e:
            print(f"切换窗口显示状态时出错: {e}")
            try:
                self.setWindowState(Qt.WindowNoState)
                self.show()
                self.activateWindow()
                self.raise_()
                if sys.platform == 'win32':
                    hwnd = int(self.winId())
                    ctypes.windll.user32.SetForegroundWindow(hwnd)
            except:
                pass

    def tray_icon_activated(self, reason):
        """处理托盘图标的点击事件"""
        # 单击(Trigger)与双击(DoubleClick)都强制显示并置顶，避免“切换”逻辑
        # 在窗口被其它窗口盖住时反而把它隐藏，造成“唤不出来”的错觉。
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.show_main_window()

    def show_main_window(self):
        """强制把主窗口显示到前台(不做隐藏切换)"""
        try:
            self.setWindowState(self.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)
            self.showNormal()
            self.show()
            self.raise_()
            self.activateWindow()
            if sys.platform == 'win32':
                try:
                    hwnd = int(self.winId())
                    foreground_hwnd = ctypes.windll.user32.GetForegroundWindow()
                    foreground_thread_id = ctypes.windll.user32.GetWindowThreadProcessId(foreground_hwnd, None)
                    current_thread_id = ctypes.windll.kernel32.GetCurrentThreadId()
                    attached = False
                    if foreground_thread_id != current_thread_id:
                        attached = ctypes.windll.user32.AttachThreadInput(foreground_thread_id, current_thread_id, True)
                    ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                    ctypes.windll.user32.BringWindowToTop(hwnd)
                    ctypes.windll.user32.SetForegroundWindow(hwnd)
                    ctypes.windll.user32.SetActiveWindow(hwnd)
                    if attached:
                        ctypes.windll.user32.AttachThreadInput(foreground_thread_id, current_thread_id, False)
                except Exception as e:
                    print(f"Windows 前台激活失败: {e}")
            if hasattr(self, 'show_action'):
                self.show_action.setText('隐藏主窗口(&S)')
        except Exception as e:
            print(f"显示主窗口时出错: {e}")

    def quit_app(self):
        """完全退出程序"""
        try:
            # 保存配置
            self.save_config()

            # 退出前务必拆除 TUN 与系统代理，否则会导致系统无法上网
            if self.tun_active:
                self.disable_tun()
            if self.system_proxy_active:
                self.disable_system_proxy()

            # 停止延迟测试
            if hasattr(self, 'speedtest_thread') and self.speedtest_thread and self.speedtest_thread.isRunning():
                self.speedtest_thread.stop()
                self.speedtest_thread.wait()

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
            allow_lan = hasattr(self, 'lan_checkbox') and self.lan_checkbox.isChecked()
            self.proxy_thread = ProxyThread(
                node_info['host'],
                node_info['port'],
                node_info['password'],
                node_info.get('sni'),
                http_port,  # 传入用户指定的端口，如果为None则使用随机端口
                node_type=node_info.get('type', 'trojan'),
                method=node_info.get('method'),
                allow_lan=allow_lan
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

                    # 若勾选了全局系统代理，则在代理就绪后应用
                    if hasattr(self, 'system_proxy_checkbox') and self.system_proxy_checkbox.isChecked():
                        self.enable_system_proxy()

                    # 若勾选了 TUN 模式，则在代理就绪后建立虚拟网卡
                    if hasattr(self, 'tun_checkbox') and self.tun_checkbox.isChecked() and is_admin():
                        self.enable_tun()

                    # 若允许局域网访问，显示局域网地址
                    if hasattr(self, 'lan_checkbox') and self.lan_checkbox.isChecked():
                        self.show_lan_address()
        except Exception as e:
            print(f"更新代理端口状态时出错: {e}")

    def stop_proxy(self):
        try:
            # 停止代理前先拆除 TUN 与系统代理，避免流量指向已关闭的端口导致断网
            if self.tun_active:
                self.disable_tun()
            if self.system_proxy_active:
                self.disable_system_proxy()

            if self.proxy_thread:
                self.proxy_thread.stop()
                self.proxy_thread.wait()
                self.proxy_thread = None

            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.restart_button.setEnabled(False)  # 禁用重启按钮
            self.status_label.setText("代理状态：未运行")
            
        except Exception as e:
            self.browser.setText(f"停止代理时发生错误: {str(e)}")

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

    # ---------------- 节点延迟测试 ----------------
    def ensure_xray_path(self):
        """确保固定目录下存在 xray.exe，返回其路径，失败返回 None"""
        xray_dest = os.path.join(self.app_data_dir, 'xray.exe')
        if not os.path.exists(xray_dest):
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(os.path.abspath(__file__))
            xray_src = os.path.join(base_path, 'xray.exe')
            if os.path.exists(xray_src):
                try:
                    shutil.copy2(xray_src, xray_dest)
                except Exception as e:
                    print(f"复制 xray.exe 失败: {e}")
        return xray_dest if os.path.exists(xray_dest) else None

    def start_speed_test(self):
        """开始测试当前订阅下所有节点的延迟"""
        try:
            # 已有测试在跑则视为停止
            if self.speedtest_thread and self.speedtest_thread.isRunning():
                self.speedtest_thread.stop()
                self.speedtest_button.setText('正在停止...')
                self.speedtest_button.setEnabled(False)
                return

            if not self.nodes:
                self.browser.setText('当前订阅没有可测试的节点')
                return

            xray_path = self.ensure_xray_path()
            if not xray_path:
                self.browser.setText('找不到 xray.exe，无法测试延迟')
                return

            # 重置结果，并把下拉框每项恢复为基础名称 + “测试中”
            self.speed_results = {}
            self.node_combo.blockSignals(True)
            for i, node in enumerate(self.nodes):
                self.node_combo.setItemText(i, f"{node['remark']}  [测试中…]")
            self.node_combo.blockSignals(False)

            self.status_browser.append(f"开始测试 {len(self.nodes)} 个节点的延迟...")
            self.browser.setText('正在测试节点延迟，请稍候...')
            self.speedtest_button.setText('停止测试(&M)')

            self.speedtest_thread = SpeedTestThread(
                list(self.nodes), xray_path, self.app_data_dir,
                timeout=5, concurrency=5
            )
            self.speedtest_thread.result.connect(self.on_speed_result)
            self.speedtest_thread.progress.connect(self.on_speed_progress)
            self.speedtest_thread.test_finished.connect(self.on_speed_finished)
            self.speedtest_thread.start()
        except Exception as e:
            self.browser.setText(f'启动延迟测试出错: {str(e)}')
            self.speedtest_button.setText('测试延迟(&M)')
            self.speedtest_button.setEnabled(True)

    def _latency_text(self, latency):
        """把延迟数值转成显示文本"""
        if latency == -1:
            return '超时'
        if latency == -2:
            return '失败'
        return f'{latency} ms'

    def on_speed_result(self, index, latency):
        """收到单个节点的测试结果"""
        self.speed_results[index] = latency
        if 0 <= index < len(self.nodes):
            base = self.nodes[index]['remark']
            self.node_combo.blockSignals(True)
            self.node_combo.setItemText(index, f"{base}  [{self._latency_text(latency)}]")
            self.node_combo.blockSignals(False)
        self.render_speed_summary()

    def on_speed_progress(self, message):
        self.status_browser.append(message)

    def on_speed_finished(self):
        """全部节点测试结束"""
        self.speedtest_button.setText('测试延迟(&M)')
        self.speedtest_button.setEnabled(True)
        self.status_browser.append('节点延迟测试完成')
        self.render_speed_summary(final=True)

    def render_speed_summary(self, final=False):
        """在下方信息区渲染按延迟升序排列的结果表"""
        rows = []
        for i, node in enumerate(self.nodes):
            if i in self.speed_results:
                rows.append((i, node, self.speed_results[i]))
        # 排序：有效毫秒在前(升序)，超时/失败排最后
        def sort_key(item):
            lat = item[2]
            return (0, lat) if lat >= 0 else (1, 0)
        rows.sort(key=sort_key)

        title = '节点延迟测试结果' + ('' if final else '（测试中…）')
        html = [
            f'<h3>{title}</h3>',
            '<table border="1" cellspacing="0" cellpadding="4" '
            'style="border-collapse:collapse;">',
            '<tr><th>排名</th><th>节点</th><th>服务器</th><th>延迟</th></tr>'
        ]
        for rank, (i, node, lat) in enumerate(rows, 1):
            if lat >= 0:
                color = '#27ae60' if lat < 500 else ('#e67e22' if lat < 1000 else '#c0392b')
            else:
                color = '#7f8c8d'
            remark = str(node.get('remark', '')).replace('<', '&lt;').replace('>', '&gt;')
            host = str(node.get('host', '')).replace('<', '&lt;').replace('>', '&gt;')
            html.append(
                f'<tr><td align="center">{rank}</td>'
                f'<td>{remark}</td>'
                f'<td>{host}:{node.get("port", "")}</td>'
                f'<td style="color:{color};" align="right">{self._latency_text(lat)}</td></tr>'
            )
        html.append('</table>')
        tested = len(rows)
        html.append(f'<p>已测试 {tested}/{len(self.nodes)} 个节点</p>')
        self.browser.setHtml('\n'.join(html))

    def on_node_changed(self, index):
        # 当节点选择改变时保存配置
        self.save_config()

    # ---------------- 全局系统代理 ----------------
    INTERNET_SETTINGS_KEY = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    PROXY_BYPASS = 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>'

    def _refresh_wininet(self):
        """通知系统代理设置已变更并立即生效"""
        try:
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
        except Exception as e:
            print(f"刷新系统代理设置时出错: {e}")

    def _write_system_proxy(self, enable, proxy_addr=None):
        """写入/清除 Windows 系统代理注册表设置"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS_KEY,
                0, winreg.KEY_WRITE
            )
            if enable and proxy_addr:
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, proxy_addr)
                winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, self.PROXY_BYPASS)
            else:
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            self._refresh_wininet()
            return True
        except Exception as e:
            print(f"写入系统代理设置时出错: {e}")
            return False

    def enable_system_proxy(self):
        """把当前运行的代理设为系统全局代理"""
        if not (self.proxy_thread and hasattr(self.proxy_thread, 'http_port')):
            return
        port = self.proxy_thread.http_port
        addr = f'127.0.0.1:{port}'
        if self._write_system_proxy(True, addr):
            self.system_proxy_active = True
            self.status_browser.append(f"已开启全局系统代理: {addr}")

    def disable_system_proxy(self):
        """关闭系统全局代理(仅当由本程序开启时)"""
        if self._write_system_proxy(False):
            if self.system_proxy_active:
                self.status_browser.append("已关闭全局系统代理")
            self.system_proxy_active = False

    def on_system_proxy_toggled(self, state):
        """勾选框切换：立即应用或撤销系统代理"""
        checked = self.system_proxy_checkbox.isChecked()
        if checked:
            # 仅在代理已运行时立即生效；否则等启动代理后自动应用
            if self.proxy_thread:
                self.enable_system_proxy()
            else:
                self.status_browser.append("已勾选全局系统代理，将在代理启动后生效")
        else:
            self.disable_system_proxy()
        self.save_config()

    # ---------------- TUN 模式(虚拟网卡) ----------------
    TUN_NAME = 'ProxyByUrlTun'      # 虚拟网卡名称
    TUN_ADDR = '198.18.0.1'         # 虚拟网卡地址(gateway)
    TUN_MASK = '255.255.255.0'
    TUN_DNS = '8.8.8.8'             # 通过 TUN 隧道解析的 DNS

    def _run_cmd(self, args):
        """执行一条系统命令，返回 (returncode, output)"""
        try:
            result = subprocess.run(
                args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            out = result.stdout.decode('gbk', errors='ignore').strip()
            return result.returncode, out
        except Exception as e:
            return -1, str(e)

    def get_default_gateway(self):
        """解析当前物理默认网关(排除 TUN 自身)"""
        try:
            code, out = self._run_cmd(['route', 'print', '-4', '0.0.0.0'])
            best_gw, best_metric = None, None
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == '0.0.0.0' and parts[1] == '0.0.0.0':
                    gw = parts[2]
                    if gw.lower() == 'on-link' or gw == self.TUN_ADDR:
                        continue
                    try:
                        metric = int(parts[4])
                    except ValueError:
                        metric = 9999
                    if best_metric is None or metric < best_metric:
                        best_gw, best_metric = gw, metric
            return best_gw
        except Exception as e:
            print(f"获取默认网关失败: {e}")
            return None

    def resolve_server_ips(self, host):
        """把节点服务器域名解析为 IP 列表(已是 IP 则直接返回)"""
        try:
            socket.inet_aton(host)
            return [host]
        except OSError:
            pass
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET)
            return list({info[4][0] for info in infos})
        except Exception as e:
            print(f"解析服务器地址失败: {e}")
            return []

    def find_tun2socks(self):
        """定位 tun2socks.exe(与 xray 同目录)"""
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
        candidate = os.path.join(base_path, 'tun2socks.exe')
        if os.path.exists(candidate):
            return candidate, base_path
        return None, base_path

    def enable_tun(self):
        """建立 TUN 虚拟网卡并配置路由，使全部流量走代理"""
        try:
            if self.tun_active:
                return
            if not is_admin():
                self.status_browser.append("[TUN] 需要管理员权限，无法启用")
                return
            if not (self.proxy_thread and hasattr(self.proxy_thread, 'socks_port')):
                self.status_browser.append("[TUN] 代理未运行，无法启用")
                return

            tun2socks, base_path = self.find_tun2socks()
            if not tun2socks:
                self.status_browser.append("[TUN] 找不到 tun2socks.exe，请放到程序目录")
                return
            if not os.path.exists(os.path.join(base_path, 'wintun.dll')):
                self.status_browser.append("[TUN] 找不到 wintun.dll，请放到程序目录")
                return

            socks_port = self.proxy_thread.socks_port

            # 1) 记录物理默认网关，并为代理服务器 IP 添加绕过路由(避免死循环)
            self.saved_gateway = self.get_default_gateway()
            if not self.saved_gateway:
                self.status_browser.append("[TUN] 无法确定物理默认网关，已中止")
                return
            self.status_browser.append(f"[TUN] 物理默认网关: {self.saved_gateway}")

            node = self.nodes[self.node_combo.currentIndex()] if self.nodes else None
            server_host = node.get('host') if node else self.proxy_thread.server
            for ip in self.resolve_server_ips(server_host):
                self._run_cmd(['route', 'add', ip, 'mask', '255.255.255.255', self.saved_gateway, 'metric', '1'])
                self.tun_routes.append(ip)
                self.status_browser.append(f"[TUN] 绕过路由: {ip} -> {self.saved_gateway}")

            # 2) 启动 tun2socks(输出重定向到日志文件，便于诊断)
            self.tun_log_path = os.path.join(self.app_data_dir, 'tun2socks.log')
            tun_cmd = [tun2socks,
                       '-device', f'tun://{self.TUN_NAME}',
                       '-proxy', f'socks5://127.0.0.1:{socks_port}',
                       '-loglevel', 'info']
            self.status_browser.append(f"[TUN] 启动: {' '.join(tun_cmd)}")
            self._tun_log_file = open(self.tun_log_path, 'w', encoding='utf-8', errors='ignore')
            self.tun_process = subprocess.Popen(
                tun_cmd,
                cwd=base_path,
                stdout=self._tun_log_file, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            self.status_browser.append("[TUN] 正在创建虚拟网卡...")

            # 3) 等待网卡出现，然后配置 IP / 路由 / DNS
            if not self._wait_for_tun_adapter(timeout=10):
                # 若进程已退出，说明 tun2socks 启动失败
                if self.tun_process and self.tun_process.poll() is not None:
                    self.status_browser.append(f"[TUN] tun2socks 已退出(code={self.tun_process.returncode})")
                else:
                    self.status_browser.append("[TUN] 网卡未按预期名称出现，当前接口列表如下")
                    self._dump_interfaces()
                self._show_tun_log()
                self.status_browser.append("[TUN] 虚拟网卡创建失败，已回滚")
                self.disable_tun()
                return

            # 配置网卡地址
            self._run_cmd(['netsh', 'interface', 'ip', 'set', 'address',
                           f'name={self.TUN_NAME}', 'static', self.TUN_ADDR, self.TUN_MASK])
            # 用两条 /1 路由覆盖默认路由(不删除原默认路由)
            self._run_cmd(['route', 'add', '0.0.0.0', 'mask', '128.0.0.0', self.TUN_ADDR, 'metric', '1'])
            self._run_cmd(['route', 'add', '128.0.0.0', 'mask', '128.0.0.0', self.TUN_ADDR, 'metric', '1'])
            self.tun_routes.extend(['0.0.0.0', '128.0.0.0'])
            # DNS 走隧道
            self._run_cmd(['netsh', 'interface', 'ip', 'set', 'dns',
                           f'name={self.TUN_NAME}', 'static', self.TUN_DNS])

            self.tun_active = True
            self.status_browser.append("[TUN] TUN 模式已启用，全部流量经虚拟网卡代理")
        except Exception as e:
            self.status_browser.append(f"[TUN] 启用失败: {e}")
            self.disable_tun()

    def _wait_for_tun_adapter(self, timeout=10):
        """轮询等待虚拟网卡出现"""
        for _ in range(timeout * 2):
            code, out = self._run_cmd(['netsh', 'interface', 'ip', 'show', 'interfaces'])
            if self.TUN_NAME in out:
                return True
            # tun2socks 若已退出则失败
            if self.tun_process and self.tun_process.poll() is not None:
                return False
            time.sleep(0.5)
        return False

    def _show_tun_log(self):
        """把 tun2socks 日志尾部输出到状态栏"""
        try:
            if getattr(self, '_tun_log_file', None):
                try:
                    self._tun_log_file.flush()
                except Exception:
                    pass
            with open(self.tun_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            if not lines:
                self.status_browser.append("[tun2socks] (无输出)")
            for ln in lines[-20:]:
                self.status_browser.append(f"[tun2socks] {ln.rstrip()}")
        except Exception as e:
            print(f"读取 tun2socks 日志失败: {e}")

    def _dump_interfaces(self):
        """把当前网络接口列表输出到状态栏"""
        try:
            code, out = self._run_cmd(['netsh', 'interface', 'ip', 'show', 'interfaces'])
            for ln in out.splitlines():
                if ln.strip():
                    self.status_browser.append(f"[接口] {ln.rstrip()}")
        except Exception as e:
            print(f"读取接口列表失败: {e}")

    def disable_tun(self):
        """拆除 TUN 路由与虚拟网卡"""
        try:
            # 删除本程序添加的路由
            for dest in self.tun_routes:
                self._run_cmd(['route', 'delete', dest])
            self.tun_routes = []

            # 结束 tun2socks 进程(虚拟网卡随之消失)
            if self.tun_process:
                try:
                    self.tun_process.terminate()
                    self.tun_process.wait(timeout=3)
                except Exception:
                    pass
                self.tun_process = None
            self._run_cmd(['taskkill', '/F', '/IM', 'tun2socks.exe'])

            # 关闭日志文件句柄
            if getattr(self, '_tun_log_file', None):
                try:
                    self._tun_log_file.close()
                except Exception:
                    pass
                self._tun_log_file = None

            if self.tun_active:
                self.status_browser.append("[TUN] TUN 模式已关闭")
            self.tun_active = False
            self.saved_gateway = None
        except Exception as e:
            print(f"关闭 TUN 时出错: {e}")

    def on_tun_toggled(self, state):
        """TUN 勾选框切换"""
        checked = self.tun_checkbox.isChecked()
        if checked:
            if not is_admin():
                reply = QMessageBox.question(
                    self, 'TUN 模式',
                    'TUN 模式需要管理员权限，是否以管理员身份重新启动程序？',
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                )
                if reply == QMessageBox.Yes:
                    if relaunch_as_admin():
                        self.save_config()
                        QApplication.instance().quit()
                        return
                    else:
                        QMessageBox.warning(self, 'TUN 模式', '提权失败，无法启用 TUN')
                # 取消勾选
                self.tun_checkbox.blockSignals(True)
                self.tun_checkbox.setChecked(False)
                self.tun_checkbox.blockSignals(False)
                return
            if self.proxy_thread:
                self.enable_tun()
            else:
                self.status_browser.append("[TUN] 已勾选，将在代理启动后生效")
        else:
            self.disable_tun()
        self.save_config()

    # ---------------- 局域网访问 ----------------
    FIREWALL_RULE_NAME = 'ProxyByUrl LAN'

    def get_lan_ip(self):
        """获取本机在局域网中的 IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))  # 不会真正发包，只为确定出口网卡
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'

    def add_lan_firewall_rule(self):
        """为 xray.exe 添加入站放行规则(需要管理员，best-effort)"""
        try:
            xray_path = os.path.join(self.app_data_dir, 'xray.exe')
            # 先删除同名旧规则避免重复
            self._run_cmd(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                           f'name={self.FIREWALL_RULE_NAME}'])
            code, out = self._run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={self.FIREWALL_RULE_NAME}', 'dir=in', 'action=allow',
                f'program={xray_path}', 'enable=yes', 'profile=private'
            ])
            if code == 0:
                self.status_browser.append("[LAN] 已添加防火墙放行规则")
            else:
                self.status_browser.append("[LAN] 防火墙规则添加失败(可能需管理员权限)，"
                                           "若其它设备连不上，请在防火墙手动放行或允许弹窗")
        except Exception as e:
            print(f"添加防火墙规则失败: {e}")

    def remove_lan_firewall_rule(self):
        """移除入站放行规则"""
        try:
            self._run_cmd(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                           f'name={self.FIREWALL_RULE_NAME}'])
        except Exception as e:
            print(f"移除防火墙规则失败: {e}")

    def show_lan_address(self):
        """在状态栏显示局域网访问地址"""
        try:
            if self.proxy_thread and hasattr(self.proxy_thread, 'http_port'):
                ip = self.get_lan_ip()
                port = self.proxy_thread.http_port
                self.status_browser.append(f"[LAN] 局域网设备请设置 HTTP 代理为: {ip}:{port}")
        except Exception as e:
            print(f"显示局域网地址失败: {e}")

    def on_lan_toggled(self, state):
        """局域网访问勾选框切换"""
        checked = self.lan_checkbox.isChecked()
        if checked:
            self.add_lan_firewall_rule()
            if self.proxy_thread:
                # 需要重新生成配置以改变监听地址
                self.status_browser.append("[LAN] 正在重启代理以应用局域网监听...")
                self.restart_proxy()
            else:
                self.status_browser.append("[LAN] 已勾选，将在代理启动后生效")
        else:
            self.remove_lan_firewall_rule()
            if self.proxy_thread:
                self.status_browser.append("[LAN] 已关闭，正在重启代理仅监听本机...")
                self.restart_proxy()
        self.save_config()

    def eventFilter(self, source, event):
        """捕获下拉列表中点击 ✕ 的事件以删除对应节点"""
        try:
            view = self.node_combo.view()
            if source is view.viewport() and event.type() == QEvent.MouseButtonPress:
                index = view.indexAt(event.pos())
                if index.isValid():
                    rect = view.visualRect(index)
                    if event.pos().x() >= rect.right() - NodeDeleteDelegate.BUTTON_WIDTH:
                        self.delete_node(index.row())
                        return True  # 消费事件，避免误选中该项
        except Exception as e:
            print(f"处理下拉列表点击事件时出错: {e}")
        return super().eventFilter(source, event)

    def delete_node(self, row):
        """删除当前订阅中指定位置的节点"""
        try:
            self.node_combo.hidePopup()
            sub = self.current_subscription()
            if sub is None:
                return
            nodes = sub.get('nodes', [])
            if not (0 <= row < len(nodes)):
                return

            remark = nodes[row].get('remark', '')
            reply = QMessageBox.question(
                self, '删除节点', f'确定要删除节点"{remark}"吗？',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return

            del nodes[row]
            self.load_current_subscription_nodes()
            self.save_config()
            self.status_browser.append(f"已删除节点: {remark}")
        except Exception as e:
            print(f"删除节点时出错: {e}")

    def node_to_link(self, node):
        """把节点字典还原成分享链接(ss:// / trojan:// / vmess://)"""
        try:
            ntype = node.get('type', 'trojan')
            host = node.get('host', '')
            port = node.get('port', '')
            remark = quote(node.get('remark', '') or '')

            if ntype == 'shadowsocks':
                method = node.get('method', '')
                pwd = node.get('password', '')
                userinfo = base64.urlsafe_b64encode(
                    f"{method}:{pwd}".encode('utf-8')
                ).decode('utf-8').rstrip('=')
                return f"ss://{userinfo}@{host}:{port}#{remark}"

            elif ntype == 'vmess':
                obj = {
                    "v": "2",
                    "ps": node.get('remark', ''),
                    "add": host,
                    "port": str(port),
                    "id": node.get('password', ''),
                    "aid": "0",
                    "scy": "auto",
                    "net": "tcp",
                    "type": "none",
                    "host": "",
                    "path": "",
                    "tls": "",
                    "sni": node.get('sni', '')
                }
                raw = json.dumps(obj, ensure_ascii=False).encode('utf-8')
                return "vmess://" + base64.b64encode(raw).decode('utf-8')

            else:  # trojan
                link = f"trojan://{node.get('password', '')}@{host}:{port}"
                sni = node.get('sni')
                if sni:
                    link += f"?sni={sni}"
                link += f"#{remark}"
                return link

        except Exception as e:
            print(f"生成分享链接失败: {e}")
            return None

    def share_to_clipboard(self):
        """把当前选中的节点复制到剪贴板"""
        try:
            index = self.node_combo.currentIndex()
            if index < 0 or not self.nodes or index >= len(self.nodes):
                QMessageBox.information(self, '分享节点', '请先选择一个节点')
                return

            node = self.nodes[index]
            link = self.node_to_link(node)
            if not link:
                QMessageBox.warning(self, '分享节点', '该节点类型暂不支持分享')
                return

            QApplication.clipboard().setText(link)
            self.status_browser.append(f"已复制节点链接到剪贴板: {node.get('remark', '')}")
            if hasattr(self, 'tray_icon'):
                self.tray_icon.showMessage(
                    '分享节点', f"已复制到剪贴板:\n{node.get('remark', '')}",
                    QSystemTrayIcon.Information, 2000
                )
        except Exception as e:
            print(f"分享节点时出错: {e}")

    def get_manual_subscription_index(self):
        """获取(必要时创建)用于手动导入的订阅，返回其索引"""
        for i, s in enumerate(self.subscriptions):
            if s.get('manual'):
                return i
        self.subscriptions.append({
            'name': '手动导入',
            'url': '',
            'nodes': [],
            'node_index': 0,
            'manual': True
        })
        return len(self.subscriptions) - 1

    def import_from_clipboard(self):
        """从剪贴板解析 ss:// / trojan:// / vmess:// 链接并导入"""
        try:
            text = QApplication.clipboard().text().strip()
            if not text:
                QMessageBox.information(self, '从剪贴板导入', '剪贴板为空')
                return

            # 复用 FetchThread 的解析逻辑(逐行识别链接前缀)
            parser = FetchThread('')
            new_nodes = parser.parse_nodes(text)

            if not new_nodes:
                QMessageBox.information(
                    self, '从剪贴板导入',
                    '未在剪贴板中找到有效的 ss:// 或 trojan:// 链接'
                )
                return

            # 把节点追加到"手动导入"订阅
            sub_index = self.get_manual_subscription_index()
            self.subscriptions[sub_index].setdefault('nodes', []).extend(new_nodes)
            self.current_sub_index = sub_index

            self.refresh_sub_combo()
            self.load_current_subscription_nodes()
            # 选中最后导入的节点
            self.node_combo.setCurrentIndex(self.node_combo.count() - 1)
            self.save_config()

            self.status_browser.append(f"已从剪贴板导入 {len(new_nodes)} 个节点")
            QMessageBox.information(
                self, '从剪贴板导入', f'成功导入 {len(new_nodes)} 个节点'
            )
        except Exception as e:
            print(f"从剪贴板导入时出错: {e}")
            QMessageBox.warning(self, '从剪贴板导入', f'导入失败: {e}')

    def setup_firewall_rules(self):
        """配置防火墙规则 - 已禁用，Windows 会在首次运行时自动弹出提示"""
        # 不再自动配置防火墙，让 Windows 在 xray.exe 首次监听端口时弹出提示
        # 用户点击"允许"即可，无需管理员权限
        pass

    def auto_connect(self):
        """自动连接到上次使用的节点"""
        try:
            if self.nodes and self.node_combo.count() > 0:
                self.start_proxy()
        except Exception as e:
            print(f"自动连接时出错: {e}")


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
        # 设置独立的 AppUserModelID，让任务栏使用本程序图标而非 Python 图标
        if sys.platform == 'win32':
            try:
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('ProxyByUrl.App')
            except Exception as e:
                print(f"设置 AppUserModelID 失败: {e}")

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
