import subprocess
import json
import os
import sys
import tempfile
import time
import requests
import zipfile
from urllib.parse import urlparse, unquote
import socket

class XrayProxy:
    def __init__(self, http_port=10809, socks_port=10808):
        self.http_port = http_port
        self.socks_port = socks_port
        self.process = None
        self.config_path = None
        self.xray_path = self.ensure_xray()

    def ensure_xray(self) -> str:
        """确保 xray 可执行文件存在"""
        app_dir = os.path.join(os.path.expanduser("~"), ".xray-proxy")
        os.makedirs(app_dir, exist_ok=True)
        
        xray_exe = os.path.join(app_dir, "xray.exe")
        
        if os.path.exists(xray_exe):
            return xray_exe
            
        print("正在下载 Xray...")
        
        # Xray 下载地址
        download_url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"
        
        try:
            response = requests.get(download_url, stream=True)
            zip_path = os.path.join(app_dir, "xray.zip")
            
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extract("xray.exe", app_dir)
            
            os.remove(zip_path)
            print("Xray 下载完���")
            return xray_exe
            
        except Exception as e:
            print(f"下载 Xray 失败: {str(e)}")
            raise

    def parse_trojan_url(self, url: str) -> dict:
        """解析 Trojan URL"""
        try:
            # 清理输入的 URL，确保只处理一个链接
            url = url.strip()
            if url.count('trojan://') > 1:
                url = url.split('trojan://')[1]
                url = 'trojan://' + url
            
            if not url.startswith('trojan://'):
                raise ValueError('无效的 Trojan 链接')
            
            url = url.replace('trojan://', '')
            
            # 分离密码和服务器信息
            if '@' not in url:
                raise ValueError('无效的 Trojan 链接格式：缺少 @ 符号')
            password = url.split('@')[0]
            remaining = url.split('@')[1]
            
            # 分离主机和端口
            if ':' not in remaining:
                raise ValueError('无效的 Trojan 链接格式：缺少端口号')
            host = remaining.split(':')[0]
            port_part = remaining.split(':')[1]
            
            # 提取端口号
            try:
                port = int(port_part.split('?')[0].split('#')[0])
            except ValueError:
                raise ValueError('无效的端口号')
            
            # 解析参数
            params = {}
            if '?' in remaining:
                query_string = remaining.split('?')[1].split('#')[0]
                for param in query_string.split('&'):
                    if '=' in param:
                        key, value = param.split('=')
                        params[key] = value.strip()
            
            return {
                "password": password.strip(),
                "host": host.strip(),
                "port": port,
                "sni": params.get('sni', host).strip(),
                "allow_insecure": params.get('allowInsecure', 'false').lower() == 'true'
            }
        
        except Exception as e:
            print(f"解析链接时出错: {str(e)}")
            raise

    def generate_config(self, trojan_info: dict) -> str:
        """生成 Xray 配置文件"""
        config = {
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [
                {
                    "port": self.http_port,
                    "protocol": "http",
                    "settings": {},
                    "tag": "http_in",
                    "listen": "127.0.0.1"
                },
                {
                    "port": self.socks_port,
                    "protocol": "socks",
                    "settings": {
                        "udp": True
                    },
                    "tag": "socks_in",
                    "listen": "127.0.0.1"
                }
            ],
            "outbounds": [
                {
                    "protocol": "trojan",
                    "settings": {
                        "servers": [
                            {
                                "address": trojan_info["host"],
                                "port": trojan_info["port"],
                                "password": trojan_info["password"]
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": trojan_info["sni"],
                            "allowInsecure": trojan_info["allow_insecure"]
                        }
                    },
                    "tag": "proxy"
                }
            ]
        }
        
        fd, path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(config, f, indent=2)
        
        self.config_path = path
        return path

    def check_port_available(self, port: int) -> bool:
        """检查端口是否可用"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return True
        except:
            return False

    def find_available_ports(self):
        """找到可用的端口"""
        base_http_port = 10809
        base_socks_port = 10808
        
        for i in range(100):  # 尝试100个端口
            http_port = base_http_port + i
            socks_port = base_socks_port + i
            
            if self.check_port_available(http_port) and self.check_port_available(socks_port):
                return http_port, socks_port
                
        raise Exception("无法找到可用的端口")

    def start_proxy(self, trojan_url: str):
        """启动代理服务"""
        try:
            # 检查并更新端口
            self.http_port, self.socks_port = self.find_available_ports()
            
            trojan_info = self.parse_trojan_url(trojan_url)
            config_path = self.generate_config(trojan_info)
            
            print(f"\n正在启动代理服务...")
            print(f"配置信息:")
            print(f"  服务器: {trojan_info['host']}:{trojan_info['port']}")
            print(f"  SNI: {trojan_info['sni']}")
            print(f"HTTP 代理: 127.0.0.1:{self.http_port}")
            print(f"SOCKS5 代理: 127.0.0.1:{self.socks_port}")
            
            # 使用管理员权限运行 xray（仅在 Windows 上）
            if os.name == 'nt':
                try:
                    cmd = [self.xray_path, "run", "-c", config_path]
                    self.process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                except Exception as e:
                    print(f"尝试以普通权限启动失败，错误: {e}")
                    # 如果普通启动失败，尝试使用管理员权限
                    try:
                        import ctypes
                        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                            print("正在请求管理员权限...")
                            ctypes.windll.shell32.ShellExecuteW(
                                None, 
                                "runas", 
                                sys.executable,
                                f'"{os.path.abspath(__file__)}"', 
                                None, 
                                1
                            )
                            sys.exit(0)
                    except Exception as admin_e:
                        print(f"请求管理员权限失败: {admin_e}")
            else:
                cmd = [self.xray_path, "run", "-c", config_path]
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            
            # 等待服务启动
            time.sleep(2)
            
            if self.process and self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                raise Exception(f"代理服务启动失败:\n{stdout}\n{stderr}")
                
            print("代理服务已启动成功")
            
            # 显示如何配置浏览器
            print("\n=== 浏览器配置说明 ===")
            print("1. Chrome 用户可以安装 SwitchyOmega 插件")
            print("2. 代理配置:")
            print(f"   HTTP 代理: 127.0.0.1:{self.http_port}")
            print(f"   SOCKS5 代理: 127.0.0.1:{self.socks_port}")
            print("3. 建议使用 SOCKS5 代理以获得更好的性能")
            
        except Exception as e:
            print(f"错误: {str(e)}")
            self.stop_proxy()
            sys.exit(1)

    def stop_proxy(self):
        """停止代理服务"""
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None
            
        if self.config_path and os.path.exists(self.config_path):
            os.remove(self.config_path)
            
        print("代理服务已停止")

def main():
    proxy = XrayProxy()
    try:
        trojan_url = input("请输入 Trojan 链接: ").strip()
        proxy.start_proxy(trojan_url)
        
        print("\n代理已启动，按 Ctrl+C 停止服务...")
        
        # 持续监控进程状态
        while True:
            if proxy.process.poll() is not None:
                stdout, stderr = proxy.process.communicate()
                print(f"代理服务意外停止:\n{stderr or stdout}")
                break
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n正在停止服务...")
        proxy.stop_proxy()
    except Exception as e:
        print(f"发生错误: {str(e)}")
        proxy.stop_proxy()

if __name__ == "__main__":
    main() 