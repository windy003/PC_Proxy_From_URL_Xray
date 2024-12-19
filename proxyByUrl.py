import base64
import requests
import re
import json
import os
import subprocess
import sys
import time
from urllib.parse import unquote
from pathlib import Path

class XrayProxy:
    def __init__(self):
        self.process = None
        self.config_path = "config.json"
        self.xray_path = self.get_xray_path()

    def get_xray_path(self):
        """获取xray.exe的路径"""
        # 检查用户目录下的.xray-proxy文件夹
        user_xray_path = Path.home() / '.xray-proxy' / 'xray.exe'
        if user_xray_path.exists():
            return str(user_xray_path)
        
        # 检查当前目录
        if Path('./xray.exe').exists():
            return './xray.exe'
        
        raise Exception("找不到xray.exe，请确保它存在于 C:\\Users\\[用户名]\\.xray-proxy 目录下")

    def create_config(self, trojan_info):
        """创建Xray配置文件"""
        # 在.xray-proxy目录下创建配置文件
        config_dir = Path.home() / '.xray-proxy'
        config_dir.mkdir(exist_ok=True)
        self.config_path = str(config_dir / 'config.json')

        config = {
            "inbounds": [{
                "port": 10808,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                }
            }],
            "outbounds": [{
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": trojan_info['server'],
                        "port": int(trojan_info['port']),
                        "password": trojan_info['password']
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "allowInsecure": True,
                        "serverName": trojan_info['params'].get('sni', trojan_info['server'])
                    }
                }
            }]
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"配置文件已创建: {self.config_path}")

    def start_proxy(self):
        """启动Xray代理"""
        try:
            print(f"使用Xray路径: {self.xray_path}")
            print(f"使用配置文件: {self.config_path}")
            
            self.process = subprocess.Popen(
                [self.xray_path, "-config", self.config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # 等待一小段时间确保进程启动
            time.sleep(1)
            
            if self.process.poll() is None:  # 如果进程还在运行
                print("代理服务已启动，SOCKS5代理地址：127.0.0.1:10808")
                return True
            else:
                # 获取错误输出
                _, stderr = self.process.communicate()
                print(f"代理启动失败，错误信息：{stderr.decode('utf-8', errors='ignore')}")
                return False
                
        except Exception as e:
            print(f"启动代理失败: {str(e)}")
            return False

    def stop_proxy(self):
        """停止代理服务"""
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None
        if os.path.exists(self.config_path):
            try:
                os.remove(self.config_path)
                print("配置文件已清理")
            except Exception as e:
                print(f"清理配置文件失败: {str(e)}")

def fetch_and_parse_trojan_links(url):
    if url.startswith('@'):
        url = url[1:]  # 移除开头的@符号
    
    try:
        # 禁用代理
        session = requests.Session()
        session.trust_env = False
        
        # 添加请求头
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # 获取URL内容
        response = session.get(url, headers=headers, timeout=10)
        
        # 如果响应状态码不是200，抛出异常
        if response.status_code != 200:
            print(f"服务器返回错误状态码: {response.status_code}")
            print("响应内容:", response.text[:200])
            return None
            
        content = response.content
        
        # 调试信息
        print("\n[调试信息]")
        print("响应状态码:", response.status_code)
        print("响应头:", dict(response.headers))
        print("原始内容前100字节:", content[:100])
        
        # 尝试不同的解码方式
        try:
            # 如果内容已经是trojan链接，直接解码
            if content.startswith(b'trojan://'):
                decoded_content = content.decode('utf-8')
            else:
                # 尝试base64解码
                try:
                    # 移除可能的空白字符和换行符
                    content_str = content.decode('ascii', errors='ignore').strip()
                    # base64解码
                    decoded_content = base64.b64decode(content_str).decode('utf-8')
                except Exception as e:
                    print(f"Base64解码失败: {str(e)}")
                    # 尝试直接解码
                    decoded_content = content.decode('utf-8', errors='ignore')
        
            # 检查解码后的内容
            print("\n[解码后的内容前100个字符]")
            print(decoded_content[:100])
            
            # 解析所有trojan链接
            links = [link for link in decoded_content.strip().split('\n') 
                    if link.strip().startswith('trojan://')]
            
            if not links:
                print("未找到有效的trojan链接")
                return None
                
            print("\n可用的服务器节点：")
            for index, link in enumerate(links, 1):
                name = unquote(link.split('#')[-1]) if '#' in link else f"节点 {index}"
                print(f"{index}. {name}")
                
            while True:
                try:
                    choice = int(input("\n请选择节点编号: "))
                    if 1 <= choice <= len(links):
                        selected_link = links[choice-1]
                        print(f"\n已选择: {unquote(selected_link.split('#')[-1])}")
                        return selected_link
                    else:
                        print("无效的选择，请输入正确的节点编号")
                except ValueError:
                    print("请输入数字！")
                
        except Exception as decode_error:
            print(f"内容解码错误: {str(decode_error)}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"网络请求错误: {str(e)}")
    except Exception as e:
        print(f"生错误: {str(e)}")
        import traceback
        print("详细错误信息:")
        print(traceback.format_exc())
    return None

def parse_trojan_url(trojan_url):
    """解���trojan链接的详细信息"""
    try:
        match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)\?(.+)', trojan_url)
        if match:
            password, server, port, params = match.groups()
            
            param_dict = {}
            for param in params.split('&'):
                key, value = param.split('=')
                param_dict[key] = value
                
            return {
                'password': password,
                'server': server,
                'port': port,
                'params': param_dict
            }
    except Exception as e:
        print(f"解析错误: {str(e)}")
    return None

def main():
    proxy = XrayProxy()
    
    while True:
        url = input("\n请输入订阅URL (输入 'q' 退出): ").strip()
        
        if url.lower() == 'q':
            print("程序已退出")
            break
            
        if not url:
            print("URL不能为空，请重新输入")
            continue
            
        # 获取并选择trojan链接
        selected_link = fetch_and_parse_trojan_links(url)
        
        if selected_link:
            # 解析选中的链接
            config = parse_trojan_url(selected_link)
            if config:
                print("\n链接详细信息:")
                print(f"服务器: {config['server']}")
                print(f"端口: {config['port']}")
                
                # 停止现有代理（如果有）
                proxy.stop_proxy()
                
                # 创建新配置并启动代理
                proxy.create_config(config)
                if proxy.start_proxy():
                    print("\n代理已启动！")
                    print("按 Ctrl+C 停止代理服务")
                    try:
                        # 保持程序运行
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        print("\n正在停止代理服务...")
                        proxy.stop_proxy()
                        print("代理服务已停止")
                        break
                else:
                    print("代理启动失败")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n程序已退出")
    finally:
        # 确保清理资源
        proxy = XrayProxy()
        proxy.stop_proxy()
