import requests 
from bs4 import BeautifulSoup

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

# 检测CSRF漏洞
def detect_csrf(url, session):
    try:
        response = session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            csrf_input = form.find('input', {'name': '_csrf'})
            if csrf_input:
                csrf_token = csrf_input.get('value')
                bad_req = session.post(url, data={'_csrf': 'malicious_token'})
                if bad_req.status_code != 200:
                    print("[+] CSRF Vulnerability Found!")
                    return
        print("x CSRF")
    except Exception as e:
        print("!! ERROR:", str(e))

# 密码爆破函数
def try_login(url, username, password):
    try:
        login_url = url + "/login"
        login_data = {'username': username, 'password': password}
        response = requests.post(login_url, data=login_data)
        if response.status_code == 200 and 'Login failed' not in response.text:
            print("[+] Login Successful! With Username:", username, "and Password:", password)
        else:
            print("x Login")
    except Exception as e:
        print("!! ERROR:", str(e))

print("Web Vulnerability Scanner CLI")
print("----------------------------")
url = input("Enter URL: ")
username = "admin"
password = "password"
session = requests.Session()
print("Scanning")
detect_xss(url)
detect_csrf(url, session)
try_login(url, username, password)
