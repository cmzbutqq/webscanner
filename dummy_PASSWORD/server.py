from flask import Flask, request, render_template_string

app = Flask(__name__)

# 登录页面
@app.route('/')
def login():
    return render_template_string(open('login.html').read())

# 处理登录请求
@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']
    if username == 'admin' and password == 'password':
        return 'Login successful!'
    else:
        return 'Login failed!'

if __name__ == '__main__':
    app.run(debug=True)
