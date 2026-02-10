# Template Injection: should NOT trigger the rule
# 使用硬編碼模板或從檔案載入

from jinja2 import Template, Environment, FileSystemLoader
from flask import render_template

def safe_template(name):
    # 安全：使用硬編碼的模板字串
    template = Template("<h1>Hello {{ name }}</h1>")
    return template.render(name=name)

def safe_file_template(env, name):
    # 安全：從檔案載入模板
    template = env.get_template("index.html")
    return template.render(name=name)

def safe_flask(name):
    # 安全：使用 render_template 從檔案載入
    return render_template("profile.html", name=name)

