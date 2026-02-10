# Template Injection: SHOULD trigger the rule
# Pattern: Jinja2 Template 使用變數作為模板內容
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

from jinja2 import Template, Environment
from flask import render_template_string, request

def unsafe_template(user_input):
    # 不安全：Template 構造器使用變數
    template = Template(user_input)
    return template.render()

def unsafe_from_string(env, user_input):
    # 不安全：from_string 使用變數
    template = env.from_string(user_input)
    return template.render()

def unsafe_flask(user_input):
    # 不安全：render_template_string 使用變數
    return render_template_string(user_input)

