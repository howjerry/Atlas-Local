# Flask Debug Mode: should NOT trigger the rule
# 不啟用 debug 模式

from flask import Flask
import os

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello"

if __name__ == "__main__":
    # 安全：不啟用 debug
    app.run(host="0.0.0.0", port=5000)

