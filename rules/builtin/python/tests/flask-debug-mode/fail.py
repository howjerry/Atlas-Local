# Flask Debug Mode: SHOULD trigger the rule
# Pattern: Flask app.run 啟用 debug 模式
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello"

if __name__ == "__main__":
    # 不安全：啟用 debug 模式
    app.run(debug=True)

