"""
Code Executor for TC-27 WAF Bypass Lab

Accepts Python code, executes it sandboxed, returns stdout/stderr + WAF logs.
"""

import os
import sys
import json
import subprocess
import tempfile
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

WAF_LOG_PATH = "/var/log/waf/waf.log"
WAF_URL = os.environ.get("WAF_URL", "http://waf:9090")


def get_waf_logs() -> list:
    logs = []
    try:
        if os.path.exists(WAF_LOG_PATH):
            with open(WAF_LOG_PATH, "r") as f:
                for line in f:
                    logs.append(line.strip())
    except Exception as e:
        logs.append(f"[log read error: {e}]")
    return logs[-100:]


def clear_waf_logs():
    try:
        if os.path.exists(WAF_LOG_PATH):
            open(WAF_LOG_PATH, "w").close()
    except Exception:
        pass


@app.route("/execute", methods=["POST"])
def execute():
    data = request.get_json()
    code = data.get("code", "")

    if not code.strip():
        return jsonify({"error": "No code provided"}), 400

    clear_waf_logs()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(f"# WAF URL: {WAF_URL}\n")
        f.write(f"import os; os.environ['WAF_URL'] = '{WAF_URL}'\n\n")
        f.write(code)
        temp_path = f.name

    start_time = time.time()

    try:
        result = subprocess.run(
            [sys.executable, temp_path],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "WAF_URL": WAF_URL},
        )
        stdout = result.stdout
        stderr = result.stderr
        exit_code = result.returncode
    except subprocess.TimeoutExpired:
        stdout = ""
        stderr = "Execution timed out (30s limit)"
        exit_code = -1
    except Exception as e:
        stdout = ""
        stderr = f"Execution error: {str(e)}"
        exit_code = -1
    finally:
        os.unlink(temp_path)

    execution_time = int((time.time() - start_time) * 1000)
    time.sleep(0.1)
    waf_logs = get_waf_logs()

    return jsonify({
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "waf_logs": waf_logs,
        "execution_time_ms": execution_time,
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "waf_url": WAF_URL})


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "name": "TC-27 WAF Bypass Lab Executor",
        "usage": {
            "endpoint": "POST /execute",
            "body": {"code": "import requests\nprint(requests.post(os.environ['WAF_URL'] + '/', ...).status_code)"},
            "response": {
                "stdout": "output",
                "stderr": "errors",
                "exit_code": 0,
                "waf_logs": ["[REQ] ...", "[BLOCKED] ..."],
                "execution_time_ms": 123,
            },
        },
        "hint": f"WAF is at {WAF_URL}. Read /waf/coraza.conf for detection rules.",
    })


if __name__ == "__main__":
    print(f"[Executor] Starting on port 8000, WAF at {WAF_URL}")
    app.run(host="0.0.0.0", port=8000)
