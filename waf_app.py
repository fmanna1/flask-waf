from flask import Flask, request, jsonify, render_template_string
import re
import os
import sqlite3
from datetime import datetime

import dash
from dash import html, dcc, dash_table
import pandas as pd
import plotly.express as px

app = Flask(__name__)

# --- SQLite Setup ---
DB_FILE = "waf_logs.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                level TEXT,
                attack_type TEXT,
                ip TEXT,
                payload TEXT
            )
        ''')

init_db()

def log_attack(level, attack_type, ip, payload):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            INSERT INTO logs (timestamp, level, attack_type, ip, payload)
            VALUES (?, ?, ?, ?, ?)''',
            (datetime.utcnow().isoformat(), level, attack_type, ip, payload))

# --- Attack Patterns ---
SQLI_PATTERNS = [
    r"(?i)(\\bor\\b|\\band\\b).*(=|\\bLIKE\\b|\\bIN\\b|\\bIS\\b|\\bNULL\\b)",
    r"(?i)(union(\\s+all)?(\\s+select))",
    r"(?i)select.+from",
    r"(?i)insert\\s+into",
    r"(?i)drop\\s+table",
    r"(?i)'\\s*or\\s*'1'='1"
]

XSS_PATTERNS = [
    r"(?i)<script.*?>.*?</script.*?>",
    r"(?i)javascript:",
    r"(?i)onerror\\s*=",
    r"(?i)<img\\s+.*?on\\w+=.*?>"
]

CSRF_TOKENS_REQUIRED = True

@app.before_request
def waf_filter():
    if request.path.startswith('/dashboard') or request.path == '/tester':
        return
    ip = request.remote_addr or "unknown"
    full_data = str(request.args.to_dict()) + str(request.form.to_dict())

    for pattern in SQLI_PATTERNS:
        if re.search(pattern, full_data):
            log_attack("WARNING", "SQL Injection", ip, full_data)
            return jsonify({"error": "Blocked: SQL Injection detected"}), 403

    for pattern in XSS_PATTERNS:
        if re.search(pattern, full_data):
            log_attack("WARNING", "XSS", ip, full_data)
            return jsonify({"error": "Blocked: XSS attempt detected"}), 403

    if CSRF_TOKENS_REQUIRED and request.method == "POST":
        token = request.headers.get("X-CSRF-Token")
        if not token or token != "securetoken123":
            log_attack("WARNING", "CSRF", ip, full_data)
            return jsonify({"error": "Blocked: CSRF token missing or invalid"}), 403

@app.route('/')
def index():
    return "Welcome to the WAF-protected app with SQLite logging."

@app.route('/waf/search')
def waf_search():
    return jsonify({"message": "Search executed (if not blocked)."})

@app.route('/waf/login', methods=['POST'])
def waf_login():
    return jsonify({"message": "Login successful (if not blocked)."})

@app.route('/tester', methods=['GET', 'POST'])
def tester():
    result = ""
    if request.method == "GET" and "q" in request.args:
        try:
            q = request.args.get("q", "")
            with app.test_client() as client:
                r = client.get("/waf/search", query_string={"q": q})
                result = f"GET /waf/search → {r.status_code} | {r.get_data(as_text=True)}"
        except Exception as e:
            result = str(e)
    elif request.method == "POST":
        try:
            uname = request.form.get("username", "")
            pwd = request.form.get("password", "")
            headers = {"X-CSRF-Token": request.form.get("csrf_token", "")}
            data = {"username": uname, "password": pwd}
            with app.test_client() as client:
                r = client.post("/waf/login", data=data, headers=headers)
                result = f"POST /waf/login → {r.status_code} | {r.get_data(as_text=True)}"
        except Exception as e:
            result = str(e)

    return render_template_string("""
        <h2>🧪 WAF Attack Tester</h2>
        <form method="get">
            <b>SQLi/XSS via GET</b><br>
            <input type="text" name="q" placeholder="Payload here" size="60"/>
            <input type="submit" value="Test GET" />
        </form>
        <br><hr><br>
        <form method="post">
            <b>CSRF via POST</b><br>
            Username: <input type="text" name="username" />
            Password: <input type="password" name="password" />
            CSRF Token: <input type="text" name="csrf_token" value="securetoken123" />
            <input type="submit" value="Test POST" />
        </form>
        <br><br>
        <textarea rows="10" cols="100">{{result}}</textarea>
    """, result=result)
