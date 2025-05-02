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
        import requests
        try:
            q = request.args.get("q", "")
            r = requests.get(f"http://127.0.0.1:5000/waf/search", params={"q": q})
            result = f"GET /waf/search → {r.status_code} | {r.text}"
        except Exception as e:
            result = str(e)
    elif request.method == "POST":
        try:
            uname = request.form.get("username", "")
            pwd = request.form.get("password", "")
            headers = {"X-CSRF-Token": request.form.get("csrf_token", "")}
            data = {"username": uname, "password": pwd}
            import requests
            r = requests.post("http://127.0.0.1:5000/waf/login", data=data, headers=headers)
            result = f"POST /waf/login → {r.status_code} | {r.text}"
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

# --- Dash Setup ---
dash_app = dash.Dash(__name__, server=app, routes_pathname_prefix='/dashboard/')
dash_app.title = "WAF Dashboard"

def query_logs():
    with sqlite3.connect(DB_FILE) as conn:
        df = pd.read_sql_query("SELECT timestamp, level, attack_type, ip, payload FROM logs", conn)
    return df

def generate_recommendations(df):
    if df.empty:
        return "✅ All clear. No suspicious activity logged."

    recs = []
    ip_counts = df['ip'].value_counts()
    csrf_count = len(df[df["attack_type"] == "CSRF"])
    sqli_count = len(df[df["attack_type"] == "SQL Injection"])

    if any(ip_counts > 5):
        recs.append("⚠️ Consider rate-limiting requests from high-frequency IPs.")
    if csrf_count > 3:
        recs.append("🛡️ Consider enforcing or rotating CSRF tokens more frequently.")
    if sqli_count > 5:
        recs.append("🔒 SQLi patterns detected frequently. Consider IP blocking or stricter input validation.")

    return "\n".join(recs) if recs else "✅ System is stable. No urgent recommendations."

dash_app.layout = html.Div([
    html.H1("🛡️ WAF Dashboard", style={"textAlign": "center"}),
    dcc.Interval(id='interval-component', interval=5000, n_intervals=0),
    dcc.Dropdown(id='attack-type-dropdown', options=[
        {'label': 'SQL Injection', 'value': 'SQL Injection'},
        {'label': 'XSS', 'value': 'XSS'},
        {'label': 'CSRF', 'value': 'CSRF'}
    ], multi=True, placeholder="Filter by attack type..."),
    dcc.Graph(id='attack-count-chart'),
    dash_table.DataTable(id='log-table',
                         columns=[
                             {"name": "Timestamp", "id": "timestamp"},
                             {"name": "Attack Type", "id": "attack_type"},
                             {"name": "IP", "id": "ip"},
                             {"name": "Payload", "id": "payload"},
                         ],
                         style_table={'overflowX': 'auto'},
                         style_cell={'textAlign': 'left'},
                         page_size=10
    ),
    html.Pre(id='recommendation-panel', style={"backgroundColor": "#f9f9f9", "padding": "10px"})
])

@dash_app.callback(
    [dash.dependencies.Output('log-table', 'data'),
     dash.dependencies.Output('attack-count-chart', 'figure'),
     dash.dependencies.Output('recommendation-panel', 'children')],
    [dash.dependencies.Input('attack-type-dropdown', 'value'),
     dash.dependencies.Input('interval-component', 'n_intervals')]
)
def update_dashboard(filter_types, _):
    df = query_logs()
    if filter_types:
        df = df[df["attack_type"].isin(filter_types)]

    if df.empty:
        fig = {
            "layout": {
                "title": "No Attack Logs Yet",
                "xaxis": {"visible": False},
                "yaxis": {"visible": False},
                "annotations": [{
                    "text": "No data available",
                    "xref": "paper", "yref": "paper",
                    "showarrow": False,
                    "font": {"size": 20}
                }]
            }
        }
        return [], fig, "✅ No suspicious activity yet."

    fig = px.histogram(df, x="attack_type", color="attack_type", title="Attack Type Frequency")
    recommendations = generate_recommendations(df)
    return df.to_dict("records"), fig, recommendations

# --- Run Server ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
