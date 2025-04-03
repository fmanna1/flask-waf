from flask import Flask, request, jsonify
import re
import logging
import os

app = Flask(__name__)

# --- Logging Setup ---
logging.basicConfig(
    filename="waf_logs.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# --- OWASP Top 10 2021 Mapping ---
OWASP_CATEGORIES = {
    "SQL Injection": "A03:2021-Injection",
    "XSS": "A03:2021-Injection (XSS included)",
    "CSRF": "A01:2021-Broken Access Control (Token Validation)"
}

# --- Attack Signatures ---
SQLI_PATTERNS = [
    r"(?i)(\bor\b|\band\b).*(=|\bLIKE\b|\bIN\b|\bIS\b|\bNULL\b)",
    r"(?i)(union(\s+all)?(\s+select))",
    r"(?i)select.+from",
    r"(?i)insert\s+into",
    r"(?i)drop\s+table"
]

XSS_PATTERNS = [
    r"(?i)<script.*?>.*?</script.*?>",
    r"(?i)javascript:",
    r"(?i)onerror\s*=",
    r"(?i)<img\s+.*?on\w+=.*?>",
    r"(?i)<.*?(alert|prompt|confirm)\s*\(",
    r"&lt;script&gt;"
]

CSRF_TOKENS_REQUIRED = True

# --- Helper Functions ---
def log_attack(ip, pattern_type, payload):
    owasp_category = OWASP_CATEGORIES.get(pattern_type, "Uncategorized")
    logging.warning(f"Blocked {pattern_type} attack (OWASP: {owasp_category}) from {ip}. Payload: {payload}")

def contains_attack_patterns(payload, patterns):
    for pattern in patterns:
        if re.search(pattern, payload):
            return pattern
    return None

# --- WAF Middleware ---
@app.before_request
def waf_filter():
    ip = request.remote_addr
    full_data = ""

    # Collect GET params
    if request.args:
        full_data += str(request.args.to_dict())

    # Collect POST form data
    if request.method == "POST":
        full_data += str(request.form.to_dict())

    # Check for SQL Injection
    if pattern := contains_attack_patterns(full_data, SQLI_PATTERNS):
        log_attack(ip, "SQL Injection", full_data)
        return jsonify({
            "error": "Blocked: SQL Injection detected",
            "owasp_category": OWASP_CATEGORIES["SQL Injection"]
        }), 403

    # Check for XSS
    if pattern := contains_attack_patterns(full_data, XSS_PATTERNS):
        log_attack(ip, "XSS", full_data)
        return jsonify({
            "error": "Blocked: XSS attempt detected",
            "owasp_category": OWASP_CATEGORIES["XSS"]
        }), 403

    # Simulate CSRF Token Check
    if CSRF_TOKENS_REQUIRED and request.method == "POST":
        token = request.headers.get("X-CSRF-Token")
        if not token or token != "securetoken123":
            log_attack(ip, "CSRF", full_data)
            return jsonify({
                "error": "Blocked: Missing/Invalid CSRF token",
                "owasp_category": OWASP_CATEGORIES["CSRF"]
            }), 403

# --- Routes ---
@app.route('/')
def index():
    return "Welcome to the WAF-protected web app!"

@app.route('/login', methods=['POST'])
def login():
    return jsonify({"message": "Login successful (if not blocked)."})

@app.route('/search')
def search():
    return jsonify({"message": "Search executed successfully (if not blocked)."})

# --- Render-compatible Run ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Use PORT from Render
    app.run(host="0.0.0.0", port=port, debug=True)
