from flask import Flask, request, jsonify
import re
import logging

app = Flask(__name__)

# --- Logging Setup ---
logging.basicConfig(
    filename="waf_logs.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

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
]

CSRF_TOKENS_REQUIRED = True

# --- Helper Functions ---
def log_attack(ip, pattern_type, payload):
    logging.warning(f"Blocked {pattern_type} attack from {ip}. Payload: {payload}")

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
        return jsonify({"error": "Blocked: SQL Injection detected"}), 403

    # Check for XSS
    if pattern := contains_attack_patterns(full_data, XSS_PATTERNS):
        log_attack(ip, "XSS", full_data)
        return jsonify({"error": "Blocked: XSS attempt detected"}), 403

    # Simulate CSRF Token Check
    if CSRF_TOKENS_REQUIRED and request.method == "POST":
        token = request.headers.get("X-CSRF-Token")
        if not token or token != "securetoken123":
            log_attack(ip, "CSRF", full_data)
            return jsonify({"error": "Blocked: Missing/Invalid CSRF token"}), 403

# --- Routes ---
@app.route('/')
def index():
    return "Welcome to the WAF-protected web app!"

@app.route('/login', methods=['POST'])
def login():
    # Simulated login logic
    return jsonify({"message": "Login successful (if not blocked)."})

@app.route('/search')
def search():
    return jsonify({"message": "Search executed successfully (if not blocked)."})

# --- Run ---
if __name__ == '__main__':
    app.run(debug=True)
