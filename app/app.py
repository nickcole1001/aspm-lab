"""
Intentionally vulnerable Flask application.
FOR LEARNING / DEMO PURPOSES ONLY — do not deploy this.

Vulnerabilities present:
  - Hardcoded AWS credentials (Gitleaks / Semgrep will flag)
  - SQL injection in /user
  - Command injection in /ping
  - Server-Side Template Injection (SSTI) in /template
  - Debug mode enabled
  - Hardcoded secret key
"""

from flask import Flask, request, render_template_string
import sqlite3
import subprocess
import os

app = Flask(__name__)

# ------------------------------------------------------------------ #
#  HARDCODED CREDENTIALS — intentional finding for secret scanners    #
# ------------------------------------------------------------------ #
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # noqa
DB_PASSWORD           = "Sup3rS3cr3tDBpassword!"

app.config["DEBUG"] = True                          # insecure: exposes debugger
app.config["SECRET_KEY"] = "hardcoded-flask-secret" # insecure: predictable key


@app.route("/")
def index():
    return "<h1>Vulnerable Demo App</h1><p>See /user, /ping, /template</p>"


@app.route("/user")
def get_user():
    """SQL injection: user-supplied input concatenated into query."""
    user_id = request.args.get("id", "")
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice')")
    # VULN: f-string directly in SQL
    query = f"SELECT * FROM users WHERE id = {user_id}"
    try:
        result = conn.execute(query).fetchall()
        return str(result)
    except Exception as exc:
        return str(exc), 400


@app.route("/ping")
def ping():
    """Command injection: shell=True with unsanitised host param."""
    host = request.args.get("host", "localhost")
    # VULN: shell=True + user input
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output.decode()


@app.route("/template")
def template():
    """Server-Side Template Injection: user input rendered as Jinja2 template."""
    name = request.args.get("name", "World")
    # VULN: render_template_string with raw user input
    return render_template_string(f"<h1>Hello {name}!</h1>")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)  # noqa: S104
