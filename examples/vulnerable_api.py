"""Example: Common AI-generated vulnerabilities"""
import subprocess
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# CRITICAL: SQL Injection via f-string
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    query = f"SELECT * FROM users WHERE id={user_id}"
    return db.execute(query).fetchone()

# CRITICAL: Command Injection
@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout

# CRITICAL: Hardcoded secret
API_KEY = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"

# HIGH: Weak randomness for tokens
import random
def generate_session_token():
    return str(random.randint(1000000, 9999999))
