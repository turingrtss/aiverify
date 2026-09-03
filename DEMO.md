# AIVerify Demo

## Vulnerable Code (AI-generated)

```python
# CRITICAL: Command Injection
@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout

# CRITICAL: Hardcoded Secret
API_KEY = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
```

## AIVerify Output

```
🔍 AIVerify found 2 security issue(s):

🚨 CRITICAL (2):
  ❌ vulnerable_api.py:19 [CRITICAL] command_injection: Command injection via string concatenation
     💡 Use subprocess with shell=False and list args
     
  ❌ vulnerable_api.py:23 [CRITICAL] hardcoded_secret: Hardcoded secret detected (20+ chars)
     💡 Use environment variables: os.environ.get("API_KEY")
```

## What AIVerify Catches

✅ Command injection (`subprocess` with `shell=True`)
✅ SQL injection (f-strings with user input)
✅ Hardcoded secrets (API keys, passwords)
✅ SSRF vulnerabilities
✅ Path traversal
✅ Dangerous eval/exec
✅ Weak cryptography
✅ Insecure randomness
✅ Template injection
✅ XXE vulnerabilities

**~0% false positive rate** - Tested on Flask, Requests, and major Python projects.
