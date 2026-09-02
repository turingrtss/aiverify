# Test file with intentional security issues

# Hardcoded secret (should trigger CRITICAL)
API_KEY = "sk-1234567890abcdef1234567890abcdef"

# SQL injection (should trigger CRITICAL)
def get_user(username):
    query = "SELECT * FROM users WHERE name = '%s'" % username
    return execute(query)

# Dangerous eval (should trigger HIGH)
def calc(expression):
    return eval(expression)

# Null deref (should trigger MEDIUM)
def process_data(data):
    result = None
    if data:
        result = parse(data)
    return result.value  # Potential null deref
