"""Real security vulnerabilities that SHOULD be flagged"""

# SHOULD FLAG: Real hardcoded secret
API_KEY = "sk-1234567890abcdef1234567890abcdef"

# SHOULD FLAG: SQL injection
def get_user(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return execute(query)

# SHOULD FLAG: Command injection
def run_command(user_input):
    os.system("ls " + user_input)

# SHOULD FLAG: Eval usage
def calculate(expression):
    return eval(expression)

# SHOULD FLAG: Insecure deserialization
def load_data(data):
    return pickle.loads(data)
