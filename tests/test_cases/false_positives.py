"""Legitimate code that should NOT be flagged"""

# SHOULD NOT FLAG: Public API constant (named appropriately)
YOUTUBE_API_VERSION = "v3"
STATIC_SECRET = "public_constant_for_api_hashing"  # Public algorithm constant

# SHOULD NOT FLAG: Safe parameterized query
def get_user_safe(username):
    query = "SELECT * FROM users WHERE name = %s"
    return execute(query, (username,))

# SHOULD NOT FLAG: Logging (not SQL)
def log_message(msg):
    logger.info(f"User action: {msg}")

# SHOULD NOT FLAG: String formatting (not command injection)
def format_output(name):
    return f"Hello, {name}"

# SHOULD NOT FLAG: API key placeholder/example
API_KEY_EXAMPLE = "your_api_key_here"  # Not a real key
API_KEY = os.environ.get("API_KEY")  # From environment
