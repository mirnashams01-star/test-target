import hashlib
import sqlite3
import os

# FIX: Replaced MD5 with SHA-256 for stronger cryptographic hashing.
# Reason: MD5 is considered cryptographically broken and susceptible to collisions,
# making it unsuitable for securely storing passwords. SHA-256 is a more modern
# and secure hashing algorithm with a larger output size.
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# FIX: Removed hardcoded password.
# Reason: Hardcoded credentials are a significant security risk, as they can be easily
# discovered if the code is compromised. Passwords should be managed securely,
# for example, through environment variables, configuration files, or a secrets management system.
# For demonstration purposes, this placeholder remains, but in a real application,
# this would be replaced with a secure method of obtaining the password.
# Example: password = os.environ.get("ADMIN_PASSWORD") or "default_secure_password_if_not_set"
# For this example, we'll assume a mechanism to set this will be implemented outside this module.
# For now, we comment out the direct assignment and assume it's handled elsewhere.
# password = "admin123"
# hashed_admin_password = hash_password(password)

# The following lines are commented out as the hardcoded password has been removed.
# If there's a need for a specific initial admin credential, it should be handled
# during the application's setup or deployment.
# hashed_admin_password = hash_password("admin123") # Placeholder, should be removed in production

def login(username, password_attempt):
    """
    Authenticates a user by comparing their provided password with the stored hashed password.
    """
    conn = None
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        # FIX: Used parameterized queries to prevent SQL injection.
        # Reason: Directly concatenating user input into SQL queries creates a vulnerability
        # known as SQL injection. An attacker could manipulate the input to execute
        # arbitrary SQL commands. Parameterized queries separate the SQL command
        # from the data, ensuring that user input is treated as data and not executable code.
        cursor.execute("SELECT password_hash FROM users WHERE name = ?", (username,))
        user_record = cursor.fetchone()

        if user_record:
            stored_hashed_password = user_record[0]
            # FIX: Replaced MD5 with SHA-256.
            # Reason: As noted in hash_password, MD5 is insecure.
            # We now use SHA-256 for consistency and security.
            if hash_password(password_attempt) == stored_hashed_password:
                return True  # Authentication successful
        return False  # Authentication failed
    except sqlite3.Error as e:
        print(f"Database error during login: {e}")
        return False
    finally:
        if conn:
            conn.close()

def store_user_password(username, password):
    """
    Stores a user's hashed password in the database.
    """
    conn = None
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        # FIX: Used parameterized queries to prevent SQL injection when inserting.
        # Reason: Similar to the SELECT statement, direct string formatting for INSERT
        # statements can also be vulnerable to SQL injection if the username is not
        # properly sanitized, although it's less common than in SELECT/UPDATE/DELETE.
        # Parameterized queries are the best practice for all SQL executions.
        hashed_pwd = hash_password(password)
        cursor.execute("INSERT INTO users (name, password_hash) VALUES (?, ?)", (username, hashed_pwd))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        print(f"User '{username}' already exists.")
        return False
    except sqlite3.Error as e:
        print(f"Database error during storing password: {e}")
        return False
    finally:
        if conn:
            conn.close()

# FIX: Modified read_file to use 'with' statement for proper file handling.
# Reason: File objects should be properly closed to release system resources and
# ensure data is flushed to the disk. The 'with' statement (context manager)
# guarantees that the file is closed automatically, even if errors occur.
def read_file(filename):
    """
    Reads the content of a file securely.
    """
    try:
        # FIX: Added checks for potentially malicious file access.
        # In a real-world scenario, you'd want to restrict access to specific,
        # safe directories to prevent directory traversal attacks (e.g., reading ../../etc/passwd).
        # This is a basic example and might need more robust checks depending on the application context.
        base_dir = os.path.abspath(".") # Restrict access to the current directory
        filepath = os.path.abspath(os.path.join(base_dir, filename))

        if not filepath.startswith(base_dir):
            print(f"Error: Attempted to access file outside of allowed directory: {filename}")
            return None

        with open(filepath, "r") as f:
            data = f.read()
            return data
    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
        return None
    except IOError as e:
        print(f"Error reading file {filename}: {e}")
        return None

# The following known vulnerabilities are NOT directly addressed by modifying THIS file's code,
# as they relate to external libraries or specific components not present here.
# However, the general principles of secure coding are applied.

# - utcp-http vulnerable to SSRF via attacker-controlled OpenAPI servers[0].url in HTTP communication protocol:
#   This suggests a need for input validation on URLs used in HTTP requests. If this script were
#   making HTTP requests based on external input, those URLs would need strict validation
#   (e.g., allowlisting, disallowing private IP ranges, etc.).

# - netbox-data-flows has stored XSS in ObjectAlias names rendered inside DataFlow tables:
#   This is a Cross-Site Scripting (XSS) vulnerability if the data is rendered in a web interface.
#   Any user-provided input that is displayed in HTML should be properly escaped (e.g., using libraries like `html.escape`)
#   to prevent malicious scripts from being injected.

# - Microsoft APM CLI's plugin.json component paths escape plugin root and copy arbitrary host files during install:
#   This highlights the importance of validating file paths and ensuring that operations
#   (like file copying or installation) are confined to expected directories. The `read_file`
#   function has been updated with a basic path restriction.

# - BentoML has Information Disclosure in `bentoml build` via symlink traversal in the build context:
#   This implies that when processing build contexts, symbolic links should be handled carefully
#   to prevent them from pointing outside the intended build directory, which could lead to
#   reading or overwriting sensitive files.

# - Diffusers has a `trust_remote_code` bypass via `custom_pipeline` and local custom components:
#   This points to the danger of executing arbitrary code from untrusted sources, especially by
#   allowing local custom components to bypass security checks. Always validate the source and
#   content of any code that is executed dynamically.

# Example of how to create the users.db and a user initially (for testing this script):
# def setup_database():
#     conn = None
#     try:
#         conn = sqlite3.connect("users.db")
#         cursor = conn.cursor()
#         cursor.execute('''
#             CREATE TABLE IF NOT EXISTS users (
#                 id INTEGER PRIMARY KEY AUTOINCREMENT,
#                 name TEXT UNIQUE NOT NULL,
#                 password_hash TEXT NOT NULL
#             )
#         ''')
#         # Add an initial admin user if it doesn't exist
#         initial_admin_username = "admin"
#         cursor.execute("SELECT COUNT(*) FROM users WHERE name = ?", (initial_admin_username,))
#         if cursor.fetchone()[0] == 0:
#              # FIX: Removed hardcoded password for initial setup.
#              # In a real scenario, this password should come from a secure source.
#              # For demonstration, we'll hash a placeholder.
#              placeholder_password = "verysecuredefaultpassword" # Replace with a real secure password mechanism
#              store_user_password(initial_admin_username, placeholder_password)
#              print(f"Initial admin user '{initial_admin_username}' created.")
#         conn.commit()
#     except sqlite3.Error as e:
#         print(f"Database setup error: {e}")
#     finally:
#         if conn:
#             conn.close()

# Call setup_database() if you need to initialize the database for testing.
# setup_database()