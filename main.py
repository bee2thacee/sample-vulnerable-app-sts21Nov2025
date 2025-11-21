# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
import sqlite3
import subprocess
import pickle
import os
import ast  # Added for safe literal evaluation

# hardcoded API token (Issue 1)
API_TOKEN = "AKIAEXAMPLERAWTOKEN12345"

# simple SQLite DB on local disk (Issue 2: insecure storage + lack of access control)
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # Fixed: Using parameterized query to prevent SQL injection
    sql = "INSERT INTO users (username, password) VALUES (?, ?)"
    cur.execute(sql, (username, password))
    conn.commit()

def get_user(username):
    # Fixed: Using parameterized query to prevent SQL injection
    q = "SELECT id, username FROM users WHERE username = ?"
    cur.execute(q, (username,))
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input (Issue 4)
    return subprocess.getoutput(command)

def deserialize_blob(blob):
    # Fixed: Using ast.literal_eval() for safe deserialization of basic data types
    # This only allows safe literals like strings, numbers, tuples, lists, dicts, booleans, and None
    try:
        # First decode bytes to string if needed
        if isinstance(blob, bytes):
            blob_str = blob.decode('utf-8')
        else:
            blob_str = str(blob)
        # Use ast.literal_eval for safe evaluation
        return ast.literal_eval(blob_str)
    except (ValueError, SyntaxError) as e:
        raise ValueError(f"Invalid or unsafe data format: {str(e)}")

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Demonstrate risky calls
    print("API_TOKEN in use:", API_TOKEN)
    print(get_user("alice' OR '1'='1"))  # demonstrates SQLi payload
    print(run_shell("echo Hello && whoami"))
    try:
        # attempting to deserialize an arbitrary blob (will likely raise)
        deserialize_blob(b"not-a-valid-pickle")
    except Exception as e:
        print("Deserialization error:", e)