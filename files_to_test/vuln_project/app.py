"""App vulnerável para teste do Trivy + Bandit."""
import os
import pickle
import hashlib
import yaml
from flask import Flask, request

app = Flask(__name__)

# Hardcoded secret (Trivy secret scanner + Bandit)
API_KEY = "AKIAIOSFODNN7EXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgresql://admin:password123@prod-db.internal:5432/users"

@app.route("/user")
def get_user():
    # SQL injection via concatenação
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    # Command injection
    filename = request.args.get("file")
    os.system(f"cat /data/{filename}")
    
    # Insecure deserialization
    data = request.args.get("data")
    obj = pickle.loads(bytes.fromhex(data))
    
    # Weak crypto
    password = request.args.get("pass")
    hashed = hashlib.md5(password.encode()).hexdigest()
    
    # Unsafe YAML load
    config = request.args.get("config")
    parsed = yaml.load(config)
    
    return str(obj)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
