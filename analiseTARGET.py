# CÓDIGO DE TESTE PRO AGENTE VER E ANALISAR OS PROBLEMAS


import sqlite3
import subprocess
import pickle
import base64
import os

def process_data(user_input, serialized_payload):
    secret_key = "super_secret_p4ssw0rd_123!"
    
    db = sqlite3.connect("test.db")
    cursor = db.cursor()
    
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    cursor.execute(query)
    results = cursor.fetchall()
    
    eval_result = eval(user_input)
    
    decoded = base64.b64decode(serialized_payload)
    obj = pickle.loads(decoded)
    
    cmd = "echo " + user_input
    subprocess.run(cmd, shell=True)
    
    db.close()
    return results, eval_result, obj

def run_simulation():
    payload = base64.b64encode(pickle.dumps({"role": "user"}))
    user_val = "admin' OR 1=1 --"
    try:
        res = process_data(user_val, payload)
        print(res)
    except Exception as e:
        pass

if __name__ == "__main__":
    run_simulation()