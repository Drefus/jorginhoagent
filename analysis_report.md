# 🔒 Relatório de Segurança
**ID:** `8240320a-6574-4a95-ba12-c29ffe8465b7`
**Risk Score:** 46.0/100

---

## 💀 Red Team

Uso de entrada direta do usuário sem sanitização; potencial injeção em comandos/queries.
Concatenacão de strings em queries detectada; possível SQLi.

**Exploitability:** HIGH

---

## 🔎 Analisador Estático

- **B608** (Linha 5) [MEDIUM]: Possible SQL injection vector through string-based query construction. (Bandit test B608 reports SQL injection risk.)
- **B324** (Linha 7) [MEDIUM]: Use of weak MD5 hash for security. Consider usedforsecurity=False
- **COMMAND_INJECTION** (Linha 0) [HIGH]: Uso de entrada direta do usuário sem sanitização; potencial injeção em comandos/queries.
- **SQL_INJECTION** (Linha 0) [HIGH]: Concatenacão de strings em queries detectada; possível SQLi.

---

## 🔍 Avaliador Central

⚠️  4 vulnerabilidade(s) encontrada(s): 2 alta(s), 2 média(s)

---

## 🔧 Correções Sugeridas

### 1. B608

**Severidade:** MEDIUM → LOW

**Explicação:** Substitua concatenação/interpolação de strings em queries SQL por queries parametrizadas.

**❌ Código vulnerável:**

```python
1 | import os
       2 | import hashlib
       3 | 
       4 | user_id = input('Enter ID: ')
>>>    5 | query = f"SELECT * FROM users WHERE id={user_id}"
       6 | result = db.execute(query)
       7 | password_hash = hashlib.md5(user_id.encode()).hexdigest()
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# query = f"SELECT * FROM users WHERE id={user_id}"

# DEPOIS (seguro):
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# ou com SQLAlchemy:
# stmt = select(users).where(users.c.id == bindparam('uid'))
# result = conn.execute(stmt, {"uid": user_id})
```

**Referências:**
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders

---

### 2. B324

**Severidade:** MEDIUM → LOW

**Explicação:** Substitua algoritmos fracos (MD5, SHA1, DES) por alternativas seguras (SHA-256, bcrypt, AES-256).

**❌ Código vulnerável:**

```python
2 | import hashlib
       3 | 
       4 | user_id = input('Enter ID: ')
       5 | query = f"SELECT * FROM users WHERE id={user_id}"
       6 | result = db.execute(query)
>>>    7 | password_hash = hashlib.md5(user_id.encode()).hexdigest()
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# hash_val = hashlib.md5(password.encode()).hexdigest()

# DEPOIS (seguro - para senhas):
import bcrypt

hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
# Verificação:
# bcrypt.checkpw(password.encode(), hashed)

# DEPOIS (seguro - para hashing geral):
import hashlib
hash_val = hashlib.sha256(data.encode()).hexdigest()
```

**Referências:**
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

---

### 3. COMMAND_INJECTION

**Severidade:** HIGH → LOW

**Explicação:** Use subprocess com lista de argumentos em vez de shell=True. Nunca passe entrada do usuário direto em comandos.

**❌ Código vulnerável:**

```python
; rm -rf /
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# os.system(f"ping {host}")

# DEPOIS (seguro):
import subprocess
import shlex

# Valide a entrada antes
if not re.match(r'^[a-zA-Z0-9.-]+$', host):
    raise ValueError("Host inválido")

result = subprocess.run(
    ["ping", "-c", "4", host],
    capture_output=True,
    text=True,
    timeout=30,
)
```

**Referências:**
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

---

### 4. SQL_INJECTION

**Severidade:** HIGH → LOW

**Explicação:** Substitua concatenação/interpolação de strings em queries SQL por queries parametrizadas.

**❌ Código vulnerável:**

```python
' OR '1'='1
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# query = f"SELECT * FROM users WHERE id={user_id}"

# DEPOIS (seguro):
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# ou com SQLAlchemy:
# stmt = select(users).where(users.c.id == bindparam('uid'))
# result = conn.execute(stmt, {"uid": user_id})
```

**Referências:**
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders

---

## 📊 Conclusão

| Métrica | Valor |
|---------|-------|
| Total de vulnerabilidades | 4 |
| Críticas | 0 |
| Altas | 2 |
| Médias | 2 |
| Baixas | 0 |
| Falsos positivos descartados | 0 |
| **Risk Score** | **46.0/100** |

### Recomendações

- Execute auditorias de segurança regulares no CI/CD
- Mantenha dependências atualizadas
- Use queries parametrizadas (nunca concatene strings SQL)
