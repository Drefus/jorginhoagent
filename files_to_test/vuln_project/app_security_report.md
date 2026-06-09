# 🔒 Relatório de Segurança
**ID:** `82feadb0-4582-42c5-ab57-d3af2a16cc90`
**Risk Score:** 100.0/100

---

## 💀 Red Team

Concatenacão de strings em queries detectada; possível SQLi.
Uso de pickle/deserialize em dados não confiáveis.

**Exploitability:** HIGH

---

## 🔎 Analisador Estático

- **CVE-2020-36242** (Linha 0) [HIGH]: [cryptography] In the cryptography package before 3.3.2 for Python, certain sequences of update calls to symmetrically encrypt multi-GB values could result in an integer overflow and buffer overflow, as demonstrated by the Fernet class.
- **CVE-2023-0286** (Linha 0) [HIGH]: [cryptography] There is a type confusion vulnerability relating to X.400 address processing
inside an X.509 GeneralName. X.400 addresses were parsed as an ASN1_STRING but
the public structure definition for GENERAL_NAME incorrectly specified the type
of the x400Address field as ASN1_TYPE. This field is subsequentl
- **CVE-2023-50782** (Linha 0) [HIGH]: [cryptography] A flaw was found in the python-cryptography package. This issue may allow a remote attacker to decrypt captured messages in TLS servers that use RSA key exchanges, which may lead to exposure of confidential or sensitive data.
- **CVE-2026-26007** (Linha 0) [HIGH]: [cryptography] cryptography is a package designed to expose cryptographic primitives and recipes to Python developers. Prior to 46.0.5, the public_key_from_numbers (or EllipticCurvePublicNumbers.public_key()), EllipticCurvePublicNumbers.public_key(), load_der_public_key() and load_pem_public_key() functions do not
- **CVE-2021-35042** (Linha 0) [CRITICAL]: [django] Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by SQL injection if order_by is untrusted input from a client of a web application.
- **CVE-2025-64459** (Linha 0) [CRITICAL]: [django] An issue was discovered in 5.1 before 5.1.14, 4.2 before 4.2.26, and 5.2 before 5.2.8.
The methods `QuerySet.filter()`, `QuerySet.exclude()`, and `QuerySet.get()`, and the class `Q()`, are subject to SQL injection when using a suitably crafted dictionary, with dictionary expansion, as the `_connecto
- **CVE-2020-24583** (Linha 0) [HIGH]: [django] An issue was discovered in Django 2.2 before 2.2.16, 3.0 before 3.0.10, and 3.1 before 3.1.1 (when Python 3.7+ is used). FILE_UPLOAD_DIRECTORY_PERMISSIONS mode was not applied to intermediate-level directories created in the process of uploading files. It was also not applied to intermediate-level c
- **CVE-2021-31542** (Linha 0) [HIGH]: [django] In Django 2.2 before 2.2.21, 3.1 before 3.1.9, and 3.2 before 3.2.1, MultiPartParser, UploadedFile, and FieldFile allowed directory traversal via uploaded files with suitably crafted file names.
- **CVE-2021-33571** (Linha 0) [HIGH]: [django] In Django 2.2 before 2.2.24, 3.x before 3.1.12, and 3.2 before 3.2.4, URLValidator, validate_ipv4_address, and validate_ipv46_address do not prohibit leading zero characters in octal literals. This may allow a bypass of access control that is based on IP addresses. (validate_ipv4_address and validat
- **CVE-2022-36359** (Linha 0) [HIGH]: [django] An issue was discovered in the HTTP FileResponse class in Django 3.2 before 3.2.15 and 4.0 before 4.0.7. An application is vulnerable to a reflected file download (RFD) attack that sets the Content-Disposition header of a FileResponse when the filename is derived from user-supplied input.
- **CVE-2025-57833** (Linha 0) [HIGH]: [django] An issue was discovered in Django 4.2 before 4.2.24, 5.1 before 5.1.12, and 5.2 before 5.2.6. FilteredRelation is subject to SQL injection in column aliases, using a suitably crafted dictionary, with dictionary expansion, as the **kwargs passed QuerySet.annotate() or QuerySet.alias().
- **CVE-2025-64458** (Linha 0) [HIGH]: [django] An issue was discovered in 5.1 before 5.1.14, 4.2 before 4.2.26, and 5.2 before 5.2.8.
NFKC normalization in Python is slow on Windows. As a consequence, `django.http.HttpResponseRedirect`, `django.http.HttpResponsePermanentRedirect`, and the shortcut `django.shortcuts.redirect`  were subject to a p
- **CVE-2023-30861** (Linha 0) [HIGH]: [flask] Flask is a lightweight WSGI web application framework. When all of the following conditions are met, a response containing data intended for one client may be cached and subsequently sent by the proxy to other clients. If the proxy also caches `Set-Cookie` headers, it may send one client's `session`
- **CVE-2021-25289** (Linha 0) [CRITICAL]: [pillow] An issue was discovered in Pillow before 8.1.1. TiffDecode has a heap-based buffer overflow when decoding crafted YCbCr files because of certain interpretation conflicts with LibTIFF in RGBA mode. NOTE: this issue exists because of an incomplete fix for CVE-2020-35654.
- **CVE-2021-34552** (Linha 0) [CRITICAL]: [pillow] Pillow through 8.2.0 and PIL (aka Python Imaging Library) through 1.1.7 allow an attacker to pass controlled parameters directly into a convert function to trigger a buffer overflow in Convert.c.
- **CVE-2022-22817** (Linha 0) [CRITICAL]: [pillow] PIL.ImageMath.eval in Pillow before 9.0.0 allows evaluation of arbitrary expressions, such as ones that use the Python exec method. A lambda expression could also be used.
- **CVE-2023-50447** (Linha 0) [CRITICAL]: [pillow] Pillow through 10.1.0 allows PIL.ImageMath.eval Arbitrary Code Execution via the environment parameter, a different vulnerability than CVE-2022-22817 (which was about the expression parameter).
- **CVE-2020-35653** (Linha 0) [HIGH]: [pillow] In Pillow before 8.1.0, PcxDecode has a buffer over-read when decoding a crafted PCX file because the user-supplied stride value is trusted for buffer calculations.
- **CVE-2020-35654** (Linha 0) [HIGH]: [pillow] In Pillow before 8.1.0, TiffDecode has a heap-based buffer overflow when decoding crafted YCbCr files because of certain interpretation conflicts with LibTIFF in RGBA mode.
- **CVE-2021-23437** (Linha 0) [HIGH]: [pillow] The package pillow 5.2.0 and before 8.3.2 are vulnerable to Regular Expression Denial of Service (ReDoS) via the getrgb function.
- **CVE-2021-25287** (Linha 0) [HIGH]: [pillow] An issue was discovered in Pillow before 8.2.0. There is an out-of-bounds read in J2kDecode, in j2ku_graya_la.
- **CVE-2021-25288** (Linha 0) [HIGH]: [pillow] An issue was discovered in Pillow before 8.2.0. There is an out-of-bounds read in J2kDecode, in j2ku_gray_i.
- **CVE-2021-25290** (Linha 0) [HIGH]: [pillow] An issue was discovered in Pillow before 8.1.1. In TiffDecode.c, there is a negative-offset memcpy with an invalid size.
- **CVE-2021-25291** (Linha 0) [HIGH]: [pillow] An issue was discovered in Pillow before 8.1.1. In TiffDecode.c, there is an out-of-bounds read in TiffreadRGBATile via invalid tile boundaries.
- **CVE-2021-25293** (Linha 0) [HIGH]: [pillow] An issue was discovered in Pillow before 8.1.1. There is an out-of-bounds read in SGIRleDecode.c.
- **CVE-2021-27921** (Linha 0) [HIGH]: [pillow] Pillow before 8.1.2 allows attackers to cause a denial of service (memory consumption) because the reported size of a contained image is not properly checked for a BLP container, and thus an attempted memory allocation can be very large.
- **CVE-2021-27922** (Linha 0) [HIGH]: [pillow] Pillow before 8.1.2 allows attackers to cause a denial of service (memory consumption) because the reported size of a contained image is not properly checked for an ICNS container, and thus an attempted memory allocation can be very large.
- **CVE-2021-27923** (Linha 0) [HIGH]: [pillow] Pillow before 8.1.2 allows attackers to cause a denial of service (memory consumption) because the reported size of a contained image is not properly checked for an ICO container, and thus an attempted memory allocation can be very large.
- **CVE-2021-28675** (Linha 0) [HIGH]: [pillow] An issue was discovered in Pillow before 8.2.0. PSDImagePlugin.PsdImageFile lacked a sanity check on the number of input layers relative to the size of the data block. This could lead to a DoS on Image.open prior to Image.load.
- **CVE-2021-28676** (Linha 0) [HIGH]: [pillow] An issue was discovered in Pillow before 8.2.0. For FLI data, FliDecode did not properly check that the block advance was non-zero, potentially leading to an infinite loop on load.
- **CVE-2021-28677** (Linha 0) [HIGH]: [pillow] An issue was discovered in Pillow before 8.2.0. For EPS data, the readline implementation used in EPSImageFile has to deal with any combination of \r and \n as line endings. It used an accidentally quadratic method of accumulating lines while looking for a line ending. A malicious EPS file could use
- **CVE-2022-24303** (Linha 0) [HIGH]: [pillow] Pillow before 9.0.1 allows attackers to delete files because spaces in temporary pathnames are mishandled.
- **CVE-2022-45198** (Linha 0) [HIGH]: [pillow] Pillow before 9.2.0 performs Improper Handling of Highly Compressed GIF Data (Data Amplification).
- **CVE-2023-44271** (Linha 0) [HIGH]: [pillow] An issue was discovered in Pillow before 10.0.0. It is a Denial of Service that uncontrollably allocates memory to process a given task, potentially causing a service to crash by having it run out of memory. This occurs for truetype in ImageFont when textlength in an ImageDraw instance operates on a
- **CVE-2023-4863** (Linha 0) [HIGH]: [pillow] Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)
- **CVE-2024-28219** (Linha 0) [HIGH]: [pillow] In _imagingcms.c in Pillow before 10.3.0, a buffer overflow exists because strcpy is used instead of strncpy.
- **CVE-2020-14343** (Linha 0) [CRITICAL]: [pyyaml] A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader. Applications that use the library to process untrusted input may be vuln
- **CVE-2021-33503** (Linha 0) [HIGH]: [urllib3] An issue was discovered in urllib3 before 1.26.5. When provided with a URL containing many @ characters in the authority component, the authority regular expression exhibits catastrophic backtracking, causing a denial of service if a URL were passed as a parameter or redirected to via an HTTP redire
- **CVE-2023-43804** (Linha 0) [HIGH]: [urllib3] urllib3 is a user-friendly HTTP client library for Python. urllib3 doesn't treat the `Cookie` HTTP header special or provide any helpers for managing cookies over HTTP, that is the responsibility of the user. However, it is possible for a user to specify a `Cookie` header and unknowingly leak inform
- **CVE-2025-66418** (Linha 0) [HIGH]: [urllib3] urllib3 is a user-friendly HTTP client library for Python. Starting in version 1.24 and prior to 2.6.0, the number of links in the decompression chain was unbounded allowing a malicious server to insert a virtually unlimited number of compression steps leading to high CPU usage and massive memory al
- **CVE-2025-66471** (Linha 0) [HIGH]: [urllib3] urllib3 is a user-friendly HTTP client library for Python. Starting in version 1.0 and prior to 2.6.0, the Streaming API improperly handles highly compressed data. urllib3's streaming API is designed for the efficient handling of large HTTP responses by reading the content in chunks, rather than loa
- **CVE-2026-21441** (Linha 0) [HIGH]: [urllib3] urllib3 is an HTTP client library for Python. urllib3's streaming API is designed for the efficient handling of large HTTP responses by reading the content in chunks, rather than loading the entire response body into memory at once. urllib3 can perform decoding or decompression based on the HTTP `Co
- **CVE-2026-44431** (Linha 0) [HIGH]: [urllib3] urllib3 is an HTTP client library for Python. From 1.23 to before 2.7.0, cross-origin redirects followed from the low-level API via ProxyManager.connection_from_url().urlopen(..., assert_same_host=False) still forward these sensitive headers. This vulnerability is fixed in 2.7.0.
- **B403** (Linha 3) [MEDIUM]: Consider possible security implications associated with pickle module. (Consulta de banco de dados construída por concatenação de strings.)
- **B105** (Linha 12) [MEDIUM]: Possible hardcoded password: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
- **B608** (Linha 19) [MEDIUM]: Possible SQL injection vector through string-based query construction. (Bandit test B608 reports SQL injection risk.)
- **B605** (Linha 23) [MEDIUM]: Starting a process with a shell, possible injection detected, security issue. (Consulta de banco de dados construída por concatenação de strings.)
- **B301** (Linha 27) [MEDIUM]: Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue. (Consulta de banco de dados construída por concatenação de strings.)
- **B324** (Linha 31) [MEDIUM]: Use of weak MD5 hash for security. Consider usedforsecurity=False
- **B506** (Linha 35) [MEDIUM]: Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().
- **B201** (Linha 40) [MEDIUM]: A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code. (Bandit test B201 reports command injection risk.)
- **B104** (Linha 40) [MEDIUM]: Possible binding to all interfaces.
- **SQL_INJECTION** (Linha 0) [HIGH]: Concatenacão de strings em queries detectada; possível SQLi.
- **INSECURE_DESERIALIZATION** (Linha 0) [MEDIUM]: Uso de pickle/deserialize em dados não confiáveis.

---

## 🔍 Avaliador Central

⚠️  54 vulnerabilidade(s) encontrada(s): 7 crítica(s), 37 alta(s), 10 média(s)

---

## 🔧 Correções Sugeridas

### 1. CVE-2020-36242

**Severidade:** HIGH → LOW

**Explicação:** Substitua algoritmos fracos (MD5, SHA1, DES) por alternativas seguras (SHA-256, bcrypt, AES-256).

**❌ Código vulnerável:**

```python
cryptography==3.3.0
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

### 2. CVE-2023-0286

**Severidade:** HIGH → LOW

**Explicação:** Substitua algoritmos fracos (MD5, SHA1, DES) por alternativas seguras (SHA-256, bcrypt, AES-256).

**❌ Código vulnerável:**

```python
cryptography==3.3.0
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

### 3. CVE-2023-50782

**Severidade:** HIGH → LOW

**Explicação:** Substitua algoritmos fracos (MD5, SHA1, DES) por alternativas seguras (SHA-256, bcrypt, AES-256).

**❌ Código vulnerável:**

```python
cryptography==3.3.0
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

### 4. CVE-2026-26007

**Severidade:** HIGH → LOW

**Explicação:** Substitua algoritmos fracos (MD5, SHA1, DES) por alternativas seguras (SHA-256, bcrypt, AES-256).

**❌ Código vulnerável:**

```python
cryptography==3.3.0
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

### 5. CVE-2021-35042

**Severidade:** CRITICAL → LOW

**Explicação:** Substitua concatenação/interpolação de strings em queries SQL por queries parametrizadas.

**❌ Código vulnerável:**

```python
django==3.1.0
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

### 6. CVE-2025-64459

**Severidade:** CRITICAL → LOW

**Explicação:** Substitua concatenação/interpolação de strings em queries SQL por queries parametrizadas.

**❌ Código vulnerável:**

```python
django==3.1.0
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

### 7. CVE-2020-24583

**Severidade:** HIGH → LOW

**Explicação:** Valide e normalize caminhos de arquivo. Use pathlib.resolve() e verifique se o caminho resultante está dentro do diretório permitido.

**❌ Código vulnerável:**

```python
django==3.1.0
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# file_path = os.path.join(BASE_DIR, user_input)
# content = open(file_path).read()

# DEPOIS (seguro):
from pathlib import Path

BASE_DIR = Path("/app/uploads").resolve()
requested = (BASE_DIR / user_input).resolve()

# Verifica se o caminho está dentro do diretório permitido
if not str(requested).startswith(str(BASE_DIR)):
    raise ValueError("Path traversal detectado!")

content = requested.read_text()
```

**Referências:**
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

---

### 8. CVE-2021-31542

**Severidade:** HIGH → LOW

**Explicação:** Valide e normalize caminhos de arquivo. Use pathlib.resolve() e verifique se o caminho resultante está dentro do diretório permitido.

**❌ Código vulnerável:**

```python
django==3.1.0
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# file_path = os.path.join(BASE_DIR, user_input)
# content = open(file_path).read()

# DEPOIS (seguro):
from pathlib import Path

BASE_DIR = Path("/app/uploads").resolve()
requested = (BASE_DIR / user_input).resolve()

# Verifica se o caminho está dentro do diretório permitido
if not str(requested).startswith(str(BASE_DIR)):
    raise ValueError("Path traversal detectado!")

content = requested.read_text()
```

**Referências:**
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

---

### 9. CVE-2021-33571

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
django==3.1.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 10. CVE-2022-36359

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
django==3.1.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 11. CVE-2025-57833

**Severidade:** HIGH → LOW

**Explicação:** Substitua concatenação/interpolação de strings em queries SQL por queries parametrizadas.

**❌ Código vulnerável:**

```python
django==3.1.0
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

### 12. CVE-2025-64458

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
django==3.1.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 13. CVE-2023-30861

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
flask==2.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 14. CVE-2021-25289

**Severidade:** CRITICAL → MEDIUM

**Explicação:** Vulnerabilidade crítica. Prioridade máxima de correção. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 15. CVE-2021-34552

**Severidade:** CRITICAL → MEDIUM

**Explicação:** Vulnerabilidade crítica. Prioridade máxima de correção. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 16. CVE-2022-22817

**Severidade:** CRITICAL → LOW

**Explicação:** Remova eval()/exec(). Para dados literais use ast.literal_eval(). Para expressões, implemente um parser seguro.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# result = eval(user_input)

# DEPOIS (seguro):
import ast

# Para literais Python (strings, números, listas, dicts):
result = ast.literal_eval(user_input)

# Para expressões matemáticas, use uma lib segura:
# from simpleeval import simple_eval
# result = simple_eval(user_input)
```

**Referências:**
- https://docs.python.org/3/library/ast.html#ast.literal_eval
- https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

---

### 17. CVE-2023-50447

**Severidade:** CRITICAL → LOW

**Explicação:** Remova eval()/exec(). Para dados literais use ast.literal_eval(). Para expressões, implemente um parser seguro.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# result = eval(user_input)

# DEPOIS (seguro):
import ast

# Para literais Python (strings, números, listas, dicts):
result = ast.literal_eval(user_input)

# Para expressões matemáticas, use uma lib segura:
# from simpleeval import simple_eval
# result = simple_eval(user_input)
```

**Referências:**
- https://docs.python.org/3/library/ast.html#ast.literal_eval
- https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

---

### 18. CVE-2020-35653

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 19. CVE-2020-35654

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 20. CVE-2021-23437

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 21. CVE-2021-25287

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 22. CVE-2021-25288

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 23. CVE-2021-25290

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 24. CVE-2021-25291

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 25. CVE-2021-25293

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 26. CVE-2021-27921

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 27. CVE-2021-27922

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 28. CVE-2021-27923

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 29. CVE-2021-28675

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 30. CVE-2021-28676

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 31. CVE-2021-28677

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 32. CVE-2022-24303

**Severidade:** HIGH → LOW

**Explicação:** Valide e normalize caminhos de arquivo. Use pathlib.resolve() e verifique se o caminho resultante está dentro do diretório permitido.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# file_path = os.path.join(BASE_DIR, user_input)
# content = open(file_path).read()

# DEPOIS (seguro):
from pathlib import Path

BASE_DIR = Path("/app/uploads").resolve()
requested = (BASE_DIR / user_input).resolve()

# Verifica se o caminho está dentro do diretório permitido
if not str(requested).startswith(str(BASE_DIR)):
    raise ValueError("Path traversal detectado!")

content = requested.read_text()
```

**Referências:**
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

---

### 33. CVE-2022-45198

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 34. CVE-2023-44271

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 35. CVE-2023-4863

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 36. CVE-2024-28219

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
pillow==8.0.0
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 37. CVE-2020-14343

**Severidade:** CRITICAL → LOW

**Explicação:** Remova eval()/exec(). Para dados literais use ast.literal_eval(). Para expressões, implemente um parser seguro.

**❌ Código vulnerável:**

```python
pyyaml==5.3.1
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# result = eval(user_input)

# DEPOIS (seguro):
import ast

# Para literais Python (strings, números, listas, dicts):
result = ast.literal_eval(user_input)

# Para expressões matemáticas, use uma lib segura:
# from simpleeval import simple_eval
# result = simple_eval(user_input)
```

**Referências:**
- https://docs.python.org/3/library/ast.html#ast.literal_eval
- https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

---

### 38. CVE-2021-33503

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
urllib3==1.26.4
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 39. CVE-2023-43804

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
urllib3==1.26.4
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 40. CVE-2025-66418

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
urllib3==1.26.4
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 41. CVE-2025-66471

**Severidade:** HIGH → LOW

**Explicação:** Substitua algoritmos fracos (MD5, SHA1, DES) por alternativas seguras (SHA-256, bcrypt, AES-256).

**❌ Código vulnerável:**

```python
urllib3==1.26.4
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

### 42. CVE-2026-21441

**Severidade:** HIGH → LOW

**Explicação:** Substitua algoritmos fracos (MD5, SHA1, DES) por alternativas seguras (SHA-256, bcrypt, AES-256).

**❌ Código vulnerável:**

```python
urllib3==1.26.4
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

### 43. CVE-2026-44431

**Severidade:** HIGH → MEDIUM

**Explicação:** Vulnerabilidade de alta severidade. Requer correção imediata. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
urllib3==1.26.4
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 44. B403

**Severidade:** MEDIUM → LOW

**Explicação:** Substitua pickle por JSON para dados não confiáveis. Se pickle for necessário, use hmac para verificar integridade.

**❌ Código vulnerável:**

```python
1 | """App vulnerável para teste do Trivy + Bandit."""
       2 | import os
>>>    3 | import pickle
       4 | import hashlib
       5 | import yaml
       6 | from flask import Flask, request
       7 | 
       8 | app = Flask(__name__)
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# data = pickle.loads(untrusted_bytes)

# DEPOIS (seguro - opção 1: usar JSON):
import json
data = json.loads(untrusted_string)

# DEPOIS (seguro - opção 2: pickle com verificação HMAC):
import hmac, hashlib, pickle

expected_mac = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
if not hmac.compare_digest(received_mac, expected_mac):
    raise ValueError("Dados adulterados!")
data = pickle.loads(payload)
```

**Referências:**
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

---

### 45. B105

**Severidade:** MEDIUM → LOW

**Explicação:** Mova credenciais para variáveis de ambiente ou um vault seguro. Nunca hardcode senhas/tokens no código.

**❌ Código vulnerável:**

```python
7 | 
       8 | app = Flask(__name__)
       9 | 
      10 | # Hardcoded secret (Trivy secret scanner + Bandit)
      11 | API_KEY = "AKIAIOSFODNN7EXAMPLE"
>>>   12 | SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      13 | DATABASE_URL = "postgresql://admin:password123@prod-db.internal:5432/users"
      14 | 
      15 | @app.route("/user")
      16 | def get_user():
      17 |     # SQL injection via concatenação
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# DB_PASSWORD = "super_secret_123"

# DEPOIS (seguro):
import os

DB_PASSWORD = os.environ["DB_PASSWORD"]
# ou com valor padrão para dev:
# DB_PASSWORD = os.getenv("DB_PASSWORD", "")
# if not DB_PASSWORD:
#     raise RuntimeError("DB_PASSWORD não configurada")
```

**Referências:**
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

---

### 46. B608

**Severidade:** MEDIUM → LOW

**Explicação:** Substitua concatenação/interpolação de strings em queries SQL por queries parametrizadas.

**❌ Código vulnerável:**

```python
14 | 
      15 | @app.route("/user")
      16 | def get_user():
      17 |     # SQL injection via concatenação
      18 |     user_id = request.args.get("id")
>>>   19 |     query = f"SELECT * FROM users WHERE id = {user_id}"
      20 |     
      21 |     # Command injection
      22 |     filename = request.args.get("file")
      23 |     os.system(f"cat /data/{filename}")
      24 |
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

### 47. B605

**Severidade:** MEDIUM → LOW

**Explicação:** Use subprocess com lista de argumentos em vez de shell=True. Nunca passe entrada do usuário direto em comandos.

**❌ Código vulnerável:**

```python
18 |     user_id = request.args.get("id")
      19 |     query = f"SELECT * FROM users WHERE id = {user_id}"
      20 |     
      21 |     # Command injection
      22 |     filename = request.args.get("file")
>>>   23 |     os.system(f"cat /data/{filename}")
      24 |     
      25 |     # Insecure deserialization
      26 |     data = request.args.get("data")
      27 |     obj = pickle.loads(bytes.fromhex(data))
      28 |
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

### 48. B301

**Severidade:** MEDIUM → LOW

**Explicação:** Substitua pickle por JSON para dados não confiáveis. Se pickle for necessário, use hmac para verificar integridade.

**❌ Código vulnerável:**

```python
22 |     filename = request.args.get("file")
      23 |     os.system(f"cat /data/{filename}")
      24 |     
      25 |     # Insecure deserialization
      26 |     data = request.args.get("data")
>>>   27 |     obj = pickle.loads(bytes.fromhex(data))
      28 |     
      29 |     # Weak crypto
      30 |     password = request.args.get("pass")
      31 |     hashed = hashlib.md5(password.encode()).hexdigest()
      32 |
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# data = pickle.loads(untrusted_bytes)

# DEPOIS (seguro - opção 1: usar JSON):
import json
data = json.loads(untrusted_string)

# DEPOIS (seguro - opção 2: pickle com verificação HMAC):
import hmac, hashlib, pickle

expected_mac = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
if not hmac.compare_digest(received_mac, expected_mac):
    raise ValueError("Dados adulterados!")
data = pickle.loads(payload)
```

**Referências:**
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

---

### 49. B324

**Severidade:** MEDIUM → LOW

**Explicação:** Substitua algoritmos fracos (MD5, SHA1, DES) por alternativas seguras (SHA-256, bcrypt, AES-256).

**❌ Código vulnerável:**

```python
26 |     data = request.args.get("data")
      27 |     obj = pickle.loads(bytes.fromhex(data))
      28 |     
      29 |     # Weak crypto
      30 |     password = request.args.get("pass")
>>>   31 |     hashed = hashlib.md5(password.encode()).hexdigest()
      32 |     
      33 |     # Unsafe YAML load
      34 |     config = request.args.get("config")
      35 |     parsed = yaml.load(config)
      36 |
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

### 50. B506

**Severidade:** MEDIUM → MEDIUM

**Explicação:** Vulnerabilidade de média severidade. Corrija na próxima iteração. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
34     config = request.args.get("config")
35     parsed = yaml.load(config)
36
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 51. B201

**Severidade:** MEDIUM → LOW

**Explicação:** Remova eval()/exec(). Para dados literais use ast.literal_eval(). Para expressões, implemente um parser seguro.

**❌ Código vulnerável:**

```python
35 |     parsed = yaml.load(config)
      36 |     
      37 |     return str(obj)
      38 | 
      39 | if __name__ == "__main__":
>>>   40 |     app.run(debug=True, host="0.0.0.0")
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# result = eval(user_input)

# DEPOIS (seguro):
import ast

# Para literais Python (strings, números, listas, dicts):
result = ast.literal_eval(user_input)

# Para expressões matemáticas, use uma lib segura:
# from simpleeval import simple_eval
# result = simple_eval(user_input)
```

**Referências:**
- https://docs.python.org/3/library/ast.html#ast.literal_eval
- https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

---

### 52. B104

**Severidade:** MEDIUM → MEDIUM

**Explicação:** Vulnerabilidade de média severidade. Corrija na próxima iteração. Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas.

**❌ Código vulnerável:**

```python
39 if __name__ == "__main__":
40     app.run(debug=True, host="0.0.0.0")
```

**✅ Correção sugerida:**

```python
# TODO: Aplicar correção de segurança (ver explicação e referências)
```

**Referências:**
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/

---

### 53. SQL_INJECTION

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

### 54. INSECURE_DESERIALIZATION

**Severidade:** MEDIUM → LOW

**Explicação:** Substitua pickle por JSON para dados não confiáveis. Se pickle for necessário, use hmac para verificar integridade.

**❌ Código vulnerável:**

```python
pickle payload executing os.system()
```

**✅ Correção sugerida:**

```python
# ANTES (vulnerável):
# data = pickle.loads(untrusted_bytes)

# DEPOIS (seguro - opção 1: usar JSON):
import json
data = json.loads(untrusted_string)

# DEPOIS (seguro - opção 2: pickle com verificação HMAC):
import hmac, hashlib, pickle

expected_mac = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
if not hmac.compare_digest(received_mac, expected_mac):
    raise ValueError("Dados adulterados!")
data = pickle.loads(payload)
```

**Referências:**
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

---

## 📊 Conclusão

| Métrica | Valor |
|---------|-------|
| Total de vulnerabilidades | 54 |
| Críticas | 7 |
| Altas | 37 |
| Médias | 10 |
| Baixas | 0 |
| Falsos positivos descartados | 0 |
| **Risk Score** | **100.0/100** |

### Recomendações

- Execute auditorias de segurança regulares no CI/CD
- Mantenha dependências atualizadas
- Substitua pickle por JSON em dados não confiáveis
- Use queries parametrizadas (nunca concatene strings SQL)
