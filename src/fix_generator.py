"""Módulo de geração de correções de segurança.

Analisa vulnerabilidades detectadas no código-fonte e gera sugestões de fix
concretas, com código corrigido, explicação e referências.

Estratégia:
1. Templates locais para padrões conhecidos (SQL injection, eval, pickle, etc.)
2. Análise contextual do código ao redor da vulnerabilidade
3. LLM para gerar fixes personalizados quando templates não cobrem
"""

import asyncio
import re
import textwrap
from typing import Dict, List, Optional, Tuple

from src.config.settings import get_settings
from src.models.schemas import FixSuggestion, Vulnerability


# ── Templates de correção para vulnerabilidades conhecidas ────────────────────

FIX_TEMPLATES: Dict[str, Dict] = {
    "SQL_INJECTION": {
        "pattern": r"(f['\"].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*['\"]|['\"].*%s.*['\"].*%)",
        "explanation": "Substitua concatenação/interpolação de strings em queries SQL por queries parametrizadas.",
        "fixed_example": textwrap.dedent("""\
            # ANTES (vulnerável):
            # query = f"SELECT * FROM users WHERE id={user_id}"
            
            # DEPOIS (seguro):
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            # ou com SQLAlchemy:
            # stmt = select(users).where(users.c.id == bindparam('uid'))
            # result = conn.execute(stmt, {"uid": user_id})
        """),
        "severity_reduced_to": "LOW",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders",
        ],
    },
    "OS_COMMAND_INJECTION": {
        "pattern": r"(os\.system|os\.popen|subprocess\.call\(.*shell\s*=\s*True)",
        "explanation": "Use subprocess com lista de argumentos em vez de shell=True. Nunca passe entrada do usuário direto em comandos.",
        "fixed_example": textwrap.dedent("""\
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
        """),
        "severity_reduced_to": "LOW",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
    },
    "CODE_INJECTION": {
        "pattern": r"(eval\(|exec\(|compile\()",
        "explanation": "Remova eval()/exec(). Para dados literais use ast.literal_eval(). Para expressões, implemente um parser seguro.",
        "fixed_example": textwrap.dedent("""\
            # ANTES (vulnerável):
            # result = eval(user_input)
            
            # DEPOIS (seguro):
            import ast
            
            # Para literais Python (strings, números, listas, dicts):
            result = ast.literal_eval(user_input)
            
            # Para expressões matemáticas, use uma lib segura:
            # from simpleeval import simple_eval
            # result = simple_eval(user_input)
        """),
        "severity_reduced_to": "LOW",
        "references": [
            "https://docs.python.org/3/library/ast.html#ast.literal_eval",
            "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "INSECURE_DESERIALIZATION": {
        "pattern": r"(pickle\.loads?|yaml\.load\((?!.*Loader))",
        "explanation": "Substitua pickle por JSON para dados não confiáveis. Se pickle for necessário, use hmac para verificar integridade.",
        "fixed_example": textwrap.dedent("""\
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
        """),
        "severity_reduced_to": "LOW",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
    },
    "WEAK_CRYPTOGRAPHY": {
        "pattern": r"(hashlib\.md5|hashlib\.sha1|DES|RC4)",
        "explanation": "Substitua algoritmos fracos (MD5, SHA1, DES) por alternativas seguras (SHA-256, bcrypt, AES-256).",
        "fixed_example": textwrap.dedent("""\
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
        """),
        "severity_reduced_to": "LOW",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        ],
    },
    "HARDCODED_CREDENTIALS": {
        "pattern": r"(password\s*=\s*['\"]|api_key\s*=\s*['\"]|secret\s*=\s*['\"])",
        "explanation": "Mova credenciais para variáveis de ambiente ou um vault seguro. Nunca hardcode senhas/tokens no código.",
        "fixed_example": textwrap.dedent("""\
            # ANTES (vulnerável):
            # DB_PASSWORD = "super_secret_123"
            
            # DEPOIS (seguro):
            import os
            
            DB_PASSWORD = os.environ["DB_PASSWORD"]
            # ou com valor padrão para dev:
            # DB_PASSWORD = os.getenv("DB_PASSWORD", "")
            # if not DB_PASSWORD:
            #     raise RuntimeError("DB_PASSWORD não configurada")
        """),
        "severity_reduced_to": "LOW",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        ],
    },
    "PATH_TRAVERSAL": {
        "pattern": r"(open\(.*\+|os\.path\.join\(.*input|Path\(.*input)",
        "explanation": "Valide e normalize caminhos de arquivo. Use pathlib.resolve() e verifique se o caminho resultante está dentro do diretório permitido.",
        "fixed_example": textwrap.dedent("""\
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
        """),
        "severity_reduced_to": "LOW",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
        ],
    },
    "SSRF": {
        "pattern": r"(requests\.get\(.*input|urllib\.request\.urlopen\(.*input)",
        "explanation": "Valide URLs antes de fazer requisições. Bloqueie endereços internos (127.0.0.1, 10.x, 192.168.x, etc.).",
        "fixed_example": textwrap.dedent("""\
            # ANTES (vulnerável):
            # response = requests.get(user_url)
            
            # DEPOIS (seguro):
            from urllib.parse import urlparse
            import ipaddress
            import socket
            
            def is_safe_url(url: str) -> bool:
                parsed = urlparse(url)
                if parsed.scheme not in ("http", "https"):
                    return False
                try:
                    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
                    return ip.is_global
                except (ValueError, socket.gaierror):
                    return False
            
            if not is_safe_url(user_url):
                raise ValueError("URL não permitida")
            response = requests.get(user_url, timeout=10)
        """),
        "severity_reduced_to": "LOW",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
}

# Mapeamento de IDs do Bandit para categorias de template
BANDIT_TO_CATEGORY: Dict[str, str] = {
    "B608": "SQL_INJECTION",
    "B602": "OS_COMMAND_INJECTION",
    "B603": "OS_COMMAND_INJECTION",
    "B605": "OS_COMMAND_INJECTION",
    "B607": "OS_COMMAND_INJECTION",
    "B307": "CODE_INJECTION",
    "B201": "CODE_INJECTION",
    "B301": "INSECURE_DESERIALIZATION",
    "B303": "WEAK_CRYPTOGRAPHY",
    "B304": "WEAK_CRYPTOGRAPHY",
    "B305": "WEAK_CRYPTOGRAPHY",
    "B324": "WEAK_CRYPTOGRAPHY",
    "B105": "HARDCODED_CREDENTIALS",
    "B106": "HARDCODED_CREDENTIALS",
    "B107": "HARDCODED_CREDENTIALS",
}


class FixGenerator:
    """Gera correções de segurança baseadas no código vulnerável.

    Combina templates locais com LLM para produzir sugestões de fix
    contextualizadas e aplicáveis.
    """

    def __init__(self):
        self.settings = get_settings()
        self._langchain = None
        try:
            from src.toolkit import client_from_settings
            self._langchain = client_from_settings(self.settings)
        except Exception:
            pass

    async def generate_fixes(
        self,
        code: str,
        vulnerabilities: List[Vulnerability],
        file_path: str = "code.py",
    ) -> List[FixSuggestion]:
        """Gera sugestões de correção para cada vulnerabilidade detectada.

        Args:
            code: Código-fonte completo do arquivo analisado.
            vulnerabilities: Lista de vulnerabilidades confirmadas.
            file_path: Caminho do arquivo (para contexto).

        Returns:
            Lista de FixSuggestion com código corrigido e explicações.
        """
        fixes: List[FixSuggestion] = []
        code_lines = code.splitlines()

        for vuln in vulnerabilities:
            # Extrai o trecho de código ao redor da vulnerabilidade
            context_snippet = self._extract_context(code_lines, vuln.line_number)

            # Tenta template local primeiro
            fix = self._try_template_fix(vuln, context_snippet)
            if fix:
                fixes.append(fix)
                continue

            # Tenta LLM para gerar fix personalizado
            llm_fix = await self._try_llm_fix(vuln, context_snippet, file_path)
            if llm_fix:
                fixes.append(llm_fix)
                continue

            # Fallback genérico
            fixes.append(self._generic_fix(vuln))

        return fixes

    def _extract_context(self, code_lines: List[str], line_number: Optional[int], context_range: int = 5) -> str:
        """Extrai linhas ao redor da vulnerabilidade para contexto."""
        if not line_number or line_number <= 0 or not code_lines:
            return ""
        idx = line_number - 1  # 0-indexed
        start = max(0, idx - context_range)
        end = min(len(code_lines), idx + context_range + 1)
        lines_with_numbers = []
        for i in range(start, end):
            marker = ">>>" if i == idx else "   "
            lines_with_numbers.append(f"{marker} {i + 1:4d} | {code_lines[i]}")
        return "\n".join(lines_with_numbers)

    def _try_template_fix(self, vuln: Vulnerability, context: str) -> Optional[FixSuggestion]:
        """Tenta aplicar um template de fix conhecido."""
        # Determina a categoria da vulnerabilidade
        category = self._resolve_category(vuln)
        if not category or category not in FIX_TEMPLATES:
            return None

        template = FIX_TEMPLATES[category]

        # Usa o contexto extraído (linhas ao redor) como código original quando disponível
        if context:
            original_code = context
        elif vuln.code_snippet:
            original_code = vuln.code_snippet
        else:
            original_code = ""

        return FixSuggestion(
            vulnerability_type=vuln.type,
            original_code=original_code.strip(),
            fixed_code=template["fixed_example"].strip(),
            explanation=template["explanation"],
            severity_reduced_from=vuln.severity,
            severity_reduced_to=template["severity_reduced_to"],
            references=template["references"],
        )

    def _resolve_category(self, vuln: Vulnerability) -> Optional[str]:
        """Resolve a categoria de fix baseado no tipo da vulnerabilidade."""
        vuln_type = vuln.type.upper()

        # Match direto por Bandit ID
        if vuln_type in BANDIT_TO_CATEGORY:
            return BANDIT_TO_CATEGORY[vuln_type]

        # Match por nome da categoria
        for category in FIX_TEMPLATES:
            if category in vuln_type or vuln_type in category:
                return category

        # Match por keywords na descrição
        desc = (vuln.description or "").upper()
        keyword_map = {
            "SQL_INJECTION": ["SQL", "QUERY", "DATABASE"],
            "OS_COMMAND_INJECTION": ["COMMAND", "SHELL", "SYSTEM", "SUBPROCESS"],
            "CODE_INJECTION": ["EVAL", "EXEC", "CODE INJECTION"],
            "INSECURE_DESERIALIZATION": ["PICKLE", "DESERIALIZ", "YAML.LOAD"],
            "WEAK_CRYPTOGRAPHY": ["MD5", "SHA1", "DES", "CRYPTO", "HASH"],
            "HARDCODED_CREDENTIALS": ["HARDCODED", "PASSWORD", "CREDENTIAL", "SECRET"],
            "PATH_TRAVERSAL": ["PATH", "TRAVERSAL", "DIRECTORY"],
            "SSRF": ["SSRF", "SERVER-SIDE REQUEST"],
        }
        for category, keywords in keyword_map.items():
            if any(kw in desc or kw in vuln_type for kw in keywords):
                return category

        return None

    async def _try_llm_fix(self, vuln: Vulnerability, context: str, file_path: str) -> Optional[FixSuggestion]:
        """Usa LLM para gerar uma correção personalizada."""
        if not self._langchain:
            return None

        prompt = textwrap.dedent(f"""\
            You are a Python security expert. Analyze the following vulnerability and provide a concrete fix.

            FILE: {file_path}
            VULNERABILITY TYPE: {vuln.type}
            SEVERITY: {vuln.severity}
            DESCRIPTION: {vuln.description}
            CWE: {vuln.cwe_id or 'N/A'}

            CODE CONTEXT:
            {context or vuln.code_snippet or 'N/A'}

            Respond with a JSON object containing:
            {{
                "fixed_code": "the corrected code (complete, ready to use)",
                "explanation": "why the original code is vulnerable and how the fix resolves it (in Portuguese)",
                "severity_reduced_to": "LOW or MEDIUM",
                "references": ["url1", "url2"]
            }}

            Important:
            - The fixed_code must be valid Python
            - Keep the same functionality, just make it secure
            - Be specific to the code shown, not generic
        """)

        try:
            resp = await asyncio.get_running_loop().run_in_executor(
                None, self._langchain.generate_text, prompt
            )
            parsed = self._parse_json_response(resp)
            if isinstance(parsed, dict) and parsed.get("fixed_code"):
                return FixSuggestion(
                    vulnerability_type=vuln.type,
                    original_code=vuln.code_snippet or context or "",
                    fixed_code=parsed["fixed_code"],
                    explanation=parsed.get("explanation", "Correção gerada por LLM."),
                    severity_reduced_from=vuln.severity,
                    severity_reduced_to=parsed.get("severity_reduced_to", "MEDIUM"),
                    references=parsed.get("references", []),
                )
        except Exception:
            pass

        return None

    def _generic_fix(self, vuln: Vulnerability) -> FixSuggestion:
        """Gera uma sugestão genérica quando não há template nem LLM disponível."""
        generic_advice = {
            "HIGH": "Vulnerabilidade de alta severidade. Requer correção imediata.",
            "CRITICAL": "Vulnerabilidade crítica. Prioridade máxima de correção.",
            "MEDIUM": "Vulnerabilidade de média severidade. Corrija na próxima iteração.",
            "LOW": "Vulnerabilidade de baixa severidade. Considere corrigir.",
        }

        explanation = generic_advice.get(vuln.severity, generic_advice["MEDIUM"])
        explanation += " Recomendações gerais: valide entradas, use parametrização, evite eval/exec, mantenha dependências atualizadas."

        return FixSuggestion(
            vulnerability_type=vuln.type,
            original_code=vuln.code_snippet or "",
            fixed_code="# TODO: Aplicar correção de segurança (ver explicação e referências)",
            explanation=explanation,
            severity_reduced_from=vuln.severity,
            severity_reduced_to="MEDIUM",
            references=[
                "https://owasp.org/www-project-top-ten/",
                "https://cheatsheetseries.owasp.org/",
            ],
        )

    @staticmethod
    def _parse_json_response(text: str) -> Optional[Dict]:
        """Extrai JSON de uma resposta de texto livre."""
        import ast
        import json

        if not text:
            return None

        try:
            return json.loads(text)
        except Exception:
            pass

        # Remove fenced code blocks
        stripped = re.sub(r"```[a-zA-Z]*\n?", "", text).replace("```", "").strip()
        match = re.search(r"(\{.*\})", stripped, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except Exception:
                pass

        # Fallback: ast.literal_eval
        clean = stripped.replace("null", "None").replace("true", "True").replace("false", "False")
        try:
            result = ast.literal_eval(clean)
            if isinstance(result, dict):
                return result
        except Exception:
            pass

        return None
