"""Analisador estático de segurança — Semgrep (multi-linguagem) + Bandit (Python)."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from src.models.schemas import Vulnerability

# Diretório de scripts do Python ativo (para encontrar bandit/semgrep no venv)
_SCRIPTS_DIR = str(Path(sys.executable).parent)


class VulnerabilityDatabase:
    """Base de conhecimento local com mapeamentos CWE/OWASP para tipos de vulnerabilidade."""

    def __init__(self):
        self.vulnerabilities = self._load_default_vulnerabilities()

    def _load_default_vulnerabilities(self) -> Dict[str, Dict]:
        return {
            "SQL_INJECTION": {
                "cwe_id": "CWE-89",
                "cwe_name": "SQL Injection",
                "owasp_category": "A03:2021 - Injection",
                "description": "Consulta de banco de dados construída por concatenação de strings.",
                "references": ["https://owasp.org/www-project-top-ten/"],
            },
            "CROSS_SITE_SCRIPTING": {
                "cwe_id": "CWE-79",
                "cwe_name": "Cross-site Scripting",
                "owasp_category": "A03:2021 - Injection",
                "description": "Dados do usuário são inseridos em HTML sem escape.",
                "references": ["https://owasp.org/www-project-top-ten/"],
            },
            "OS_COMMAND_INJECTION": {
                "cwe_id": "CWE-78",
                "cwe_name": "OS Command Injection",
                "owasp_category": "A03:2021 - Injection",
                "description": "Comandos do sistema são construídos com entrada não confiável.",
                "references": ["https://owasp.org/www-project-top-ten/"],
            },
            "WEAK_CRYPTOGRAPHY": {
                "cwe_id": "CWE-327",
                "cwe_name": "Use of a Broken or Risky Cryptographic Algorithm",
                "owasp_category": "A02:2021 - Cryptographic Failures",
                "description": "Algoritmos fracos como MD5 ou DES estão sendo usados.",
                "references": ["https://owasp.org/www-project-top-ten/"],
            },
            "CODE_INJECTION": {
                "cwe_id": "CWE-95",
                "cwe_name": "Improper Neutralization of Directives",
                "owasp_category": "A03:2021 - Injection",
                "description": "Código ou expressões são executadas diretamente sem validação.",
                "references": ["https://owasp.org/www-project-top-ten/"],
            },
            "B201": {
                "cwe_id": "CWE-78",
                "cwe_name": "OS Command Injection",
                "owasp_category": "A03:2021 - Injection",
                "description": "Bandit: command injection risk.",
                "references": ["https://bandit.readthedocs.io/"],
            },
            "B303": {
                "cwe_id": "CWE-327",
                "cwe_name": "Use of insecure hash function",
                "owasp_category": "A02:2021 - Cryptographic Failures",
                "description": "Bandit: uso de MD5/SHA1 para hashing.",
                "references": ["https://bandit.readthedocs.io/"],
            },
            "B304": {
                "cwe_id": "CWE-327",
                "cwe_name": "Use of a Broken or Risky Cryptographic Algorithm",
                "owasp_category": "A02:2021 - Cryptographic Failures",
                "description": "Bandit: weak cryptography.",
                "references": ["https://bandit.readthedocs.io/"],
            },
            "B307": {
                "cwe_id": "CWE-95",
                "cwe_name": "Code Injection",
                "owasp_category": "A03:2021 - Injection",
                "description": "Bandit: uso de eval/exec.",
                "references": ["https://bandit.readthedocs.io/"],
            },
            "B608": {
                "cwe_id": "CWE-89",
                "cwe_name": "SQL Injection",
                "owasp_category": "A03:2021 - Injection",
                "description": "Bandit: SQL injection risk.",
                "references": ["https://bandit.readthedocs.io/"],
            },
        }

    def get_vulnerability_info(self, vuln_type: str) -> Optional[Dict]:
        if vuln_type in self.vulnerabilities:
            return self.vulnerabilities[vuln_type]
        for key, value in self.vulnerabilities.items():
            if key.lower() == vuln_type.lower():
                return value
        return None

    def search_by_keyword(self, text: str) -> Optional[Dict]:
        if not text:
            return None
        normalized = text.lower()
        for key, value in self.vulnerabilities.items():
            if key.lower() in normalized:
                return value
        return None

    def search_by_cwe(self, cwe_id: str) -> Optional[Dict]:
        for vuln in self.vulnerabilities.values():
            if vuln.get("cwe_id") == cwe_id:
                return vuln
        return None


_db_instance: Optional[VulnerabilityDatabase] = None


def get_vulnerability_db() -> VulnerabilityDatabase:
    """Retorna instância singleton do banco de vulnerabilidades."""
    global _db_instance
    if _db_instance is None:
        _db_instance = VulnerabilityDatabase()
    return _db_instance


def _find_tool(name: str) -> Optional[str]:
    """Encontra um executável no venv ou PATH do sistema."""
    for ext in ("", ".exe"):
        candidate = Path(_SCRIPTS_DIR) / f"{name}{ext}"
        if candidate.exists():
            return str(candidate)
    # Fallback: PATH do sistema
    try:
        result = subprocess.run(
            [name, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return name
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


class StaticAnalyzer:
    """Analisador estático: Semgrep (todas as linguagens) + Bandit (Python)."""

    def __init__(self, severity_level: str = "high"):
        self.severity_level = severity_level
        self.vuln_db = get_vulnerability_db()

    def analyze_code(self, code: str, file_path: str = "code.py", language: str = "python") -> List[Vulnerability]:
        """Executa análise estática com ferramentas adequadas à linguagem."""
        ext_map = {"python": ".py", "javascript": ".js", "typescript": ".ts", "java": ".java", "csharp": ".cs"}
        suffix = ext_map.get(language, ".py")

        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, dir=tempfile.gettempdir(), encoding="utf-8") as tmp_file:
            tmp_file.write(code)
            tmp_path = tmp_file.name

        vulnerabilities: List[Vulnerability] = []

        has_semgrep = _find_tool("semgrep") is not None
        has_bandit = _find_tool("bandit") is not None

        print(f"  [DEBUG] Semgrep: {has_semgrep} | Bandit: {has_bandit}")
        print(f"  [DEBUG] Linguagem: {language} | Arquivo temporário: {tmp_path}")

        if not has_semgrep and not has_bandit:
            print("  [AVISO] Nenhuma ferramenta SAST disponível.")
            Path(tmp_path).unlink(missing_ok=True)
            return vulnerabilities

        try:
            # ── Semgrep (todas as linguagens) ─────────────────────────────
            if has_semgrep:
                semgrep_vulns = self._run_semgrep(tmp_path, file_path)
                print(f"  [DEBUG] Semgrep retornou {len(semgrep_vulns)} achado(s)")
                vulnerabilities.extend(semgrep_vulns)

            # ── Bandit (complementar, só Python) ──────────────────────────
            if language == "python" and has_bandit:
                bandit_vulns = self._run_bandit(tmp_path, file_path)
                print(f"  [DEBUG] Bandit retornou {len(bandit_vulns)} achado(s)")
                existing = {(v.type, v.line_number) for v in vulnerabilities}
                for bv in bandit_vulns:
                    if (bv.type, bv.line_number) not in existing:
                        vulnerabilities.append(bv)

        finally:
            Path(tmp_path).unlink(missing_ok=True)

        return vulnerabilities

    # ── Semgrep ───────────────────────────────────────────────────────────────

    def _run_semgrep(self, tmp_path: str, file_path: str) -> List[Vulnerability]:
        """Executa Semgrep com regras automáticas."""
        semgrep_cmd = _find_tool("semgrep")
        if not semgrep_cmd:
            return []

        try:
            cmd = [
                semgrep_cmd, "scan",
                "--config", "auto",
                "--json",
                "--quiet",
                tmp_path,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            print(f"  [DEBUG] Semgrep returncode: {result.returncode}")
            return self._parse_semgrep_output(result.stdout, file_path)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            print(f"  [DEBUG] Semgrep exception: {e}")
            return []

    def _parse_semgrep_output(self, json_output: str, file_path: str) -> List[Vulnerability]:
        """Parseia output JSON do Semgrep."""
        vulnerabilities = []
        if not json_output or not json_output.strip():
            return vulnerabilities

        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return vulnerabilities

        for result in data.get("results", []):
            check_id = result.get("check_id", "UNKNOWN")
            severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
            severity = severity_map.get(
                result.get("extra", {}).get("severity", "WARNING"), "MEDIUM"
            )

            message = result.get("extra", {}).get("message", "Security issue detected")
            line_number = result.get("start", {}).get("line", 0)
            code_snippet = result.get("extra", {}).get("lines", "")

            metadata = result.get("extra", {}).get("metadata", {})
            cwe_list = metadata.get("cwe", [])
            cwe_id = cwe_list[0] if cwe_list else None
            owasp_list = metadata.get("owasp", [])
            owasp = owasp_list[0] if owasp_list else None

            vuln = Vulnerability(
                type=check_id.split(".")[-1] if "." in check_id else check_id,
                severity=severity,
                line_number=line_number,
                description=message[:300],
                code_snippet=code_snippet[:200] if code_snippet else None,
                confidence=0.80,
                cwe_id=cwe_id,
                cwe_name=check_id,
                owasp_category=owasp,
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    # ── Bandit (Python only) ──────────────────────────────────────────────────

    def _run_bandit(self, tmp_path: str, file_path: str) -> List[Vulnerability]:
        """Executa Bandit localmente."""
        bandit_cmd = _find_tool("bandit")
        if not bandit_cmd:
            return []

        try:
            cmd = [bandit_cmd, "-f", "json", tmp_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            print(f"  [DEBUG] Bandit returncode: {result.returncode}")
            return self._parse_bandit_output(result.stdout, file_path)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            print(f"  [DEBUG] Bandit exception: {e}")
            return []

    def _parse_bandit_output(self, json_output: str, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return vulnerabilities

        for result in data.get("results", []):
            severity = result.get("severity", "MEDIUM").upper()
            confidence = result.get("confidence", "MEDIUM").upper()

            issue_text = result.get("issue_text", "").strip()
            bandit_id = result.get("test_id", "Unknown")
            code_line = result.get("code", "")
            vuln_info = self.vuln_db.get_vulnerability_info(bandit_id) or self.vuln_db.search_by_keyword(issue_text)

            cwe_id = vuln_info.get("cwe_id") if vuln_info else self._extract_cwe_id(bandit_id)
            cwe_name = vuln_info.get("cwe_name") if vuln_info else None
            owasp_category = vuln_info.get("owasp_category") if vuln_info else None
            description = issue_text
            if vuln_info and vuln_info.get("description"):
                description = f"{issue_text} ({vuln_info['description']})"

            confidence_score = {"LOW": 0.5, "MEDIUM": 0.75, "HIGH": 0.95}.get(confidence, 0.7)
            vuln = Vulnerability(
                type=bandit_id,
                severity=severity,
                line_number=result.get("line_number", 0),
                description=description,
                code_snippet=code_line,
                confidence=confidence_score,
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                owasp_category=owasp_category,
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    @staticmethod
    def _extract_cwe_id(bandit_test_id: str) -> Optional[str]:
        mapping = {
            "B201": "CWE-78", "B303": "CWE-327", "B304": "CWE-327",
            "B307": "CWE-95", "B602": "CWE-78", "B603": "CWE-78",
            "B607": "CWE-426", "B608": "CWE-89", "B609": "CWE-426",
            "B610": "CWE-74", "B611": "CWE-91"
        }
        return mapping.get(bandit_test_id)
