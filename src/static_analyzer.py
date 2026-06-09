"""Analisador estático de segurança — Trivy (primário) + Bandit (complementar)."""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from src.models.schemas import Vulnerability


class VulnerabilityDatabase:
    """Base de conhecimento local com mapeamentos CWE/OWASP para tipos de vulnerabilidade."""

    def __init__(self):
        self.vulnerabilities = self._load_default_vulnerabilities()

    def _load_default_vulnerabilities(self) -> Dict[str, Dict]:
        return {
            "SQL_INJECTION": {
                "cwe_id": "CWE-89",
                "cwe_name": "SQL Injection",
                "owasp_category": "A01:2021 - Broken Access Control",
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
                "owasp_category": "A01:2021 - Broken Access Control",
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
            "MISSING_AUTHENTICATION": {
                "cwe_id": "CWE-306",
                "cwe_name": "Missing Authentication for Critical Function",
                "owasp_category": "A03:2021 - Injection",
                "description": "Função crítica pode ser acessada sem autenticação.",
                "references": ["https://owasp.org/www-project-top-ten/"],
            },
            "B201": {
                "cwe_id": "CWE-78",
                "cwe_name": "OS Command Injection",
                "owasp_category": "A01:2021 - Broken Access Control",
                "description": "Bandit test B201 reports command injection risk.",
                "references": ["https://bandit.readthedocs.io/"],
            },
            "B303": {
                "cwe_id": "CWE-345",
                "cwe_name": "Insufficient Verification of Data Authenticity",
                "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                "description": "Bandit test B303 reports pickle deserialization risk.",
                "references": ["https://bandit.readthedocs.io/"],
            },
            "B304": {
                "cwe_id": "CWE-327",
                "cwe_name": "Use of a Broken or Risky Cryptographic Algorithm",
                "owasp_category": "A02:2021 - Cryptographic Failures",
                "description": "Bandit test B304 reports weak cryptography.",
                "references": ["https://bandit.readthedocs.io/"],
            },
            "B307": {
                "cwe_id": "CWE-95",
                "cwe_name": "Code Injection",
                "owasp_category": "A03:2021 - Injection",
                "description": "Bandit test B307 reports unsafe string formatting for exec/eval.",
                "references": ["https://bandit.readthedocs.io/"],
            },
            "B608": {
                "cwe_id": "CWE-89",
                "cwe_name": "SQL Injection",
                "owasp_category": "A03:2021 - Injection",
                "description": "Bandit test B608 reports SQL injection risk.",
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
            if any(word.lower() in normalized for word in ["sql", "xss", "pickle", "shell", "command", "crypto", "auth"]):
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


class StaticAnalyzer:
    """Analisador estático que usa Trivy (primário) com fallback para Bandit."""

    def __init__(self, severity_level: str = "high"):
        self.severity_level = severity_level
        self.severity_map = {"low": 1, "medium": 2, "high": 3}
        self.vuln_db = get_vulnerability_db()

    def _check_docker(self) -> bool:
        """Verifica se o Docker está disponível para rodar scanners."""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _check_local_trivy(self) -> bool:
        """Verifica se o Trivy está instalado localmente (ex: dentro de container)."""
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _check_local_bandit(self) -> bool:
        """Verifica se o Bandit está instalado localmente."""
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def analyze_code(self, code: str, file_path: str = "code.py", language: str = "python") -> List[Vulnerability]:
        """Executa análise estática — ferramentas variam por linguagem."""
        # Determina extensão correta para o arquivo temporário
        ext_map = {"python": ".py", "javascript": ".js", "typescript": ".ts", "java": ".java", "csharp": ".cs"}
        suffix = ext_map.get(language, ".py")

        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, dir=tempfile.gettempdir()) as tmp_file:
            tmp_file.write(code)
            tmp_path = tmp_file.name

        vulnerabilities: List[Vulnerability] = []
        has_docker = self._check_docker()
        has_local_trivy = self._check_local_trivy()
        has_local_bandit = self._check_local_bandit()

        print(f"  [DEBUG] Docker: {has_docker} | Trivy local: {has_local_trivy} | Bandit local: {has_local_bandit}")
        print(f"  [DEBUG] Linguagem: {language} | Arquivo temporário: {tmp_path}")

        if not has_docker and not has_local_trivy and not has_local_bandit:
            print("  [AVISO] Nem Docker nem binários locais disponíveis. Análise estática desabilitada.")
            Path(tmp_path).unlink(missing_ok=True)
            return vulnerabilities

        try:
            # ── Trivy scan (escaneia o diretório do projeto para pegar dependências) ──
            scan_dir = self._resolve_scan_dir(file_path)
            trivy_vulns = self._run_trivy(scan_dir, file_path, use_docker=has_docker, use_local=has_local_trivy)
            print(f"  [DEBUG] Trivy retornou {len(trivy_vulns)} achado(s)")
            vulnerabilities.extend(trivy_vulns)

            # ── Ferramentas por linguagem ─────────────────────────────────
            if language == "python":
                bandit_vulns = self._run_bandit(tmp_path, file_path, use_docker=has_docker, use_local=has_local_bandit)
                print(f"  [DEBUG] Bandit retornou {len(bandit_vulns)} achado(s)")
                existing_lines = {(v.type, v.line_number) for v in vulnerabilities}
                for bv in bandit_vulns:
                    if (bv.type, bv.line_number) not in existing_lines:
                        vulnerabilities.append(bv)
            elif language in ("javascript", "typescript", "java", "csharp"):
                semgrep_vulns = self._run_semgrep(tmp_path, file_path, language, use_docker=has_docker)
                print(f"  [DEBUG] Semgrep retornou {len(semgrep_vulns)} achado(s)")
                existing_lines = {(v.type, v.line_number) for v in vulnerabilities}
                for sv in semgrep_vulns:
                    if (sv.type, sv.line_number) not in existing_lines:
                        vulnerabilities.append(sv)

        finally:
            Path(tmp_path).unlink(missing_ok=True)

        return vulnerabilities

    def _resolve_scan_dir(self, file_path: str) -> str:
        """Resolve o diretório a escanear com Trivy (busca onde tem requirements.txt)."""
        path = Path(file_path).resolve()
        # Sobe nos diretórios procurando requirements.txt ou Pipfile.lock
        for parent in [path.parent] + list(path.parents):
            if (parent / "requirements.txt").exists() or (parent / "Pipfile.lock").exists() or (parent / "poetry.lock").exists():
                # Não escaneia diretórios muito grandes (raiz do projeto com venv)
                # Escaneia só o arquivo de dependências
                return str(parent / "requirements.txt") if (parent / "requirements.txt").exists() else str(parent)
        # Fallback: só o arquivo em si
        return file_path

    # ── Trivy ─────────────────────────────────────────────────────────────────

    def _run_trivy(self, scan_path: str, file_path: str, use_docker: bool = False, use_local: bool = False) -> List[Vulnerability]:
        """Executa Trivy filesystem scan no diretório do projeto."""
        try:
            if use_local:
                cmd = [
                    "trivy", "fs",
                    "--scanners", "vuln,secret,misconfig",
                    "--format", "json",
                    "--severity", self._trivy_severity_filter(),
                    "--quiet",
                    scan_path,
                ]
            elif use_docker:
                scan_dir = str(Path(scan_path).resolve()).replace("\\", "/")
                cmd = [
                    "docker", "run", "--rm",
                    "--memory=512m",
                    "-v", f"{scan_dir}:/scan",
                    "aquasec/trivy:latest",
                    "fs",
                    "--scanners", "vuln,secret,misconfig",
                    "--format", "json",
                    "--severity", self._trivy_severity_filter(),
                    "--quiet",
                    "/scan",
                ]
            else:
                return []

            print(f"  [DEBUG] Trivy scan path: {scan_path}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            print(f"  [DEBUG] Trivy returncode: {result.returncode}")
            if result.stderr:
                print(f"  [DEBUG] Trivy stderr: {result.stderr[:300]}")
            if result.returncode not in (0, 1):
                return []
            return self._parse_trivy_output(result.stdout, file_path)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            print(f"  [DEBUG] Trivy exception: {e}")
            return []

    def _trivy_severity_filter(self) -> str:
        """Mapeia o severity_level para o filtro do Trivy."""
        mapping = {
            "high": "HIGH,CRITICAL",
            "medium": "MEDIUM,HIGH,CRITICAL",
            "low": "LOW,MEDIUM,HIGH,CRITICAL",
        }
        return mapping.get(self.severity_level, "HIGH,CRITICAL")

    def _parse_trivy_output(self, json_output: str, file_path: str) -> List[Vulnerability]:
        """Parseia o JSON do Trivy e converte para Vulnerability."""
        vulnerabilities: List[Vulnerability] = []
        if not json_output or not json_output.strip():
            return vulnerabilities

        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return vulnerabilities

        # Trivy JSON pode ter "Results" (lista de targets)
        results = data.get("Results", [])
        if not results and isinstance(data, list):
            results = data

        for target in results:
            # ── Vulnerabilidades de dependências ──────────────────────────
            for vuln in target.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "MEDIUM").upper()
                vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
                pkg_name = vuln.get("PkgName", "")
                title = vuln.get("Title", "")
                description = vuln.get("Description", title or "Vulnerability detected by Trivy")
                installed_ver = vuln.get("InstalledVersion", "")
                fixed_ver = vuln.get("FixedVersion", "")

                # Extrai CWE se disponível
                cwe_ids = vuln.get("CweIDs", [])
                cwe_id = cwe_ids[0] if cwe_ids else None

                # CVSS score → confidence
                cvss_score = None
                cvss_data = vuln.get("CVSS", {})
                for source in cvss_data.values():
                    if "V3Score" in source:
                        cvss_score = source["V3Score"]
                        break

                confidence = min(1.0, (cvss_score or 7.0) / 10.0)

                remediation = None
                if fixed_ver:
                    remediation = f"Atualizar {pkg_name} de {installed_ver} para {fixed_ver}"

                v = Vulnerability(
                    type=vuln_id,
                    severity=severity,
                    line_number=0,
                    description=f"[{pkg_name}] {description[:300]}",
                    code_snippet=f"{pkg_name}=={installed_ver}" if installed_ver else None,
                    confidence=confidence,
                    cwe_id=cwe_id,
                    cwe_name=title[:100] if title else None,
                    owasp_category=self._map_owasp(cwe_id),
                    remediation=remediation,
                )
                vulnerabilities.append(v)

            # ── Secrets detectados ────────────────────────────────────────
            for secret in target.get("Secrets", []):
                severity = secret.get("Severity", "HIGH").upper()
                rule_id = secret.get("RuleID", "SECRET")
                title = secret.get("Title", "Exposed secret")
                start_line = secret.get("StartLine", 0)
                match_text = secret.get("Match", "")

                v = Vulnerability(
                    type=f"SECRET_{rule_id}",
                    severity=severity,
                    line_number=start_line,
                    description=f"Secret exposto: {title}",
                    code_snippet=match_text[:100] if match_text else None,
                    confidence=0.95,
                    cwe_id="CWE-798",
                    cwe_name="Use of Hard-coded Credentials",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                )
                vulnerabilities.append(v)

            # ── Misconfigurations ─────────────────────────────────────────
            for misconf in target.get("Misconfigurations", []):
                severity = misconf.get("Severity", "MEDIUM").upper()
                misconf_id = misconf.get("ID", "MISCONFIG")
                title = misconf.get("Title", "")
                description = misconf.get("Description", title)
                resolution = misconf.get("Resolution", "")

                v = Vulnerability(
                    type=f"MISCONFIG_{misconf_id}",
                    severity=severity,
                    line_number=misconf.get("CauseMetadata", {}).get("StartLine", 0),
                    description=description[:300],
                    code_snippet=misconf.get("CauseMetadata", {}).get("Code", {}).get("Lines", [{}])[0].get("Content", "") if misconf.get("CauseMetadata") else None,
                    confidence=0.85,
                    cwe_id=None,
                    cwe_name=title[:100] if title else None,
                    remediation=resolution[:200] if resolution else None,
                )
                vulnerabilities.append(v)

        return vulnerabilities

    @staticmethod
    def _map_owasp(cwe_id: Optional[str]) -> Optional[str]:
        """Mapeamento básico CWE → OWASP Top 10 2021."""
        if not cwe_id:
            return None
        mapping = {
            "CWE-78": "A03:2021 - Injection",
            "CWE-79": "A03:2021 - Injection",
            "CWE-89": "A03:2021 - Injection",
            "CWE-94": "A03:2021 - Injection",
            "CWE-95": "A03:2021 - Injection",
            "CWE-327": "A02:2021 - Cryptographic Failures",
            "CWE-328": "A02:2021 - Cryptographic Failures",
            "CWE-330": "A02:2021 - Cryptographic Failures",
            "CWE-502": "A08:2021 - Software and Data Integrity Failures",
            "CWE-798": "A07:2021 - Identification and Authentication Failures",
            "CWE-22": "A01:2021 - Broken Access Control",
            "CWE-276": "A01:2021 - Broken Access Control",
            "CWE-918": "A10:2021 - Server-Side Request Forgery",
        }
        return mapping.get(cwe_id)

    # ── Bandit (fallback/complementar) ────────────────────────────────────────

    def _run_bandit(self, tmp_path: str, file_path: str, use_docker: bool = False, use_local: bool = False) -> List[Vulnerability]:
        """Executa Bandit via binário local ou Docker."""
        try:
            if use_local:
                cmd = ["bandit", "-f", "json", tmp_path]
            elif use_docker:
                tmp_dir = str(Path(tmp_path).parent).replace("\\", "/")
                tmp_filename = Path(tmp_path).name
                cmd = [
                    "docker", "run", "--rm",
                    "--memory=256m",
                    "-v", f"{tmp_dir}:/scan",
                    "python:3.11-slim",
                    "bash", "-c",
                    f"pip install -q bandit && bandit -f json /scan/{tmp_filename}",
                ]
            else:
                return []

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            print(f"  [DEBUG] Bandit returncode: {result.returncode}")
            if result.stderr:
                print(f"  [DEBUG] Bandit stderr: {result.stderr[:300]}")
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

    # ── Semgrep (JavaScript, TypeScript, Java, C#) ──────────────────────────────

    def _run_semgrep(self, tmp_path: str, file_path: str, language: str, use_docker: bool = False) -> List[Vulnerability]:
        """Executa Semgrep via Docker para linguagens não-Python."""
        if not use_docker:
            # Tenta semgrep local
            try:
                result = subprocess.run(["semgrep", "--version"], capture_output=True, timeout=5)
                if result.returncode != 0:
                    return []
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return []
            cmd = [
                "semgrep", "scan",
                "--config", "auto",
                "--json",
                "--quiet",
                tmp_path,
            ]
        else:
            tmp_dir = str(Path(tmp_path).parent).replace("\\", "/")
            tmp_filename = Path(tmp_path).name
            cmd = [
                "docker", "run", "--rm",
                "--memory=512m",
                "-v", f"{tmp_dir}:/scan",
                "returntocorp/semgrep:latest",
                "semgrep", "scan",
                "--config", "auto",
                "--json",
                "--quiet",
                f"/scan/{tmp_filename}",
            ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            print(f"  [DEBUG] Semgrep returncode: {result.returncode}")
            if result.stderr and "error" in result.stderr.lower():
                print(f"  [DEBUG] Semgrep stderr: {result.stderr[:200]}")
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
            severity = severity_map.get(result.get("extra", {}).get("severity", "WARNING"), "MEDIUM")

            message = result.get("extra", {}).get("message", "Security issue detected by Semgrep")
            line_number = result.get("start", {}).get("line", 0)
            code_snippet = result.get("extra", {}).get("lines", "")

            # CWE extraction
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

    @staticmethod
    def _extract_cwe_id(bandit_test_id: str) -> Optional[str]:
        mapping = {
            "B201": "CWE-78", "B303": "CWE-345", "B304": "CWE-327",
            "B307": "CWE-95", "B602": "CWE-78", "B603": "CWE-78",
            "B607": "CWE-426", "B608": "CWE-89", "B609": "CWE-426",
            "B610": "CWE-74", "B611": "CWE-91"
        }
        return mapping.get(bandit_test_id)
