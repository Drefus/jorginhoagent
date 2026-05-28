import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

import requests

from src.models.schemas import SecurityReport, Vulnerability


class LLMClient:
    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        default_model: str = "llama3.2:3b",
        default_embed_model: str = "nomic-embed-text:latest",
        temperature: float = 0.0,
    ):
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.api_key = api_key
        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["X-API-Key"] = api_key
        self.default_model = default_model
        self.default_embed_model = default_embed_model
        self.temperature = temperature

    def check_api(self) -> None:
        if not self.base_url:
            raise RuntimeError("BASE_URL missing")
        try:
            requests.get(f"{self.base_url}/health", timeout=5)
        except requests.exceptions.ConnectionError:
            raise RuntimeError(f"Connection error: {self.base_url}")
        except requests.exceptions.Timeout:
            raise RuntimeError("Timeout")

        if self.api_key:
            r = requests.get(f"{self.base_url}/api/tags", headers=self.headers)
            r.raise_for_status()

    def listar_modelos(self) -> List[str]:
        r = requests.get(f"{self.base_url}/api/tags", headers=self.headers)
        r.raise_for_status()
        return [m["name"] for m in r.json().get("models", [])]

    def gerar_texto(self, prompt: str, modelo: Optional[str] = None) -> str:
        payload = {
            "model": modelo or self.default_model,
            "prompt": prompt,
            "stream": False
        }
        r = requests.post(f"{self.base_url}/api/generate", headers=self.headers, json=payload)
        r.raise_for_status()
        return r.json().get("response", "")

    def chat(self, messages: List[Dict], modelo: Optional[str] = None) -> str:
        payload = {
            "model": modelo or self.default_model,
            "messages": messages,
            "stream": False
        }
        r = requests.post(f"{self.base_url}/api/chat", headers=self.headers, json=payload)
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "")

    def gerar_embedding(self, texto: str, modelo: Optional[str] = None) -> List[float]:
        payload = {
            "model": modelo or self.default_model,
            "prompt": texto
        }
        r = requests.post(f"{self.base_url}/api/embeddings", headers=self.headers, json=payload)
        r.raise_for_status()
        return r.json().get("embedding", [])

    @staticmethod
    def similaridade_cosseno(v1: List[float], v2: List[float]) -> float:
        dot = sum(a * b for a, b in zip(v1, v2))
        norm1 = sum(a * a for a in v1) ** 0.5
        norm2 = sum(b * b for b in v2) ** 0.5
        if norm1 and norm2:
            return dot / (norm1 * norm2)
        return 0.0


class StaticAnalyzer:
    def __init__(self, severity_level: str = "high"):
        self.severity_level = severity_level
        self.severity_map = {"low": 1, "medium": 2, "high": 3}

    def analyze_code(self, code: str, file_path: str = "code.py") -> List[Vulnerability]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp_file:
            tmp_file.write(code)
            tmp_path = tmp_file.name

        try:
            result = subprocess.run(
                ["bandit", "-f", "json", "-ll", tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return self._parse_bandit_output(result.stdout, file_path)
        except Exception:
            return []
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def _parse_bandit_output(self, json_output: str, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return vulnerabilities

        for result in data.get("results", []):
            severity = result.get("severity", "MEDIUM").upper()
            confidence = result.get("confidence", "MEDIUM").upper()
            
            if self.severity_map.get(severity.lower(), 0) < self.severity_map.get(self.severity_level, 2):
                continue

            confidence_score = {"LOW": 0.5, "MEDIUM": 0.75, "HIGH": 0.95}.get(confidence, 0.7)
            cwe_id = self._extract_cwe_id(result.get("test_id", ""))
            
            vuln = Vulnerability(
                type=result.get("test_id", "Unknown"),
                severity=severity,
                line_number=result.get("line_number", 0),
                description=result.get("issue_text", ""),
                code_snippet=result.get("line", ""),
                confidence=confidence_score,
                cwe_id=cwe_id,
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


class VulnerabilityDatabase:
    def __init__(self):
        self.vulnerabilities = self._load_default_vulnerabilities()

    def _load_default_vulnerabilities(self) -> Dict[str, Dict]:
        return {
            "SQL_INJECTION": {"cwe_id": "CWE-89"},
            "CROSS_SITE_SCRIPTING": {"cwe_id": "CWE-79"},
            "OS_COMMAND_INJECTION": {"cwe_id": "CWE-78"},
            "WEAK_CRYPTOGRAPHY": {"cwe_id": "CWE-327"},
            "CODE_INJECTION": {"cwe_id": "CWE-95"},
            "MISSING_AUTHENTICATION": {"cwe_id": "CWE-306"},
        }

    def get_vulnerability_info(self, vuln_type: str) -> Optional[Dict]:
        if vuln_type in self.vulnerabilities:
            return self.vulnerabilities[vuln_type]
        for key, value in self.vulnerabilities.items():
            if key.lower() == vuln_type.lower():
                return value
        return None

    def search_by_cwe(self, cwe_id: str) -> Optional[Dict]:
        for vuln in self.vulnerabilities.values():
            if vuln["cwe_id"] == cwe_id:
                return vuln
        return None


_db_instance: Optional[VulnerabilityDatabase] = None

def get_vulnerability_db() -> VulnerabilityDatabase:
    global _db_instance
    if _db_instance is None:
        _db_instance = VulnerabilityDatabase()
    return _db_instance


class ReportGenerator:
    @staticmethod
    def generate_markdown_report(report: SecurityReport) -> str:
        lines = []
        lines.append(f"RELATÓRIO DE SEGURANÇA: {report.analysis_id}")
        lines.append("-" * 60)
        
        if report.red_team_summary:
            lines.append("[RED TEAM]")
            lines.append(report.red_team_summary)
            lines.append(f"Exploitability: {getattr(report, 'red_team_exploitability', 'N/A')}")
            lines.append("")

        lines.append("[ANALISADOR E AVALIADOR CENTRAL]")
        if not report.analyzed_files or not report.analyzed_files[0].vulnerabilities:
            lines.append("Nenhuma vulnerabilidade confirmada.")
        else:
            for file_result in report.analyzed_files:
                for vuln in file_result.vulnerabilities:
                    if not vuln.is_false_positive:
                        lines.append(f"-> {vuln.type} (Linha {vuln.line_number}): {vuln.description}")
        
        if report.fix_suggestions:
            lines.append("")
            lines.append("[FIX GENERATOR]")
            for fix in report.fix_suggestions:
                lines.append(f"-> {fix.vulnerability_type}: {fix.explanation}")

        lines.append("-" * 60)
        lines.append(f"CONCLUSÃO FINAL (RISCO): {report.overall_risk_score:.1f}/100")
        
        return "\n".join(lines)

    @staticmethod
    def generate_json_report(report: SecurityReport) -> str:
        return report.model_dump_json(indent=2)


def client_from_settings(settings) -> LLMClient:
    return LLMClient(
        base_url=settings.ollama_base_url,
        api_key=settings.ollama_api_key or settings.llm_api_key,
        default_model=settings.llm_model,
        temperature=settings.llm_temperature,
    )