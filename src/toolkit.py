import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from langchain.agents import create_agent
from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage

try:
    from langgraph import Graph
except ImportError:
    Graph = None

from src.models.schemas import SecurityReport, Vulnerability


class LangChainClient:
    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.0):
        self.llm = init_chat_model(model, temperature=temperature)

    def generate_text(self, prompt: str) -> str:
        response = self.llm.generate([HumanMessage(content=prompt)])
        if response and response.generations and response.generations[0]:
            return response.generations[0][0].text
        return ""

    def run_agent(self, prompt: str, tools: List[Any]) -> str:
        agent = create_agent(
            self.llm,
            tools,
            debug=False,
        )
        output = agent.invoke(prompt)
        return str(output)


class LangGraphPipeline:
    def __init__(self, name: str = "JorginhoAgent"):
        self.graph = Graph(name=name) if Graph is not None else None

    def add_node(self, node_name: str, metadata: Optional[Dict[str, str]] = None):
        if self.graph is None:
            return
        if hasattr(self.graph, "add_node"):
            self.graph.add_node(node_name, metadata or {})
        elif hasattr(self.graph, "add"):
            self.graph.add(node_name, metadata or {})

    def add_edge(self, source: str, target: str):
        if self.graph is None:
            return
        if hasattr(self.graph, "add_edge"):
            self.graph.add_edge(source, target)

    def render(self) -> str:
        if self.graph is None:
            return ""
        if hasattr(self.graph, "serialize"):
            return self.graph.serialize()
        return str(self.graph)


class StaticAnalyzer:
    def __init__(self, severity_level: str = "high"):
        self.severity_level = severity_level
        self.severity_map = {"low": 1, "medium": 2, "high": 3}
        self.vuln_db = get_vulnerability_db()

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

            issue_text = result.get("issue_text", "").strip()
            bandit_id = result.get("test_id", "Unknown")
            code_line = result.get("line", "")
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

        lines.append("[ANALISADOR ESTÁTICO]")
        if not report.analyzed_files or not report.analyzed_files[0].vulnerabilities:
            lines.append("Nenhuma vulnerabilidade estática confirmada.")
        else:
            for file_result in report.analyzed_files:
                for vuln in file_result.vulnerabilities:
                    if not vuln.is_false_positive:
                        lines.append(f"-> {vuln.type} (Linha {vuln.line_number}): {vuln.description}")
        lines.append("")

        lines.append("[AVALIADOR CENTRAL]")
        lines.append(report.summary)
        lines.append("")

        if report.fix_suggestions:
            lines.append("[FIX GENERATOR]")
            for fix in report.fix_suggestions:
                lines.append(f"-> {fix.vulnerability_type}: {fix.explanation}")

        lines.append("-" * 60)
        lines.append(f"CONCLUSÃO FINAL (RISCO): {report.overall_risk_score:.1f}/100")
        return "\n".join(lines)

    @staticmethod
    def generate_json_report(report: SecurityReport) -> str:
        return report.model_dump_json(indent=2)


def client_from_settings(settings) -> LangChainClient:
    return LangChainClient(model=settings.llm_model, temperature=settings.llm_temperature)