import ast
import json
import re
from typing import List, Optional

from src.config.settings import get_settings
from src.models.schemas import (
    Vulnerability,
    AttackVector,
    RedTeamReport,
    FixSuggestion,
)

from langchain.tools import tool

from src.toolkit import StaticAnalyzer, client_from_settings, LangChainClient
import asyncio


def _parse_json(text: str):
    """Tenta extrair e parsear JSON/Dict de texto livre.

    Estratégia:
    1. Tenta json.loads direto.
    2. Extrai primeira substring que parece JSON e tenta carregar.
    3. Usa ast.literal_eval após normalizar null/true/false.
    """
    if not text or not isinstance(text, str):
        raise ValueError("Input must be a text string")

    try:
        return json.loads(text)
    except Exception:
        pass

    # Remove fenced code blocks e busca por primeira estrutura JSON-like
    stripped = re.sub(r"```[a-zA-Z]*\n?", "", text).replace("```", "").strip()
    match = re.search(r"(\[\s*\{.*\}\s*\]|\{.*\}|\[.*\])", stripped, re.DOTALL)
    if match:
        candidate = match.group(1)
        try:
            return json.loads(candidate)
        except Exception:
            pass

    # Fallback: normalize tokens and use ast.literal_eval
    clean = (
        stripped.replace("null", "None").replace("true", "True").replace("false", "False")
    )
    clean = re.sub(r":\s*NaN\b", ": None", clean)
    try:
        return ast.literal_eval(clean)
    except Exception:
        raise ValueError("Falha ao parsear JSON/DICt do texto fornecido")


def _safe_int(value, default=0):
    try:
        if value is None:
            return default

        return int(float(value))

    except Exception:
        return default


def _safe_float(value, default=0.0):
    try:
        if value is None:
            return default

        value = float(value)

        if value > 1:
            value = value / 100

        return max(0.0, min(value, 1.0))

    except Exception:
        return default


def _safe_str(value, default="Unknown"):
    try:
        if value is None:
            return default

        return str(value).strip()

    except Exception:
        return default


def _normalize_level(value, default="MEDIUM"):
    if value is None:
        return default

    value = str(value).upper().strip()

    if value in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        return value

    if value in ["1", "2"]:
        return "LOW"

    if value in ["3", "4", "5", "6"]:
        return "MEDIUM"

    if value in ["7", "8", "9", "10"]:
        return "HIGH"

    return default


def _sanitize_vulnerability(item):
    return {
        "type": _safe_str(item.get("type"), "Unknown"),
        "severity": _normalize_level(item.get("severity"), "MEDIUM"),
        "line_number": _safe_int(item.get("line_number"), 0),
        "description": _safe_str(item.get("description"), "Unknown"),
        "code_snippet": _safe_str(item.get("code_snippet"), ""),
        "confidence": _safe_float(item.get("confidence"), 0.8),
        "is_false_positive": bool(item.get("is_false_positive", False)),
    }


def _sanitize_attack_vector(item):
    return {
        "attack_type": _safe_str(item.get("attack_type"), "Unknown"),
        "line_number": _safe_int(item.get("line_number"), 0),
        "description": _safe_str(item.get("description"), "Unknown"),
        "exploitability": _normalize_level(item.get("exploitability"), "MEDIUM"),
        "payload_example": _safe_str(item.get("payload_example"), ""),
        "impact": _safe_str(item.get("impact"), "Unknown"),
    }


class StaticAnalyzerAgent:
    def __init__(self, severity: str = "high"):
        # Prefer configured bandit level from settings when available
        try:
            settings = get_settings()
            level = getattr(settings, "bandit_level", severity) or severity
        except Exception:
            level = severity
        self._analyzer = StaticAnalyzer(severity_level=level)

    async def analyze(self, code: str, file_path: str = "code.py") -> List[Vulnerability]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._analyzer.analyze_code, code, file_path)


class RedTeamAgent:
    def __init__(self):
        self.settings = get_settings()
        self.langchain: Optional[LangChainClient] = None
        try:
            self.langchain = client_from_settings(self.settings)
        except Exception:
            self.langchain = None

    async def attack(self, code: str, file_path: str = "code.py") -> RedTeamReport:
        """Gera um RedTeamReport com vetores de ataque heurísticos e (opcionalmente) LLM-augmentado."""
        vectors: List[AttackVector] = []

        # Heurísticas simples
        if "input(" in code or "raw_input(" in code:
            vectors.append(AttackVector(
                attack_type="COMMAND_INJECTION",
                line_number=0,
                description="Uso de entrada direta do usuário sem sanitização; potencial injeção em comandos/queries.",
                exploitability="HIGH",
                payload_example="; rm -rf /",
                impact="Execução de comandos arbitrários"
            ))

        if "SELECT" in code.upper() or "WHERE" in code.upper():
            vectors.append(AttackVector(
                attack_type="SQL_INJECTION",
                line_number=0,
                description="Concatenacão de strings em queries detectada; possível SQLi.",
                exploitability="HIGH",
                payload_example="' OR '1'='1",
                impact="Exfiltração de dados / bypass de autenticação"
            ))

        if "pickle" in code or "loads(" in code and "pickle" in code:
            vectors.append(AttackVector(
                attack_type="INSECURE_DESERIALIZATION",
                line_number=0,
                description="Uso de pickle/deserialize em dados não confiáveis.",
                exploitability="MEDIUM",
                payload_example="pickle payload executing os.system()",
                impact="RCE ou elevação de privilégio"
            ))

        # Tenta enriquecer com LLM se disponível
        if self.langchain:
            prompt = (
                "You are a red-team security assistant. Given the following Python code, "
                "return a JSON object with keys: executive_summary (string), overall_exploitability (HIGH|MEDIUM|LOW), "
                "and attack_vectors (list of {attack_type,line_number,description,exploitability,payload_example,impact}).\n\n"
                "CODE:\n" + code
            )
            try:
                resp = await asyncio.get_running_loop().run_in_executor(None, self.langchain.generate_text, prompt)
                parsed = _parse_json(resp)
                exec_sum = parsed.get("executive_summary") if isinstance(parsed, dict) else None
                overall = parsed.get("overall_exploitability") if isinstance(parsed, dict) else None
                parsed_vectors = parsed.get("attack_vectors") if isinstance(parsed, dict) else None

                if isinstance(parsed_vectors, list):
                    for it in parsed_vectors:
                        vectors.append(AttackVector(**_sanitize_attack_vector(it)))

                report = RedTeamReport(
                    attack_vectors=vectors,
                    executive_summary=exec_sum or "Red Team analysis generated",
                    overall_exploitability=(overall or "LOW").upper(),
                    most_critical_attack=vectors[0].attack_type if vectors else None,
                )
                return report
            except Exception:
                pass

        # Fallback report
        summary = "\n".join([v.description for v in vectors]) or "No obvious attack vectors found."
        overall = "HIGH" if any(v.exploitability == "HIGH" for v in vectors) else ("MEDIUM" if vectors else "LOW")
        return RedTeamReport(
            attack_vectors=vectors,
            executive_summary=summary,
            overall_exploitability=overall,
            most_critical_attack=vectors[0].attack_type if vectors else None,
        )


class ContextEvaluatorAgent:
    def __init__(self):
        self.settings = get_settings()
        try:
            self.react_agent = client_from_settings(self.settings)
        except Exception:
            self.react_agent = None

    async def evaluate(self, code: str, static_vulns: List[Vulnerability], red_team_report: Optional[RedTeamReport] = None, file_path: str = "code.py") -> List[Vulnerability]:
        """Confirma e prioriza vulnerabilidades combinando análise estática e Red Team."""
        confirmed: List[Vulnerability] = []
        rt_vectors = red_team_report.attack_vectors if red_team_report else []
        rt_types = {getattr(av, 'attack_type', '').upper() for av in rt_vectors}

        # Confirma vulnerabilidades estáticas.
        for v in static_vulns:
            v_conf = v.confidence
            if v.type and any(k in v.type.upper() or v.type.upper() in k for k in rt_types):
                v_conf = min(1.0, v_conf + 0.20)
            if v_conf >= 0.5:
                v.confidence = v_conf
                confirmed.append(v)

        # Se não há vulnerabilidades estáticas ou há vetores do Red Team não cobertos,
        # mantenha os avisos do Red Team como vulnerabilidades sintéticas.
        for av in rt_vectors:
            match = next(
                (v for v in confirmed if v.line_number == getattr(av, 'line_number', None) and v.type and v.type.upper() in getattr(av, 'attack_type', '').upper()),
                None,
            )
            if match:
                # Atualiza a vulnerabilidade existente com sinal de alta prioridade
                if getattr(av, 'exploitability', 'MEDIUM').upper() == 'HIGH':
                    match.severity = 'HIGH'
                    match.confidence = max(match.confidence, 0.9)
                continue

            expl = getattr(av, 'exploitability', 'MEDIUM').upper()
            severity = 'HIGH' if expl == 'HIGH' else ('MEDIUM' if expl == 'MEDIUM' else 'LOW')
            confidence = 0.85 if expl == 'HIGH' else (0.70 if expl == 'MEDIUM' else 0.50)

            synthetic = Vulnerability(
                type=getattr(av, 'attack_type', 'RED_TEAM_WARNING'),
                severity=severity,
                line_number=getattr(av, 'line_number', None) or 0,
                description=getattr(av, 'description', '') or 'Issue reported by Red Team',
                code_snippet=getattr(av, 'payload_example', '') or None,
                confidence=confidence,
            )
            if synthetic.confidence >= 0.5:
                confirmed.append(synthetic)

        # Use LangChain ReAct agent to reconcile static and red team reports if available
        if self.react_agent and static_vulns is not None:
            try:
                static_payload = json.dumps([v.model_dump() for v in static_vulns], default=str)
                red_payload = json.dumps({
                    "executive_summary": red_team_report.executive_summary if red_team_report else "",
                    "overall_exploitability": red_team_report.overall_exploitability if red_team_report else "LOW",
                    "attack_vectors": [av.dict() for av in rt_vectors],
                }, default=str)

                @tool("static_report")
                def static_report_tool(_: str) -> str:
                    return static_payload

                @tool("red_team_report")
                def red_team_report_tool(_: str) -> str:
                    return red_payload

                tools = [static_report_tool, red_team_report_tool]

                prompt = (
                    "You are a ReAct security triage agent. Use the static_report and red_team_report tools to decide which vulnerabilities are confirmed. "
                    "Return a JSON array of vulnerability objects with fields: type, severity, line_number, description, confidence, code_snippet, cwe_id, cwe_name, owasp_category. "
                    "If the Red Team indicates high exploitability, include it even if the static analyzer found no direct match.\n\n"
                    "Use the tools to answer."
                )
                resp = await asyncio.get_running_loop().run_in_executor(None, self.react_agent.run_agent, prompt, tools)
                parsed = _parse_json(resp)
                if isinstance(parsed, list):
                    confirmed = []
                    for item in parsed:
                        try:
                            it = _sanitize_vulnerability(item)
                            confirmed.append(Vulnerability(**it))
                        except Exception:
                            continue
            except Exception:
                pass

        return confirmed


class FixGeneratorAgent:
    def __init__(self):
        self.settings = get_settings()
        try:
            self.langchain = client_from_settings(self.settings)
        except Exception:
            self.langchain = None

    async def generate_fixes(self, code: str, vulns: List[Vulnerability], file_path: str = "code.py") -> List[FixSuggestion]:
        fixes: List[FixSuggestion] = []
        for v in vulns:
            # Simple templates for common types
            if "SQL" in v.type.upper() or "SQL_INJECTION" in v.type.upper():
                fixed = (
                    "Use parameterized queries. Example using sqlite3:\n"
                    "cursor.execute(\"SELECT * FROM users WHERE id=?\", (user_id,))"
                )
                fixes.append(FixSuggestion(
                    vulnerability_type=v.type,
                    original_code=v.code_snippet or "",
                    fixed_code=fixed,
                    explanation="Substitui concatenação de strings por queries parametrizadas",
                    severity_reduced_from=v.severity,
                    severity_reduced_to="LOW",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]
                ))
            else:
                # Try to use LLM to craft a fix when available
                if self.langchain:
                    prompt = (
                        "You are a secure code assistant. Provide a concise fix for the following vulnerability. Return JSON {vulnerability_type, original_code, fixed_code, explanation, severity_reduced_to, references}.\n\n"
                        f"VULN: {v.type}\nCODE:\n{v.code_snippet or ''}"
                    )
                    try:
                        resp = await asyncio.get_running_loop().run_in_executor(None, self.langchain.generate_text, prompt)
                        parsed = _parse_json(resp)
                        if isinstance(parsed, dict):
                            fixes.append(FixSuggestion(
                                vulnerability_type=parsed.get("vulnerability_type", v.type),
                                original_code=parsed.get("original_code", v.code_snippet or ""),
                                fixed_code=parsed.get("fixed_code", ""),
                                explanation=parsed.get("explanation", ""),
                                severity_reduced_from=v.severity,
                                severity_reduced_to=parsed.get("severity_reduced_to"),
                                references=parsed.get("references", []),
                            ))
                            continue
                    except Exception:
                        pass

                # Default generic suggestion
                fixes.append(FixSuggestion(
                    vulnerability_type=v.type,
                    original_code=v.code_snippet or "",
                    fixed_code="See remediation best practices",
                    explanation="Recomendações gerais: validar entradas, usar parametrização e evitar eval().",
                    severity_reduced_from=v.severity,
                    severity_reduced_to="MEDIUM",
                    references=["https://owasp.org/www-project-top-ten/"]
                ))

        return fixes
