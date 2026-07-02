from typing import Any, Dict, List, Optional

from langchain.agents import create_agent
from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage

try:
    from langgraph import Graph
except ImportError:
    Graph = None

from src.models.schemas import SecurityReport, Vulnerability
from src.static_analyzer import StaticAnalyzer, VulnerabilityDatabase, get_vulnerability_db


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


class ReportGenerator:
    @staticmethod
    def generate_markdown_report(report: SecurityReport) -> str:
        lines = []
        lines.append(f"# 🔒 Relatório de Segurança")
        lines.append(f"**ID:** `{report.analysis_id}`")
        lines.append(f"**Risk Score:** {report.overall_risk_score:.1f}/100")
        lines.append("")
        lines.append("---")
        lines.append("")

        # ── Red Team ──────────────────────────────────────────────────────
        if report.red_team_summary:
            lines.append("## 💀 Red Team")
            lines.append("")
            lines.append(report.red_team_summary)
            lines.append("")
            lines.append(f"**Exploitability:** {getattr(report, 'red_team_exploitability', 'N/A')}")
            lines.append("")
            lines.append("---")
            lines.append("")

        # ── Analisador Estático ───────────────────────────────────────────
        lines.append("## 🔎 Analisador Estático")
        lines.append("")
        if not report.analyzed_files or not report.analyzed_files[0].vulnerabilities:
            lines.append("Nenhuma vulnerabilidade estática confirmada.")
        else:
            for file_result in report.analyzed_files:
                for vuln in file_result.vulnerabilities:
                    if not vuln.is_false_positive:
                        lines.append(f"- **{vuln.type}** (Linha {vuln.line_number}) [{vuln.severity}]: {vuln.description}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # ── Avaliador Central ─────────────────────────────────────────────
        lines.append("## 🔍 Avaliador Central")
        lines.append("")
        lines.append(report.summary)
        lines.append("")
        lines.append("---")
        lines.append("")

        # ── Fix Generator — código vulnerável + correção ──────────────────
        if report.fix_suggestions:
            lines.append("## 🔧 Correções Sugeridas")
            lines.append("")

            for i, fix in enumerate(report.fix_suggestions, 1):
                lines.append(f"### {i}. {fix.vulnerability_type}")
                lines.append("")
                lines.append(f"**Severidade:** {fix.severity_reduced_from} → {fix.severity_reduced_to or '?'}")
                lines.append("")
                lines.append(f"**Explicação:** {fix.explanation}")
                lines.append("")

                # Bloco de código vulnerável
                if fix.original_code and fix.original_code.strip():
                    lines.append("**❌ Código vulnerável:**")
                    lines.append("")
                    lines.append("```python")
                    lines.append(fix.original_code.strip())
                    lines.append("```")
                    lines.append("")

                # Bloco de código corrigido
                if fix.fixed_code and fix.fixed_code.strip():
                    lines.append("**✅ Correção sugerida:**")
                    lines.append("")
                    lines.append("```python")
                    lines.append(fix.fixed_code.strip())
                    lines.append("```")
                    lines.append("")

                # Referências
                if fix.references:
                    lines.append("**Referências:**")
                    for ref in fix.references:
                        lines.append(f"- {ref}")
                    lines.append("")

                lines.append("---")
                lines.append("")

        # ── Conclusão ─────────────────────────────────────────────────────
        lines.append("## 📊 Conclusão")
        lines.append("")
        lines.append(f"| Métrica | Valor |")
        lines.append(f"|---------|-------|")
        lines.append(f"| Total de vulnerabilidades | {report.total_vulnerabilities} |")
        lines.append(f"| Críticas | {report.critical_count} |")
        lines.append(f"| Altas | {report.high_count} |")
        lines.append(f"| Médias | {report.medium_count} |")
        lines.append(f"| Baixas | {report.low_count} |")
        lines.append(f"| Falsos positivos descartados | {report.false_positive_count} |")
        lines.append(f"| **Risk Score** | **{report.overall_risk_score:.1f}/100** |")
        lines.append("")

        if report.recommendations:
            lines.append("### Recomendações")
            lines.append("")
            for rec in report.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def generate_json_report(report: SecurityReport) -> str:
        return report.model_dump_json(indent=2)


def client_from_settings(settings) -> LangChainClient:
    return LangChainClient(model=settings.llm_model, temperature=settings.llm_temperature)