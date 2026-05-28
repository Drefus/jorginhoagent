"""Orchestrates the JorginhoAgent security analysis pipeline."""

import asyncio
import uuid
from datetime import datetime
from typing import Optional

from src.agents import (
    ContextEvaluatorAgent,
    FixGeneratorAgent,
    RedTeamAgent,
    StaticAnalyzerAgent,
)
from src.models.schemas import (
    AgentState,
    CodeAnalysisResult,
    SecurityReport,
)
from src.toolkit import LangGraphPipeline, ReportGenerator


class AgentOrchestrator:
    """
    Pipeline de segurança com 4 agentes:

      [Analisador] ──┐
                     ├──→ [Avaliador Central] → [Fix Generator] → Relatório
      [Red Team]  ──┘

    Analisador e Red Team rodam em paralelo (asyncio.gather).
    O Avaliador Central recebe os dois relatórios e toma a decisão final.
    """

    def __init__(self):
        self.static_analyzer  = StaticAnalyzerAgent()
        self.red_team         = RedTeamAgent()
        self.context_evaluator = ContextEvaluatorAgent()
        self.fix_generator    = FixGeneratorAgent()
        self.langgraph        = LangGraphPipeline()
        self.langgraph.add_node("StaticAnalyzer", {"role": "analyzer"})
        self.langgraph.add_node("RedTeam", {"role": "red_team"})
        self.langgraph.add_node("Evaluator", {"role": "central_evaluator"})
        self.langgraph.add_node("FixGenerator", {"role": "fix_generator"})
        self.langgraph.add_edge("StaticAnalyzer", "Evaluator")
        self.langgraph.add_edge("RedTeam", "Evaluator")
        self.langgraph.add_edge("Evaluator", "FixGenerator")

    # ── Pipeline nodes ────────────────────────────────────────────────────────

    async def _parallel_analysis(self, state: AgentState) -> AgentState:
        """Roda Analisador e Red Team em paralelo."""
        print("\n" + "═" * 60)
        print("  🚀 Iniciando análise paralela (Analisador + Red Team)")
        print("═" * 60)

        static_task   = self.static_analyzer.analyze(state.input_code, state.file_path)
        red_team_task = self.red_team.attack(state.input_code, state.file_path)

        static_results, red_team_report = await asyncio.gather(
            static_task, red_team_task
        )

        state.static_analysis_results = static_results
        state.static_analysis_report = CodeAnalysisResult(
            file_path=state.file_path,
            language="python",
            vulnerabilities=static_results,
            static_analysis_tool="Bandit + CWE database",
        )
        state.red_team_report = red_team_report

        print(f"  [Analisador Estático] {len(static_results)} vulnerabilidade(s) detectada(s)")
        print(f"  [Red Team] {len(red_team_report.attack_vectors)} vetor(es) de ataque identificado(s)")
        return state

    async def _context_evaluation_node(self, state: AgentState) -> AgentState:
        """LLM central avalia com base nos dois relatórios."""
        print("\n" + "─" * 60)
        print("  🔍 Avaliador Central recebendo entradas dos nós")
        print(f"    - Analisador Estático: {len(state.static_analysis_results)} vulnerabilidade(s)")
        print(f"    - Red Team: {len(state.red_team_report.attack_vectors) if state.red_team_report else 0} vetor(es)")
        try:
            confirmed = await self.context_evaluator.evaluate(
                state.input_code,
                state.static_analysis_results,
                red_team_report=state.red_team_report,
                file_path=state.file_path,
            )
            state.context_evaluation_results = confirmed
            print(f"    - Avaliador Central confirmou {len(confirmed)} vulnerabilidade(s)")
        except Exception as e:
            print(f"Context evaluation error: {e}")
            state.context_evaluation_results = state.static_analysis_results
        return state

    async def _fix_generation_node(self, state: AgentState) -> AgentState:
        print("\n" + "─" * 60)
        try:
            fixes = await self.fix_generator.generate_fixes(
                state.input_code,
                state.context_evaluation_results,
                state.file_path,
            )
            state.fix_suggestions = fixes
        except Exception as e:
            print(f"Fix generation error: {e}")
            state.fix_suggestions = []
        return state

    async def _generate_report_node(self, state: AgentState) -> AgentState:
        print("\n" + "─" * 60)
        print("📄 [Relatório] Compilando resultados finais...")
        try:
            vulns = state.context_evaluation_results
            false_pos = len(state.static_analysis_results) - len(vulns)

            critical = sum(1 for v in vulns if v.severity == "CRITICAL")
            high     = sum(1 for v in vulns if v.severity == "HIGH")
            medium   = sum(1 for v in vulns if v.severity == "MEDIUM")
            low      = sum(1 for v in vulns if v.severity == "LOW")
            risk     = min(100.0, critical * 25 + high * 15 + medium * 8 + low * 3)

            file_result = CodeAnalysisResult(
                file_path=state.file_path,
                language="python",
                vulnerabilities=vulns,
                static_analysis_tool="LLM + Bandit",
            )

            report = SecurityReport(
                analysis_id=state.analysis_id,
                pr_id=state.metadata.get("pr_id"),
                pr_url=state.metadata.get("pr_url"),
                timestamp=datetime.utcnow(),
                analyzed_files=[file_result],
                total_vulnerabilities=len(vulns),
                critical_count=critical,
                high_count=high,
                medium_count=medium,
                low_count=low,
                false_positive_count=max(0, false_pos),
                fix_suggestions=state.fix_suggestions,
                overall_risk_score=risk,
                summary=self._build_summary(critical, high, medium, low),
                recommendations=self._build_recommendations(vulns),
                # Red Team no relatório
                red_team_summary=(
                    state.red_team_report.executive_summary
                    if state.red_team_report else None
                ),
                red_team_exploitability=(
                    state.red_team_report.overall_exploitability
                    if state.red_team_report else None
                ),
            )
            state.final_report = report
        except Exception as e:
            print(f"Report generation error: {e}")
        return state

    # ── Main entry point ──────────────────────────────────────────────────────

    async def process_code(
        self,
        code: str,
        file_path: str = "code.py",
        pr_id: Optional[str] = None,
        pr_url: Optional[str] = None,
    ) -> Optional[SecurityReport]:

        start = datetime.utcnow()
        state = AgentState(
            analysis_id=str(uuid.uuid4()),
            input_code=code,
            file_path=file_path,
            metadata={"pr_id": pr_id, "pr_url": pr_url},
        )

        state = await self._parallel_analysis(state)
        state = await self._context_evaluation_node(state)
        state = await self._fix_generation_node(state)
        state = await self._generate_report_node(state)

        if state.final_report:
            state.final_report.analysis_duration_seconds = (
                datetime.utcnow() - start
            ).total_seconds()

        return state.final_report

    # ── Graph rendering ───────────────────────────────────────────────────────

    def render_graph(self, output_path: str = "agents_graph.png") -> str:
        from graphviz import Digraph

        dot = Digraph(name="JorginhoAgent")
        dot.attr(rankdir="LR", bgcolor="white")

        # Nodes
        dot.node("input",     "📄 Código",            shape="rectangle", style="filled", fillcolor="#e8f4f8")
        dot.node("analyzer",  "🔎 Analisador\n(LLM)",  shape="rectangle", style="filled", fillcolor="#fff3cd")
        dot.node("redteam",   "💀 Red Team\n(LLM)",    shape="rectangle", style="filled", fillcolor="#f8d7da")
        dot.node("evaluator", "🔍 Avaliador\nCentral", shape="rectangle", style="filled", fillcolor="#d4edda")
        dot.node("fixer",     "🔧 Fix\nGenerator",     shape="rectangle", style="filled", fillcolor="#cce5ff")
        dot.node("report",    "📊 Relatório",          shape="rectangle", style="filled", fillcolor="#e2e3e5")

        # Edges
        dot.edge("input",     "analyzer",  label="código")
        dot.edge("input",     "redteam",   label="código")
        dot.edge("analyzer",  "evaluator", label="vulns")
        dot.edge("redteam",   "evaluator", label="vetores\nde ataque")
        dot.edge("evaluator", "fixer",     label="confirmadas")
        dot.edge("fixer",     "report",    label="fixes")

        dot.format = output_path.split(".")[-1]
        filename   = ".".join(output_path.split(".")[:-1])
        graph_path = dot.render(filename=filename, cleanup=True)
        if hasattr(self.langgraph, "render"):
            langgraph_output = self.langgraph.render()
            if langgraph_output:
                print(f"LangGraph pipeline metadata: {langgraph_output[:300]}")
        return graph_path

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _build_summary(critical: int, high: int, medium: int, low: int) -> str:
        total = critical + high + medium + low
        if total == 0:
            return "✅ Nenhuma vulnerabilidade confirmada."
        parts = []
        if critical: parts.append(f"{critical} crítica(s)")
        if high:     parts.append(f"{high} alta(s)")
        if medium:   parts.append(f"{medium} média(s)")
        if low:      parts.append(f"{low} baixa(s)")
        return f"⚠️  {total} vulnerabilidade(s) encontrada(s): {', '.join(parts)}"

    @staticmethod
    def _build_recommendations(vulns) -> list:
        recs = set()
        types = {v.type for v in vulns}
        mapping = {
            "SQL_INJECTION":          "Use queries parametrizadas (nunca concatene strings SQL)",
            "OS_COMMAND_INJECTION":   "Evite shell commands; use subprocess com lista de argumentos",
            "CODE_INJECTION":         "Remova eval(); use ast.literal_eval() para dados literais",
            "INSECURE_DESERIALIZATION": "Substitua pickle por JSON em dados não confiáveis",
            "WEAK_CRYPTOGRAPHY":      "Use SHA-256 ou bcrypt; nunca MD5/DES para segurança",
            "HARDCODED_CREDENTIALS":  "Mova credenciais para variáveis de ambiente ou vault",
            "PATH_TRAVERSAL":         "Valide e normalize caminhos de arquivo com pathlib",
        }
        for t, rec in mapping.items():
            if t in types:
                recs.add(rec)
        if vulns:
            recs.add("Execute auditorias de segurança regulares no CI/CD")
            recs.add("Mantenha dependências atualizadas")
        return sorted(recs)
