"""LangGraph orchestrator for multi-agent security analysis pipeline."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from langgraph.graph import StateGraph

from src.agents.context_evaluator import ContextEvaluatorAgent
from src.agents.fix_generator import FixGeneratorAgent
from src.agents.static_analyzer import StaticAnalyzerAgent
from src.models.schemas import AgentState, SecurityReport, Vulnerability
from src.tools.report_generator import ReportGenerator


class AgentOrchestrator:
    """Orchestrates the multi-agent security analysis pipeline."""

    def __init__(self):
        """Initialize the orchestrator with all agents."""
        self.static_analyzer = StaticAnalyzerAgent()
        self.context_evaluator = ContextEvaluatorAgent()
        self.fix_generator = FixGeneratorAgent()
        self.report_generator = ReportGenerator()

        # Build the LangGraph
        self.graph = self._build_graph()
        self.compiled_graph = self.graph.compile()

    def _build_graph(self) -> StateGraph:
        """Build the LangGraph state machine.

        Returns:
            Configured StateGraph
        """
        graph = StateGraph(AgentState)

        # Add nodes for each agent
        graph.add_node("static_analysis", self._static_analysis_node)
        graph.add_node("context_evaluation", self._context_evaluation_node)
        graph.add_node("fix_generation", self._fix_generation_node)
        graph.add_node("generate_report", self._generate_report_node)

        # Define edges (flow control)
        graph.add_edge("static_analysis", "context_evaluation")
        graph.add_edge("context_evaluation", "fix_generation")
        graph.add_edge("fix_generation", "generate_report")

        # Set entry and exit points
        graph.set_entry_point("static_analysis")
        graph.set_finish_point("generate_report")

        return graph

    async def _static_analysis_node(self, state: AgentState) -> AgentState:
        """Node: Execute static analysis.

        Args:
            state: Current agent state

        Returns:
            Updated state with static analysis results
        """
        print("\n" + "=" * 60)
        print("STAGE 1: STATIC ANALYSIS")
        print("=" * 60)

        try:
            vulnerabilities = await self.static_analyzer.analyze(
                state.input_code, state.file_path
            )
            state.static_analysis_results = vulnerabilities
            print(f"\n✓ Static analysis complete: {len(vulnerabilities)} issues found")
        except Exception as e:
            print(f"✗ Error in static analysis: {e}")
            state.static_analysis_results = []

        return state

    async def _context_evaluation_node(self, state: AgentState) -> AgentState:
        """Node: Evaluate vulnerabilities in context.

        Args:
            state: Current agent state

        Returns:
            Updated state with context-evaluated results
        """
        print("\n" + "=" * 60)
        print("STAGE 2: CONTEXT EVALUATION & SEVERITY ASSESSMENT")
        print("=" * 60)

        try:
            evaluated = await self.context_evaluator.evaluate(
                state.input_code,
                state.static_analysis_results,
                state.file_path,
            )
            state.context_evaluation_results = evaluated

            false_positives = len(state.static_analysis_results) - len(evaluated)
            print(
                f"\n✓ Context evaluation complete: "
                f"{len(evaluated)} confirmed, {false_positives} false positives"
            )
        except Exception as e:
            print(f"✗ Error in context evaluation: {e}")
            state.context_evaluation_results = state.static_analysis_results

        return state

    async def _fix_generation_node(self, state: AgentState) -> AgentState:
        """Node: Generate fixes for vulnerabilities.

        Args:
            state: Current agent state

        Returns:
            Updated state with fix suggestions
        """
        print("\n" + "=" * 60)
        print("STAGE 3: FIX GENERATION")
        print("=" * 60)

        try:
            fixes = await self.fix_generator.generate_fixes(
                state.input_code,
                state.context_evaluation_results,
                state.file_path,
            )
            state.fix_suggestions = fixes
            print(f"\n✓ Fix generation complete: {len(fixes)} fixes generated")
        except Exception as e:
            print(f"✗ Error in fix generation: {e}")
            state.fix_suggestions = []

        return state

    async def _generate_report_node(self, state: AgentState) -> AgentState:
        """Node: Generate final security report.

        Args:
            state: Current agent state

        Returns:
            Updated state with final report
        """
        print("\n" + "=" * 60)
        print("STAGE 4: REPORT GENERATION")
        print("=" * 60)

        try:
            # Calculate metrics
            vulns = state.context_evaluation_results
            critical_count = sum(1 for v in vulns if v.severity == "CRITICAL")
            high_count = sum(1 for v in vulns if v.severity == "HIGH")
            medium_count = sum(1 for v in vulns if v.severity == "MEDIUM")
            low_count = sum(1 for v in vulns if v.severity == "LOW")

            # Calculate risk score (0-100)
            risk_score = min(
                100,
                critical_count * 25 + high_count * 15 + medium_count * 8 + low_count * 3,
            )

            # Generate recommendations
            recommendations = self._generate_recommendations(vulns)

            # Create report
            report = SecurityReport(
                analysis_id=state.analysis_id,
                pr_id=state.metadata.get("pr_id"),
                pr_url=state.metadata.get("pr_url"),
                timestamp=datetime.utcnow(),
                analyzed_files=[
                    {
                        "file_path": state.file_path,
                        "language": "python",
                        "vulnerabilities": vulns,
                    }
                ],
                total_vulnerabilities=len(vulns),
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                false_positive_count=len(state.static_analysis_results)
                - len(vulns),
                fix_suggestions=state.fix_suggestions,
                overall_risk_score=risk_score,
                summary=self._generate_summary(
                    critical_count, high_count, medium_count, low_count
                ),
                recommendations=recommendations,
                analysis_duration_seconds=state.metadata.get(
                    "analysis_duration", 0
                ),
            )

            state.final_report = report
            print(f"\n✓ Report generated successfully")
            print(f"  Risk Score: {risk_score:.1f}/100")
            print(f"  Total Issues: {len(vulns)}")

        except Exception as e:
            print(f"✗ Error generating report: {e}")

        return state

    def _generate_summary(
        self, critical: int, high: int, medium: int, low: int
    ) -> str:
        """Generate executive summary.

        Args:
            critical: Count of critical vulnerabilities
            high: Count of high vulnerabilities
            medium: Count of medium vulnerabilities
            low: Count of low vulnerabilities

        Returns:
            Summary string
        """
        total = critical + high + medium + low

        if total == 0:
            return "✅ No security vulnerabilities detected!"

        issues = []
        if critical > 0:
            issues.append(f"{critical} critical")
        if high > 0:
            issues.append(f"{high} high")
        if medium > 0:
            issues.append(f"{medium} medium")
        if low > 0:
            issues.append(f"{low} low")

        return f"⚠️  Found {total} vulnerabilities: {', '.join(issues)}"

    def _generate_recommendations(self, vulns: List[Vulnerability]) -> List[str]:
        """Generate recommendations based on vulnerabilities.

        Args:
            vulns: List of vulnerabilities

        Returns:
            List of recommendation strings
        """
        recommendations = set()

        # Add recommendations based on vulnerability types
        vuln_types = {v.type for v in vulns}

        if "SQL_INJECTION" in vuln_types:
            recommendations.add("Use parameterized queries instead of string concatenation")

        if "CROSS_SITE_SCRIPTING" in vuln_types:
            recommendations.add(
                "Escape all user input in HTML context, implement Content Security Policy"
            )

        if "OS_COMMAND_INJECTION" in vuln_types:
            recommendations.add("Avoid shell commands; use subprocess or library APIs instead")

        if "WEAK_CRYPTOGRAPHY" in vuln_types:
            recommendations.add("Use SHA-256+ for hashing, AES-256 for encryption")

        if "CODE_INJECTION" in vuln_types:
            recommendations.add("Never use eval(); use safe alternatives like ast.literal_eval()")

        if "MISSING_AUTHENTICATION" in vuln_types:
            recommendations.add("Implement authentication checks for all sensitive operations")

        if "MISSING_AUTHORIZATION" in vuln_types:
            recommendations.add("Implement role-based access control (RBAC)")

        # Add general recommendations
        if len(vulns) > 0:
            recommendations.add("Conduct regular security code reviews")
            recommendations.add("Implement automated security testing in CI/CD pipeline")
            recommendations.add(
                "Keep dependencies updated to patch known vulnerabilities"
            )

        return sorted(list(recommendations))

    async def process_code(
        self,
        code: str,
        file_path: str = "code.py",
        pr_id: Optional[str] = None,
        pr_url: Optional[str] = None,
    ) -> SecurityReport:
        """Process code through the complete analysis pipeline.

        Args:
            code: Source code to analyze
            file_path: Path or name of the file
            pr_id: GitHub PR ID (optional)
            pr_url: GitHub PR URL (optional)

        Returns:
            SecurityReport with complete analysis results
        """
        print("\n" + "╔" + "=" * 58 + "╗")
        print("║" + " " * 58 + "║")
        print("║" + "JorginhoAgent - Security Code Analysis Pipeline".center(58) + "║")
        print("║" + " " * 58 + "║")
        print("╚" + "=" * 58 + "╝")

        start_time = datetime.utcnow()

        # Create initial state
        state = AgentState(
            analysis_id=str(uuid.uuid4()),
            input_code=code,
            file_path=file_path,
            metadata={
                "pr_id": pr_id,
                "pr_url": pr_url,
            },
        )

        # Execute the pipeline
        try:
            # Run through graph (note: in real implementation, would use async properly)
            # For now, we run each node sequentially
            state = await self._static_analysis_node(state)
            state = await self._context_evaluation_node(state)
            state = await self._fix_generation_node(state)
            state = await self._generate_report_node(state)

            # Calculate duration
            duration = (datetime.utcnow() - start_time).total_seconds()
            if state.final_report:
                state.final_report.analysis_duration_seconds = duration

        except Exception as e:
            print(f"✗ Pipeline execution failed: {e}")

        return state.final_report


# Test orchestrator
if __name__ == "__main__":
    import asyncio

    test_code = """
import os
import hashlib

def vulnerable_login(username, password):
    # SQL Injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = db.execute(query)
    
    # Weak cryptography
    hash_value = hashlib.md5(password.encode()).hexdigest()
    
    # Command injection
    os.system(f"log_user {username}")
    
    return user
"""

    async def test():
        orchestrator = AgentOrchestrator()
        report = await orchestrator.process_code(test_code, "vulnerable.py")

        if report:
            print("\n" + "=" * 60)
            print("FINAL REPORT")
            print("=" * 60)
            markdown = ReportGenerator.generate_markdown_report(report)
            print(markdown)

    asyncio.run(test())
