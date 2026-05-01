"""Report generation for security analysis results."""

from typing import List

from src.models.schemas import SecurityReport, Vulnerability


class ReportGenerator:
    """Generate formatted security analysis reports."""

    @staticmethod
    def generate_markdown_report(report: SecurityReport) -> str:
        """Generate a Markdown formatted report.

        Args:
            report: SecurityReport object

        Returns:
            Formatted Markdown report
        """
        lines = []

        # Header
        lines.append("# 🔒 Security Analysis Report\n")

        # Summary Section
        lines.append("## 📊 Summary\n")
        lines.append(f"**Analysis ID:** `{report.analysis_id}`\n")
        if report.pr_url:
            lines.append(f"**Pull Request:** [{report.pr_url}]({report.pr_url})\n")
        lines.append(f"**Timestamp:** {report.timestamp.isoformat()}\n")
        lines.append(f"**Duration:** {report.analysis_duration_seconds:.2f}s\n")
        lines.append(f"**Overall Risk Score:** {report.overall_risk_score:.1f}/100\n")
        lines.append(f"\n**{report.summary}**\n\n")

        # Vulnerability Counts
        lines.append("### Vulnerability Breakdown\n")
        lines.append("| Severity | Count |\n")
        lines.append("|----------|-------|\n")
        lines.append(f"| 🔴 CRITICAL | {report.critical_count} |\n")
        lines.append(f"| 🟠 HIGH | {report.high_count} |\n")
        lines.append(f"| 🟡 MEDIUM | {report.medium_count} |\n")
        lines.append(f"| 🟢 LOW | {report.low_count} |\n")
        lines.append(f"| ❓ False Positives | {report.false_positive_count} |\n\n")

        # Vulnerabilities by File
        if report.analyzed_files:
            lines.append("## 📁 Vulnerabilities by File\n")

            for file_result in report.analyzed_files:
                if not file_result.vulnerabilities:
                    continue

                lines.append(f"### {file_result.file_path}\n")

                for vuln in file_result.vulnerabilities:
                    if not vuln.is_false_positive:
                        lines.extend(
                            ReportGenerator._format_vulnerability(vuln)
                        )

                lines.append("\n")

        # Fix Suggestions
        if report.fix_suggestions:
            lines.append("## 🔧 Suggested Fixes\n")

            for i, fix in enumerate(report.fix_suggestions, 1):
                lines.append(f"### Fix #{i}: {fix.vulnerability_type}\n")
                lines.append(
                    f"**Severity:** {fix.severity_reduced_from} → {fix.severity_reduced_to}\n\n"
                )

                lines.append("**Before (Vulnerable):**\n")
                lines.append("```python\n")
                lines.append(fix.original_code)
                lines.append("\n```\n\n")

                lines.append("**After (Fixed):**\n")
                lines.append("```python\n")
                lines.append(fix.fixed_code)
                lines.append("\n```\n\n")

                lines.append(f"**Explanation:**\n{fix.explanation}\n\n")

                if fix.references:
                    lines.append("**References:**\n")
                    for ref in fix.references:
                        lines.append(f"- {ref}\n")
                    lines.append("\n")

        # Recommendations
        if report.recommendations:
            lines.append("## 💡 General Recommendations\n")
            for rec in report.recommendations:
                lines.append(f"- {rec}\n")
            lines.append("\n")

        # Footer
        lines.append("---\n")
        lines.append(
            "*This report was generated automatically by JorginhoAgent security analysis.*\n"
        )

        return "".join(lines)

    @staticmethod
    def _format_vulnerability(vuln: Vulnerability) -> List[str]:
        """Format a single vulnerability for Markdown.

        Args:
            vuln: Vulnerability object

        Returns:
            List of Markdown lines
        """
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }.get(vuln.severity, "❓")

        lines = []
        lines.append(f"#### {severity_emoji} {vuln.type} (Line {vuln.line_number})\n")

        if vuln.cwe_id:
            lines.append(f"**CWE:** [{vuln.cwe_id}](https://cwe.mitre.org/data/definitions/{vuln.cwe_id.split('-')[1]}.html)\n")

        if vuln.owasp_category:
            lines.append(f"**OWASP:** {vuln.owasp_category}\n")

        lines.append(f"**Confidence:** {vuln.confidence * 100:.0f}%\n\n")

        lines.append(f"**Issue:**\n{vuln.description}\n\n")

        if vuln.code_snippet:
            lines.append("**Code:**\n")
            lines.append("```python\n")
            lines.append(vuln.code_snippet)
            lines.append("\n```\n\n")

        if vuln.remediation:
            lines.append(f"**Remediation:**\n{vuln.remediation}\n\n")

        return lines

    @staticmethod
    def generate_github_comment(report: SecurityReport) -> str:
        """Generate a concise GitHub PR comment.

        Args:
            report: SecurityReport object

        Returns:
            Formatted comment for GitHub
        """
        lines = []

        # Title
        risk_indicator = "🔴" if report.overall_risk_score > 70 else (
            "🟠" if report.overall_risk_score > 40 else "🟢"
        )
        lines.append(f"{risk_indicator} **Security Analysis Results**\n\n")

        # Quick summary
        total = report.total_vulnerabilities
        if total == 0:
            lines.append("✅ No security vulnerabilities detected!\n")
        else:
            lines.append(
                f"Found **{total}** vulnerabilities:\n"
                f"- {report.critical_count}🔴 Critical\n"
                f"- {report.high_count}🟠 High\n"
                f"- {report.medium_count}🟡 Medium\n"
                f"- {report.low_count}🟢 Low\n\n"
            )

        # Risk score
        lines.append(f"**Risk Score:** {report.overall_risk_score:.1f}/100\n\n")

        # Recommendations
        if report.recommendations:
            lines.append("**Key Recommendations:**\n")
            for i, rec in enumerate(report.recommendations[:3], 1):
                lines.append(f"{i}. {rec}\n")
            lines.append("\n")

        # Link to detailed report
        lines.append(
            f"[📋 View Detailed Report](#{report.analysis_id})\n"
        )

        return "".join(lines)

    @staticmethod
    def generate_json_report(report: SecurityReport) -> str:
        """Generate a JSON formatted report.

        Args:
            report: SecurityReport object

        Returns:
            JSON string representation
        """
        return report.model_dump_json(indent=2)


if __name__ == "__main__":
    # Example usage
    from datetime import datetime

    example_report = SecurityReport(
        analysis_id="test_analysis_001",
        timestamp=datetime.utcnow(),
        total_vulnerabilities=2,
        critical_count=1,
        high_count=1,
        overall_risk_score=85.0,
        summary="1 critical and 1 high severity vulnerability detected",
        recommendations=[
            "Use parameterized queries",
            "Implement input validation",
        ],
    )

    generator = ReportGenerator()
    markdown = generator.generate_markdown_report(example_report)
    print(markdown)

    print("\n---\n")
    comment = generator.generate_github_comment(example_report)
    print(comment)
