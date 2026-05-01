"""Main entry point for the JorginhoAgent security analysis system."""

import asyncio
import sys
from pathlib import Path

from src.config.settings import get_settings
from src.graph.orchestrator import AgentOrchestrator
from src.tools.report_generator import ReportGenerator


async def main():
    """Main function to run security analysis."""
    settings = get_settings()

    print("\n")
    print("🔒 JorginhoAgent - Multi-Agent Code Security Analysis System")
    print("=" * 60)
    print(f"LLM Provider: {settings.llm_provider}")
    print(f"LLM Model: {settings.llm_model}")
    print(f"Debug Mode: {settings.debug}")
    print("=" * 60)

    # Example 1: Analyze code snippet
    example_code = '''
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search():
    """Example vulnerable endpoint."""
    query = request.args.get('q', '')
    
    # Vulnerability 1: SQL Injection
    sql = f"SELECT * FROM products WHERE name LIKE '{query}'"
    results = db.execute(sql)
    
    # Vulnerability 2: OS Command Injection
    filename = request.args.get('file', '')
    os.system(f"cat {filename}")
    
    # Vulnerability 3: Weak Password Hashing
    import hashlib
    password = request.args.get('pwd', '')
    hashed = hashlib.md5(password.encode()).hexdigest()
    
    # Vulnerability 4: Code Injection via eval
    user_code = request.args.get('code', '')
    eval(user_code)
    
    return {"results": results}

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode in production!
'''

    # Run analysis
    orchestrator = AgentOrchestrator()
    report = await orchestrator.process_code(
        example_code,
        file_path="app.py",
        pr_id="PR-123",
        pr_url="https://github.com/example/repo/pull/123",
    )

    if report:
        # Generate reports in multiple formats
        print("\n" + "=" * 60)
        print("DETAILED MARKDOWN REPORT")
        print("=" * 60)

        markdown_report = ReportGenerator.generate_markdown_report(report)
        print(markdown_report)

        # Save markdown report
        report_file = Path("analysis_report.md")
        report_file.write_text(markdown_report)
        print(f"\n✓ Report saved to {report_file}")

        # GitHub comment
        print("\n" + "=" * 60)
        print("GITHUB PR COMMENT")
        print("=" * 60)

        gh_comment = ReportGenerator.generate_github_comment(report)
        print(gh_comment)

        # JSON report
        if settings.debug:
            json_report = ReportGenerator.generate_json_report(report)
            print("\n" + "=" * 60)
            print("JSON REPORT (DEBUG)")
            print("=" * 60)
            print(json_report)


async def analyze_file(file_path: str):
    """Analyze a file passed as argument.

    Args:
        file_path: Path to Python file to analyze
    """
    file = Path(file_path)

    if not file.exists():
        print(f"Error: File {file_path} not found")
        return

    if not file.suffix == ".py":
        print("Error: Only Python files (.py) are supported")
        return

    code = file.read_text()
    orchestrator = AgentOrchestrator()
    report = await orchestrator.process_code(
        code, file_path=str(file), pr_id=None, pr_url=None
    )

    if report:
        markdown_report = ReportGenerator.generate_markdown_report(report)
        print(markdown_report)

        # Save report
        report_file = file.parent / f"{file.stem}_security_report.md"
        report_file.write_text(markdown_report)
        print(f"\n✓ Report saved to {report_file}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Analyze file passed as argument
        asyncio.run(analyze_file(sys.argv[1]))
    else:
        # Run example analysis
        asyncio.run(main())
