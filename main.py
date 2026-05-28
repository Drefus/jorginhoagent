"""Launch the JorginhoAgent security analysis pipeline."""

import asyncio
import sys
from pathlib import Path

from src.config.settings import get_settings
from src.orchestrator import AgentOrchestrator
from src.toolkit import ReportGenerator


async def analyze_file(file_path: str) -> None:
    file = Path(file_path)
    if not file.exists():
        print(f"Error: File {file_path} not found")
        return
    if file.suffix != ".py":
        print("Error: Only Python files (.py) are supported")
        return

    code = file.read_text()
    orchestrator = AgentOrchestrator()
    report = await orchestrator.process_code(code, file_path=str(file))
    if report:
        markdown_report = ReportGenerator.generate_markdown_report(report)
        print(markdown_report)
        report_file = file.parent / f"{file.stem}_security_report.md"
        report_file.write_text(markdown_report, encoding='utf-8')
        print(f"\nReport saved to {report_file}")


async def main() -> None:
    settings = get_settings()
    orchestrator = AgentOrchestrator()

    print("JorginhoAgent - Security analysis")
    print(f"LLM Provider: {settings.llm_provider}")
    print(f"LLM Model: {settings.llm_model}")

    try:
        graph_path = orchestrator.render_graph("agents_graph.png")
        print(f"✓ Agent graph saved to {graph_path}")
    except Exception as e:
        print(f"Could not render graph: {e}")


    # testezinho rápido se n tiver outro arquivo
    example_code = '''
        import os
        import hashlib

        user_id = input("Enter ID: ")
        query = f"SELECT * FROM users WHERE id={user_id}"
        result = db.execute(query)
    ''' 
    report = await orchestrator.process_code(example_code, file_path="example.py")
    if report:
        markdown_report = ReportGenerator.generate_markdown_report(report)
        print(markdown_report)
        Path("analysis_report.md").write_text(markdown_report)
        print("✓ Report saved to analysis_report.md")
        if settings.debug:
            print(ReportGenerator.generate_json_report(report))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        asyncio.run(analyze_file(sys.argv[1]))
    else:
        asyncio.run(main())
