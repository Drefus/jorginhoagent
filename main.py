"""Launch the JorginhoAgent security analysis pipeline."""

import argparse
import asyncio
import os
import sys
from pathlib import Path

from src.config.settings import get_settings
from src.language_detector import detect_language, SUPPORTED_LANGUAGES
from src.orchestrator import AgentOrchestrator
from src.toolkit import ReportGenerator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="JorginhoAgent - Security Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Arquivo fonte para analisar (Python, JavaScript, Java, C#)",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        default=False,
        help="Ativa o dashboard HTML local após a análise",
    )
    return parser.parse_args()


async def analyze_file(file_path: str, enable_dashboard: bool = False) -> None:
    file = Path(file_path)
    if not file.exists():
        print(f"Error: File {file_path} not found")
        return

    # Detecta linguagem
    try:
        language = detect_language(str(file))
    except ValueError as e:
        print(f"Error: {e}")
        return

    print(f"  Linguagem detectada: {language}")

    code = file.read_text(encoding="utf-8", errors="ignore")
    orchestrator = AgentOrchestrator()
    report = await orchestrator.process_code(code, file_path=str(file), language=language)

    if report:
        # Sempre gera Markdown
        markdown_report = ReportGenerator.generate_markdown_report(report)
        print(markdown_report)
        report_file = file.parent / f"{file.stem}_security_report.md"
        report_file.write_text(markdown_report, encoding="utf-8")
        print(f"\n✓ Report saved to {report_file}")

        # Dashboard se solicitado
        if enable_dashboard:
            from src.dashboard import save_dashboard
            save_dashboard(report, str(file.parent / f"{file.stem}_dashboard.html"))


async def main(enable_dashboard: bool = False) -> None:
    settings = get_settings()
    orchestrator = AgentOrchestrator()

    print("JorginhoAgent - Security analysis")
    print(f"LLM Provider: {settings.llm_provider}")
    print(f"LLM Model: {settings.llm_model}")
    print(f"Linguagens suportadas: {', '.join(sorted(SUPPORTED_LANGUAGES))}")

    try:
        graph_path = orchestrator.render_graph("agents_graph.png")
        print(f"✓ Agent graph saved to {graph_path}")
    except Exception as e:
        print(f"Could not render graph: {e}")

    # Demo com código de exemplo
    example_code = (
        "import os\n"
        "import hashlib\n"
        "\n"
        "user_id = input('Enter ID: ')\n"
        "query = f\"SELECT * FROM users WHERE id={user_id}\"\n"
        "result = db.execute(query)\n"
        "password_hash = hashlib.md5(user_id.encode()).hexdigest()\n"
    )
    report = await orchestrator.process_code(example_code, file_path="example.py", language="python")
    if report:
        markdown_report = ReportGenerator.generate_markdown_report(report)
        print(markdown_report)
        Path("analysis_report.md").write_text(markdown_report, encoding="utf-8")
        print("✓ Report saved to analysis_report.md")

        if enable_dashboard:
            from src.dashboard import save_dashboard
            save_dashboard(report, "dashboard.html")

        if settings.debug:
            print(ReportGenerator.generate_json_report(report))


if __name__ == "__main__":
    args = parse_args()

    # Dashboard via flag ou env var
    dashboard_enabled = args.dashboard or os.getenv("JORGINHO_DASHBOARD", "").lower() == "true"

    if args.file:
        asyncio.run(analyze_file(args.file, enable_dashboard=dashboard_enabled))
    else:
        asyncio.run(main(enable_dashboard=dashboard_enabled))
