#!/usr/bin/env python
"""Example usage of JorginhoAgent system."""

import asyncio
from pathlib import Path

from src.graph.orchestrator import AgentOrchestrator
from src.tools.report_generator import ReportGenerator


async def example_1_simple_analysis():
    """Example 1: Analyze a simple vulnerable code snippet."""
    print("\n" + "=" * 70)
    print("EXAMPLE 1: Simple Vulnerable Code Analysis")
    print("=" * 70)

    vulnerable_code = """
import os
import hashlib

def login(username, password):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}'"
    user = db.execute(query)
    
    # Weak password hashing
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    
    # OS command injection
    os.system(f"echo User {username} logged in >> logs.txt")
    
    return user
"""

    orchestrator = AgentOrchestrator()
    report = await orchestrator.process_code(
        vulnerable_code, file_path="login.py"
    )

    if report:
        print(f"\n✓ Analysis Complete!")
        print(f"  Risk Score: {report.overall_risk_score:.1f}/100")
        print(f"  Total Issues: {report.total_vulnerabilities}")
        print(f"  Critical: {report.critical_count} | High: {report.high_count}")


async def example_2_detailed_report():
    """Example 2: Generate detailed markdown report."""
    print("\n" + "=" * 70)
    print("EXAMPLE 2: Detailed Report Generation")
    print("=" * 70)

    code_with_issues = """
def search_products(query):
    # SQL Injection
    sql = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
    return db.query(sql)

def process_file(filename):
    # OS Command Injection
    os.system(f"process_file.sh {filename}")

def evaluate_expression(expr):
    # Code Injection
    return eval(expr)
"""

    orchestrator = AgentOrchestrator()
    report = await orchestrator.process_code(
        code_with_issues, file_path="search.py"
    )

    if report:
        # Generate markdown report
        markdown = ReportGenerator.generate_markdown_report(report)

        # Save to file
        report_path = Path("example_report.md")
        report_path.write_text(markdown)
        print(f"\n✓ Report saved to {report_path}")

        # Show summary
        print(f"\n📊 Report Summary:")
        print(f"   Risk Score: {report.overall_risk_score:.1f}/100")
        print(f"   Summary: {report.summary}")


async def example_3_github_integration():
    """Example 3: GitHub comment generation."""
    print("\n" + "=" * 70)
    print("EXAMPLE 3: GitHub Comment Format")
    print("=" * 70)

    flask_app = """
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/api/user/<user_id>')
def get_user(user_id):
    # SQL Injection
    query = f"SELECT * FROM users WHERE id={user_id}"
    return db.execute(query)

@app.route('/render')
def render():
    # XSS vulnerability
    content = request.args.get('content', '')
    return render_template_string(f"<h1>{content}</h1>")

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode in production!
"""

    orchestrator = AgentOrchestrator()
    report = await orchestrator.process_code(
        flask_app, file_path="app.py", pr_id="PR-456"
    )

    if report:
        # Generate GitHub comment
        comment = ReportGenerator.generate_github_comment(report)
        print("\n📝 GitHub PR Comment:")
        print("-" * 70)
        print(comment)
        print("-" * 70)


async def example_4_safe_code():
    """Example 4: Analysis of safe code."""
    print("\n" + "=" * 70)
    print("EXAMPLE 4: Safe Code Analysis (Should have low risk)")
    print("=" * 70)

    safe_code = """
import hashlib
from cryptography.fernet import Fernet

def login_safe(username, password):
    # Parameterized query
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password_hash = ?",
        (username, hash_password(password))
    )
    return cursor.fetchone()

def hash_password(password):
    # Secure password hashing
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return key

def process_file_safe(filename):
    # Safe file processing
    import subprocess
    result = subprocess.run(['process_script.sh', filename], 
                          capture_output=True, timeout=30)
    return result
"""

    orchestrator = AgentOrchestrator()
    report = await orchestrator.process_code(
        safe_code, file_path="secure_app.py"
    )

    if report:
        print(f"\n✓ Safe code analysis complete")
        print(f"  Risk Score: {report.overall_risk_score:.1f}/100")
        print(f"  Vulnerabilities Found: {report.total_vulnerabilities}")
        if report.total_vulnerabilities == 0:
            print("  ✅ No security issues detected!")


async def main():
    """Run all examples."""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "JorginhoAgent - Example Usage".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "=" * 68 + "╝")

    try:
        await example_1_simple_analysis()
        await example_2_detailed_report()
        await example_3_github_integration()
        await example_4_safe_code()

        print("\n" + "=" * 70)
        print("✓ All examples completed successfully!")
        print("=" * 70)

    except Exception as e:
        print(f"\n✗ Error running examples: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
