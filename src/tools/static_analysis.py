"""Static analysis tools using Bandit."""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from src.models.schemas import Vulnerability


class StaticAnalyzer:
    """Wrapper for Bandit static analysis tool."""

    def __init__(self, severity_level: str = "high"):
        """Initialize static analyzer.

        Args:
            severity_level: Minimum severity level to report (low, medium, high)
        """
        self.severity_level = severity_level
        self.severity_map = {"low": 1, "medium": 2, "high": 3}

    def analyze_code(self, code: str, file_path: str = "code.py") -> List[Vulnerability]:
        """Analyze code using Bandit.

        Args:
            code: Python code to analyze
            file_path: Path or name of the file being analyzed

        Returns:
            List of detected vulnerabilities
        """
        # Create temporary file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as tmp_file:
            tmp_file.write(code)
            tmp_path = tmp_file.name

        try:
            # Run Bandit
            result = subprocess.run(
                ["bandit", "-f", "json", "-ll", tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            vulnerabilities = self._parse_bandit_output(
                result.stdout, file_path
            )
            return vulnerabilities

        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            print("Bandit not installed. Install with: pip install bandit")
            return []
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def _parse_bandit_output(
        self, json_output: str, file_path: str
    ) -> List[Vulnerability]:
        """Parse Bandit JSON output.

        Args:
            json_output: Bandit JSON output
            file_path: Path of analyzed file

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []

        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return vulnerabilities

        for result in data.get("results", []):
            severity = result.get("severity", "MEDIUM").upper()
            confidence = result.get("confidence", "MEDIUM").upper()

            # Skip if below severity threshold
            if (
                self.severity_map.get(severity.lower(), 0)
                < self.severity_map.get(self.severity_level, 2)
            ):
                continue

            # Map confidence to confidence score
            confidence_score = {
                "LOW": 0.5,
                "MEDIUM": 0.75,
                "HIGH": 0.95,
            }.get(confidence, 0.7)

            vuln = Vulnerability(
                type=result.get("test_id", "Unknown"),
                severity=severity,
                line_number=result.get("line_number", 0),
                description=result.get("issue_text", ""),
                code_snippet=result.get("line", ""),
                confidence=confidence_score,
                cwe_id=self._extract_cwe_id(result.get("test_id", "")),
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    @staticmethod
    def _extract_cwe_id(bandit_test_id: str) -> Optional[str]:
        """Map Bandit test ID to CWE.

        Args:
            bandit_test_id: Bandit test identifier

        Returns:
            CWE ID if available
        """
        # Mapping of common Bandit tests to CWE
        bandit_to_cwe = {
            "B201": "CWE-78",  # flask_debug_true -> Command Injection
            "B303": "CWE-345",  # use_of_md5 -> Weak Cryptography
            "B304": "CWE-327",  # use_of_des -> Weak Cryptography
            "B307": "CWE-95",   # eval -> Code Injection
            "B602": "CWE-78",   # shell_injection -> OS Command Injection
            "B603": "CWE-78",   # subprocess -> Improper Neutralization
            "B607": "CWE-426",  # start_process_with_partial_path -> Untrusted Search Path
            "B608": "CWE-89",   # sql_injection -> SQL Injection
            "B609": "CWE-426",  # paramiko_calls -> Improper Verification
            "B610": "CWE-74",   # django_sql_injection -> Improper Neutralization
            "B611": "CWE-91",   # flask_sqlalchemy -> SQL Injection
        }
        return bandit_to_cwe.get(bandit_test_id)


# Test the analyzer
if __name__ == "__main__":
    test_code = '''
import os
import subprocess

# Bad: SQL injection
user_id = input("Enter ID: ")
query = f"SELECT * FROM users WHERE id={user_id}"  # B608: SQL Injection

# Bad: Command injection
filename = input("Enter filename: ")
os.system(f"cat {filename}")  # B602: Shell Injection

# Bad: Eval
eval_code = input("Enter code: ")
eval(eval_code)  # B307: eval
'''

    analyzer = StaticAnalyzer()
    vulns = analyzer.analyze_code(test_code, "test.py")
    for vuln in vulns:
        print(f"[{vuln.severity}] {vuln.type} at line {vuln.line_number}: {vuln.description}")
