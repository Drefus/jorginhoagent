"""Agent 1: Static Code Analyzer Agent"""

import json
from typing import List, Optional

from src.config.settings import get_settings
from src.models.schemas import Vulnerability
from src.tools.static_analysis import StaticAnalyzer
from src.tools.vulnerability_db import get_vulnerability_db


class StaticAnalyzerAgent:
    """Agent for static code analysis and vulnerability detection."""

    def __init__(self, llm_model: Optional[str] = None):
        """Initialize static analyzer agent.

        Args:
            llm_model: LLM model to use. If None, uses setting from config.
        """
        self.settings = get_settings()
        self.llm_model = llm_model or self.settings.llm_model
        self.static_analyzer = StaticAnalyzer(
            severity_level=self.settings.bandit_level
        )
        self.vuln_db = get_vulnerability_db()

        # Initialize LLM (if LLM provider is available)
        self.llm = self._initialize_llm()

    def _initialize_llm(self):
        """Initialize LLM based on provider setting.

        Returns:
            LLM instance or None if LLM is not available
        """
        try:
            if self.settings.llm_provider == "openai":
                from langchain_openai import ChatOpenAI

                return ChatOpenAI(
                    api_key=self.settings.llm_api_key,
                    model=self.llm_model,
                    temperature=self.settings.llm_temperature,
                )
            elif self.settings.llm_provider == "anthropic":
                from langchain_anthropic import ChatAnthropic

                return ChatAnthropic(
                    api_key=self.settings.llm_api_key,
                    model=self.llm_model,
                )
            else:
                print(f"LLM provider {self.settings.llm_provider} not configured")
                return None
        except Exception as e:
            print(f"Warning: Could not initialize LLM: {e}")
            return None

    async def analyze(self, code: str, file_path: str = "code.py") -> List[Vulnerability]:
        """Analyze code for vulnerabilities.

        This agent:
        1. Runs Bandit static analysis
        2. Enriches results with CWE/OWASP information
        3. Uses LLM for additional context (if available)

        Args:
            code: Source code to analyze
            file_path: Path or name of the file being analyzed

        Returns:
            List of detected vulnerabilities
        """
        print(f"[Agent 1] Starting static analysis of {file_path}")

        # Step 1: Run Bandit
        print("[Agent 1] Running Bandit static analyzer...")
        vulns = self.static_analyzer.analyze_code(code, file_path)

        # Step 2: Enrich with CWE/OWASP info
        print("[Agent 1] Enriching vulnerability data...")
        for vuln in vulns:
            # Try to find vulnerability info by type
            vuln_info = self.vuln_db.get_vulnerability_info(vuln.type)

            # Try to find by CWE ID if exact match not found
            if not vuln_info and vuln.cwe_id:
                vuln_info = self.vuln_db.search_by_cwe(vuln.cwe_id)

            # Update vulnerability with enriched data
            if vuln_info:
                vuln.cwe_id = vuln.cwe_id or vuln_info.get("cwe_id")
                vuln.cwe_name = vuln_info.get("cwe_name")
                vuln.owasp_category = vuln_info.get("owasp")
                if not vuln.description:
                    vuln.description = vuln_info.get("description")
                if not vuln.remediation:
                    vuln.remediation = vuln_info.get("remediation")

        # Step 3: Use LLM to enhance descriptions (optional)
        if self.llm and vulns:
            print("[Agent 1] Enhancing descriptions with LLM...")
            vulns = await self._enhance_with_llm(code, vulns, file_path)

        print(f"[Agent 1] Analysis complete. Found {len(vulns)} vulnerabilities")
        return vulns

    async def _enhance_with_llm(
        self, code: str, vulns: List[Vulnerability], file_path: str
    ) -> List[Vulnerability]:
        """Enhance vulnerability descriptions using LLM.

        Args:
            code: Source code being analyzed
            vulns: Initial vulnerability list from static analysis
            file_path: Path of analyzed file

        Returns:
            Enhanced vulnerability list
        """
        try:
            # Create a prompt for the LLM
            vuln_list = "\n".join(
                [f"- Line {v.line_number}: {v.type} - {v.description}" for v in vulns]
            )

            prompt = f"""You are a security code reviewer. 
            
Analyze the following code vulnerabilities and provide:
1. Confirm if the vulnerability is real (not false positive)
2. Suggest a simple fix
3. Explain the security impact

Code:
```
{code}
```

Detected vulnerabilities:
{vuln_list}

Provide response as JSON array with format:
[
  {{
    "line_number": <number>,
    "type": "<type>",
    "is_real": <boolean>,
    "confidence_adjustment": <0.0 to 1.0>,
    "suggested_fix": "<brief fix>"
  }}
]"""

            # Call LLM (in a real implementation, use async)
            if self.llm:
                response = self.llm.invoke(prompt)
                print("[Agent 1] LLM enhancement skipped (requires async handling)")

            return vulns

        except Exception as e:
            print(f"[Agent 1] Error enhancing with LLM: {e}")
            return vulns


if __name__ == "__main__":
    import asyncio

    test_code = """
import os
import subprocess

def query_users(user_id):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id={user_id}"
    return execute_query(query)

def run_command(filename):
    # OS Command Injection vulnerability
    os.system(f"cat {filename}")

def unsafe_eval(user_code):
    # Code Injection vulnerability
    eval(user_code)
"""

    agent = StaticAnalyzerAgent()

    async def test():
        vulns = await agent.analyze(test_code, "test.py")
        for vuln in vulns:
            print(f"\n[{vuln.severity}] {vuln.type}")
            print(f"  Line: {vuln.line_number}")
            print(f"  Description: {vuln.description}")
            if vuln.cwe_id:
                print(f"  CWE: {vuln.cwe_id}")
            if vuln.owasp_category:
                print(f"  OWASP: {vuln.owasp_category}")

    asyncio.run(test())
