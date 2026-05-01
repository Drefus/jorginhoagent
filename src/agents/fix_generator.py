"""Agent 3: Fix Generator Agent"""

from typing import List, Optional

from src.config.settings import get_settings
from src.models.schemas import FixSuggestion, Vulnerability


class FixGeneratorAgent:
    """Agent for generating code fixes and recommendations."""

    def __init__(self, llm_model: Optional[str] = None):
        """Initialize fix generator agent.

        Args:
            llm_model: LLM model to use. If None, uses setting from config.
        """
        self.settings = get_settings()
        self.llm_model = llm_model or self.settings.llm_model
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
                return None
        except Exception as e:
            print(f"Warning: Could not initialize LLM: {e}")
            return None

    async def generate_fixes(
        self,
        code: str,
        vulnerabilities: List[Vulnerability],
        file_path: str = "code.py",
    ) -> List[FixSuggestion]:
        """Generate fixes for detected vulnerabilities.

        This agent:
        1. For each vulnerability, finds the vulnerable code
        2. Generates a corrected version
        3. Explains the changes
        4. Provides references

        Args:
            code: Source code being analyzed
            vulnerabilities: List of vulnerabilities to fix
            file_path: Path of analyzed file

        Returns:
            List of fix suggestions
        """
        print(f"[Agent 3] Generating fixes for {len(vulnerabilities)} vulnerabilities...")

        fixes = []
        lines = code.split("\n")

        for vuln in vulnerabilities:
            print(f"[Agent 3] Generating fix for {vuln.type} at line {vuln.line_number}")

            # Extract vulnerable code
            vulnerable_code = self._extract_code_context(
                lines, vuln.line_number, context_lines=3
            )

            # Generate fix
            fix = await self._generate_fix_for_vulnerability(
                code, vuln, vulnerable_code, file_path
            )

            if fix:
                fixes.append(fix)

        print(f"[Agent 3] Generated {len(fixes)} fixes")
        return fixes

    def _extract_code_context(
        self, lines: List[str], line_number: int, context_lines: int = 3
    ) -> str:
        """Extract code snippet around a line.

        Args:
            lines: List of code lines
            line_number: Target line number (1-indexed)
            context_lines: Number of lines to include before/after

        Returns:
            Code snippet as string
        """
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        snippet_lines = lines[start:end]
        return "\n".join(snippet_lines)

    async def _generate_fix_for_vulnerability(
        self,
        full_code: str,
        vuln: Vulnerability,
        vulnerable_code: str,
        file_path: str,
    ) -> Optional[FixSuggestion]:
        """Generate fix for a specific vulnerability.

        Args:
            full_code: Full source code
            vuln: Vulnerability to fix
            vulnerable_code: Code snippet containing vulnerability
            file_path: File path

        Returns:
            FixSuggestion or None if generation fails
        """
        # Get template-based fix if available
        fix = self._get_template_fix(vuln, vulnerable_code)

        if fix and self.llm:
            # Use LLM to enhance the fix
            fix = await self._enhance_fix_with_llm(full_code, vuln, fix)

        return fix

    def _get_template_fix(
        self, vuln: Vulnerability, vulnerable_code: str
    ) -> Optional[FixSuggestion]:
        """Get template-based fix for vulnerability type.

        Args:
            vuln: Vulnerability
            vulnerable_code: Vulnerable code snippet

        Returns:
            FixSuggestion or None
        """
        fixes_templates = {
            "SQL_INJECTION": self._fix_sql_injection,
            "CROSS_SITE_SCRIPTING": self._fix_xss,
            "OS_COMMAND_INJECTION": self._fix_command_injection,
            "WEAK_CRYPTOGRAPHY": self._fix_weak_crypto,
            "CODE_INJECTION": self._fix_code_injection,
        }

        fix_func = fixes_templates.get(vuln.type)
        if fix_func:
            return fix_func(vuln, vulnerable_code)

        # Generic fix template
        return FixSuggestion(
            vulnerability_type=vuln.type,
            original_code=vulnerable_code,
            fixed_code="# Add your fix here",
            explanation=f"Review and fix {vuln.type} vulnerability",
            severity_reduced_from=vuln.severity,
            severity_reduced_to="RESOLVED",
            references=self._get_references(vuln),
        )

    def _fix_sql_injection(
        self, vuln: Vulnerability, vulnerable_code: str
    ) -> FixSuggestion:
        """Generate SQL injection fix template."""
        original = 'query = f"SELECT * FROM users WHERE id={user_id}"'
        fixed = 'cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))'

        explanation = (
            "Replace f-string SQL queries with parameterized queries. "
            "Use placeholders (?) and pass parameters separately. "
            "This prevents SQL injection by ensuring user input is properly escaped."
        )

        return FixSuggestion(
            vulnerability_type="SQL_INJECTION",
            original_code=vulnerable_code if original in vulnerable_code else original,
            fixed_code=fixed,
            explanation=explanation,
            severity_reduced_from=vuln.severity,
            severity_reduced_to="RESOLVED",
            references=self._get_references(vuln),
        )

    def _fix_xss(
        self, vuln: Vulnerability, vulnerable_code: str
    ) -> FixSuggestion:
        """Generate XSS fix template."""
        original = "return f'<h1>{user_input}</h1>'"
        fixed = "from markupsafe import escape\nreturn f'<h1>{escape(user_input)}</h1>'"

        explanation = (
            "Escape HTML special characters using markupsafe or similar library. "
            "This prevents XSS attacks by converting dangerous characters to HTML entities."
        )

        return FixSuggestion(
            vulnerability_type="CROSS_SITE_SCRIPTING",
            original_code=vulnerable_code if original in vulnerable_code else original,
            fixed_code=fixed,
            explanation=explanation,
            severity_reduced_from=vuln.severity,
            severity_reduced_to="RESOLVED",
            references=self._get_references(vuln),
        )

    def _fix_command_injection(
        self, vuln: Vulnerability, vulnerable_code: str
    ) -> FixSuggestion:
        """Generate command injection fix template."""
        original = 'os.system(f"cat {filename}")'
        fixed = "import subprocess\nresult = subprocess.run(['cat', filename], capture_output=True)"

        explanation = (
            "Avoid os.system() with user input. Use subprocess.run() with a list of arguments "
            "instead. This prevents shell interpretation of special characters."
        )

        return FixSuggestion(
            vulnerability_type="OS_COMMAND_INJECTION",
            original_code=vulnerable_code if original in vulnerable_code else original,
            fixed_code=fixed,
            explanation=explanation,
            severity_reduced_from=vuln.severity,
            severity_reduced_to="RESOLVED",
            references=self._get_references(vuln),
        )

    def _fix_weak_crypto(
        self, vuln: Vulnerability, vulnerable_code: str
    ) -> FixSuggestion:
        """Generate weak cryptography fix template."""
        original = "import hashlib\nhash = hashlib.md5(password.encode()).hexdigest()"
        fixed = "import hashlib\nhash = hashlib.sha256(password.encode()).hexdigest()"

        explanation = (
            "Replace weak cryptographic algorithms (MD5, DES, RC4) with secure alternatives "
            "(SHA-256, AES-256). Use cryptography libraries like 'cryptography' or 'bcrypt' "
            "for password hashing instead of raw hash functions."
        )

        return FixSuggestion(
            vulnerability_type="WEAK_CRYPTOGRAPHY",
            original_code=vulnerable_code if original in vulnerable_code else original,
            fixed_code=fixed,
            explanation=explanation,
            severity_reduced_from=vuln.severity,
            severity_reduced_to="RESOLVED",
            references=self._get_references(vuln),
        )

    def _fix_code_injection(
        self, vuln: Vulnerability, vulnerable_code: str
    ) -> FixSuggestion:
        """Generate code injection fix template."""
        original = 'result = eval(user_code)'
        fixed = "import ast\ntree = ast.parse(user_code, mode='eval')\nresult = eval(compile(tree, '<string>', 'eval'))"

        explanation = (
            "Never use eval() with untrusted input. "
            "Use ast.literal_eval() for safe Python literals, or implement a custom DSL with restricted operators. "
            "If code execution is necessary, use sandboxing or restricted environments."
        )

        return FixSuggestion(
            vulnerability_type="CODE_INJECTION",
            original_code=vulnerable_code if original in vulnerable_code else original,
            fixed_code=fixed,
            explanation=explanation,
            severity_reduced_from=vuln.severity,
            severity_reduced_to="RESOLVED",
            references=self._get_references(vuln),
        )

    async def _enhance_fix_with_llm(
        self, code: str, vuln: Vulnerability, fix: FixSuggestion
    ) -> FixSuggestion:
        """Enhance fix using LLM.

        Args:
            code: Full source code
            vuln: Vulnerability
            fix: Initial fix suggestion

        Returns:
            Enhanced fix
        """
        try:
            prompt = f"""Review this security fix and improve it:

Vulnerability: {vuln.type}
Current Fix:
{fix.fixed_code}

Requirements:
1. Make it more practical and production-ready
2. Ensure it's compatible with the existing codebase
3. Add any necessary imports
4. Explain the fix clearly

Return as JSON:
{{
    "improved_code": "<fixed code>",
    "explanation": "<detailed explanation>"
}}"""

            if self.llm:
                # In a real implementation, call LLM asynchronously
                print(f"[Agent 3]   → LLM enhancement skipped (requires API setup)")

            return fix

        except Exception as e:
            print(f"[Agent 3] Error enhancing fix: {e}")
            return fix

    def _get_references(self, vuln: Vulnerability) -> List[str]:
        """Get reference links for vulnerability.

        Args:
            vuln: Vulnerability

        Returns:
            List of reference URLs
        """
        refs = []

        if vuln.cwe_id:
            cwe_num = vuln.cwe_id.split("-")[-1]
            refs.append(f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")

        # Add OWASP references
        owasp_links = {
            "A01:2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "A02:2021": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "A03:2021": "https://owasp.org/Top10/A03_2021-Injection/",
            "A04:2021": "https://owasp.org/Top10/A04_2021-Insecure_Deserialization/",
            "A07:2021": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        }

        if vuln.owasp_category:
            for key, url in owasp_links.items():
                if key in vuln.owasp_category:
                    refs.append(url)

        return refs


if __name__ == "__main__":
    import asyncio

    test_vuln = Vulnerability(
        type="SQL_INJECTION",
        severity="CRITICAL",
        line_number=3,
        description="SQL Injection",
        confidence=0.95,
        cwe_id="CWE-89",
        owasp_category="A03:2021",
    )

    agent = FixGeneratorAgent()

    async def test():
        fixes = await agent.generate_fixes(
            'query = f"SELECT * FROM users WHERE id={user_id}"',
            [test_vuln],
            "test.py",
        )
        for fix in fixes:
            print(f"\n{fix.vulnerability_type}:")
            print(f"Before: {fix.original_code}")
            print(f"After: {fix.fixed_code}")
            print(f"Explanation: {fix.explanation}")

    asyncio.run(test())
