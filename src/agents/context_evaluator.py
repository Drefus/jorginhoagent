"""Agent 2: Context Evaluator Agent"""

from typing import List, Optional

from src.config.settings import get_settings
from src.models.schemas import Vulnerability


class ContextEvaluatorAgent:
    """Agent for context-aware vulnerability evaluation and severity assessment."""

    def __init__(self, llm_model: Optional[str] = None):
        """Initialize context evaluator agent.

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

    async def evaluate(
        self, code: str, vulnerabilities: List[Vulnerability], file_path: str = "code.py"
    ) -> List[Vulnerability]:
        """Evaluate vulnerabilities in context and adjust severity.

        This agent:
        1. Analyzes data flow
        2. Checks for existing validations
        3. Confirms or discards alerts (false positive detection)
        4. Reclassifies severity based on context

        Args:
            code: Source code being analyzed
            vulnerabilities: Initial vulnerability list from static analyzer
            file_path: Path of analyzed file

        Returns:
            Updated vulnerability list after context evaluation
        """
        print(f"[Agent 2] Starting context evaluation for {file_path}")
        print(f"[Agent 2] Evaluating {len(vulnerabilities)} vulnerabilities...")

        if not vulnerabilities:
            return vulnerabilities

        evaluated_vulns = []

        for vuln in vulnerabilities:
            print(f"[Agent 2] Evaluating: {vuln.type} at line {vuln.line_number}")

            # Check for validation in surrounding context
            has_validation = self._check_for_validation(code, vuln.line_number)
            has_sanitization = self._check_for_sanitization(code, vuln.line_number)
            has_protection = self._check_for_protection(code, vuln.type)

            # Adjust confidence based on context
            original_confidence = vuln.confidence
            if has_validation or has_sanitization or has_protection:
                # Reduce confidence if there's evidence of protection
                vuln.confidence = max(0.1, vuln.confidence - 0.2)
                print(f"[Agent 2]   → Found protection measure, confidence reduced to {vuln.confidence:.2f}")

            # Use LLM for deeper analysis if available
            if self.llm and vuln.confidence > 0.5:
                vuln = await self._llm_context_analysis(code, vuln, file_path)

            # Mark as false positive if confidence too low
            if vuln.confidence < 0.3:
                vuln.is_false_positive = True
                print(f"[Agent 2]   → Marked as false positive (confidence: {vuln.confidence:.2f})")
            else:
                evaluated_vulns.append(vuln)

        print(f"[Agent 2] Context evaluation complete. {len(evaluated_vulns)} confirmed vulnerabilities")
        return evaluated_vulns

    def _check_for_validation(self, code: str, line_number: int) -> bool:
        """Check if there's input validation around the vulnerable line.

        Args:
            code: Source code
            line_number: Line number of vulnerability

        Returns:
            True if validation found nearby
        """
        lines = code.split("\n")
        search_range = 5

        # Look for validation keywords in surrounding lines
        validation_keywords = [
            "validate",
            "check",
            "assert",
            "if ",
            "raise",
            "verify",
        ]

        start = max(0, line_number - search_range)
        end = min(len(lines), line_number + search_range)

        for i in range(start, end):
            if i < len(lines):
                line = lines[i].lower()
                if any(keyword in line for keyword in validation_keywords):
                    return True

        return False

    def _check_for_sanitization(self, code: str, line_number: int) -> bool:
        """Check if there's input sanitization around the vulnerable line.

        Args:
            code: Source code
            line_number: Line number of vulnerability

        Returns:
            True if sanitization found nearby
        """
        lines = code.split("\n")
        search_range = 5

        # Look for sanitization keywords
        sanitization_keywords = [
            "strip",
            "replace",
            "escape",
            "sanitize",
            "clean",
            "filter",
            "encode",
            "quote",
            "parameterize",
        ]

        start = max(0, line_number - search_range)
        end = min(len(lines), line_number + search_range)

        for i in range(start, end):
            if i < len(lines):
                line = lines[i].lower()
                if any(keyword in line for keyword in sanitization_keywords):
                    return True

        return False

    def _check_for_protection(self, code: str, vuln_type: str) -> bool:
        """Check for specific protections based on vulnerability type.

        Args:
            code: Source code
            vuln_type: Type of vulnerability

        Returns:
            True if protection found
        """
        code_lower = code.lower()

        protections = {
            "SQL_INJECTION": [
                "parameterized",
                "prepared statement",
                "execute(",
                "query(",
                "orm",
            ],
            "XSS": ["escape", "htmlencode", "sanitize", "xss"],
            "OS_COMMAND_INJECTION": ["shlex", "subprocess", "popen"],
            "CODE_INJECTION": ["ast.literal_eval", "json.loads"],
        }

        if vuln_type in protections:
            return any(prot in code_lower for prot in protections[vuln_type])

        return False

    async def _llm_context_analysis(
        self, code: str, vuln: Vulnerability, file_path: str
    ) -> Vulnerability:
        """Use LLM for deeper context analysis.

        Args:
            code: Source code
            vuln: Vulnerability to analyze
            file_path: Path of analyzed file

        Returns:
            Updated vulnerability
        """
        try:
            # Extract code context
            lines = code.split("\n")
            start = max(0, vuln.line_number - 5)
            end = min(len(lines), vuln.line_number + 5)
            context = "\n".join(
                f"{i+1}: {line}" for i, line in enumerate(lines[start:end], start)
            )

            prompt = f"""As a security expert, analyze this code vulnerability in context:

File: {file_path}
Vulnerability Type: {vuln.type}
Confidence: {vuln.confidence}

Code Context (around line {vuln.line_number}):
```
{context}
```

Question: Is this a real security vulnerability or a false positive?
Consider: existing validations, sanitization, protective measures, data flow.

Answer with JSON:
{{
    "is_false_positive": <boolean>,
    "confidence_adjustment": <-0.3 to 0.3>,
    "reasoning": "<brief explanation>"
}}"""

            if self.llm:
                # In a real implementation, call LLM asynchronously
                # For now, we'll skip this to avoid API calls
                print(f"[Agent 2]   → LLM analysis skipped (requires API setup)")

            return vuln

        except Exception as e:
            print(f"[Agent 2] Error in LLM analysis: {e}")
            return vuln


if __name__ == "__main__":
    import asyncio
    from src.models.schemas import Vulnerability

    test_code = """
def query_users(user_id):
    # Check if user_id is valid
    if not isinstance(user_id, int) or user_id < 0:
        raise ValueError("Invalid user ID")
    
    # Still vulnerable despite validation
    query = f"SELECT * FROM users WHERE id={user_id}"
    return execute_query(query)
"""

    test_vuln = Vulnerability(
        type="SQL_INJECTION",
        severity="HIGH",
        line_number=7,
        description="Unsanitized input in query",
        confidence=0.9,
    )

    agent = ContextEvaluatorAgent()

    async def test():
        result = await agent.evaluate(test_code, [test_vuln], "test.py")
        for vuln in result:
            print(
                f"\n{vuln.type} - Confidence: {vuln.confidence:.2f} "
                f"- False Positive: {vuln.is_false_positive}"
            )

    asyncio.run(test())
