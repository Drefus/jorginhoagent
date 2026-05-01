"""Tests for static analyzer agent."""

import pytest

from src.agents.static_analyzer import StaticAnalyzerAgent
from tests.fixtures.sample_code import (
    VULNERABLE_CODE_COMMAND_INJECTION,
    VULNERABLE_CODE_EVAL,
    VULNERABLE_CODE_SQL_INJECTION,
    VULNERABLE_CODE_WEAK_CRYPTO,
    VULNERABLE_CODE_XSS,
)


@pytest.fixture
def analyzer():
    """Create analyzer agent instance."""
    return StaticAnalyzerAgent()


@pytest.mark.asyncio
async def test_sql_injection_detection(analyzer):
    """Test detection of SQL injection vulnerability."""
    vulns = await analyzer.analyze(VULNERABLE_CODE_SQL_INJECTION)
    assert len(vulns) > 0
    # At least one vulnerability should be detected
    assert any("SQL" in v.type or v.line_number == 2 for v in vulns)


@pytest.mark.asyncio
async def test_command_injection_detection(analyzer):
    """Test detection of command injection."""
    vulns = await analyzer.analyze(VULNERABLE_CODE_COMMAND_INJECTION)
    assert len(vulns) > 0


@pytest.mark.asyncio
async def test_eval_detection(analyzer):
    """Test detection of eval vulnerability."""
    vulns = await analyzer.analyze(VULNERABLE_CODE_EVAL)
    assert len(vulns) > 0
    # Should find eval-related issue
    assert any("eval" in v.type.lower() or "307" in str(v.cwe_id) for v in vulns)


@pytest.mark.asyncio
async def test_vulnerability_enrichment(analyzer):
    """Test that vulnerabilities are enriched with CWE info."""
    vulns = await analyzer.analyze(VULNERABLE_CODE_SQL_INJECTION)
    
    if len(vulns) > 0:
        vuln = vulns[0]
        # Check enrichment
        assert vuln.cwe_id is not None or len(vulns) == 0
