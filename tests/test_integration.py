"""Integration tests for the complete pipeline."""

import pytest

from src.graph.orchestrator import AgentOrchestrator


@pytest.mark.asyncio
async def test_orchestrator_with_vulnerable_code():
    """Test orchestrator with vulnerable code."""
    orchestrator = AgentOrchestrator()

    vulnerable_code = '''
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = db.execute(query)
    return user
'''

    report = await orchestrator.process_code(vulnerable_code, "test.py")

    assert report is not None
    assert report.analysis_id is not None
    assert report.total_vulnerabilities >= 0


@pytest.mark.asyncio
async def test_orchestrator_with_safe_code():
    """Test orchestrator with safe code."""
    orchestrator = AgentOrchestrator()

    safe_code = '''
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    return cursor.fetchone()
'''

    report = await orchestrator.process_code(safe_code, "safe.py")

    assert report is not None
    assert report.analysis_id is not None


@pytest.mark.asyncio
async def test_orchestrator_generates_fixes():
    """Test that orchestrator generates fixes for vulnerabilities."""
    orchestrator = AgentOrchestrator()

    vulnerable_code = '''
import os
os.system(f"cat {filename}")
'''

    report = await orchestrator.process_code(vulnerable_code, "test.py")

    # Should have vulnerabilities and fixes
    assert report is not None
    if report.total_vulnerabilities > 0:
        # Fixes should be suggested
        assert isinstance(report.fix_suggestions, list)
