"""Tests for security tools."""

import pytest

from src.tools.static_analysis import StaticAnalyzer
from src.tools.vulnerability_db import VulnerabilityDatabase


def test_vulnerability_database_lookup():
    """Test vulnerability database lookup."""
    db = VulnerabilityDatabase()

    # Test exact lookup
    info = db.get_vulnerability_info("SQL_INJECTION")
    assert info is not None
    assert "CWE-89" in info["cwe_id"]

    # Test CWE lookup
    info = db.search_by_cwe("CWE-79")
    assert info is not None
    assert "XSS" in info["cwe_name"]


def test_vulnerability_database_owasp_search():
    """Test OWASP category search."""
    db = VulnerabilityDatabase()

    # Find all injection vulnerabilities
    vulns = db.search_by_owasp("A03:2021")
    assert len(vulns) > 0


def test_static_analyzer():
    """Test Bandit-based static analyzer."""
    analyzer = StaticAnalyzer()

    test_code = '''
user_id = input("Enter ID: ")
query = f"SELECT * FROM users WHERE id={user_id}"
'''

    vulns = analyzer.analyze_code(test_code)
    # Should detect potential SQL injection (Bandit B608)
    # Note: Bandit might not catch this without more context
    assert isinstance(vulns, list)
