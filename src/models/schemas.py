"""Pydantic schemas for data validation and serialization."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    """Detected vulnerability information."""

    type: str = Field(..., description="Type of vulnerability (e.g., SQL Injection, XSS)")
    severity: str = Field(
        ..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW"
    )
    line_number: int = Field(..., description="Line number in source code")
    column_number: Optional[int] = Field(None, description="Column number in source code")
    description: str = Field(..., description="Detailed description of the vulnerability")
    code_snippet: Optional[str] = Field(None, description="Relevant code snippet")
    cwe_id: Optional[str] = Field(None, description="CWE identifier (e.g., CWE-89)")
    cwe_name: Optional[str] = Field(None, description="CWE name")
    owasp_category: Optional[str] = Field(None, description="OWASP Top 10 category")
    confidence: float = Field(
        default=0.8, ge=0.0, le=1.0, description="Confidence score 0-1"
    )
    remediation: Optional[str] = Field(None, description="Suggested remediation")
    is_false_positive: bool = Field(
        default=False, description="Marked as false positive after context analysis"
    )

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "type": "SQL Injection",
                "severity": "CRITICAL",
                "line_number": 42,
                "description": "Unsanitized user input in SQL query",
                "code_snippet": "query = f\"SELECT * FROM users WHERE id={user_id}\"",
                "cwe_id": "CWE-89",
                "cwe_name": "SQL Injection",
                "owasp_category": "A03:2021 - Injection",
                "confidence": 0.95,
                "remediation": "Use parameterized queries",
            }
        }


class CodeAnalysisResult(BaseModel):
    """Result of analyzing a single code file."""

    file_path: str = Field(..., description="Path to the analyzed file")
    file_content: Optional[str] = Field(None, description="Content of the file")
    language: Optional[str] = Field(None, description="Programming language")
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list, description="List of detected vulnerabilities"
    )
    static_analysis_tool: Optional[str] = Field(
        None, description="Tool used for static analysis (e.g., Bandit)"
    )
    analysis_timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="When analysis was performed"
    )

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "file_path": "src/api.py",
                "language": "python",
                "vulnerabilities": [],
                "static_analysis_tool": "bandit",
                "analysis_timestamp": "2024-05-01T10:30:00Z",
            }
        }


class FixSuggestion(BaseModel):
    """Suggested fix for a vulnerability."""

    vulnerability_type: str = Field(..., description="Type of vulnerability fixed")
    original_code: str = Field(..., description="Original vulnerable code")
    fixed_code: str = Field(..., description="Corrected code")
    explanation: str = Field(..., description="Explanation of the fix")
    severity_reduced_from: str = Field(..., description="Original severity level")
    severity_reduced_to: Optional[str] = Field(None, description="Severity after fix")
    references: List[str] = Field(
        default_factory=list, description="Links to CWE/OWASP docs"
    )

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "vulnerability_type": "SQL Injection",
                "original_code": 'query = f"SELECT * FROM users WHERE id={user_id}"',
                "fixed_code": "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
                "explanation": "Use parameterized queries to prevent SQL injection",
                "severity_reduced_from": "CRITICAL",
                "severity_reduced_to": "RESOLVED",
                "references": ["https://cwe.mitre.org/data/definitions/89.html"],
            }
        }


class SecurityReport(BaseModel):
    """Complete security analysis report."""

    pr_id: Optional[str] = Field(None, description="GitHub PR ID if applicable")
    pr_url: Optional[str] = Field(None, description="GitHub PR URL")
    analysis_id: str = Field(..., description="Unique analysis identifier")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Report generation time"
    )
    analyzed_files: List[CodeAnalysisResult] = Field(
        default_factory=list, description="Results for each analyzed file"
    )
    total_vulnerabilities: int = Field(
        default=0, description="Total vulnerabilities found"
    )
    critical_count: int = Field(default=0, description="Number of CRITICAL vulnerabilities")
    high_count: int = Field(default=0, description="Number of HIGH vulnerabilities")
    medium_count: int = Field(default=0, description="Number of MEDIUM vulnerabilities")
    low_count: int = Field(default=0, description="Number of LOW vulnerabilities")
    false_positive_count: int = Field(
        default=0, description="Number of false positives confirmed"
    )
    fix_suggestions: List[FixSuggestion] = Field(
        default_factory=list, description="Suggested fixes"
    )
    overall_risk_score: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Overall risk score 0-100"
    )
    summary: str = Field(..., description="Executive summary of findings")
    recommendations: List[str] = Field(
        default_factory=list, description="General recommendations"
    )
    analysis_duration_seconds: float = Field(
        default=0.0, description="Time taken for analysis"
    )

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "analysis_id": "analysis_12345",
                "timestamp": "2024-05-01T10:30:00Z",
                "analyzed_files": [],
                "total_vulnerabilities": 3,
                "critical_count": 1,
                "high_count": 2,
                "overall_risk_score": 75.5,
                "summary": "3 vulnerabilities found, 1 critical",
                "recommendations": ["Use parameterized queries", "Implement input validation"],
            }
        }


class AgentState(BaseModel):
    """Shared state between agents in the orchestration graph."""

    analysis_id: str = Field(..., description="Unique analysis ID")
    input_code: str = Field(..., description="Code to analyze")
    file_path: str = Field(..., description="Path of file being analyzed")
    static_analysis_results: List[Vulnerability] = Field(
        default_factory=list, description="Results from static analyzer"
    )
    context_evaluation_results: List[Vulnerability] = Field(
        default_factory=list, description="Results after context evaluation"
    )
    fix_suggestions: List[FixSuggestion] = Field(
        default_factory=list, description="Generated fix suggestions"
    )
    final_report: Optional[SecurityReport] = Field(None, description="Final report")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        """Pydantic config."""

        arbitrary_types_allowed = True
