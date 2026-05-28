"""Pydantic schemas for data validation and serialization."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    type: str = Field(..., description="Tipo da vulnerabilidade (ex: SQL_INJECTION, XSS)")
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM ou LOW")
    line_number: Optional[int] = Field(..., description="Linha no código-fonte")
    column_number: Optional[int] = Field(None)
    description: str = Field(..., description="Descrição detalhada")
    code_snippet: Optional[str] = Field(None, description="Trecho de código vulnerável")
    cwe_id: Optional[str] = Field(None)
    cwe_name: Optional[str] = Field(None)
    owasp_category: Optional[str] = Field(None)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    remediation: Optional[str] = Field(None)
    is_false_positive: bool = Field(default=False)

    class Config:
        arbitrary_types_allowed = True


class CodeAnalysisResult(BaseModel):
    file_path: str
    file_content: Optional[str] = None
    language: Optional[str] = None
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    static_analysis_tool: Optional[str] = None
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)


class FixSuggestion(BaseModel):
    vulnerability_type: str
    original_code: str
    fixed_code: str
    explanation: str
    severity_reduced_from: str
    severity_reduced_to: Optional[str] = None
    references: List[str] = Field(default_factory=list)


# ── Red Team schemas ──────────────────────────────────────────────────────────

class AttackVector(BaseModel):
    """Um vetor de ataque identificado pelo agente Red Team."""
    attack_type: str = Field(..., description="Tipo do ataque (ex: SQL Injection, RCE, Pickle RCE)")
    line_number: Optional[int] = Field(None, description="Linha alvo no código")
    description: str = Field(..., description="Como o ataque seria executado")
    exploitability: str = Field(..., description="HIGH, MEDIUM ou LOW")
    payload_example: Optional[str] = Field(None, description="Exemplo de payload exploitável")
    impact: str = Field(..., description="O que o atacante conseguiria")


class RedTeamReport(BaseModel):
    """Relatório produzido pelo agente Red Team."""
    attack_vectors: List[AttackVector] = Field(default_factory=list)
    executive_summary: str = Field(..., description="Resumo da superfície de ataque")
    overall_exploitability: str = Field(default="LOW", description="HIGH, MEDIUM ou LOW")
    most_critical_attack: Optional[str] = Field(None, description="Ataque mais perigoso identificado")


# ── Report ────────────────────────────────────────────────────────────────────

class SecurityReport(BaseModel):
    analysis_id: str
    pr_id: Optional[str] = None
    pr_url: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    analyzed_files: List[CodeAnalysisResult] = Field(default_factory=list)
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    false_positive_count: int = 0
    fix_suggestions: List[FixSuggestion] = Field(default_factory=list)
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    summary: str
    recommendations: List[str] = Field(default_factory=list)
    analysis_duration_seconds: float = 0.0
    # Red team summary incluído no relatório final
    red_team_summary: Optional[str] = Field(None, description="Resumo do Red Team")
    red_team_exploitability: Optional[str] = Field(None)

    class Config:
        arbitrary_types_allowed = True


# ── Shared pipeline state ─────────────────────────────────────────────────────

class AgentState(BaseModel):
    analysis_id: str
    input_code: str
    file_path: str
    static_analysis_results: List[Vulnerability] = Field(default_factory=list)
    red_team_report: Optional[RedTeamReport] = Field(None)
    context_evaluation_results: List[Vulnerability] = Field(default_factory=list)
    fix_suggestions: List[FixSuggestion] = Field(default_factory=list)
    final_report: Optional[SecurityReport] = Field(None)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        arbitrary_types_allowed = True
