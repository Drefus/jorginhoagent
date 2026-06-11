"""Dashboard HTML para visualização de resultados de segurança.

Gera um arquivo HTML self-contained com gráficos, risk score gauge,
vulnerabilidades e sugestões de fix. Opcionalmente serve via HTTP local.
"""

import json
from pathlib import Path
from typing import Optional

from src.models.schemas import SecurityReport


def generate_dashboard_html(report: SecurityReport) -> str:
    """Gera HTML self-contained com os resultados da análise."""

    # Prepara dados para os gráficos
    severity_data = json.dumps({
        "CRITICAL": report.critical_count,
        "HIGH": report.high_count,
        "MEDIUM": report.medium_count,
        "LOW": report.low_count,
    })

    # Vulnerabilidades por tipo
    type_counts: dict = {}
    for file_result in report.analyzed_files:
        for vuln in file_result.vulnerabilities:
            vtype = vuln.type
            type_counts[vtype] = type_counts.get(vtype, 0) + 1
    type_data = json.dumps(type_counts)

    # Vulnerabilidades detalhadas
    vulns_list = []
    for file_result in report.analyzed_files:
        for vuln in file_result.vulnerabilities:
            vulns_list.append({
                "type": vuln.type,
                "severity": vuln.severity,
                "line_number": vuln.line_number or 0,
                "description": vuln.description,
                "file_path": file_result.file_path,
                "cwe_id": vuln.cwe_id or "N/A",
                "owasp_category": vuln.owasp_category or "N/A",
                "code_snippet": vuln.code_snippet or "",
            })
    vulns_json = json.dumps(vulns_list, ensure_ascii=False)

    # Fix suggestions
    fixes_list = []
    for fix in report.fix_suggestions:
        fixes_list.append({
            "vulnerability_type": fix.vulnerability_type,
            "original_code": fix.original_code,
            "fixed_code": fix.fixed_code,
            "explanation": fix.explanation,
            "severity_from": fix.severity_reduced_from,
            "severity_to": fix.severity_reduced_to or "?",
        })
    fixes_json = json.dumps(fixes_list, ensure_ascii=False)

    # Risk score color
    score = report.overall_risk_score
    if score > 70:
        gauge_color = "#e74c3c"
    elif score >= 30:
        gauge_color = "#f39c12"
    else:
        gauge_color = "#27ae60"

    # Red team
    red_team_html = ""
    if report.red_team_summary:
        red_team_html = f"""
        <div class="section">
            <h2>💀 Red Team</h2>
            <p>{_escape_html(report.red_team_summary)}</p>
            <p><strong>Exploitability:</strong> {report.red_team_exploitability or 'N/A'}</p>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JorginhoAgent - Security Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ text-align: center; margin-bottom: 10px; font-size: 2em; }}
        h2 {{ margin-bottom: 15px; color: #00d4ff; border-bottom: 1px solid #333; padding-bottom: 8px; }}
        .subtitle {{ text-align: center; color: #888; margin-bottom: 30px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: #16213e; border-radius: 12px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        .gauge-container {{ text-align: center; }}
        .gauge {{ width: 150px; height: 150px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 2.5em; font-weight: bold; border: 8px solid {gauge_color}; color: {gauge_color}; }}
        .severity-badges {{ display: flex; gap: 10px; flex-wrap: wrap; justify-content: center; margin: 15px 0; }}
        .badge {{ padding: 8px 16px; border-radius: 20px; font-weight: bold; font-size: 0.9em; }}
        .badge-critical {{ background: #7b2d3b; color: #ff6b6b; }}
        .badge-high {{ background: #5c3a1e; color: #ffa94d; }}
        .badge-medium {{ background: #4a3f1e; color: #ffd43b; }}
        .badge-low {{ background: #1e4a2e; color: #69db7c; }}
        .chart-container {{ position: relative; height: 250px; }}
        canvas {{ width: 100% !important; height: 100% !important; }}
        .section {{ background: #16213e; border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
        .vuln-item {{ background: #0f3460; border-radius: 8px; padding: 15px; margin-bottom: 10px; border-left: 4px solid #e74c3c; }}
        .vuln-item.high {{ border-left-color: #ffa94d; }}
        .vuln-item.medium {{ border-left-color: #ffd43b; }}
        .vuln-item.low {{ border-left-color: #69db7c; }}
        .vuln-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
        .vuln-type {{ font-weight: bold; color: #00d4ff; }}
        .vuln-severity {{ padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
        .fix-item {{ background: #0f3460; border-radius: 8px; padding: 15px; margin-bottom: 15px; }}
        .code-block {{ background: #0a0a1a; border-radius: 6px; padding: 12px; font-family: 'Courier New', monospace; font-size: 0.85em; overflow-x: auto; margin: 8px 0; white-space: pre-wrap; word-break: break-all; }}
        .code-vulnerable {{ border-left: 3px solid #e74c3c; }}
        .code-fixed {{ border-left: 3px solid #27ae60; }}
        .no-vulns {{ text-align: center; padding: 40px; color: #27ae60; font-size: 1.3em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 JorginhoAgent Dashboard</h1>
        <p class="subtitle">Analysis ID: {report.analysis_id}</p>

        <div class="grid">
            <div class="card gauge-container">
                <h2>Risk Score</h2>
                <div class="gauge">{score:.0f}</div>
                <p style="margin-top:10px;color:#888;">de 100</p>
            </div>
            <div class="card">
                <h2>Resumo</h2>
                <div class="severity-badges">
                    <span class="badge badge-critical">CRITICAL: {report.critical_count}</span>
                    <span class="badge badge-high">HIGH: {report.high_count}</span>
                    <span class="badge badge-medium">MEDIUM: {report.medium_count}</span>
                    <span class="badge badge-low">LOW: {report.low_count}</span>
                </div>
                <p style="text-align:center;margin-top:10px;">Total: {report.total_vulnerabilities} vulnerabilidades</p>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Por Severidade</h2>
                <div class="chart-container"><canvas id="severityChart"></canvas></div>
            </div>
            <div class="card">
                <h2>Por Tipo</h2>
                <div class="chart-container"><canvas id="typeChart"></canvas></div>
            </div>
        </div>

        {red_team_html}

        <div class="section">
            <h2>🔎 Vulnerabilidades</h2>
            <div id="vulns-container"></div>
        </div>

        <div class="section">
            <h2>🔧 Correções Sugeridas</h2>
            <div id="fixes-container"></div>
        </div>

        <div class="section">
            <h2>📋 Recomendações</h2>
            <ul style="padding-left:20px;">
                {"".join(f'<li style="margin-bottom:6px;">{_escape_html(r)}</li>' for r in report.recommendations)}
            </ul>
        </div>
    </div>

    <script>
    const severityData = {severity_data};
    const typeData = {type_data};
    const vulns = {vulns_json};
    const fixes = {fixes_json};

    // ── Bar Chart (Severity) ──
    function drawBarChart(canvasId, data) {{
        const canvas = document.getElementById(canvasId);
        const ctx = canvas.getContext('2d');
        canvas.width = canvas.parentElement.clientWidth;
        canvas.height = 240;
        const colors = {{'CRITICAL':'#ff6b6b','HIGH':'#ffa94d','MEDIUM':'#ffd43b','LOW':'#69db7c'}};
        const labels = Object.keys(data);
        const values = Object.values(data);
        const maxVal = Math.max(...values, 1);
        const barW = canvas.width / (labels.length * 2);
        const gap = barW;
        ctx.clearRect(0,0,canvas.width,canvas.height);
        labels.forEach((label, i) => {{
            const x = gap + i * (barW + gap);
            const h = (values[i] / maxVal) * (canvas.height - 50);
            const y = canvas.height - h - 30;
            ctx.fillStyle = colors[label] || '#00d4ff';
            ctx.fillRect(x, y, barW, h);
            ctx.fillStyle = '#ccc';
            ctx.font = '12px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(label, x + barW/2, canvas.height - 10);
            ctx.fillText(values[i], x + barW/2, y - 5);
        }});
    }}

    // ── Pie Chart (Type) ──
    function drawPieChart(canvasId, data) {{
        const canvas = document.getElementById(canvasId);
        const ctx = canvas.getContext('2d');
        canvas.width = canvas.parentElement.clientWidth;
        canvas.height = 240;
        const entries = Object.entries(data);
        if (entries.length === 0) {{ ctx.fillStyle='#888'; ctx.fillText('Sem dados',canvas.width/2,canvas.height/2); return; }}
        const total = entries.reduce((s,[,v])=>s+v,0);
        const colors = ['#ff6b6b','#ffa94d','#ffd43b','#69db7c','#00d4ff','#a29bfe','#fd79a8','#55efc4'];
        const cx = canvas.width * 0.35, cy = canvas.height / 2, r = Math.min(cx,cy) - 20;
        let angle = -Math.PI/2;
        entries.forEach(([label, val], i) => {{
            const slice = (val/total) * Math.PI * 2;
            ctx.beginPath();
            ctx.moveTo(cx,cy);
            ctx.arc(cx,cy,r,angle,angle+slice);
            ctx.fillStyle = colors[i % colors.length];
            ctx.fill();
            // Legend
            const ly = 20 + i * 18;
            ctx.fillRect(canvas.width*0.7, ly, 12, 12);
            ctx.fillStyle = '#ccc';
            ctx.font = '11px sans-serif';
            ctx.textAlign = 'left';
            ctx.fillText(label + ' ('+val+')', canvas.width*0.7 + 18, ly+10);
            angle += slice;
        }});
    }}

    // ── Render Vulns ──
    function renderVulns() {{
        const container = document.getElementById('vulns-container');
        if (vulns.length === 0) {{ container.innerHTML = '<div class="no-vulns">✅ Nenhuma vulnerabilidade encontrada</div>'; return; }}
        container.innerHTML = vulns.map(v => `
            <div class="vuln-item ${{v.severity.toLowerCase()}}">
                <div class="vuln-header">
                    <span class="vuln-type">${{v.type}}</span>
                    <span class="vuln-severity">${{v.severity}}</span>
                </div>
                <p>${{v.description}}</p>
                <p style="color:#888;font-size:0.85em;margin-top:5px;">
                    📄 ${{v.file_path}} | Linha ${{v.line_number}} | CWE: ${{v.cwe_id}} | OWASP: ${{v.owasp_category}}
                </p>
                ${{v.code_snippet ? '<div class="code-block code-vulnerable">'+escapeHtml(v.code_snippet)+'</div>' : ''}}
            </div>
        `).join('');
    }}

    // ── Render Fixes ──
    function renderFixes() {{
        const container = document.getElementById('fixes-container');
        if (fixes.length === 0) {{ container.innerHTML = '<p style="color:#888;">Nenhuma correção sugerida.</p>'; return; }}
        container.innerHTML = fixes.map((f, i) => `
            <div class="fix-item">
                <h3 style="color:#00d4ff;margin-bottom:8px;">${{i+1}}. ${{f.vulnerability_type}} (${{f.severity_from}} → ${{f.severity_to}})</h3>
                <p style="margin-bottom:10px;">${{f.explanation}}</p>
                ${{f.original_code ? '<p style="color:#e74c3c;">❌ Código vulnerável:</p><div class="code-block code-vulnerable">'+escapeHtml(f.original_code)+'</div>' : ''}}
                ${{f.fixed_code ? '<p style="color:#27ae60;">✅ Correção:</p><div class="code-block code-fixed">'+escapeHtml(f.fixed_code)+'</div>' : ''}}
            </div>
        `).join('');
    }}

    function escapeHtml(text) {{
        return text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }}

    // Init
    drawBarChart('severityChart', severityData);
    drawPieChart('typeChart', typeData);
    renderVulns();
    renderFixes();
    </script>
</body>
</html>"""
    return html


def _escape_html(text: str) -> str:
    """Escapa caracteres HTML."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def save_dashboard(report: SecurityReport, output_path: str = "dashboard.html") -> str:
    """Gera e salva o dashboard HTML estático."""
    html = generate_dashboard_html(report)
    Path(output_path).write_text(html, encoding="utf-8")
    print(f"\n  ✓ Dashboard HTML salvo em: {output_path}")
    print(f"    Abra no navegador para visualizar.")
    return output_path
