import sqlite3
import json
from datetime import datetime
from core.config import DB_PATH

def get_run_summary(run_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
    run = dict(cursor.fetchone())

    cursor.execute("SELECT * FROM results WHERE run_id = ?", (run_id,))
    results = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return run, results

def categorize_results(results):
    by_type = {}
    by_severity = {"critical": [], "high": [], "medium": [], "low": []}

    for result in results:
        attack_type = result["attack_type"]
        if attack_type not in by_type:
            by_type[attack_type] = {"total": 0, "succeeded": 0, "results": []}

        by_type[attack_type]["total"] += 1
        if result["success"]:
            by_type[attack_type]["succeeded"] += 1

        by_severity[result["severity"]].append(result)
        by_type[attack_type]["results"].append(result)

    return by_type, by_severity

def severity_color(severity):
    colors = {
        "critical": "#ff4444",
        "high":     "#ff8800",
        "medium":   "#ffcc00",
        "low":      "#44bb44"
    }
    return colors.get(severity, "#888888")

def severity_badge(severity):
    color = severity_color(severity)
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;">{severity.upper()}</span>'

def generate_html_report(run_id):
    run, results = get_run_summary(run_id)
    by_type, by_severity = categorize_results(results)

    total = run["total_tests"]
    succeeded = run["passed"]
    failed = run["failed"]
    critical = len(by_severity["critical"])
    high = len(by_severity["high"])
    medium = len(by_severity["medium"])
    low = len(by_severity["low"])

    # Detect silent vs detected for indirect injection
    indirect_results = by_type.get("indirect_injection", {}).get("results", [])
    silent_count = sum(1 for r in indirect_results if not r["success"] and "detected=False" in (r["notes"] or ""))
    detected_count = sum(1 for r in indirect_results if "detected=True" in (r["notes"] or ""))

    timestamp = run["timestamp"]
    model = run["model"]

    # Build findings HTML
    findings_html = ""
    for severity in ["critical", "high", "medium", "low"]:
        for result in by_severity[severity]:
            if not result["success"] and severity == "low":
                continue  # Skip low severity failures to keep report clean
            notes = result.get("notes", "")
            detected_tag = ""
            if "detected=True" in (notes or ""):
                detected_tag = ' <span style="background:#4488ff;color:white;padding:2px 6px;border-radius:4px;font-size:11px;">DETECTED</span>'
            elif "detected=False" in (notes or ""):
                detected_tag = ' <span style="background:#888;color:white;padding:2px 6px;border-radius:4px;font-size:11px;">SILENT</span>'

            clean_notes = notes.split(" | detected=")[0] if notes else ""

            findings_html += f"""
            <div style="border:1px solid #ddd;border-radius:8px;padding:16px;margin-bottom:16px;">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                    {severity_badge(severity)}
                    {detected_tag}
                    <strong>{clean_notes}</strong>
                    <span style="color:#888;font-size:12px;margin-left:auto;">{result['attack_type'].replace('_', ' ').title()}</span>
                </div>
                <div style="margin-bottom:8px;">
                    <div style="font-size:12px;color:#888;margin-bottom:4px;">PROMPT</div>
                    <div style="background:#f5f5f5;padding:8px;border-radius:4px;font-family:monospace;font-size:12px;white-space:pre-wrap;">{result['prompt'][:400]}{'...' if len(result['prompt']) > 400 else ''}</div>
                </div>
                <div>
                    <div style="font-size:12px;color:#888;margin-bottom:4px;">RESPONSE</div>
                    <div style="background:#f5f5f5;padding:8px;border-radius:4px;font-family:monospace;font-size:12px;white-space:pre-wrap;">{result['response'][:400]}{'...' if len(result['response']) > 400 else ''}</div>
                </div>
            </div>
            """

    # Build attack type summary rows
    type_rows = ""
    for attack_type, data in by_type.items():
        rate = (data['succeeded'] / data['total'] * 100) if data['total'] > 0 else 0
        type_rows += f"""
        <tr>
            <td style="padding:8px 12px;">{attack_type.replace('_', ' ').title()}</td>
            <td style="padding:8px 12px;">{data['total']}</td>
            <td style="padding:8px 12px;">{data['succeeded']}</td>
            <td style="padding:8px 12px;">{data['total'] - data['succeeded']}</td>
            <td style="padding:8px 12px;">{rate:.0f}%</td>
        </tr>
        """

    # Indirect injection insight row
    indirect_insight = ""
    if indirect_results:
        indirect_insight = f"""
        <div style="background:#fff8e1;border:1px solid #ffcc00;border-radius:8px;padding:16px;margin-bottom:24px;">
            <strong>Indirect Injection Detection Analysis</strong>
            <p style="margin:8px 0 0 0;color:#555;">
                Of {len(indirect_results)} indirect injection attempts,
                <strong>{detected_count} were explicitly detected</strong> by the model and
                <strong>{silent_count} failed silently</strong> without detection.
                Silent failures represent higher residual risk as subtle variations
                in injection technique may succeed where these did not.
            </p>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLM Red Team Report — Run {run_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f8f9fa; color: #333; }}
        .container {{ max-width: 960px; margin: 0 auto; padding: 32px 16px; }}
        h1 {{ font-size: 24px; margin-bottom: 4px; }}
        h2 {{ font-size: 18px; margin: 32px 0 16px 0; border-bottom: 2px solid #eee; padding-bottom: 8px; }}
        .meta {{ color: #888; font-size: 14px; margin-bottom: 32px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 32px; }}
        .card {{ background: white; border-radius: 8px; padding: 16px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .card .number {{ font-size: 36px; font-weight: bold; }}
        .card .label {{ font-size: 12px; color: #888; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th {{ background: #f5f5f5; padding: 10px 12px; text-align: left; font-size: 13px; color: #555; }}
        td {{ border-top: 1px solid #eee; font-size: 14px; }}
    </style>
</head>
<body>
<div class="container">
    <h1>LLM Red Team Report</h1>
    <div class="meta">
        Run ID: {run_id} &nbsp;|&nbsp;
        Model: {model} &nbsp;|&nbsp;
        Date: {timestamp[:19].replace('T', ' ')} UTC
    </div>

    <h2>Executive Summary</h2>
    <div class="summary-grid">
        <div class="card"><div class="number">{total}</div><div class="label">Total Tests</div></div>
        <div class="card"><div class="number" style="color:#ff4444">{succeeded}</div><div class="label">Succeeded</div></div>
        <div class="card"><div class="number" style="color:#44bb44">{failed}</div><div class="label">Resisted</div></div>
        <div class="card"><div class="number" style="color:#ff4444">{critical}</div><div class="label">Critical</div></div>
        <div class="card"><div class="number" style="color:#ff8800">{high}</div><div class="label">High</div></div>
        <div class="card"><div class="number" style="color:#ffcc00">{medium}</div><div class="label">Medium</div></div>
    </div>

    <h2>Results by Attack Type</h2>
    <table style="margin-bottom:32px;">
        <thead>
            <tr>
                <th>Attack Type</th>
                <th>Total</th>
                <th>Succeeded</th>
                <th>Resisted</th>
                <th>Success Rate</th>
            </tr>
        </thead>
        <tbody>
            {type_rows}
        </tbody>
    </table>

    {indirect_insight}

    <h2>Findings</h2>
    <p style="color:#888;font-size:13px;margin-bottom:16px;">Showing successful attacks and notable findings only. Low severity failures omitted.</p>
    {findings_html if findings_html.strip() else '<p style="color:#888;">No successful attacks recorded in this run.</p>'}

</div>
</body>
</html>"""

    # Save report
    filename = f"reports/redteam_run{run_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w") as f:
        f.write(html)

    print(f"\n[*] Report saved to {filename}")
    return filename