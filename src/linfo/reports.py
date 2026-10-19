"""Human-readable HTML, structured JSON and CSV outputs. Files may include hostnames/IPs."""
from __future__ import annotations
import csv
from html import escape
import json
from pathlib import Path
from .models import AuditReport


def render_html(report: AuditReport) -> str:
    stats = " ".join(f'<span class="chip">{escape(s)}: {n}</span>' for s, n in report.counts().items())
    inventory = "".join(f"<tr><th>{escape(str(k))}</th><td><pre>{escape(json.dumps(v, ensure_ascii=False, indent=2))}</pre></td></tr>"
                        for k, v in report.inventory.items())
    rows = "\n".join(
        '<section class="finding"><h3>' + escape(f.title) + '</h3>'
        + f'<small>{escape(f.category)} | {escape(f.status)} | {escape(f.severity)}</small>'
        + '<p>' + escape(f.summary) + '</p>'
        + ('<pre>' + escape(f.evidence) + '</pre>' if f.evidence else '')
        + ('<p><b>Recommendation:</b> ' + escape(f.recommendation) + '</p>' if f.recommendation else '')
        + '</section>' for f in report.findings)
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>LinFo Audit Report</title>'
            '<style>body{max-width:1100px;margin:auto;padding:32px;font:15px system-ui;background:#10171c;color:#e1e7e9}'
            'h1{color:#93ecaf}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #374249;padding:8px;text-align:left;vertical-align:top}'
            'pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1c262c;padding:10px;border-radius:6px;font-size:12px}'
            '.chip{display:inline-block;margin:4px;padding:8px;border-radius:6px;background:#24332f}.finding{padding:12px 16px;margin:10px 0;background:#1c262c;border-left:3px solid #74bc96}'
            'small{color:#b4c4d0}</style></head><body>'
            f'<h1>LinFo Hardening Assessment</h1><p>UTC: {escape(report.created_utc)} | Profile: {escape(report.profile)}</p>'
            f'<div>{stats}</div><h2>Inventory</h2><table>{inventory}</table><h2>Findings</h2>{rows}'
            '<footer><p>Assessment reflects observable host configuration, not proof of security or standards compliance.</p></footer></body></html>')


def export_report(report: AuditReport, dest: str) -> Path:
    path = Path(dest).expanduser()
    suffix = path.suffix.lower()
    if suffix == ".json":
        content = json.dumps(report.as_dict(), indent=2, ensure_ascii=False)
        path.write_text(content + "\n", encoding="utf-8")
    elif suffix in (".html", ".htm"):
        path.write_text(render_html(report), encoding="utf-8")
    elif suffix == ".csv":
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(report.findings[0].as_dict()) if report.findings else ["id", "title"])
            writer.writeheader()
            writer.writerows(f.as_dict() for f in report.findings)
    else:
        raise ValueError("Choose a .json, .html, or .csv file")
    return path


def compare_reports(previous: dict, current: AuditReport) -> dict:
    """Compare stable finding IDs across scans. No naïve severity-score claims."""
    prior_rows = previous.get("findings", [])
    if not isinstance(prior_rows, list):
        raise ValueError("Baseline JSON does not contain findings")
    prior = {row["id"]: row for row in prior_rows if isinstance(row, dict) and
             isinstance(row.get("id"), str) and isinstance(row.get("status"), str)}
    latest = {f.id: f for f in current.findings}
    changes = []
    for ident, finding in latest.items():
        if ident not in prior:
            changes.append({"id": ident, "change": "new", "was": None, "now": finding.status,
                            "title": finding.title})
        elif prior[ident]["status"] != finding.status:
            changes.append({"id": ident, "change": "status_changed", "was": prior[ident]["status"],
                            "now": finding.status, "title": finding.title})
    for ident in prior.keys() - latest.keys():
        changes.append({"id": ident, "change": "removed", "was": prior[ident]["status"],
                        "now": None, "title": prior[ident].get("title", ident)})
    return {"previous_utc": previous.get("created_utc", "unknown"),
            "current_utc": current.created_utc, "changes": sorted(changes, key=lambda x: x["id"]),
            "count": len(changes)}
