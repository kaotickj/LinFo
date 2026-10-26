"""Human-readable HTML, structured JSON and CSV outputs. Files may include hostnames/IPs."""
from __future__ import annotations
import csv
from dataclasses import fields
from html import escape
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from .models import AuditReport, Finding
from .probe import clean_text


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
    state = "Stopped — partial assessment" if report.cancelled else ("Completed with visibility limits" if report.incomplete else "Completed")
    limits = '<h2>Collection limits</h2><pre>' + escape("\n".join(report.probe_errors)) + '</pre>' if report.probe_errors else ''
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LinFo Audit Report</title>'
            '<style>body{max-width:1100px;margin:auto;padding:32px;font:15px system-ui;background:#10171c;color:#e1e7e9}'
            'h1{color:#93ecaf}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #374249;padding:8px;text-align:left;vertical-align:top}'
            'pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1c262c;padding:10px;border-radius:6px;font-size:12px}'
            '.chip{display:inline-block;margin:4px;padding:8px;border-radius:6px;background:#24332f}.finding{padding:12px 16px;margin:10px 0;background:#1c262c;border-left:3px solid #74bc96}'
            'small{color:#b4c4d0}</style></head><body>'
            f'<h1>LinFo Hardening Assessment</h1><p>UTC: {escape(report.created_utc)} | Profile: {escape(report.profile)}</p>'
            f'<p><b>{escape(state)}</b> · LinFo {escape(report.version)}</p><div>{stats}</div>{limits}<h2>Inventory</h2><table>{inventory}</table><h2>Findings</h2>{rows}'
            '<footer><p>Assessment reflects observable host configuration, not proof of security or standards compliance.</p></footer></body></html>')


def render_text(report: AuditReport) -> str:
    state = "Stopped — partial assessment" if report.cancelled else ("Completed with visibility limits" if report.incomplete else "Completed")
    lines = [f"LinFo {report.version} | Kaotick Jay", f"UTC: {report.created_utc}",
             f"Profile: {report.profile}", f"Status: {state}", "",
             "Counts: " + ", ".join(f"{key}: {value}" for key, value in report.counts().items()),
             "", "INVENTORY", json.dumps(report.inventory, ensure_ascii=False, indent=2), ""]
    if report.probe_errors:
        lines += ["COLLECTION LIMITS", *report.probe_errors, ""]
    for finding in report.findings:
        lines += ["=" * 76, f"[{finding.status} / {finding.severity}] {finding.title}",
                  f"{finding.id} | {finding.category}", finding.summary]
        if finding.evidence:
            lines += ["", "Evidence:", finding.evidence]
        if finding.recommendation:
            lines += ["", "Recommendation:", finding.recommendation]
        lines.append("")
    return "\n".join(lines) + "\n"


def _csv_value(value):
    # Collected filenames/configuration may otherwise become spreadsheet formulas.
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def export_report(report: AuditReport, dest: str) -> Path:
    path = Path(dest).expanduser().absolute()
    suffix = path.suffix.lower()
    if suffix == ".json":
        content = json.dumps(report.as_dict(), indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    elif suffix in (".html", ".htm"):
        content = render_html(report)
    elif suffix == ".txt":
        content = render_text(report)
    elif suffix == ".csv":
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=[f.name for f in fields(Finding)])
        writer.writeheader()
        writer.writerows({key: _csv_value(value) for key, value in f.as_dict().items()} for f in report.findings)
        content = stream.getvalue()
    else:
        raise ValueError("Choose a .json, .html, .csv, or .txt file")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("Choose a regular filename, not a symbolic link or device")
    fd, temporary = tempfile.mkstemp(prefix=".linfo-report-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def load_report(filename: str | Path) -> AuditReport:
    """Read bounded JSON data; reports never execute code or authorize changes."""
    fd = os.open(filename, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Select a regular JSON report file")
        raw = stream.read(20_000_001)
    if len(raw) > 20_000_000:
        raise ValueError("Report exceeds 20 MB")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Report is not valid UTF-8 JSON") from exc
    if not isinstance(data, dict) or data.get("app") != "LinFo":
        raise ValueError("This is not a LinFo report")
    if data.get("profile") not in ("workstation", "server") or not isinstance(data.get("inventory"), dict):
        raise ValueError("Invalid report profile or inventory")
    rows = data.get("findings")
    if not isinstance(rows, list) or len(rows) > 10000:
        raise ValueError("Invalid findings or more than 10,000 findings")
    finding_fields = {f.name for f in fields(Finding)}
    findings = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid finding record")
        values = {key: value for key, value in row.items() if key in finding_fields}
        if any(not isinstance(value, str) and not (key == "action_id" and value is None) for key, value in values.items()):
            raise ValueError("Finding fields must contain text")
        values = {key: clean_text(value) if isinstance(value, str) else value for key, value in values.items()}
        if values.get("status") not in ("PASS", "WARN", "FAIL", "INFO", "UNKNOWN"):
            raise ValueError("Unknown finding status")
        if values.get("severity") not in ("critical", "high", "medium", "low", "info"):
            raise ValueError("Unknown finding severity")
        try:
            findings.append(Finding(**values))
        except TypeError as exc:
            raise ValueError("Finding is missing required fields") from exc
    metadata = {}
    for key in ("created_utc", "completed_utc", "version"):
        if key in data:
            if not isinstance(data[key], str):
                raise ValueError(f"Invalid {key}")
            metadata[key] = clean_text(data[key])
    for key in ("cancelled", "incomplete"):
        if key in data:
            if not isinstance(data[key], bool):
                raise ValueError(f"Invalid {key}")
            metadata[key] = data[key]
    errors = data.get("probe_errors", [])
    if not isinstance(errors, list) or any(not isinstance(value, str) for value in errors):
        raise ValueError("Invalid collection notes")
    metadata["incomplete"] = bool(metadata.get("incomplete") or metadata.get("cancelled") or errors
                                  or any(f.status == "UNKNOWN" for f in findings))
    return AuditReport(data["profile"], data["inventory"], findings,
                       probe_errors=[clean_text(value) for value in errors], **metadata)


def compare_reports(previous: dict, current: AuditReport) -> dict:
    """Compare stable finding IDs across scans. No naïve severity-score claims."""
    if not isinstance(previous, dict):
        raise ValueError("Baseline must be a JSON object")
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
        changes.append({"id": ident, "change": "not_observed" if current.cancelled or current.incomplete else "removed", "was": prior[ident]["status"],
                        "now": None, "title": prior[ident].get("title", ident)})
    return {"previous_utc": previous.get("created_utc", "unknown"),
            "current_utc": current.created_utc, "changes": sorted(changes, key=lambda x: x["id"]),
            "count": len(changes), "partial_current": current.cancelled or current.incomplete,
            "partial_previous": bool(previous.get("cancelled") or previous.get("incomplete")),
            "note": "A missing control in a partial assessment was not observed; it does not establish remediation."}
