from __future__ import annotations

from html import escape
from pathlib import Path


def _alert_rows(report: dict) -> str:
    rows = []
    for alert in report.get("alerts", []):
        severity = escape(str(alert["severity"]).lower())
        rows.append(
            "<tr>"
            f"<td><span class='badge {severity}'>{severity.upper()}</span></td>"
            f"<td>{escape(str(alert['rule_id']))}</td>"
            f"<td>{escape(str(alert['src_ip']))}</td>"
            f"<td>{escape(str(alert['dst_ip']))}</td>"
            f"<td>{escape(str(alert['description']))}</td>"
            f"<td>{escape(str(alert.get('timestamp_iso', '')))}</td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan='6' class='empty'>No alerts detected</td></tr>"


def build_dashboard(report: dict) -> str:
    severity = report.get("alerts_by_severity", {})
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetGuard IDS Report</title>
  <style>
    :root {{ color-scheme: dark; --panel:#151b2b; --muted:#91a0b8; --line:#27314a; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:#0b1020; color:#eef3ff; font:14px/1.5 Inter,Segoe UI,sans-serif; }}
    main {{ max-width:1180px; margin:0 auto; padding:38px 22px; }}
    header {{ display:flex; justify-content:space-between; gap:20px; align-items:end; margin-bottom:26px; }}
    h1 {{ margin:0; font-size:30px; }} h2 {{ margin:0 0 14px; }}
    .subtitle,.generated {{ color:var(--muted); }}
    .cards {{ display:grid; grid-template-columns:repeat(5,1fr); gap:14px; margin-bottom:22px; }}
    .card,.table-wrap {{ background:var(--panel); border:1px solid var(--line); border-radius:14px; }}
    .card {{ padding:18px; }} .card strong {{ display:block; font-size:28px; margin-top:4px; }}
    .label {{ color:var(--muted); text-transform:uppercase; font-size:11px; letter-spacing:.08em; }}
    .table-wrap {{ padding:20px; overflow:auto; }} table {{ width:100%; border-collapse:collapse; min-width:900px; }}
    th,td {{ text-align:left; padding:13px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
    th {{ color:var(--muted); font-size:11px; text-transform:uppercase; }}
    .badge {{ display:inline-block; border-radius:999px; padding:3px 9px; font-size:11px; font-weight:700; }}
    .critical {{ background:#70283a; color:#ffdce4; }} .high {{ background:#6b3b20; color:#ffe0c2; }}
    .medium {{ background:#604f1b; color:#fff0a8; }} .low {{ background:#174a3b; color:#b9ffe5; }}
    .empty {{ color:var(--muted); text-align:center; padding:32px; }}
    footer {{ color:var(--muted); margin-top:16px; font-size:12px; }}
    @media(max-width:800px) {{ .cards {{ grid-template-columns:repeat(2,1fr); }} header {{ display:block; }} }}
  </style>
</head>
<body><main>
  <header><div><h1>NetGuard IDS</h1><div class="subtitle">Explainable network security report</div></div>
  <div class="generated">Generated {escape(str(report.get('generated_at', '')))}</div></header>
  <section class="cards">
    <div class="card"><span class="label">Events</span><strong>{int(report.get('processed_events', 0))}</strong></div>
    <div class="card"><span class="label">All alerts</span><strong>{int(report.get('alert_count', 0))}</strong></div>
    <div class="card"><span class="label">Critical</span><strong>{int(severity.get('critical', 0))}</strong></div>
    <div class="card"><span class="label">High</span><strong>{int(severity.get('high', 0))}</strong></div>
    <div class="card"><span class="label">Medium</span><strong>{int(severity.get('medium', 0))}</strong></div>
  </section>
  <section class="table-wrap"><h2>Security alerts</h2><table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Source</th><th>Destination</th><th>Explanation</th><th>UTC time</th></tr></thead>
    <tbody>{_alert_rows(report)}</tbody>
  </table></section>
  <footer>Defensive research prototype — validate alerts before operational use.</footer>
</main></body></html>"""


def save_dashboard(report: dict, path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(build_dashboard(report), encoding="utf-8")
