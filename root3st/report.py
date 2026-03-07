"""Report generation for Root3st scan results.

Supports JSON and HTML output formats.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Template

# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def save_json(results: dict[str, Any], output_dir: str) -> Path:
    """Write results to a timestamped JSON file."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    target = results.get("target", "unknown").replace("/", "_").replace("@", "_at_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filepath = out / f"root3st_{target}_{ts}.json"

    with open(filepath, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    return filepath


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Root3st Report &mdash; {{ target }}</title>
<style>
  :root {
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #c9d1d9; --accent: #58a6ff; --green: #3fb950;
    --red: #f85149; --yellow: #d29922; --mono: 'Fira Code', 'Courier New', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem;
  }
  h1 { color: var(--accent); margin-bottom: .5rem; font-size: 1.8rem; }
  h2 {
    color: var(--accent); margin: 1.5rem 0 .75rem; font-size: 1.3rem;
    border-bottom: 1px solid var(--border); padding-bottom: .3rem;
  }
  h3 { color: var(--green); margin: 1rem 0 .5rem; font-size: 1.1rem; }
  .meta { color: #8b949e; font-size: .9rem; margin-bottom: 1.5rem; }
  .card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1rem;
  }
  table { width: 100%; border-collapse: collapse; margin: .5rem 0; }
  th, td {
    text-align: left; padding: .4rem .6rem;
    border-bottom: 1px solid var(--border); font-size: .9rem;
  }
  th { color: var(--accent); font-weight: 600; }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .8rem; font-weight: 600;
  }
  .badge-found { background: #238636; color: #fff; }
  .badge-notfound { background: #30363d; color: #8b949e; }
  .badge-open { background: #238636; color: #fff; }
  pre {
    background: #0d1117; border: 1px solid var(--border); border-radius: 6px;
    padding: .75rem; overflow-x: auto; font-family: var(--mono); font-size: .85rem;
    color: var(--text); white-space: pre-wrap; word-break: break-all;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: .75rem;
  }
</style>
</head>
<body>
<h1>Root3st OSINT Report</h1>
<p class="meta">Target: <strong>{{ target }}</strong>
| Type: <strong>{{ scan_type }}</strong>
| Generated: {{ timestamp }}</p>

<div class="card">
<h2>Raw Data</h2>
<pre>{{ raw_json }}</pre>
</div>

</body>
</html>
"""


def save_html(results: dict[str, Any], output_dir: str) -> Path:
    """Render results into a styled HTML report."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    target = results.get("target", "unknown").replace("/", "_").replace("@", "_at_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filepath = out / f"root3st_{target}_{ts}.html"

    template = Template(HTML_TEMPLATE)
    html = template.render(
        target=results.get("target", "unknown"),
        scan_type=results.get("type", "unknown"),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        raw_json=json.dumps(results, indent=2, default=str),
    )

    filepath.write_text(html)
    return filepath
