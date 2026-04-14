#!/usr/bin/env python3
"""
ASPM Pipeline Normalizer
========================
Reads JSON output from Semgrep, Gitleaks, and Checkov.
Normalises findings into a common schema.
Detects toxic combinations (e.g. exposed secret + public infrastructure).
Outputs a prioritised findings.json and a standalone HTML report.

Usage:
    python pipeline/normalize.py \\
        --semgrep  scan-results/semgrep.json \\
        --gitleaks scan-results/gitleaks.json \\
        --checkov  scan-results/checkov.json \\
        --output   scan-results/findings.json \\
        --html     scan-results/report.html
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Severity ordering (lower index = more severe)
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEVERITY_COLOUR = {
    "CRITICAL": "#ff4d4d",
    "HIGH":     "#ff8c00",
    "MEDIUM":   "#ffd700",
    "LOW":      "#4db8ff",
    "INFO":     "#aaaaaa",
}


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _finding_id(source: str, raw: object) -> str:
    blob = json.dumps(raw, sort_keys=True).encode()
    return f"{source}-{hashlib.sha1(blob).hexdigest()[:8]}"


def parse_semgrep(filepath: str) -> list[dict]:
    """
    Semgrep --json output:
      { "results": [ { "check_id", "path", "start": {"line"}, "extra": {"message", "severity"} } ] }
    """
    findings = []
    data = _load_json(filepath, "Semgrep")
    if data is None:
        return findings

    sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW", "CRITICAL": "CRITICAL"}

    for r in data.get("results", []):
        extra    = r.get("extra", {})
        meta     = extra.get("metadata", {})
        rule_id  = r.get("check_id", "unknown")

        # Semgrep exposes severity in extra.severity or metadata.severity
        raw_sev  = (meta.get("severity") or extra.get("severity") or "WARNING").upper()
        severity = sev_map.get(raw_sev, "MEDIUM")

        # Promote obvious secrets to CRITICAL
        if any(kw in rule_id.lower() for kw in ("secret", "key", "token", "password", "credential", "api-key")):
            severity = "CRITICAL"
            category = "SECRET"
        elif any(kw in rule_id.lower() for kw in ("injection", "sqli", "xss", "ssrf", "ssti", "traversal")):
            category = "INJECTION"
        else:
            category = "CODE_VULN"

        findings.append({
            "id":          _finding_id("semgrep", r),
            "source":      "semgrep",
            "category":    category,
            "severity":    severity,
            "title":       rule_id,
            "description": extra.get("message", ""),
            "file":        r.get("path", ""),
            "line":        r.get("start", {}).get("line"),
            "rule_id":     rule_id,
            "raw":         r,
        })

    return findings


def parse_gitleaks(filepath: str) -> list[dict]:
    """
    Gitleaks JSON output is a list:
      [ { "RuleID", "File", "StartLine", "Match", "Description" }, … ]
    """
    findings = []
    data = _load_json(filepath, "Gitleaks")
    if data is None:
        return findings

    if isinstance(data, dict):          # older gitleaks wraps in { "findings": [...] }
        data = data.get("findings", [])

    for leak in (data or []):
        rule_id = leak.get("RuleID") or leak.get("ruleID") or "unknown-secret"
        match   = leak.get("Match") or leak.get("match") or ""
        # Truncate so we never persist an actual secret value
        safe_match = (match[:40] + "…") if len(match) > 40 else match

        findings.append({
            "id":          _finding_id("gitleaks", {k: v for k, v in leak.items() if k not in ("Secret", "secret")}),
            "source":      "gitleaks",
            "category":    "SECRET",
            "severity":    "CRITICAL",
            "title":       f"Secret: {rule_id}",
            "description": leak.get("Description") or leak.get("description") or "",
            "file":        leak.get("File") or leak.get("file") or "",
            "line":        leak.get("StartLine") or leak.get("startLine") or leak.get("Line") or leak.get("line"),
            "rule_id":     rule_id,
            "match":       safe_match,
            # Never store raw secret value
            "raw":         {k: v for k, v in leak.items() if k.lower() not in ("secret",)},
        })

    return findings


def parse_checkov(filepath: str) -> list[dict]:
    """
    Checkov --output json produces either a single runner dict or a list of them:
      { "results": { "failed_checks": [ { "check_id", "check": {"name","severity"}, "resource", "file_path" } ] } }
    """
    findings = []
    data = _load_json(filepath, "Checkov")
    if data is None:
        return findings

    # Normalise to list of runner dicts
    runners = data if isinstance(data, list) else [data]

    ckv_severity: dict[str, str] = {
        "CRITICAL": "CRITICAL",
        "HIGH":     "HIGH",
        "MEDIUM":   "MEDIUM",
        "LOW":      "LOW",
        "INFO":     "INFO",
    }

    for runner in runners:
        for chk in runner.get("results", {}).get("failed_checks", []):
            chk_obj   = chk.get("check", {})
            raw_sev   = (chk.get("severity") or chk_obj.get("severity") or "MEDIUM")
            if isinstance(raw_sev, str):
                severity = ckv_severity.get(raw_sev.upper(), "MEDIUM")
            else:
                severity = "MEDIUM"

            findings.append({
                "id":          _finding_id("checkov", chk),
                "source":      "checkov",
                "category":    "MISCONFIG",
                "severity":    severity,
                "title":       chk_obj.get("name") or chk.get("check_id") or "Unknown check",
                "description": f"Resource: {chk.get('resource', 'unknown')}",
                "file":        chk.get("file_path", ""),
                "line":        (chk.get("file_line_range") or [None])[0],
                "rule_id":     chk.get("check_id", ""),
                "resource":    chk.get("resource", ""),
                "raw":         chk,
            })

    return findings


def _load_json(filepath: str, label: str) -> Optional[object]:
    if not filepath or not Path(filepath).exists():
        print(f"  [{label}] file not found: {filepath!r} — skipping", file=sys.stderr)
        return None
    try:
        with open(filepath) as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"  [{label}] JSON parse error: {exc} — skipping", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Toxic-combination detection
# ---------------------------------------------------------------------------

def detect_toxic_combinations(findings: list[dict]) -> list[dict]:
    """
    Cross-scanner correlation: find pairs / groups of findings that together
    create a risk greater than the sum of their parts.
    """
    toxic = []

    secrets    = [f for f in findings if f["category"] == "SECRET"]
    misconfigs = [f for f in findings if f["category"] == "MISCONFIG"]
    injections = [f for f in findings if f["category"] == "INJECTION"]

    public_infra = [
        f for f in misconfigs
        if any(kw in (f.get("title") or "").lower() for kw in
               ("public", "acl", "unrestricted", "0.0.0.0", "open", "all traffic"))
        or f.get("rule_id", "") in (
            "CKV_AWS_20", "CKV_AWS_57", "CKV2_AWS_6", "CKV2_AWS_65",
            "CKV_AWS_24", "CKV_AWS_25",
        )
    ]

    no_encrypt = [
        f for f in misconfigs
        if "encrypt" in (f.get("title") or "").lower()
        or f.get("rule_id", "") in ("CKV_AWS_19", "CKV_AWS_145")
    ]

    # ── Combo 1: Secret + Public infrastructure ──────────────────────────────
    if secrets and public_infra:
        toxic.append({
            "id":       "toxic-001",
            "source":   "correlator",
            "category": "TOXIC_COMBINATION",
            "severity": "CRITICAL",
            "title":    "TOXIC: Exposed Secret + Public Infrastructure",
            "description": (
                f"{len(secrets)} hardcoded secret(s) found in source code AND "
                f"{len(public_infra)} public-access misconfiguration(s) in infrastructure. "
                "An attacker who reads the public bucket gains valid AWS credentials."
            ),
            "file":  "multiple",
            "line":  None,
            "rule_id": "TOXIC-001",
            "contributing_findings": [f["id"] for f in secrets[:5] + public_infra[:5]],
            "raw":   {},
        })

    # ── Combo 2: Secret + Unencrypted storage ────────────────────────────────
    if secrets and no_encrypt:
        toxic.append({
            "id":       "toxic-002",
            "source":   "correlator",
            "category": "TOXIC_COMBINATION",
            "severity": "CRITICAL",
            "title":    "TOXIC: Exposed Secret + Unencrypted Storage",
            "description": (
                f"{len(secrets)} secret(s) committed to source AND storage is unencrypted. "
                "Credential theft + plaintext data access in a single breach scenario."
            ),
            "file":  "multiple",
            "line":  None,
            "rule_id": "TOXIC-002",
            "contributing_findings": [f["id"] for f in secrets[:5] + no_encrypt[:5]],
            "raw":   {},
        })

    # ── Combo 3: Multiple distinct secrets ───────────────────────────────────
    distinct_rules = {f["rule_id"] for f in secrets}
    if len(distinct_rules) > 1:
        toxic.append({
            "id":       "toxic-003",
            "source":   "correlator",
            "category": "TOXIC_COMBINATION",
            "severity": "HIGH",
            "title":    "TOXIC: Multiple Credential Types Exposed",
            "description": (
                f"{len(secrets)} secrets across {len(distinct_rules)} distinct rule categories "
                f"({', '.join(sorted(distinct_rules)[:4])}). "
                "Indicates a systemic credential-management failure, not an isolated slip."
            ),
            "file":  "multiple",
            "line":  None,
            "rule_id": "TOXIC-003",
            "contributing_findings": [f["id"] for f in secrets],
            "raw":   {},
        })

    # ── Combo 4: Code injection + exposed infrastructure ─────────────────────
    if injections and public_infra:
        toxic.append({
            "id":       "toxic-004",
            "source":   "correlator",
            "category": "TOXIC_COMBINATION",
            "severity": "HIGH",
            "title":    "TOXIC: Injection Vulnerability + Public Infrastructure",
            "description": (
                f"{len(injections)} injection vulnerability/ies in application code alongside "
                f"{len(public_infra)} publicly accessible infrastructure resource(s). "
                "Exploiting the injection enables lateral movement into cloud resources."
            ),
            "file":  "multiple",
            "line":  None,
            "rule_id": "TOXIC-004",
            "contributing_findings": [f["id"] for f in injections[:3] + public_infra[:3]],
            "raw":   {},
        })

    return toxic


# ---------------------------------------------------------------------------
# Sorting + summary
# ---------------------------------------------------------------------------

def prioritise(findings: list[dict]) -> list[dict]:
    source_rank = {"correlator": 0, "gitleaks": 1, "semgrep": 2, "checkov": 3}
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f["severity"], 99),
            source_rank.get(f["source"], 9),
        ),
    )


def summarise(findings: list[dict]) -> dict:
    return {
        "total":      len(findings),
        "by_severity": {sev: sum(1 for f in findings if f["severity"] == sev)
                        for sev in SEVERITY_ORDER},
        "by_source":  {src: sum(1 for f in findings if f["source"] == src)
                       for src in ("semgrep", "gitleaks", "checkov", "correlator")},
        "toxic_combinations": sum(1 for f in findings if f["category"] == "TOXIC_COMBINATION"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# HTML report generation
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ASPM Security Report</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: "Segoe UI", system-ui, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    min-height: 100vh;
  }

  header {
    background: #161b22;
    border-bottom: 1px solid #30363d;
    padding: 1.25rem 2rem;
    display: flex;
    align-items: center;
    gap: 1rem;
  }
  header h1 { font-size: 1.4rem; color: #e6edf3; }
  header .subtitle { font-size: 0.8rem; color: #8b949e; margin-top: .2rem; }
  .badge {
    display: inline-block;
    padding: .2rem .6rem;
    border-radius: 999px;
    font-size: .7rem;
    font-weight: 700;
    letter-spacing: .05em;
    text-transform: uppercase;
  }

  main { max-width: 1200px; margin: 0 auto; padding: 2rem; }

  /* ── Summary cards ──────────────────────────────────────── */
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1rem;
    text-align: center;
  }
  .card .count { font-size: 2.2rem; font-weight: 700; line-height: 1; }
  .card .label { font-size: .75rem; color: #8b949e; margin-top: .4rem; text-transform: uppercase; }

  /* ── Toxic combinations ─────────────────────────────────── */
  .section-title {
    font-size: 1rem;
    font-weight: 600;
    color: #e6edf3;
    margin-bottom: 1rem;
    padding-bottom: .5rem;
    border-bottom: 1px solid #30363d;
  }

  .toxic-list { margin-bottom: 2.5rem; }
  .toxic-card {
    background: #1a0a0a;
    border: 1px solid #ff4d4d55;
    border-left: 4px solid #ff4d4d;
    border-radius: 6px;
    padding: 1rem 1.25rem;
    margin-bottom: .75rem;
  }
  .toxic-card .tc-title { font-weight: 600; color: #ff7070; margin-bottom: .4rem; }
  .toxic-card .tc-desc  { font-size: .85rem; color: #aaaaaa; line-height: 1.5; }

  /* ── Findings table ─────────────────────────────────────── */
  .filters {
    display: flex;
    gap: .75rem;
    flex-wrap: wrap;
    margin-bottom: 1rem;
  }
  .filters select, .filters input {
    background: #161b22;
    border: 1px solid #30363d;
    color: #c9d1d9;
    border-radius: 6px;
    padding: .4rem .75rem;
    font-size: .85rem;
  }
  .filters select:focus, .filters input:focus {
    outline: none;
    border-color: #58a6ff;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: .82rem;
  }
  thead th {
    background: #161b22;
    color: #8b949e;
    text-align: left;
    padding: .6rem .75rem;
    font-weight: 600;
    border-bottom: 2px solid #30363d;
    white-space: nowrap;
    cursor: pointer;
    user-select: none;
  }
  thead th:hover { color: #e6edf3; }
  tbody tr { border-bottom: 1px solid #21262d; transition: background .1s; }
  tbody tr:hover { background: #161b22; }
  tbody td { padding: .55rem .75rem; vertical-align: top; }

  .sev-badge { border-radius: 4px; padding: .15rem .5rem; font-size: .7rem; font-weight: 700; }
  .source-tag {
    background: #21262d;
    border-radius: 4px;
    padding: .15rem .5rem;
    font-size: .7rem;
    color: #8b949e;
  }
  .rule-id { font-family: monospace; font-size: .75rem; color: #58a6ff; }
  .file-loc { font-family: monospace; font-size: .75rem; color: #8b949e; }
  .desc-cell { max-width: 380px; }
  .desc-text { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 360px; }

  .no-results {
    text-align: center;
    color: #8b949e;
    padding: 3rem;
    font-size: .9rem;
  }

  footer {
    text-align: center;
    color: #8b949e;
    font-size: .75rem;
    padding: 2rem;
    border-top: 1px solid #21262d;
    margin-top: 3rem;
  }
</style>
</head>
<body>
<header>
  <div>
    <h1>&#128737; ASPM Security Dashboard</h1>
    <div class="subtitle" id="generated-at"></div>
  </div>
</header>

<main>
  <!-- Summary cards -->
  <div class="cards" id="summary-cards"></div>

  <!-- Toxic combinations -->
  <div class="toxic-list" id="toxic-section" style="display:none">
    <div class="section-title">&#9888;&#65039; Toxic Combinations</div>
    <div id="toxic-list"></div>
  </div>

  <!-- Findings table -->
  <div class="section-title">All Findings</div>
  <div class="filters">
    <select id="filter-sev">
      <option value="">All severities</option>
      <option>CRITICAL</option><option>HIGH</option>
      <option>MEDIUM</option><option>LOW</option><option>INFO</option>
    </select>
    <select id="filter-src">
      <option value="">All sources</option>
      <option>semgrep</option><option>gitleaks</option>
      <option>checkov</option><option>correlator</option>
    </select>
    <select id="filter-cat">
      <option value="">All categories</option>
      <option>SECRET</option><option>INJECTION</option>
      <option>CODE_VULN</option><option>MISCONFIG</option>
      <option>TOXIC_COMBINATION</option>
    </select>
    <input id="filter-text" type="search" placeholder="Filter by title or file…" style="flex:1;min-width:180px">
  </div>

  <table id="findings-table">
    <thead>
      <tr>
        <th data-col="severity">Severity &#8597;</th>
        <th data-col="source">Source</th>
        <th data-col="category">Category</th>
        <th>Title / Rule</th>
        <th>Description</th>
        <th data-col="file">Location</th>
      </tr>
    </thead>
    <tbody id="findings-body"></tbody>
  </table>
  <div class="no-results" id="no-results" style="display:none">No findings match the current filters.</div>
</main>

<footer>Generated by ASPM Pipeline Normalizer &bull; <span id="footer-date"></span></footer>

<script>
// ── Data injected by normalize.py ──────────────────────────────────────────
const REPORT = $REPORT_JSON;
// ───────────────────────────────────────────────────────────────────────────

const SEV_COLOUR = {
  CRITICAL: "#ff4d4d", HIGH: "#ff8c00", MEDIUM: "#ffd700", LOW: "#4db8ff", INFO: "#888"
};
const SEV_ORDER  = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};

function esc(s) {
  return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function sevBadge(sev) {
  const c = SEV_COLOUR[sev] || "#888";
  return `<span class="sev-badge" style="background:${c}22;color:${c};border:1px solid ${c}66">${esc(sev)}</span>`;
}

// ── Summary cards ───────────────────────────────────────────────────────────
function renderSummary() {
  const s = REPORT.summary;
  const el = document.getElementById("summary-cards");
  const cards = [
    { label: "Total",    count: s.total,               colour: "#e6edf3" },
    { label: "Critical", count: s.by_severity.CRITICAL, colour: SEV_COLOUR.CRITICAL },
    { label: "High",     count: s.by_severity.HIGH,     colour: SEV_COLOUR.HIGH },
    { label: "Medium",   count: s.by_severity.MEDIUM,   colour: SEV_COLOUR.MEDIUM },
    { label: "Low",      count: s.by_severity.LOW,      colour: SEV_COLOUR.LOW },
    { label: "Toxic",    count: s.toxic_combinations,   colour: "#ff4d4d" },
  ];
  el.innerHTML = cards.map(c =>
    `<div class="card">
      <div class="count" style="color:${c.colour}">${c.count}</div>
      <div class="label">${c.label}</div>
    </div>`
  ).join("");

  const ts = s.generated_at ? new Date(s.generated_at).toUTCString() : "";
  document.getElementById("generated-at").textContent = `Generated: ${ts}`;
  document.getElementById("footer-date").textContent  = ts;
}

// ── Toxic combinations ──────────────────────────────────────────────────────
function renderToxic() {
  const toxics = REPORT.findings.filter(f => f.category === "TOXIC_COMBINATION");
  if (!toxics.length) return;
  document.getElementById("toxic-section").style.display = "";
  document.getElementById("toxic-list").innerHTML = toxics.map(f =>
    `<div class="toxic-card">
      <div class="tc-title">&#9888; ${esc(f.title)}</div>
      <div class="tc-desc">${esc(f.description)}</div>
    </div>`
  ).join("");
}

// ── Findings table ──────────────────────────────────────────────────────────
let sortCol = null, sortDir = 1;

function renderTable() {
  const sevFilter  = document.getElementById("filter-sev").value;
  const srcFilter  = document.getElementById("filter-src").value;
  const catFilter  = document.getElementById("filter-cat").value;
  const textFilter = document.getElementById("filter-text").value.toLowerCase();

  let rows = REPORT.findings.filter(f => {
    if (sevFilter  && f.severity !== sevFilter)          return false;
    if (srcFilter  && f.source   !== srcFilter)          return false;
    if (catFilter  && f.category !== catFilter)          return false;
    if (textFilter && !f.title.toLowerCase().includes(textFilter)
                   && !(f.file||"").toLowerCase().includes(textFilter)) return false;
    return true;
  });

  if (sortCol) {
    rows = [...rows].sort((a, b) => {
      let av = a[sortCol] ?? "", bv = b[sortCol] ?? "";
      if (sortCol === "severity") { av = SEV_ORDER[av]??9; bv = SEV_ORDER[bv]??9; }
      return (av < bv ? -1 : av > bv ? 1 : 0) * sortDir;
    });
  }

  const tbody = document.getElementById("findings-body");
  tbody.innerHTML = rows.map(f => {
    const loc = f.file ? `${esc(f.file)}${f.line ? `:${f.line}` : ""}` : "—";
    return `<tr>
      <td>${sevBadge(f.severity)}</td>
      <td><span class="source-tag">${esc(f.source)}</span></td>
      <td><span class="source-tag">${esc(f.category)}</span></td>
      <td><span class="rule-id">${esc(f.title)}</span></td>
      <td class="desc-cell"><div class="desc-text" title="${esc(f.description)}">${esc(f.description)}</div></td>
      <td><span class="file-loc">${loc}</span></td>
    </tr>`;
  }).join("");

  document.getElementById("no-results").style.display = rows.length ? "none" : "";
}

// ── Sort on column header click ─────────────────────────────────────────────
document.querySelectorAll("thead th[data-col]").forEach(th => {
  th.addEventListener("click", () => {
    const col = th.dataset.col;
    if (sortCol === col) { sortDir *= -1; } else { sortCol = col; sortDir = 1; }
    renderTable();
  });
});

// ── Filter controls ─────────────────────────────────────────────────────────
["filter-sev","filter-src","filter-cat","filter-text"].forEach(id => {
  document.getElementById(id).addEventListener("input", renderTable);
});

// ── Init ────────────────────────────────────────────────────────────────────
renderSummary();
renderToxic();
renderTable();
</script>
</body>
</html>
"""


def generate_html(report: dict, template_str: str) -> str:
    """Inject report JSON into the HTML template."""
    report_json = json.dumps(report, indent=2)
    return template_str.replace("$REPORT_JSON", report_json)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ASPM normalizer: merge Semgrep + Gitleaks + Checkov findings"
    )
    parser.add_argument("--semgrep",  default="scan-results/semgrep.json",  help="Semgrep JSON output")
    parser.add_argument("--gitleaks", default="scan-results/gitleaks.json", help="Gitleaks JSON output")
    parser.add_argument("--checkov",  default="scan-results/checkov.json",  help="Checkov JSON output")
    parser.add_argument("--output",   default="scan-results/findings.json", help="Normalised output path")
    parser.add_argument("--html",     default="scan-results/report.html",   help="Standalone HTML report")
    args = parser.parse_args()

    print("── Loading scan results ──────────────────────────────")
    sem  = parse_semgrep(args.semgrep)
    git  = parse_gitleaks(args.gitleaks)
    chk  = parse_checkov(args.checkov)
    print(f"  semgrep : {len(sem):>4} finding(s)")
    print(f"  gitleaks: {len(git):>4} finding(s)")
    print(f"  checkov : {len(chk):>4} finding(s)")

    all_findings = sem + git + chk

    print("── Detecting toxic combinations ──────────────────────")
    toxic = detect_toxic_combinations(all_findings)
    for tc in toxic:
        print(f"  [{tc['severity']}] {tc['title']}")

    all_findings = toxic + all_findings
    prioritised  = prioritise(all_findings)
    summary      = summarise(prioritised)
    report       = {"summary": summary, "findings": prioritised}

    # Write findings.json
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n── Output ────────────────────────────────────────────")
    print(f"  findings JSON → {out_path}")

    # Write standalone HTML report
    html_path = Path(args.html)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    with open(html_path, "w") as fh:
        fh.write(generate_html(report, HTML_TEMPLATE))
    print(f"  HTML report   → {html_path}")

    # Print summary table
    print("\n── Risk summary ──────────────────────────────────────")
    print(f"  {'Severity':<12} {'Count':>5}")
    print(f"  {'-'*20}")
    for sev in SEVERITY_ORDER:
        cnt = summary["by_severity"][sev]
        if cnt:
            print(f"  {sev:<12} {cnt:>5}")
    if summary["toxic_combinations"]:
        print(f"\n  ⚠  {summary['toxic_combinations']} TOXIC COMBINATION(S) detected")

    # Exit 1 if any CRITICAL findings (useful for breaking CI on real repos)
    # Commented out because this is a demo repo — every push would fail.
    # critical = summary["by_severity"]["CRITICAL"]
    # if critical:
    #     sys.exit(1)


if __name__ == "__main__":
    main()
