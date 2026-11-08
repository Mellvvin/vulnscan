"""One report per engagement: scanner findings and manual checks together, with your own notes and
fix offers beside each item.  It reuses the styling and helpers of the technical report.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from . import __version__
from . import report as base
from .engagement import Engagement

SEV_RANK = base.SEV_RANK
RESULT_WORD = {"pass": "Pass", "fail": "Fail", "na": "Not applicable", "todo": "Not checked yet"}
EXTRA_CSS = """
.mine{border-left:3px solid var(--accent);padding:6px 12px;margin:10px 0;background:var(--wash);border-radius:0 8px 8px 0}
.mine b{display:block;font-size:13px;color:var(--ink2);font-weight:600;margin-bottom:2px}
.offer{font-weight:600}
.res-fail{color:var(--crit);font-weight:600}.res-pass{color:var(--good);font-weight:600}.res-todo{color:var(--muted)}
.tw table td{overflow-wrap:anywhere}
"""


def money(eng: Engagement, value) -> str:
    return f"{eng.data.get('currency', 'USD')} {value:,.2f}" if value else ""


def collect(eng: Engagement) -> dict:
    counted = eng.counted_findings()
    rows = eng.checklist_rows()
    manual_fail = [r for r in rows if r["manual"] == "fail"]
    sev = {s: 0 for s in base.SEV_ORDER}
    for f in counted:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    for r in manual_fail:
        sev[r["severity"]] += 1
    others = [f for f in eng.findings() if f["status"] not in ("open", "accepted-risk")]
    return {"findings": sorted(counted, key=base.priority_key, reverse=True), "rows": rows,
            "manual_fail": sorted(manual_fail, key=lambda r: -SEV_RANK[r["severity"]]), "sev": sev,
            "dismissed": others, "total": sum(sev.values()),
            "todo": [r for r in rows if r["effective"] == "todo"],
            "passed": [r for r in rows if r["effective"] == "pass"],
            "failed_rows": [r for r in rows if r["effective"] == "fail"]}


def verdict(c: dict) -> str:
    high = c["sev"]["CRITICAL"] + c["sev"]["HIGH"]
    if c["total"] == 0:
        s = "No issues are recorded"
    else:
        s = f"{c['total']} issue{'s' if c['total'] != 1 else ''} found, " + \
            (f"{high} rated Critical or High" if high else "none rated Critical or High")
    if c["todo"]:
        s += f". {len(c['todo'])} check{'s' if len(c['todo']) != 1 else ''} still not done, so this is not a clean bill of health"
    return s + "."


def fix_first(c: dict, limit: int = 8) -> List[Tuple[str, str]]:
    items: List[Tuple[tuple, str, str]] = []
    for f in c["findings"]:
        if f["severity"] in ("CRITICAL", "HIGH"):
            items.append(((SEV_RANK[f["severity"]], 1 if base.details(f).get("kev") else 0),
                          f["title"], f["note"] or base.why(f)))
    for r in c["manual_fail"]:
        if r["severity"] in ("CRITICAL", "HIGH"):
            items.append(((SEV_RANK[r["severity"]], 0), f"{r['area']}: {r['title']}", r["note"] or r["look_for"]))
    items.sort(key=lambda t: t[0], reverse=True)
    return [(t, w) for _k, t, w in items[:limit]]


def _runs_table(eng: Engagement) -> str:
    rows = "".join(
        f"<tr><td>{base.esc(r['kind'])}</td><td>{base.esc(r['started'].replace('T', ' ')[:19])} UTC</td>"
        f"<td>{base.esc(', '.join(r['targets']))}</td><td>{r['findings']}</td></tr>" for r in eng.data["runs"])
    return (f'<div class="card tw"><table><tr><th>Step</th><th>When</th><th>Targets</th><th>Findings</th></tr>'
            f"{rows}</table></div>") if rows else '<p class="sub">No automated steps have been run yet.</p>'


def _finding_card(eng: Engagement, f: dict) -> str:
    d = base.details(f)
    where = f"{f['host']}:{f['port']}" if f.get("port") else f["host"]
    tags = []
    if d.get("kev"):
        tags.append('<span class="tag kev">Exploited in the wild</span>')
    if d.get("cvss") is not None:
        tags.append(f'<span class="tag">CVSS {d["cvss"]:.1f}</span>')
    if f["status"] != "open":
        tags.append(f'<span class="tag">{base.esc(f["status"])}</span>')
    if f["fix"]:
        tags.append('<span class="tag">I can fix this</span>')
    rows = []
    if f.get("cwe"):
        rows.append(f"<dt>Weakness</dt><dd>{base.esc(f['cwe'])}</dd>")
    rows.append(f"<dt>OWASP</dt><dd>{base.esc(f['owasp'])} {base.esc(f['owasp_name'])}</dd>")
    if f.get("evidence"):
        rows.append(f"<dt>Evidence</dt><dd><code>{base.esc(f['evidence'])}</code></dd>")
    mine = f'<div class="mine"><b>What it means</b>{base.esc(f["note"])}</div>' if f["note"] else ""
    if f["fix"] or f["price"]:
        price = f' <span class="offer">{base.esc(money(eng, f["price"]))}</span>' if f["price"] else ""
        mine += f'<div class="mine"><b>What I can do about it</b>{base.esc(f["fix"])}{price}</div>'
    return (f'<details class="f s-{f["severity"]}"><summary>{base._badge(f["severity"])}'
            f'<span><span class="main">{base.esc(f["title"])}</span>'
            f'<span class="where" style="display:block">{base.esc(where)}</span>'
            f'<span class="tags">{"".join(tags)}</span></span><span class="oid">{base.esc(f["owasp"])}</span>'
            f'</summary><div class="panel"><p>{base.esc(f["description"])}</p>{mine}<dl>{"".join(rows)}</dl>'
            f'<h3>How to fix</h3><p>{base.esc(f["remediation"])}</p></div></details>')


def _manual_card(eng: Engagement, r: dict) -> str:
    mine = f'<div class="mine"><b>What it means</b>{base.esc(r["note"])}</div>' if r["note"] else ""
    if r["fix"] or r["price"]:
        price = f' <span class="offer">{base.esc(money(eng, r["price"]))}</span>' if r["price"] else ""
        mine += f'<div class="mine"><b>What I can do about it</b>{base.esc(r["fix"])}{price}</div>'
    return (f'<details class="f s-{r["severity"]}"><summary>{base._badge(r["severity"])}'
            f'<span><span class="main">{base.esc(r["area"])}: {base.esc(r["title"])}</span>'
            f'<span class="where" style="display:block">Found by manual check</span></span>'
            f'<span class="oid">checklist</span></summary><div class="panel"><p>{base.esc(r["look_for"])}</p>'
            f"{mine}</div></details>")


def render_html(eng: Engagement, generated: Optional[datetime] = None) -> str:
    c = collect(eng)
    generated = generated or datetime.now(timezone.utc)
    sev = c["sev"]
    seg = "".join(f'<i class="s-{s}" style="flex:{sev[s]}" title="{base.SEV_WORD[s]}: {sev[s]}"></i>'
                  for s in base.SEV_ORDER if sev[s])
    legend = "".join(f'<li class="s-{s}"><span class="sw"></span><span class="n">{sev[s]}</span>{base.SEV_WORD[s]}</li>'
                     for s in base.SEV_ORDER)
    total_offer = eng.offer_total()
    facts = (f'<div class="fact"><b>{len(c["passed"])}</b><span>checks passed</span></div>'
             f'<div class="fact"><b>{len(c["failed_rows"])}</b><span>checks failed</span></div>'
             f'<div class="fact"><b>{len(c["todo"])}</b><span>checks not done yet</span></div>')
    if total_offer:
        facts += f'<div class="fact"><b>{base.esc(money(eng, total_offer))}</b><span>fixes I can do</span></div>'
    ff = fix_first(c)
    ff_html = ""
    if ff:
        items = "".join(f'<li><span class="t">{base.esc(t)}</span><span class="w">{base.esc(w)}</span></li>'
                        for t, w in ff)
        ff_html = (f'<section><h2>Fix first</h2><p class="sub">The Critical and High issues, most urgent '
                   f'first.</p><ol class="fixfirst card">{items}</ol></section>')
    cards = "".join(_finding_card(eng, f) for f in c["findings"]) + "".join(_manual_card(eng, r) for r in c["manual_fail"])
    issues_html = (f'<section><h2>Issues</h2>{cards}</section>' if cards else
                   '<section><h2>Issues</h2><p class="sub">Nothing is recorded as an issue.</p></section>')
    crow = []
    for r in c["rows"]:
        how = {"auto": "scanner", "partial": "scanner + manual", "manual": "manual"}[r["coverage"]]
        res = RESULT_WORD[r["effective"]] + (f" ({r['hint']})" if r["hint"] else "")
        crow.append(f'<tr><td>{base.esc(r["area"])}</td><td>{base.esc(r["title"])}</td><td>{base.esc(how)}</td>'
                    f'<td class="res-{r["effective"]}">{base.esc(res)}</td><td>{base.esc(r["note"])}</td></tr>')
    check_html = ('<section><h2>Checklist</h2><div class="card tw"><table><tr><th>Area</th><th>Check</th>'
                  '<th>Done by</th><th>Result</th><th>Notes</th></tr>' + "".join(crow) + "</table></div></section>")
    dismissed = ""
    if c["dismissed"]:
        drows = "".join(f'<tr><td>{base.esc(f["title"])}</td><td>{base.esc(f["host"])}</td>'
                        f'<td>{base.esc(f["status"])}</td><td>{base.esc(f["note"])}</td></tr>'
                        for f in c["dismissed"])
        dismissed = ('<section><h2>Resolved or dismissed</h2><div class="card tw"><table><tr><th>Finding</th>'
                     f'<th>Where</th><th>Status</th><th>Note</th></tr>{drows}</table></div></section>')
    auth = eng.data.get("authorization")
    auth_text = (f"Signed by {auth['signer']} on {auth['signed_on']}"
                 + (f", reference {auth['reference']}" if auth.get("reference") else "")
                 + (f", valid until {auth['expires']}" if auth.get("expires") else "")) if auth else \
        "None recorded (only private or lab targets can be scanned)"
    meta = (f'<dl class="meta"><dt>Client</dt><dd>{base.esc(eng.client)}</dd>'
            f'<dt>Prepared</dt><dd>{base.esc(generated.strftime("%Y-%m-%d"))}</dd>'
            f'<dt>Scope</dt><dd>{base.esc(", ".join(eng.data["scope"]))}</dd>'
            f'<dt>Authorization</dt><dd>{base.esc(auth_text)}</dd>'
            f'<dt>Standard</dt><dd>OWASP Top 10:{base.esc(eng.data["owasp_edition"])}</dd></dl>')
    limits = ("A scan is a snapshot of what could be seen on the day. It finds known problems and common "
              "misconfigurations; it does not prove a system is secure, and the manual checks depend on what "
              "the client showed or told me. Only the listed scope was tested.")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security assessment: {base.esc(eng.client)}</title>
<style>{base.CSS}{EXTRA_CSS}</style></head><body><main>
<header><h1>Security assessment: {base.esc(eng.client)}</h1>
<p class="lead">{base.esc(verdict(c))}</p>{meta}</header>
{ff_html}
<section><h2>Summary</h2><div class="card"><div class="seg" role="img" aria-label="Issues by severity">{seg}</div>
<ul class="legend">{legend}</ul><div class="facts">{facts}</div></div></section>
{issues_html}
{check_html}
{dismissed}
<section><h2>Scope and method</h2>{_runs_table(eng)}<p class="note">{base.esc(limits)}</p></section>
<footer>Generated by vulnscan {base.esc(__version__)}. Only systems covered by the signed authorization were tested.</footer>
</main></body></html>
"""


def render_markdown(eng: Engagement, generated: Optional[datetime] = None) -> str:
    c = collect(eng)
    generated = generated or datetime.now(timezone.utc)
    auth = eng.data.get("authorization")
    out = [f"# Security assessment: {eng.client}", "", verdict(c), "",
           f"- Prepared: {generated.strftime('%Y-%m-%d')}", f"- Scope: {', '.join(eng.data['scope'])}",
           "- Authorization: " + (f"signed by {auth['signer']} on {auth['signed_on']}" if auth else "none recorded"),
           "", "## Summary", "", "| Severity | Issues |", "|---|---:|"]
    out += [f"| {base.SEV_WORD[s]} | {c['sev'][s]} |" for s in base.SEV_ORDER]
    total_offer = eng.offer_total()
    if total_offer:
        out += ["", f"Fixes I can do: {money(eng, total_offer)}"]
    ff = fix_first(c)
    if ff:
        out += ["", "## Fix first", ""] + [f"{i}. **{base._md(t)}**: {base._md(w)}" for i, (t, w) in enumerate(ff, 1)]
    out += ["", "## Issues", ""]
    if not c["findings"] and not c["manual_fail"]:
        out.append("Nothing is recorded as an issue.")
    for f in c["findings"]:
        where = f"{f['host']}:{f['port']}" if f.get("port") else f["host"]
        out += [f"### {base.SEV_WORD[f['severity']]}: {f['title']}", "", f"Where: {where}", "", f["description"], ""]
        if f["note"]:
            out += [f"What it means: {f['note']}", ""]
        if f["fix"] or f["price"]:
            out += [f"What I can do: {f['fix']} {money(eng, f['price'])}".rstrip(), ""]
        out += [f"How to fix: {f['remediation']}", ""]
    for r in c["manual_fail"]:
        out += [f"### {base.SEV_WORD[r['severity']]}: {r['area']}: {r['title']} (manual check)", "", r["look_for"], ""]
        if r["note"]:
            out += [f"What it means: {r['note']}", ""]
        if r["fix"] or r["price"]:
            out += [f"What I can do: {r['fix']} {money(eng, r['price'])}".rstrip(), ""]
    out += ["## Checklist", "", "| Area | Check | Result | Notes |", "|---|---|---|---|"]
    for r in c["rows"]:
        res = RESULT_WORD[r["effective"]] + (f" ({r['hint']})" if r["hint"] else "")
        out.append(f"| {base._md(r['area'])} | {base._md(r['title'])} | {base._md(res)} | {base._md(r['note'])} |")
    out += ["", "## Scope and method", ""]
    out += [f"- {r['kind']} run {r['started'][:19]} UTC: {', '.join(r['targets'])} ({r['findings']} findings)"
            for r in eng.data["runs"]] or ["- No automated steps run yet."]
    return "\n".join(out) + "\n"


def write_report(eng: Engagement, out_dir: Optional[str] = None) -> List[str]:
    out_dir = out_dir or str(eng.dir / "reports" / datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    for name, content in (("report.html", render_html(eng)), ("report.md", render_markdown(eng))):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        paths.append(path)
    return paths
