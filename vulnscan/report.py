"""Report generation (HTML + Markdown) from results.json.  Pure Python, so it works the
same on Linux, macOS and Windows.  Everything that comes from outside the tool
(advisory text, banners, package names) is HTML-escaped; links are http(s) only.
"""

from __future__ import annotations

import html
import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .owasp import EDITIONS, not_testable_ids

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: len(SEV_ORDER) - i for i, s in enumerate(SEV_ORDER)}
SEV_WORD = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}
ELLIPSIS = "\u2026"
SEV_GLYPH = {"CRITICAL": "\u25c6", "HIGH": "\u25b2", "MEDIUM": "\u25cf", "LOW": "\u25bc", "INFO": "\u2013"}


def esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def safe_url(url: str) -> str:
    return url if re.match(r"https?://", url or "") else ""


def details(f: dict) -> dict:
    return f.get("details") or {}


def priority_key(f: dict):
    d = details(f)
    return (1 if d.get("kev") else 0, SEV_RANK.get(f["severity"], 0), d.get("epss") or 0.0,
            d.get("cvss") or 0.0, 1 if d.get("fixed") else 0)


def merge_docs(docs: List[dict]) -> dict:
    """Combine several results.json documents into one."""
    if len(docs) == 1:
        return docs[0]
    base = json.loads(json.dumps(docs[0]))
    seen = {(f["host"], f.get("port"), f["check_id"]) for f in base["findings"]}
    for d in docs[1:]:
        for f in d["findings"]:
            k = (f["host"], f.get("port"), f["check_id"])
            if k not in seen:
                seen.add(k)
                base["findings"].append(f)
        base.setdefault("systems", []).extend(d.get("systems", []))
        base.setdefault("hosts", []).extend(d.get("hosts", []))
        base.setdefault("warnings", []).extend(d.get("warnings", []))
        for k, v in (d.get("sources") or {}).items():
            base.setdefault("sources", {}).setdefault(k, v)
    base["summary"] = {s: sum(1 for f in base["findings"] if f["severity"] == s) for s in SEV_ORDER}
    return base


# ------------------------------------------------------------------ derived numbers

def stats(doc: dict) -> dict:
    fs = doc["findings"]
    counts = {s: sum(1 for f in fs if f["severity"] == s) for s in SEV_ORDER}
    kev = [f for f in fs if details(f).get("kev")]
    fixable = [f for f in fs if details(f).get("fixed")]
    pkgs = [f for f in fs if details(f).get("kind") == "package"]
    unrated = [f for f in pkgs if "unrated" in str(details(f).get("severity_basis", ""))]
    total_pkgs = sum(s.get("packages", 0) for s in doc.get("systems", []))
    return {"counts": counts, "total": len(fs), "kev": kev, "fixable": fixable, "pkg_findings": pkgs,
            "unrated": unrated, "packages_checked": total_pkgs,
            "vuln_components": sum(s.get("vulnerable_components", 0) for s in doc.get("systems", []))}


def verdict(doc: dict, st: dict) -> str:
    c, total = st["counts"], st["total"]
    incomplete = (doc.get("sources", {}).get("osv") or {}).get("incomplete")
    if total == 0:
        base = "No known vulnerabilities or misconfigurations were found"
        if st["packages_checked"]:
            base += f" in the {st['packages_checked']} packages checked"
        return base + (". The data behind this result is incomplete, so do not treat it as clean."
                       if incomplete else ".")
    parts = [f"{total} finding{'s' if total != 1 else ''}"]
    high = c["CRITICAL"] + c["HIGH"]
    parts.append(f"{high} rated Critical or High" if high else "none rated Critical or High")
    s = ", ".join(parts)
    if st["kev"]:
        n = len(st["kev"])
        s += f". {n} {'is' if n == 1 else 'are'} on CISA's list of vulnerabilities exploited in the wild"
    return s + "."


def why(f: dict) -> str:
    d, bits = details(f), []
    if d.get("kev"):
        bits.append(f"exploited in the wild (CISA KEV, added {d['kev'].get('added', '?')})")
    if d.get("epss") is not None and d["epss"] >= 0.1:
        bits.append(f"{d['epss'] * 100:.0f}% chance of exploitation in the next 30 days (EPSS)")
    if d.get("cvss") is not None:
        bits.append(f"CVSS {d['cvss']:.1f}")
    if d.get("fixed"):
        bits.append(f"fixed in {d['fixed']}")
    elif d.get("kind") == "package":
        bits.append("no fix published yet")
    if bits:
        return "; ".join(bits)
    desc = re.sub(r"\s+", " ", f.get("description", "")).strip()
    where = f"{f['host']}:{f['port']}" if f.get("port") else f["host"]
    return f"{where}: {desc[:140]}{ELLIPSIS if len(desc) > 140 else ''}" if desc else SEV_WORD.get(f["severity"], "")


def owasp_rows(doc: dict) -> List[dict]:
    edition = doc.get("meta", {}).get("owasp_edition", "2025")
    names: Dict[str, str] = {}
    for _k, (cid, name) in EDITIONS[edition].items():
        names.setdefault(cid, name)
    for f in doc["findings"]:
        names.setdefault(f["owasp"], f["owasp_name"])
    skip = set(not_testable_ids(edition))
    rows = []
    for cid in sorted(names):
        fs = [f for f in doc["findings"] if f["owasp"] == cid]
        rows.append({"id": cid, "name": names[cid], "count": len(fs),
                     "high": sum(1 for f in fs if SEV_RANK[f["severity"]] >= SEV_RANK["HIGH"]),
                     "testable": cid not in skip})
    return rows


# ------------------------------------------------------------------ HTML

CSS = """
:root{--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--hair:#e1e0d9;
--line:#c3c2b7;--accent:#2a78d6;--accent-ink:#184f95;--crit:#d03b3b;--high:#ec835a;--med:#fab219;
--low:#6da7ec;--info:#898781;--good:#006300;--wash:rgba(11,11,11,.04);--ring:rgba(11,11,11,.10)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--page:#0d0d0d;--surface:#1a1a19;
--ink:#f0efec;--ink2:#c3c2b7;--hair:#2c2c2a;--line:#383835;--accent:#3987e5;--accent-ink:#86b6ef;
--good:#0ca30c;--wash:rgba(255,255,255,.05);--ring:rgba(255,255,255,.10)}}
:root[data-theme="dark"]{--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--hair:#2c2c2a;
--line:#383835;--accent:#3987e5;--accent-ink:#86b6ef;--good:#0ca30c;--wash:rgba(255,255,255,.05);
--ring:rgba(255,255,255,.10)}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:40px 16px 96px}
h1{font-size:clamp(26px,4.2vw,38px);line-height:1.15;font-weight:650;letter-spacing:-.015em;margin:0 0 10px}
h2{font-size:20px;font-weight:650;letter-spacing:-.005em;margin:0 0 6px}
h3{font-size:15px;margin:0 0 6px}
section{margin-top:52px}
p{margin:0 0 10px;max-width:68ch}.sub{color:var(--ink2)}
a{color:var(--accent-ink)}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.lead{font-size:18px;line-height:1.45;max-width:60ch;margin-bottom:18px}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 18px;margin:0;color:var(--ink2);max-width:760px}
dl.meta dt{color:var(--muted)}dl.meta dd{margin:0}
.notice{border:1px solid var(--ring);background:var(--wash);border-radius:8px;padding:12px 14px;margin:18px 0;
max-width:760px}.notice strong{display:block;margin-bottom:4px}.notice ul{margin:4px 0 0;padding-left:20px}
.card{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:20px}
.fixfirst{list-style:none;padding:0;margin:14px 0 0;counter-reset:ff}
.fixfirst li{counter-increment:ff;display:grid;grid-template-columns:28px 1fr;gap:4px 10px;padding:12px 0;
border-top:1px solid var(--hair)}
.fixfirst li:first-child{border-top:0}
.fixfirst li::before{content:counter(ff);font-weight:650;color:var(--ink2);text-align:right}
.fixfirst .t{font-weight:600}.fixfirst .w{color:var(--ink2);grid-column:2}
.seg{display:flex;gap:2px;height:16px;margin:14px 0 12px}
.seg i{display:block;border-radius:4px;min-width:4px}
.legend{display:flex;flex-wrap:wrap;gap:6px 22px;margin:0;padding:0;list-style:none}
.legend li{display:flex;align-items:center;gap:8px}.legend .n{font-weight:650}
.sw{width:10px;height:10px;border-radius:3px;display:inline-block}
.s-CRITICAL{--c:var(--crit)}.s-HIGH{--c:var(--high)}.s-MEDIUM{--c:var(--med)}.s-LOW{--c:var(--low)}.s-INFO{--c:var(--info)}
.seg i,.sw{background:var(--c)}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-top:20px}
.fact b{display:block;font-size:26px;line-height:1.1;font-weight:650}.fact span{color:var(--ink2);font-size:14px}
.bars{display:grid;gap:2px;margin-top:14px}
.bar{display:grid;grid-template-columns:minmax(150px,280px) 1fr 120px;gap:12px;align-items:center;
width:100%;min-height:38px;padding:4px 8px;border:0;border-radius:8px;background:none;color:inherit;
font:inherit;text-align:left;cursor:pointer}
.bar:hover:not(:disabled){background:var(--wash)}.bar:disabled{cursor:default;color:var(--ink2)}
.bar:focus-visible,button:focus-visible,summary:focus-visible,select:focus-visible,input:focus-visible{
outline:2px solid var(--accent);outline-offset:2px}
.bar .id{font-weight:600}.track{height:10px;position:relative}
.fill{position:absolute;left:0;top:0;bottom:0;background:var(--accent);border-radius:0 4px 4px 0;min-width:3px}
.bar .v{text-align:right;color:var(--ink2);white-space:nowrap}.bar .v b{color:var(--ink)}
.note{color:var(--ink2);font-size:14px;max-width:72ch;margin-top:12px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-top:1px solid var(--hair);vertical-align:top}
th{color:var(--muted);font-weight:500;border-top:0}
.cmd{position:relative;margin:8px 0 14px}
.cmd pre{margin:0;padding:12px 84px 12px 14px;background:var(--wash);border:1px solid var(--ring);
border-radius:8px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
.cmd button{position:absolute;top:8px;right:8px}
button.chip,.cmd button{font:inherit;font-size:13px;background:var(--surface);color:var(--ink);
border:1px solid var(--line);border-radius:999px;padding:5px 12px;cursor:pointer;min-height:30px}
button.chip[aria-pressed="true"]{background:var(--ink);color:var(--surface);border-color:var(--ink)}
.filters{position:sticky;top:0;z-index:5;background:var(--page);padding:12px 0;display:flex;flex-wrap:wrap;
gap:8px;align-items:center;border-bottom:1px solid var(--hair);margin-top:14px}
.filters select{max-width:100%}
.tw{overflow-x:auto}
.filters select,.filters input[type=search]{font:inherit;font-size:14px;padding:6px 10px;border-radius:8px;
border:1px solid var(--line);background:var(--surface);color:var(--ink);min-height:34px}
.filters input[type=search]{flex:1;min-width:160px}
.filters label{display:flex;gap:6px;align-items:center;font-size:14px;color:var(--ink2)}
#count{color:var(--ink2);font-size:14px;margin:12px 0 4px}
details.f{border-bottom:1px solid var(--hair)}
details.f>summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:92px 1fr auto;gap:4px 14px;
padding:12px 6px;align-items:start}
details.f>summary::-webkit-details-marker{display:none}
details.f>summary:hover{background:var(--wash)}
.badge{display:inline-flex;gap:6px;align-items:center;font-size:12.5px;font-weight:650;padding:2px 9px 2px 7px;
border-radius:6px;background:var(--c);color:#0b0b0b;white-space:nowrap}
.s-CRITICAL .badge{color:#fff}
.main{font-weight:600;overflow-wrap:anywhere}.where{color:var(--ink2);font-size:14px;overflow-wrap:anywhere}
.tags{display:flex;gap:6px;flex-wrap:wrap;margin-top:4px}
.tag{font-size:12.5px;border:1px solid var(--line);border-radius:6px;padding:0 7px;color:var(--ink2)}
.tag.kev{border-color:var(--crit);color:var(--ink);font-weight:600}
.oid{font-size:13px;color:var(--ink2);text-align:right;white-space:nowrap}
.panel{padding:4px 6px 20px 112px}
.panel dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 18px;margin:12px 0}
.panel dt{color:var(--muted)}.panel dd{margin:0;overflow-wrap:anywhere}
.panel ul.refs{margin:6px 0 0;padding-left:18px}
.empty{padding:28px 6px;color:var(--ink2)}
footer{margin-top:64px;color:var(--ink2);font-size:14px}
.visually{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
@media (max-width:720px){
.bar{grid-template-columns:1fr auto}.bar .track{grid-column:1/-1;order:3}.bar .v{white-space:normal}
details.f>summary{grid-template-columns:1fr}.oid{text-align:left}.panel{padding-left:6px}
dl.meta,.panel dl{grid-template-columns:1fr}dl.meta dt,.panel dt{margin-top:6px}}
@media print{.filters,.cmd button{display:none}details.f{break-inside:avoid}}
"""

JS = """
(function(){
var rows=[].slice.call(document.querySelectorAll('details.f'));
var st={sev:'ALL',owasp:'',q:'',fix:false,kev:false};
var count=document.getElementById('count'),empty=document.getElementById('none');
function apply(){var n=0;rows.forEach(function(r){
var ok=(st.sev==='ALL'||r.dataset.sev===st.sev)&&(!st.owasp||r.dataset.owasp===st.owasp)&&
(!st.fix||r.dataset.fix==='1')&&(!st.kev||r.dataset.kev==='1')&&(!st.q||r.dataset.text.indexOf(st.q)>-1);
r.hidden=!ok;if(ok)n++;});
count.textContent=n+' of '+rows.length+' findings shown';empty.hidden=n!==0;}
document.querySelectorAll('[data-sevbtn]').forEach(function(b){b.addEventListener('click',function(){
st.sev=b.dataset.sevbtn;document.querySelectorAll('[data-sevbtn]').forEach(function(x){
x.setAttribute('aria-pressed',x===b?'true':'false');});apply();});});
var sel=document.getElementById('owaspsel');
sel.addEventListener('change',function(){st.owasp=sel.value;apply();});
document.querySelectorAll('.bar[data-owasp]').forEach(function(b){b.addEventListener('click',function(){
sel.value=b.dataset.owasp;st.owasp=b.dataset.owasp;apply();
document.getElementById('findings').scrollIntoView({behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'});});});
document.getElementById('q').addEventListener('input',function(e){st.q=e.target.value.toLowerCase();apply();});
document.getElementById('fix').addEventListener('change',function(e){st.fix=e.target.checked;apply();});
document.getElementById('kev').addEventListener('change',function(e){st.kev=e.target.checked;apply();});
document.querySelectorAll('[data-copy]').forEach(function(b){b.addEventListener('click',function(){
var t=document.getElementById(b.dataset.copy).textContent;
function done(){var o=b.textContent;b.textContent='Copied';setTimeout(function(){b.textContent=o;},1400);}
if(navigator.clipboard){navigator.clipboard.writeText(t).then(done,function(){});}
else{var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();
try{document.execCommand('copy');done();}catch(e){}document.body.removeChild(a);}});});
apply();})();
"""


def _badge(sev: str) -> str:
    return (f'<span class="badge"><span aria-hidden="true">{SEV_GLYPH[sev]}</span>{SEV_WORD[sev]}</span>')


def _finding_html(f: dict, idx: int) -> str:
    d = details(f)
    sev = f["severity"]
    is_pkg = d.get("kind") == "package"
    where = f"{f['host']}:{f['port']}" if f.get("port") else f["host"]
    if is_pkg:
        main = f"{(d.get('cves') or [d.get('advisories', [''])[0]])[0]}  {d.get('summary', '')}".strip()
        fixed = d.get("fixed")
        sub = f"{d['component']} {d['installed']}" + (f" \u2192 {fixed}" if fixed else " (no fix published)")
        sub += f"  on {where}"
    else:
        main, sub = f["title"], where
    tags = []
    if d.get("kev"):
        tags.append('<span class="tag kev">Exploited in the wild</span>')
    if d.get("epss") is not None and d["epss"] >= 0.1:
        tags.append(f'<span class="tag">EPSS {d["epss"] * 100:.0f}%</span>')
    if d.get("cvss") is not None:
        tags.append(f'<span class="tag">CVSS {d["cvss"]:.1f}</span>')
    if d.get("fixed"):
        tags.append('<span class="tag">Fix available</span>')
    if "unrated" in str(d.get("severity_basis", "")):
        tags.append('<span class="tag">Unrated by source</span>')
    text = " ".join(str(x) for x in [f["title"], f["host"], f["owasp"], f["owasp_name"], f.get("cwe", ""),
                                      " ".join(d.get("cves", [])), d.get("component", "")]).lower()

    rows = []

    def row(label: str, value: str) -> None:
        if value:
            rows.append(f"<dt>{esc(label)}</dt><dd>{value}</dd>")

    if is_pkg:
        row("Component", esc(f"{d['component']} {d['installed']}") +
            (f" <span class=\"sub\">(packages: {esc(', '.join(d['packages'][:8]))}"
             f"{ELLIPSIS if len(d['packages']) > 8 else ''})</span>" if d.get("packages") else ""))
        row("Fixed in", esc(d.get("fixed") or "no fixed version listed"))
        if d.get("cvss") is not None:
            row("CVSS", esc(f"{d['cvss']:.1f}") + (f" <code>{esc(d['cvss_vector'])}</code>" if d.get("cvss_vector") else ""))
        row("Severity basis", esc(d.get("severity_basis", "")))
        if d.get("epss") is not None:
            row("EPSS", esc(f"{d['epss'] * 100:.1f}% (percentile {d['epss_percentile'] * 100:.0f})"))
        if d.get("kev"):
            k = d["kev"]
            row("CISA KEV", esc(f"added {k['added']}, remediation due {k['due']}; ransomware use: {k['ransomware']}"))
        row("Identifiers", esc(", ".join(d.get("cves", []) + d.get("advisories", []))))
    row("Weakness", esc(", ".join(d.get("cwes", [])) if is_pkg else f.get("cwe", "")))
    row("OWASP", esc(f"{f['owasp']} {f['owasp_name']}") +
        (f" <span class=\"sub\">({esc(d['owasp_basis'])})</span>" if d.get("owasp_basis") else ""))
    if f.get("evidence"):
        row("Evidence", f"<code>{esc(f['evidence'])}</code>")

    cmd_html = ""
    remediation = f["remediation"]
    if is_pkg and d.get("upgrade_command"):
        remediation = remediation.split("  Run:")[0]
        cmd_html = (f'<div class="cmd"><pre id="c{idx}">{esc(d["upgrade_command"])}</pre>'
                    f'<button type="button" data-copy="c{idx}">Copy</button></div>')
    refs = "".join(f'<li><a href="{esc(u)}" rel="noopener noreferrer">{esc(u)}</a></li>'
                   for u in d.get("references", []) if safe_url(u))
    return (
        f'<details class="f s-{sev}" data-sev="{sev}" data-owasp="{esc(f["owasp"])}" '
        f'data-fix="{1 if d.get("fixed") else 0}" data-kev="{1 if d.get("kev") else 0}" data-text="{esc(text)}">'
        f'<summary>{_badge(sev)}<span><span class="main">{esc(main)}</span>'
        f'<span class="where" style="display:block">{esc(sub)}</span>'
        f'<span class="tags">{"".join(tags)}</span></span>'
        f'<span class="oid">{esc(f["owasp"])}</span></summary>'
        f'<div class="panel"><p>{esc(f["description"])}</p><dl>{"".join(rows)}</dl>'
        f'<h3>How to fix</h3><p>{esc(remediation)}</p>{cmd_html}'
        f'{"<h3>References</h3><ul class=refs>" + refs + "</ul>" if refs else ""}</div></details>')


def _remediation_plan(doc: dict) -> str:
    """Group upgrade commands so the user can fix many findings at once."""
    groups: Dict[tuple, set] = {}
    for f in doc["findings"]:
        d = details(f)
        if d.get("kind") != "package" or not d.get("fixed") or d.get("source") != "host":
            continue
        groups.setdefault((f["host"], d["manager"]), set()).update(d.get("packages", []))
    blocks = []
    for i, ((host, manager), pkgs) in enumerate(sorted(groups.items())):
        names = " ".join(sorted(pkgs))
        cmd = {"dpkg": f"sudo apt-get update && sudo apt-get install --only-upgrade {names}",
               "apk": f"apk upgrade {names}", "rpm": f"sudo dnf upgrade {names}",
               "pip": "\n".join(f'python -m pip install --upgrade "{p}"' for p in sorted(pkgs)),
               "npm": "\n".join(f"npm install -g {p}@latest" for p in sorted(pkgs))}.get(manager)
        if not cmd:
            continue
        blocks.append(f'<h3>{esc(host)}: {esc(manager)} packages with a fix available ({len(pkgs)})</h3>'
                      f'<div class="cmd"><pre id="plan{i}">{esc(cmd)}</pre>'
                      f'<button type="button" data-copy="plan{i}">Copy</button></div>')
    if not blocks:
        return ""
    return ('<section><h2>Upgrade plan</h2><p class="sub">One command per package manager clears every '
            'finding that already has a fix. Review before running, then scan again to confirm.</p>'
            + "".join(blocks) + "</section>")


def render_html(doc: dict) -> str:
    meta, sources = doc.get("meta", {}), doc.get("sources", {})
    st = stats(doc)
    edition = meta.get("owasp_edition", "2025")
    findings = sorted(doc["findings"], key=priority_key, reverse=True)
    names = ", ".join(sorted({s["label"] for s in doc.get("systems", [])} |
                             {h["host"] for h in doc.get("hosts", [])})) or ", ".join(meta.get("targets", []))
    started = meta.get("started", "")
    c = st["counts"]
    total = max(1, st["total"])

    # severity bar + legend
    seg = "".join(f'<i class="s-{s}" style="flex:{c[s]}" title="{SEV_WORD[s]}: {c[s]}"></i>'
                  for s in SEV_ORDER if c[s])
    legend = "".join(f'<li class="s-{s}"><span class="sw"></span><span class="n">{c[s]}</span>{SEV_WORD[s]}</li>'
                     for s in SEV_ORDER)
    facts = (f'<div class="fact"><b>{len(st["kev"])}</b><span>exploited in the wild (CISA KEV)</span></div>'
             f'<div class="fact"><b>{len(st["fixable"])}</b><span>already have a fixed version</span></div>')
    if st["packages_checked"]:
        facts += (f'<div class="fact"><b>{st["vuln_components"]} of {st["packages_checked"]}</b>'
                  f'<span>installed packages have known vulnerabilities</span></div>')

    # fix-first list
    top = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH") or details(f).get("kev")][:8]
    fix_first = ""
    if top:
        items = "".join(
            f'<li><span class="t">{esc(details(f).get("component", "") + ": " if details(f).get("component") else "")}'
            f'{esc((details(f).get("cves") or [""])[0] or f["title"])}</span>'
            f'<span class="w">{esc(why(f))}</span></li>' for f in top)
        fix_first = (f'<section><h2>Fix first</h2><p class="sub">Ordered by exploitation evidence, then severity, '
                     f'then exploit likelihood.</p><ol class="fixfirst card">{items}</ol></section>')

    # OWASP bars
    orows = owasp_rows(doc)
    mx = max([r["count"] for r in orows] + [1])
    bars = []
    for r in orows:
        w = f'{r["count"] / mx * 100:.1f}%'
        if r["count"]:
            val = f'<b>{r["count"]}</b> finding{"s" if r["count"] != 1 else ""}' + \
                  (f' ({r["high"]} high+)' if r["high"] else "")
            bars.append(f'<button class="bar" type="button" data-owasp="{esc(r["id"])}">'
                        f'<span><span class="id">{esc(r["id"])}</span> {esc(r["name"])}</span>'
                        f'<span class="track"><span class="fill" style="width:{w}"></span></span>'
                        f'<span class="v">{val}</span></button>')
        else:
            val = "not assessable" if not r["testable"] else "none found"
            bars.append(f'<button class="bar" type="button" disabled>'
                        f'<span><span class="id">{esc(r["id"])}</span> {esc(r["name"])}</span>'
                        f'<span class="track"></span><span class="v">{val}</span></button>')
    owasp_origin = sources.get("owasp", {})
    owasp_note = (
        f"Each package vulnerability is placed by its weakness type (CWE) using OWASP's own CWE lists for "
        f"{edition}. Weaknesses that OWASP does not list, such as memory-safety bugs, are filed under "
        f"{esc(EDITIONS[edition]['supply_chain'][0])} because the real problem is a known-vulnerable component. "
        f"Zero findings in a category is not proof of safety: Insecure Design and Logging &amp; Alerting "
        f"are design and process issues no scanner can see from the outside.")

    # targets table
    trows = "".join(
        f'<tr><td>{esc(s["label"])}</td><td>{esc(s.get("os") or s["kind"])}</td>'
        f'<td>{s.get("packages", 0)}</td><td>{s.get("vulnerable_components", 0)}</td>'
        f'<td>{esc("; ".join(s.get("notes", [])) or "")}</td></tr>' for s in doc.get("systems", []))
    targets = (f'<section><h2>What was assessed</h2><div class="card tw"><table><tr><th>Target</th><th>System</th>'
               f'<th>Packages</th><th>Vulnerable</th><th>Notes</th></tr>{trows}</table></div></section>'
               if trows else "")

    warns = doc.get("warnings", [])
    warn_html = (f'<div class="notice" role="note"><strong>Read this first</strong><ul>'
                 + "".join(f"<li>{esc(w)}</li>" for w in dict.fromkeys(warns)) + "</ul></div>") if warns else ""

    osv_s, kev_s = sources.get("osv", {}), sources.get("kev", {})
    data_rows = [
        ("Vulnerability matching", f"OSV.dev: {osv_s.get('package_versions', 0)} package versions checked, "
                                   f"{osv_s.get('records', 0)} advisories read" if osv_s else "not run"),
        ("OWASP mapping", f"OWASP Top 10:{edition}, {owasp_origin.get('cwes_mapped', 0)} CWEs mapped "
                          f"({owasp_origin.get('origin', '?')}, fetched {str(owasp_origin.get('fetched_at', ''))[:10]})"
         if owasp_origin else f"OWASP Top 10:{edition}"),
        ("Exploited in the wild", f"CISA KEV catalog {kev_s.get('version', '')} ({kev_s.get('origin', '')}, "
                                  f"{kev_s.get('count', 0)} entries)" if kev_s else "not used"),
        ("Exploit likelihood", f"FIRST EPSS, {sources.get('epss', {}).get('cves_scored', 0)} CVEs scored"
         if sources.get("epss") else "not used"),
        ("Weakness and score gaps", f"CVE.org records for {sources.get('cve_org', {}).get('records_used', 0)} CVEs"
         if sources.get("cve_org") else "not used"),
    ]
    data_html = "".join(f"<tr><td>{esc(a)}</td><td>{esc(b)}</td></tr>" for a, b in data_rows)

    sev_buttons = '<button class="chip" type="button" data-sevbtn="ALL" aria-pressed="true">All</button>' + "".join(
        f'<button class="chip" type="button" data-sevbtn="{s}" aria-pressed="false">{SEV_WORD[s]} ({c[s]})</button>'
        for s in SEV_ORDER if c[s])
    opts = '<option value="">All OWASP categories</option>' + "".join(
        f'<option value="{esc(r["id"])}">{esc(r["id"])} {esc(r["name"])} ({r["count"]})</option>'
        for r in orows if r["count"])
    list_html = "".join(_finding_html(f, i) for i, f in enumerate(findings)) or \
        '<p class="empty">Nothing to list.</p>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security assessment: {esc(names)}</title>
<style>{CSS}</style></head><body><main>
<header>
<h1>Security assessment of {esc(names)}</h1>
<p class="lead">{esc(verdict(doc, st))}</p>
<dl class="meta">
<dt>Scanned</dt><dd>{esc(started.replace("T", " ")[:19])} UTC, took {esc(meta.get("duration_seconds", "?"))} s</dd>
<dt>Standard</dt><dd>OWASP Top 10:{esc(edition)}</dd>
<dt>Tool</dt><dd>vulnscan {esc(meta.get("version", ""))}</dd>
</dl>
{warn_html}
</header>
{fix_first}
<section><h2>Severity</h2>
<div class="card"><div class="seg" role="img" aria-label="Findings by severity">{seg}</div>
<ul class="legend">{legend}</ul><div class="facts">{facts}</div></div></section>
<section><h2>OWASP Top 10:{esc(edition)}</h2>
<div class="card"><p class="sub" style="margin:0">Select a category to filter the findings below.</p>
<div class="bars">{"".join(bars)}</div><p class="note">{owasp_note}</p></div></section>
{_remediation_plan(doc)}
<section id="findings"><h2>All findings</h2>
<div class="filters" role="search">{sev_buttons}
<select id="owaspsel" aria-label="OWASP category">{opts}</select>
<input id="q" type="search" placeholder="Search package, CVE, host" aria-label="Search findings">
<label><input id="fix" type="checkbox"> Fix available</label>
<label><input id="kev" type="checkbox"> Exploited in the wild</label></div>
<p id="count" aria-live="polite"></p>
{list_html}
<p id="none" class="empty" hidden>No findings match these filters.</p></section>
{targets}
<section><h2>Method and data</h2>
<div class="card tw"><table>{data_html}</table></div>
<p class="note">Vulnerabilities are matched by exact installed version against published advisories, so a
finding means a known advisory applies to that version, not that the flaw is reachable on this system.
Severity comes from CVSS where available; advisories without a score are shown as Medium and tagged
unrated, and anything on CISA's exploited list is raised to at least High.</p></section>
<footer>Generated by vulnscan {esc(meta.get("version", ""))}. Only scan systems you own or are authorized to test.</footer>
</main><script>{JS}</script></body></html>
"""


# ------------------------------------------------------------------ Markdown

def _md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(doc: dict) -> str:
    meta = doc.get("meta", {})
    st = stats(doc)
    edition = meta.get("owasp_edition", "2025")
    fs = sorted(doc["findings"], key=priority_key, reverse=True)
    out = ["# Security assessment", "", verdict(doc, st), "",
           f"- Scanned: {meta.get('started', '')} UTC", f"- Standard: OWASP Top 10:{edition}",
           f"- Tool: vulnscan {meta.get('version', '')}", ""]
    for w in dict.fromkeys(doc.get("warnings", [])):
        out.append(f"> Note: {w}")
    out += ["", "## Severity", "", "| Severity | Findings |", "|---|---:|"]
    out += [f"| {SEV_WORD[s]} | {st['counts'][s]} |" for s in SEV_ORDER]
    out += ["", f"## OWASP Top 10:{edition}", "", "| Category | Findings | High or Critical |", "|---|---:|---:|"]
    for r in owasp_rows(doc):
        label = f"{r['id']} {r['name']}" + ("" if r["testable"] else " (not assessable by scanning)")
        out.append(f"| {_md(label)} | {r['count']} | {r['high']} |")
    top = [f for f in fs if f["severity"] in ("CRITICAL", "HIGH") or details(f).get("kev")][:10]
    if top:
        out += ["", "## Fix first", ""]
        for i, f in enumerate(top, 1):
            d = details(f)
            name = f"{d['component']}: {(d.get('cves') or [f['title']])[0]}" if d.get("component") else f["title"]
            out.append(f"{i}. **{_md(name)}** ({f['owasp']}): {_md(why(f))}")
    out += ["", "## All findings", "", "| Severity | Target | Finding | Fixed in | OWASP |", "|---|---|---|---|---|"]
    for f in fs:
        d = details(f)
        where = f"{f['host']}:{f['port']}" if f.get("port") else f["host"]
        title = f"{d['component']} {d['installed']}: {(d.get('cves') or [''])[0]} {d.get('summary', '')}" \
            if d.get("kind") == "package" else f["title"]
        out.append(f"| {SEV_WORD[f['severity']]} | {_md(where)} | {_md(title.strip())} | "
                   f"{_md(d.get('fixed') or '')} | {f['owasp']} |")
    return "\n".join(out) + "\n"


def write_reports(out_dir: str, docs: List[dict]) -> List[str]:
    doc = merge_docs(docs)
    paths = []
    for name, content in (("report.html", render_html(doc)), ("report.md", render_markdown(doc))):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        paths.append(path)
    return paths


def load_results(path: str) -> dict:
    if os.path.isdir(path):
        path = os.path.join(path, "results.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
