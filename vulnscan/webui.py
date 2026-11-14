"""Local web interface for engagements.  Standard library only, bound to 127.0.0.1.

Every request needs the random token printed at start-up, and the Host and Origin headers must
be local, which blocks other web pages (DNS rebinding / cross-site requests) from driving it.
All dynamic text is inserted into the page with textContent, never as HTML.
"""

from __future__ import annotations

import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from . import checklist
from .engage_cli import sorted_findings
from .engage_report import write_report
from .engagement import (Engagement, EngagementError, FINDING_STATUSES, list_engagements)

MAX_BODY = 1_000_000


def state_of(eng: Engagement) -> dict:
    d = eng.data
    return {"slug": eng.slug, "client": eng.client, "contact": d.get("contact", ""), "scope": d["scope"],
            "email_domains": eng.email_domains(), "currency": d.get("currency", "USD"),
            "authorization": d.get("authorization"), "authorization_problem": eng.authorization_problem(),
            "runs": d["runs"][-10:], "log": d["log"][-15:], "statuses": list(checklist.STATUSES),
            "finding_statuses": list(FINDING_STATUSES), "offer_total": eng.offer_total(),
            "findings": [dict(f, number=i) for i, f in enumerate(sorted_findings(eng), 1)],
            "checklist": eng.checklist_rows()}


class Handler(BaseHTTPRequestHandler):
    server_version = "vulnscan-ui"
    token = ""
    root: Optional[Path] = None
    port = 0

    def log_message(self, *a):  # quiet
        pass

    # --- helpers -------------------------------------------------------------------------
    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        if host not in (f"127.0.0.1:{self.port}", f"localhost:{self.port}"):
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in (f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}")

    def _token_ok(self, query: dict) -> bool:
        given = self.headers.get("X-Token") or (query.get("t") or [""])[0]
        return secrets.compare_digest(given, self.token)

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                             "connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _gate(self):
        if not self._host_ok():
            self._json(403, {"error": "bad host or origin"})
            return None
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if not self._token_ok(query):
            self._json(403, {"error": "missing or wrong token"})
            return None
        return parsed

    def _eng(self, slug: str) -> Engagement:
        return Engagement.load(slug, self.root)

    # --- routes --------------------------------------------------------------------------
    def do_GET(self):
        parsed = self._gate()
        if parsed is None:
            return
        parts = [p for p in parsed.path.split("/") if p]
        try:
            if not parts:
                page = PAGE.replace("__TOKEN__", self.token).encode()
                return self._send(200, page, "text/html; charset=utf-8")
            if parts == ["api", "engagements"]:
                return self._json(200, list_engagements(self.root))
            if len(parts) == 3 and parts[:2] == ["api", "e"]:
                return self._json(200, state_of(self._eng(parts[2])))
            if len(parts) == 3 and parts[0] == "report":
                eng = self._eng(parts[1])
                files = write_report(eng)
                html = next(p for p in files if str(p).endswith(".html"))
                return self._send(200, Path(html).read_bytes(), "text/html; charset=utf-8")
            self._json(404, {"error": "not found"})
        except EngagementError as exc:
            self._json(400, {"error": str(exc)})

    def do_POST(self):
        parsed = self._gate()
        if parsed is None:
            return
        parts = [p for p in parsed.path.split("/") if p]
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._json(413, {"error": "too large"})
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise EngagementError("body must be a JSON object")
            if parts == ["api", "new"]:
                scope = [s for s in str(body.get("scope", "")).replace(",", "\n").split() if s]
                eng = Engagement.create(str(body.get("client", "")), scope, self.root,
                                        str(body.get("contact", "")), [], str(body.get("currency") or "USD"))
                return self._json(200, state_of(eng))
            if len(parts) == 4 and parts[:2] == ["api", "e"]:
                eng, action = self._eng(parts[2]), parts[3]
                if action == "authorize":
                    eng.set_authorization(str(body.get("signer", "")), str(body.get("signed_on", "")),
                                          str(body.get("reference", "")), body.get("expires") or None)
                elif action == "scan":
                    eng.run_scan(str(body.get("ports") or "top"), 1.0, 200, bool(body.get("web", True)), None)
                elif action == "dns":
                    eng.run_dns()
                elif action == "finding":
                    eng.set_finding(str(body.get("key", "")), body.get("note"), body.get("fix"),
                                    body.get("price"), body.get("status"), "price" in body)
                elif action == "check":
                    eng.set_check(str(body.get("id", "")), body.get("status"), body.get("note"), body.get("fix"),
                                  body.get("price"), "price" in body)
                else:
                    return self._json(404, {"error": "not found"})
                return self._json(200, state_of(eng))
            self._json(404, {"error": "not found"})
        except (EngagementError, ValueError) as exc:
            self._json(400, {"error": str(exc)})


def make_server(root: Optional[Path], port: int = 8765, token: Optional[str] = None) -> ThreadingHTTPServer:
    token = token or secrets.token_urlsafe(24)
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    Handler.token, Handler.root, Handler.port = token, root, srv.server_address[1]
    srv.token = token  # type: ignore[attr-defined]
    return srv


def serve(root: Optional[Path], port: int = 8765, open_browser: bool = True) -> int:
    srv = make_server(root, port)
    url = f"http://127.0.0.1:{srv.server_address[1]}/?t={srv.token}"  # type: ignore[attr-defined]
    print(f"vulnscan UI: {url}\nPress Ctrl+C to stop. Only this computer can reach it.")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>vulnscan workbench</title><style>
:root{--bg:#f6f7f9;--fg:#1c2330;--mut:#667085;--card:#fff;--line:#d9dde5;--acc:#1f5fbf;--bad:#b42318;--ok:#067647}
@media(prefers-color-scheme:dark){:root{--bg:#12151b;--fg:#e6e9ef;--mut:#98a2b3;--card:#1b1f27;--line:#303642;--acc:#6ea8ff;--bad:#f97066;--ok:#47cd89}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}
header{display:flex;gap:12px;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line);background:var(--card);flex-wrap:wrap}
header h1{font-size:17px;margin:0}main{max-width:1000px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;margin:0 0 14px}
h2{font-size:16px;margin:0 0 8px}label{display:block;font-size:13px;color:var(--mut);margin:8px 0 2px}
input,select,textarea,button{font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px 8px}
input,textarea{width:100%}button{cursor:pointer;background:var(--acc);color:#fff;border-color:var(--acc)}button.sec{background:transparent;color:var(--fg);border-color:var(--line)}
button:disabled{opacity:.5}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.row>*{flex:0 0 auto}.grow{flex:1 1 200px!important}
.tag{font-size:12px;padding:1px 7px;border-radius:10px;border:1px solid var(--line)}.CRITICAL,.HIGH,.fail{color:var(--bad);border-color:var(--bad)}.pass{color:var(--ok);border-color:var(--ok)}
.mut{color:var(--mut);font-size:13px}.item{border-top:1px solid var(--line);padding:10px 0}.err{color:var(--bad)}nav{display:flex;gap:6px;margin:0 0 14px;flex-wrap:wrap}nav button.on{background:var(--acc);color:#fff}nav button{background:transparent;color:var(--fg);border-color:var(--line)}
</style></head><body>
<header><h1>vulnscan workbench</h1><select id="pick" aria-label="Engagement"></select><button class="sec" id="newbtn">New engagement</button><a id="rep" target="_blank" rel="noopener" class="mut">Open report</a><span id="busy" class="mut"></span></header>
<main><div id="err" class="err" role="alert"></div><div id="view"></div></main>
<script>
const T="__TOKEN__";let cur=null,S=null,tab="findings";
const $=id=>document.getElementById(id);
function h(tag,props,...kids){const e=document.createElement(tag);for(const[k,v]of Object.entries(props||{})){if(k==="class")e.className=v;else if(k.startsWith("on"))e.addEventListener(k.slice(2),v);else if(v!==null&&v!==undefined&&v!==false)e.setAttribute(k,v===true?"":v)}
for(const c of kids.flat())if(c!==null&&c!==undefined&&c!==false)e.append(c.nodeType?c:document.createTextNode(String(c)));return e}
async function api(path,body){$("err").textContent="";$("busy").textContent="working...";
try{const r=await fetch(path,{method:body?"POST":"GET",headers:{"X-Token":T,"Content-Type":"application/json"},body:body?JSON.stringify(body):undefined});
const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j}catch(e){$("err").textContent=e.message;throw e}finally{$("busy").textContent=""}}
async function loadList(sel){const l=await api("/api/engagements");const p=$("pick");p.replaceChildren(h("option",{value:""},"Choose..."),...l.map(x=>h("option",{value:x.slug},x.client)));
if(sel){p.value=sel}}
async function open(slug){cur=slug;if(!slug){S=null;$("rep").removeAttribute("href");return render()}S=await api("/api/e/"+encodeURIComponent(slug));
$("rep").href="/report/"+encodeURIComponent(slug)+"?t="+encodeURIComponent(T);render()}
async function act(action,body){S=await api("/api/e/"+encodeURIComponent(cur)+"/"+action,body);render()}
function field(label,id,val,type){return h("div",{},h("label",{for:id},label),h("input",{id,type:type||"text",value:val||""}))}
function render(){const v=$("view");v.replaceChildren();
if(!S){v.append(h("div",{class:"card"},h("h2",{},"Start"),h("p",{class:"mut"},"Pick an engagement above or create a new one.")));return}
v.append(head());
v.append(h("nav",{},["findings","checklist","scope"].map(t=>h("button",{class:t===tab?"on":"",onclick:()=>{tab=t;render()}},t[0].toUpperCase()+t.slice(1)))));
v.append(tab==="findings"?findings():tab==="checklist"?checks():scope())}
function head(){const a=S.authorization;return h("div",{class:"card"},h("h2",{},S.client),
h("div",{class:"mut"},"Scope: "+S.scope.join(", ")),
h("div",{class:a&&!S.authorization_problem?"":"err"},a?("Authorization: "+a.signer+", "+a.signed_on+(S.authorization_problem?" - "+S.authorization_problem:"")):"No signed authorization recorded: public targets cannot be scanned."),
h("div",{class:"mut"},S.findings.length+" findings, fixes priced: "+S.currency+" "+S.offer_total.toFixed(2)),
h("div",{class:"row",style:"margin-top:8px"},h("button",{onclick:()=>act("scan",{})},"Run scan"),h("button",{class:"sec",onclick:()=>act("dns",{})},"Check email records")))}
function noteBox(o,save){const sn=!o.note&&o.suggest_note,sf=!o.fix&&o.suggest_fix;const n=h("textarea",{rows:3,"aria-label":"What it means"},o.note||o.suggest_note||""),f=h("textarea",{rows:3,"aria-label":"What I can do"},o.fix||o.suggest_fix||""),p=h("input",{"aria-label":"Price",value:o.price??"",style:"width:110px"});
return [h("label",{},"What it means (your words)"+(sn?" - suggested, edit freely":"")),n,h("label",{},"What I can do about it"+(sf?" - suggested, edit freely":"")),f,h("div",{class:"row",style:"margin-top:6px"},h("span",{class:"mut"},"Price"),p,...save(n,f,p))]}
function findings(){const box=h("div",{});if(!S.findings.length)box.append(h("div",{class:"card mut"},"No findings yet. Run a scan or the email check."));
for(const f of S.findings){const st=h("select",{"aria-label":"Status"},S.finding_statuses.map(x=>h("option",{value:x,selected:x===f.status},x)));
box.append(h("div",{class:"card"},h("div",{class:"row"},h("span",{class:"tag "+f.severity},f.severity),h("strong",{class:"grow"},f.title),h("span",{class:"mut"},f.host+(f.port?":"+f.port:""))),
h("p",{class:"mut"},f.description),...noteBox(f,(n,fx,p)=>[st,h("button",{onclick:()=>act("finding",{key:f.key,note:n.value,fix:fx.value,price:p.value,status:st.value})},"Save")])))}return box}
function checks(){const box=h("div",{class:"card"});let area="";
for(const r of S.checklist){if(r.area!==area){area=r.area;box.append(h("h2",{style:"margin-top:12px"},area))}
const st=h("select",{"aria-label":"Result"},S.statuses.map(x=>h("option",{value:x,selected:x===r.manual},x)));
box.append(h("div",{class:"item"},h("div",{class:"row"},h("strong",{class:"grow"},r.title),h("span",{class:"tag "+r.effective},r.effective),h("span",{class:"tag"},r.coverage)),
h("div",{class:"mut"},r.look_for),r.ask?h("div",{class:"mut"},"Ask/inspect: "+r.ask):null,r.hint?h("div",{class:"mut"},"Note: "+r.hint):null,
...noteBox(r,(n,fx,p)=>[st,h("button",{onclick:()=>act("check",{id:r.id,status:st.value,note:n.value,fix:fx.value,price:p.value})},"Save")])))}return box}
function scope(){const a=S.authorization||{};const s=field("Signed by","a-s",a.signer),d=field("Date signed","a-d",a.signed_on,"date"),r=field("Letter reference","a-r",a.reference),x=field("Testing window ends","a-x",a.expires,"date");
return h("div",{class:"card"},h("h2",{},"Authorization letter"),h("p",{class:"mut"},"Record this only once the client has signed. Scans of public targets are blocked without it."),s,d,r,x,
h("p",{},h("button",{onclick:()=>act("authorize",{signer:$("a-s").value,signed_on:$("a-d").value,reference:$("a-r").value,expires:$("a-x").value})},"Save authorization")),
h("h2",{},"Recent activity"),h("pre",{class:"mut",style:"white-space:pre-wrap"},S.log.join("\n")))}
$("pick").addEventListener("change",e=>open(e.target.value).catch(()=>{}));
$("newbtn").addEventListener("click",()=>{const v=$("view");v.replaceChildren(h("div",{class:"card"},h("h2",{},"New engagement"),field("Client name","n-c"),field("Contact","n-t"),
h("div",{},h("label",{for:"n-s"},"Scope (domains/IPs, one per line)"),h("textarea",{id:"n-s",rows:3})),
h("p",{},h("button",{onclick:async()=>{try{const j=await api("/api/new",{client:$("n-c").value,contact:$("n-t").value,scope:$("n-s").value});await loadList(j.slug);await open(j.slug)}catch(e){}}},"Create"))))});
loadList().catch(()=>{});render();
</script></body></html>"""
