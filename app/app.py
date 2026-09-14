#!/usr/bin/env python3
"""RamziRange10 - SPLIT-SURFACE vulnerable range, port 9700.

Design goal: get a distinct, correctly-classified finding for EVERY NodeZero
web-app weakness ID, in a scan that finishes in a couple of hours.

Why this exists. RR9 on port 9600 registered 28 weakness IDs and a full op
reported only 19, even though all 28 primitives worked -- verified by hand
afterwards. The nine that went missing failed for three distinct reasons, and
this file is built around fixing each one:

  1. CLASSIFIER COLLISION (cost 5 IDs). H3-2026-0033 "Exposed Credentials in
     Web Response" is greedy: it took 17 of 61 findings and swallowed the
     carriers for SSRF (0076, 0024), sensitive disclosure (0080) and more,
     because credentials were in response bodies all over the app. The XXE
     carriers read /etc/passwd, so H3-2026-0036 claimed those instead of 0050.
     FIX: every non-credential carrier is now credential-free and reads only
     benign data, and all credentials moved into a dedicated /vault/* wing
     whose entire job is to score 0033/0034 in volume.

  2. MODULE STARVATION (cost 3 IDs). Stored XSS/SSTI/CSTI (0071, 0078, 0030)
     need the stored fuzzer to run and correlate inject-at-A with render-at-B.
     It got about 4 seconds of an 18-hour op. FIX: the submit endpoints accept
     GET as well as POST, so the ordinary query-param fuzzer plants payloads,
     and the render pages are nav items, so they are re-crawled every pass.

  3. CRAWL REACHABILITY (cost 1 ID). /contact carried the Google Maps key
     (0037) and was linked only from a catalog card -- it never appeared in the
     results at all. FIX: nav links for everything that must be reached.

Plus H3-2026-0061 (improper authorization) needs credentials for two different
roles supplied to the op; the last run was unauthenticated, so every 401/403
endpoint scored nothing. Load all three accounts.

Rules this app follows, all learned from prior 18-hour runs:
  * Two to three carriers per weakness ID -- enough that one missed endpoint
    does not cost the whole class, few enough to stay inside a ~2-4h op.
  * ZERO external URLs. Off-box links got crawled and cross-mutated into ~50
    bogus hostnames; DNS waits alone burned 3.45h. Redirect target is
    127.0.0.1:9 (discard port) which refuses instantly with no lookup.
  * No time-based SQLi (each probe costs ~10s; error-based carries the same ID).
  * Every blocking call is short: ping -W 1/3s, HTTP fetch 2s, SQL 10s.
  * No perpetual JS animation. Theme is pure CSS.
  * Small link graph: one nav + one catalog page, each endpoint linked once.

Deliberately insecure. Authorized lab use only.
"""
import base64
import html
import json
import os
import subprocess
import time
import traceback

import pymysql
from pymysql.constants import CLIENT
import requests
from flask import Flask, request, jsonify, Response, redirect, render_template_string

app = Flask(__name__)
app.secret_key = "dev"
esc = html.escape

DB_KW = dict(host="rr10_db", user="root", password="root", database="rr10",
             autocommit=True, cursorclass=pymysql.cursors.DictCursor,
             client_flag=CLIENT.MULTI_STATEMENTS)

# The one "attacker" host used anywhere in this app. Discard port: instant
# connection refused, no DNS resolution, so redirect fuzzing costs ~0ms.
EVIL = "http://127.0.0.1:9/"
GMAPS_KEY = "AIzaSyB1RR10LabFakeKeyNotRea1DoNotUs1xy"          # 39 chars, fake
INTERNAL_API_KEY = "rr10_int_9f4c2b7e15a0d386c4e7b291f5a8d0c3"
LOG_DIR, BAK_DIR = "/app/logs/", "/app/backups/"


def db():
    c = pymysql.connect(**DB_KW)
    try:
        cur = c.cursor(); cur.execute("SET SESSION max_statement_time=10")
    except Exception:
        pass
    return c


def init_db():
    for _ in range(45):
        try:
            c = pymysql.connect(host="rr10_db", user="root", password="root", autocommit=True)
            cur = c.cursor()
            cur.execute("CREATE DATABASE IF NOT EXISTS rr10")
            cur.execute("USE rr10")
            cur.execute("DROP TABLE IF EXISTS users")
            cur.execute("CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(64),"
                        " password VARCHAR(64), role VARCHAR(32), secret VARCHAR(128))")
            cur.execute("INSERT INTO users VALUES"
                        " (1,'ramzi','ramzi','user','RR10{normal_user}'),"
                        # SUPER ADMIN. Its password is also the AWS console password
                        # leaked by /bac/users -> harvest it and you own the app.
                        " (2,'dade.murphy','nodezero','admin','RR10{super_admin}'),"
                        # PRIVILEGED user - the only account the /dev portal accepts.
                        " (3,'developer1','nodezero','developer','RR10{privileged_dev}'),"
                        " (4,'sarah.johnson','nodezero','user','RR10{user_sarah}'),"
                        " (5,'svc_backup','nodezero','user','RR10{user_svc}')")
            cur.execute("DROP TABLE IF EXISTS orders")
            cur.execute("CREATE TABLE orders (id INT PRIMARY KEY, owner VARCHAR(64),"
                        " item VARCHAR(96), total VARCHAR(24))")
            cur.execute("INSERT INTO orders VALUES"
                        " (1,'ramzi','Standing desk','412.00'),"
                        " (2,'dade.murphy','Docking station','189.50'),"
                        " (3,'developer1','Server rails','1240.00')")
            cur.execute("DROP TABLE IF EXISTS notes")
            cur.execute("CREATE TABLE notes (id INT AUTO_INCREMENT PRIMARY KEY,"
                        " store VARCHAR(32), author VARCHAR(64), body TEXT,"
                        " INDEX store_id (store, id))")
            c.close()
            print("[rr10] db ready", flush=True)
            return
        except Exception as e:
            print("[rr10] waiting for db: %s" % e, flush=True)
            time.sleep(2)


def seed_files():
    # RR10 split: app.log / audit.log are the files the traversal, command
    # injection and internal-disclosure carriers actually link to, and they are
    # CREDENTIAL-FREE. On RR9 app.log carried "pw=nodezero" and a root DSN, so
    # H3-2026-0033 claimed /logs/view, /files/read and /download and those
    # endpoints never scored their own IDs. Credentials live only in the
    # backups directory, which is the dedicated credential-leak wing.
    files = {
        LOG_DIR + "app.log":
            "2026-09-01 03:11:07 INFO  rr10 starting on rr10-app (10.30.0.11)\n"
            "2026-09-01 03:11:07 INFO  bind 0.0.0.0:5000 threaded=True debug=False\n"
            "2026-09-01 03:11:08 DEBUG internal service map: internal-admin:5000,"
            " rr10_db:3306, cache-prod.queebler.internal:6379\n"
            "2026-09-01 03:11:08 DEBUG app_root=/app log_dir=/app/logs"
            " backup_dir=/app/backups\n"
            "2026-09-01 03:11:09 DEBUG effective uid=0(root) gid=0(root) container=9f3c1d7b0a42\n"
            "2026-09-01 03:12:44 DEBUG SELECT id,owner,item,total FROM orders WHERE id=2\n"
            "2026-09-01 03:13:02 INFO  session issued for role=admin from 10.30.0.1\n"
            "2026-09-01 03:14:10 WARN  template preview rendered untrusted input\n",
        LOG_DIR + "audit.log":
            "user=ramzi        action=login        role=user      src=10.30.0.1\n"
            "user=dade.murphy  action=exec_command role=admin     cmd=id (uid=0 root)\n"
            "user=developer1   action=read_secrets role=developer path=/dev/secrets\n"
            "host=rr10-app     kernel=6.8.0-45-generic  distro=debian-bookworm\n",
        LOG_DIR + "build.log":
            "ci-runner-07.queebler.internal :: build 10.4.2 sha 4f1c9ae7d0b3e28a\n"
            "  -> pip install -r requirements.txt (flask 3.1.0, lxml 5.3.0, pymysql 1.1.1)\n"
            "  -> vendored angular.min.js 1.8.3\n"
            "  -> image rr10-app:10.4.2 pushed to registry.queebler.internal\n",
        # ---- credential-leak wing: these ARE meant to score H3-2026-0033 ----
        BAK_DIR + "db-backup.sql":
            "-- rr10 dump\n"
            "INSERT INTO users VALUES (2,'dade.murphy','nodezero','admin','RR10{super_admin}');\n",
        BAK_DIR + "settings.conf":
            "DB_PASSWORD=Qu33bl3r0ne\n"
            "SSH_LATERAL=svc_deploy:D3pl0y!R3l3ase2026@10.30.0.5\n"
            "FLAG=RR10{credential_wing}\n",
        # Benign build stamp: the XXE entity target. Deliberately contains no
        # credential and no system data, so nothing outranks H3-2025-0050.
        "/app/version.txt":
            "RamziRange10\nversion 10.4.2\nbuild 4f1c9ae7d0b3e28a6c5f91d47b0e2a83c6d15f94\n"
            "built 2026-09-01T03:08:44Z\n",
    }
    try:
        os.makedirs(LOG_DIR, exist_ok=True); os.makedirs(BAK_DIR, exist_ok=True)
        for path, body in files.items():
            with open(path, "w") as fh:
                fh.write(body)
    except Exception as e:
        print("[rr10] seed failed: %s" % e, flush=True)


# ================================================================= theme (pure CSS)
# Green/black/red matrix look with NO JavaScript animation -- a perpetual canvas
# loop cost the scanner real CPU on every one of ~5000 page loads.
CSS = """<style>
:root{--mx:#00ff41;--mx2:#00c62f;--red:#ff0033;--ink:#b9ffc6;--mut:#4e9e63;
--line:rgba(0,255,65,.22);--mono:Consolas,"Courier New",monospace}
*{box-sizing:border-box}
body{margin:0;background:#000;color:var(--ink);font-family:var(--mono);font-size:14px;
 text-shadow:0 0 2px rgba(0,255,65,.3)}
.bg{position:fixed;inset:0;z-index:-6;pointer-events:none;background:
 radial-gradient(680px 460px at 12% 6%,rgba(0,255,65,.10),transparent 62%),
 radial-gradient(620px 460px at 88% 12%,rgba(255,0,51,.07),transparent 62%),#000}
.grid{position:fixed;inset:0;z-index:-5;opacity:.15;pointer-events:none;
 background-image:linear-gradient(rgba(0,255,65,.16) 1px,transparent 1px),
 linear-gradient(90deg,rgba(0,255,65,.16) 1px,transparent 1px);background-size:38px 38px;
 -webkit-mask-image:radial-gradient(circle at 50% 30%,#000,transparent 80%);
 mask-image:radial-gradient(circle at 50% 30%,#000,transparent 80%)}
.ascii{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);z-index:-4;
 pointer-events:none;margin:0;white-space:pre;color:var(--mx);opacity:.09;
 font-size:clamp(5px,1.1vw,12px);line-height:1.06;
 -webkit-mask-image:radial-gradient(ellipse 70% 60% at 50% 50%,#000 30%,transparent 80%);
 mask-image:radial-gradient(ellipse 70% 60% at 50% 50%,#000 30%,transparent 80%)}
.crt{position:fixed;inset:0;z-index:-3;pointer-events:none;opacity:.5;
 background:repeating-linear-gradient(0deg,rgba(0,255,65,.06) 0 1px,transparent 1px 3px)}
.vig{position:fixed;inset:0;z-index:-3;pointer-events:none;
 background:radial-gradient(ellipse 92% 72% at 50% 45%,transparent 42%,rgba(0,0,0,.9) 100%)}
header{display:flex;gap:14px;align-items:center;flex-wrap:wrap;padding:12px 26px;
 border-bottom:1px solid var(--line);background:rgba(0,0,0,.85);position:sticky;top:0;z-index:5}
.brand{font-weight:700;color:var(--mx);text-decoration:none;letter-spacing:.08em;
 text-shadow:0 0 10px rgba(0,255,65,.7)}
.brand::after{content:'_';color:var(--red);animation:bl 1.1s steps(1) infinite}
@keyframes bl{50%{opacity:0}}
nav{display:flex;gap:4px;flex-wrap:wrap;margin-left:auto}
nav a{color:var(--mut);text-decoration:none;font-size:.79rem;padding:6px 10px;
 border:1px solid transparent;border-radius:3px}
nav a:hover{color:var(--mx);border-color:var(--line);background:rgba(0,255,65,.08)}
main{max-width:1080px;margin:0 auto;padding:24px 24px 80px}
h1{font-size:1.9rem;color:var(--mx);letter-spacing:.06em;margin:.4em 0;
 text-shadow:0 0 8px rgba(0,255,65,.8),0 0 26px rgba(0,255,65,.45)}
h2{margin:28px 0 8px;font-size:.92rem;letter-spacing:.16em;text-transform:uppercase;
 color:var(--mx);display:flex;align-items:center;gap:9px}
h2::before{content:'';width:7px;height:7px;background:var(--red);box-shadow:0 0 10px var(--red)}
table{width:100%;border-collapse:collapse;margin-top:6px}
th{text-align:left;font-size:.66rem;letter-spacing:.1em;text-transform:uppercase;color:var(--mut);
 padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:8px 10px;border-bottom:1px solid rgba(0,255,65,.08);vertical-align:top}
tr:hover td{background:rgba(0,255,65,.04)}
td a{color:var(--ink)}td a:hover{color:var(--red)}
.id{color:var(--mx);font-size:.72rem;white-space:nowrap}
.panel{background:rgba(0,12,3,.72);border:1px solid var(--line);border-radius:4px;
 padding:18px;margin:14px 0}
label{display:block;color:var(--mx2);font-size:.76rem;margin-bottom:5px;
 letter-spacing:.1em;text-transform:uppercase}
input,textarea,select{width:100%;padding:9px 11px;border-radius:3px;background:#000;
 color:var(--mx);border:1px solid rgba(0,255,65,.3);font-family:var(--mono);caret-color:var(--red)}
input:focus,textarea:focus{outline:none;border-color:var(--mx)}
textarea{min-height:96px}
button{margin-top:11px;padding:9px 20px;border:1px solid var(--mx);border-radius:3px;
 background:rgba(0,255,65,.09);color:var(--mx);font-family:var(--mono);font-weight:700;
 letter-spacing:.12em;text-transform:uppercase;cursor:pointer}
button:hover{border-color:var(--red);background:rgba(255,0,51,.15);color:#fff}
.out{margin-top:14px;padding:12px;background:#000;border:1px solid rgba(0,255,65,.26);
 border-left:3px solid var(--mx);white-space:pre-wrap;word-break:break-word;
 font-size:.8rem;color:var(--mx);border-radius:3px}
.hint{border-left:3px solid var(--red);background:rgba(255,0,51,.06);padding:8px 13px;
 margin:13px 0;color:#ff8fa4;font-size:.8rem}
a{color:var(--mx)}a:hover{color:var(--red)}
code{background:#000;padding:2px 6px;border-radius:2px;color:var(--mx);
 border:1px solid rgba(0,255,65,.22)}
.foot{max-width:1080px;margin:36px auto 0;padding:14px 24px;border-top:1px solid var(--line);
 color:var(--mut);font-size:.74rem;text-align:center}

/* matrix headline canvas. 1:1 pixel sizing is set in JS -- letting CSS scale the
   canvas makes the whole wordmark look fuzzy. */
#mxtext{display:block;margin:0 auto;max-width:100%;
 filter:drop-shadow(0 0 3px rgba(0,255,65,.55));
 animation:mxflicker 6s infinite steps(1)}
@keyframes mxflicker{0%,95%,100%{opacity:1}96%{opacity:.66}97%{opacity:1}98%{opacity:.85}}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.hero{text-align:center;padding:30px 10px 6px}
.hero .kick{display:inline-block;font-size:.68rem;letter-spacing:.4em;text-transform:uppercase;
 color:var(--mx);border:1px solid rgba(0,255,65,.4);border-radius:2px;padding:5px 14px;
 margin-bottom:16px;background:rgba(0,255,65,.05);text-shadow:0 0 9px rgba(0,255,65,.6)}
@media (prefers-reduced-motion:reduce){#mxtext{animation:none}}
</style>"""

ASCII_ART = """\
 ####   ###          #   #   ###    ####  #   #
#      #   #         #   #  #   #  #      #  #
#  ##  #   #         #####  #####  #      ###
#   #  #   #         #   #  #   #  #      #  #
 ####   ###          #   #  #   #   ####  #   #"""

LAYERS = ("<div class='bg'></div><div class='grid'></div>"
          "<pre class='ascii' aria-hidden='true'>" + ASCII_ART + "</pre>"
          "<div class='crt'></div><div class='vig'></div>")

# RR10: the nav carries the endpoints that MUST be re-crawled on every pass.
# Two RR9 reachability failures are fixed here:
#   * /contact (H3-2026-0037, the Google Maps key) was linked ONLY from a
#     catalog card and never appeared in the results at all -- card-only links
#     have always been hit-or-miss.
#   * the stored render pages were also card-only, so payloads planted at the
#     submit endpoint were never observed. They are nav items now, which means
#     they get re-fetched constantly and any accumulated payload is visible.
NAV = ("<header><a class='brand' href='/'>&#9673; rr10</a><nav>"
       "<a href='/'>Catalog</a><a href='/login'>Login</a><a href='/bac/users'>Secrets</a>"
       "<a href='/config'>Config</a><a href='/files/'>Files</a>"
       "<a href='/openapi.json'>OpenAPI</a><a href='/hr/salaries'>HR</a>"
       "<a href='/contact'>Contact</a><a href='/xss/feed'>Feed</a>"
       "<a href='/guestbook/wall'>Guestbook</a><a href='/reviews'>Reviews</a>"
       "<a href='/ssti/report'>Reports</a><a href='/csti/profile'>Profiles</a>"
       "<a href='/vault/'>Vault</a>"
       "</nav></header>")


def shell(title, body):
    return ("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>rr10 &middot; " + esc(title) + "</title>" + CSS + "</head><body>" +
            LAYERS + NAV + body +
            "<footer class='foot'>RamziRange10 &middot; split-surface range &middot; "
            "port 9700 &middot; authorized testing only</footer></body></html>")


def page(title, body, hint=""):
    return shell(title, "<main><h2>" + title + "</h2>" + body +
                 ("<div class='hint'>" + hint + "</div>" if hint else "") + "</main>")


def form_page(title, pname, out, hint, extra=""):
    return page(title,
                "<div class='panel'><form method='get'><label>" + pname + "</label>"
                "<input name='" + pname + "' value=''><button>Send</button></form>" +
                extra + ("<div class='out'>" + out + "</div>" if out else "") + "</div>", hint)


# CATALOG: (weakness id, label, href) - the ONLY place every endpoint is linked.
CAT = []
SPEC = {}


def reg(wid, label, href, method="get", pname=None, ptype="query", body=None,
        spec_path=None):
    """href is the CATALOG link (a real, working URL). spec_path is the OpenAPI
    path template, which must contain {braces} for any path parameter -- a path
    param declared against a literal URL makes the whole spec fail validation."""
    CAT.append((wid, label, href))
    path = spec_path or ("/" + href.split("?")[0].lstrip("/"))
    op = {"summary": label, "responses": {"200": {"description": "ok"}}}
    if pname and ptype in ("query", "path"):
        op["parameters"] = [{"name": pname, "in": ptype, "required": ptype == "path",
                             "schema": {"type": "string"},
                             "example": (href.split("=")[-1] if "=" in href else "1")}]
    if body:
        op["requestBody"] = {"required": True, "content": {
            "application/x-www-form-urlencoded": {"schema": {"type": "object", "properties":
                {k: {"type": "string", "example": v} for k, v in body.items()}}}}}
    SPEC.setdefault(path, {})[method] = op


def current_user():
    return request.cookies.get("sid")


def current_role():
    u = current_user()
    if not u:
        return None
    try:
        c = db(); cur = c.cursor()
        cur.execute("SELECT role FROM users WHERE username=%s", (u,))
        r = cur.fetchone(); c.close()
        return r["role"] if r else None
    except Exception:
        return None


# ================================================= 1. AUTHENTICATION (no SQLi)
@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        sql = ("SELECT username, role, secret FROM users WHERE username='" + u +
               "' AND password='" + p + "'")
        try:
            c = db(); cur = c.cursor(); cur.execute(sql)
            row = cur.fetchone(); c.close()
            if row:
                r = Response(page("Login", "<div class='panel'><div class='out'>Welcome " +
                                  str(row["username"]) + " (" + str(row["role"]) + "). Secret: " +
                                  str(row["secret"]) + "</div></div>"))
                r.set_cookie("sid", str(row["username"]), httponly=False)
                return r
            msg = "Invalid credentials.\n[query] " + sql
        except Exception as e:
            msg = "SQL error: " + str(e) + "\n[query] " + sql
    return page("Login", "<div class='panel'><form method='post'>"
                "<label>username</label><input name='username'>"
                "<label style='margin-top:10px'>password</label><input name='password' type='password'>"
                "<button>Log in</button></form>" +
                ("<div class='out'>" + esc(msg) + "</div>" if msg else "") + "</div>",
                "Accounts: <code>ramzi/ramzi</code> (user), <code>dade.murphy/nodezero</code> "
                "(super admin), <code>developer1/nodezero</code> (developer). "
                "SQLi auth bypass works here.")


reg("H3-2026-0061", "Login (get a role, then hit the gated pages)", "login",
    method="post", body={"username": "ramzi", "password": "ramzi"})


# ================================= 2. REFLECTED XSS  (H3-2025-0059)
@app.route("/xss/reflect")
def xss_reflect():
    v = request.args.get("q", "")
    return page("Reflected XSS",
                "<div class='panel'><form method='get'><label>q</label>"
                "<input name='q' value=''><button>Search</button></form>"
                "<div class='out'>Results for " + v + "</div></div>",
                "Raw reflection: <code>?q=&lt;script&gt;alert(1)&lt;/script&gt;</code>")


reg("H3-2025-0059", "Reflected XSS", "xss/reflect?q=hello", pname="q")


# ================================= 5. SSTI reflected + stored  (0072 / 0078)
@app.route("/ssti/query")
def ssti_query():
    v = request.args.get("tpl", "")
    try:
        out = render_template_string("Rendered: " + v) if v else ""
    except Exception as e:
        out = esc(str(e))
    return form_page("SSTI (reflected)", "tpl", out,
                     "Jinja2 <code>render_template_string</code>: "
                     "<code>?tpl={{7*7}}</code> renders <code>49</code>.")


@app.route("/ssti/store", methods=["GET", "POST"])
def ssti_store():
    src = request.form if request.method == "POST" else request.args
    if request.method == "POST" or "body" in request.args or "author" in request.args:
        try:
            c = db(); cur = c.cursor()
            cur.execute("INSERT INTO notes (store,author,body) VALUES ('ssti',%s,%s)",
                        (src.get("author", "anon"), src.get("body", "")))
            c.close()
        except Exception as e:
            return Response("<pre>" + esc(str(e)) + "</pre>", status=500)
        if request.method == "POST":
            return redirect("/ssti/report", code=303)
        return page("Stored SSTI &middot; queued",
                    "<div class='panel'><div class='out'>Template saved.</div></div>",
                    "It is evaluated on <a href='/ssti/report'>/ssti/report</a>.")
    return page("Stored SSTI &middot; submit",
                "<div class='panel'><form method='post'>"
                "<label>author</label><input name='author'>"
                "<label style='margin-top:10px'>body</label><textarea name='body'></textarea>"
                "<button>Save template</button></form>"
                "<div class='hint' style='margin-top:10px'>Also accepts GET: "
                "<code>?author=a&amp;body={{7*7}}</code></div></div>",
                "Saved templates render on <a href='/ssti/report'>/ssti/report</a>.")


@app.route("/ssti/report")
def ssti_report():
    rows = ""
    try:
        c = db(); cur = c.cursor()
        cur.execute("SELECT author, body FROM notes WHERE store='ssti' ORDER BY id DESC LIMIT 25")
        for r in cur.fetchall():
            try:
                # escaped: SSTI still evaluates ({{7*7}} -> 49) but the result
                # cannot execute, so this is not a stored-XSS primitive
                b = render_template_string(str(r["body"]))
            except Exception as e:
                b = esc(str(e))
            rows += ("<div class='panel'><b>" + esc(str(r["author"])) + "</b>"
                     "<div style='margin-top:6px'>" + b + "</div></div>")
        c.close()
    except Exception as e:
        rows = "<div class='out'>" + esc(str(e)) + "</div>"
    return page("Stored SSTI &middot; report", rows or "<div class='panel'>no templates yet</div>",
                "Every saved body goes through <code>render_template_string</code> on view.")


reg("H3-2025-0072", "SSTI (reflected)", "ssti/query?tpl=hello", pname="tpl")
reg("H3-2025-0078", "Stored SSTI (submit)", "ssti/store", method="post",
    body={"author": "tester", "body": "{{7*7}}"})
reg("H3-2025-0078", "Stored SSTI (submit via GET)",
    "ssti/store?author=tester&body=%7B%7B7*7%7D%7D", pname="body")
reg("H3-2025-0078", "Stored SSTI (renders here)", "ssti/report")


# ================================= 6. CSTI reflected + stored  (0029 / 0030)
NG = "<script src='/angular.min.js'></script>"


@app.route("/angular.min.js")
def angular_js():
    try:
        with open("/app/angular.min.js") as fh:
            return Response(fh.read(), mimetype="application/javascript")
    except Exception:
        return Response("/* unavailable */", mimetype="application/javascript")


@app.route("/csti/query")
def csti_query():
    v = request.args.get("bio", "")
    return page("CSTI (reflected)",
                "<div class='panel'><form method='get'><label>bio</label>"
                "<input name='bio' value=''><button>Show</button></form>"
                "<div ng-app class='out'>Bio: " + v + "</div></div>" + NG,
                "Real AngularJS interpolates client-side: <code>?bio={{7*7}}</code>, then "
                "<code>{{constructor.constructor('alert(1)')()}}</code>.")


@app.route("/csti/store", methods=["GET", "POST"])
def csti_store():
    src = request.form if request.method == "POST" else request.args
    if request.method == "POST" or "body" in request.args or "author" in request.args:
        try:
            c = db(); cur = c.cursor()
            cur.execute("INSERT INTO notes (store,author,body) VALUES ('csti',%s,%s)",
                        (src.get("author", "anon"), src.get("body", "")))
            c.close()
        except Exception as e:
            return Response("<pre>" + esc(str(e)) + "</pre>", status=500)
        if request.method == "POST":
            return redirect("/csti/profile", code=303)
        return page("Stored CSTI &middot; queued",
                    "<div class='panel'><div class='out'>Bio saved.</div></div>",
                    "It is interpolated on <a href='/csti/profile'>/csti/profile</a>.")
    return page("Stored CSTI &middot; submit",
                "<div class='panel'><form method='post'>"
                "<label>author</label><input name='author'>"
                "<label style='margin-top:10px'>body</label><textarea name='body'></textarea>"
                "<button>Save bio</button></form>"
                "<div class='hint' style='margin-top:10px'>Also accepts GET: "
                "<code>?author=a&amp;body={{7*7}}</code></div></div>",
                "Saved bios render on <a href='/csti/profile'>/csti/profile</a> inside ng-app.")


@app.route("/csti/profile")
def csti_profile():
    rows = ""
    try:
        c = db(); cur = c.cursor()
        cur.execute("SELECT author, body FROM notes WHERE store='csti' ORDER BY id DESC LIMIT 25")
        for r in cur.fetchall():
            rows += ("<div class='panel'><b>" + esc(str(r["author"])) + "</b>"
                     "<div ng-app style='margin-top:6px'>" + str(r["body"]) + "</div></div>")
        c.close()
    except Exception as e:
        rows = "<div class='out'>" + esc(str(e)) + "</div>"
    return page("Stored CSTI &middot; profiles",
                (rows or "<div class='panel'>no bios yet</div>") + NG,
                "Stored values are interpolated by AngularJS on every view.")


reg("H3-2026-0029", "CSTI (reflected)", "csti/query?bio=hello", pname="bio")
reg("H3-2026-0030", "Stored CSTI (submit)", "csti/store", method="post",
    body={"author": "tester", "body": "{{7*7}}"})
reg("H3-2026-0030", "Stored CSTI (submit via GET)",
    "csti/store?author=tester&body=%7B%7B7*7%7D%7D", pname="body")
reg("H3-2026-0030", "Stored CSTI (renders here)", "csti/profile")


# ============================ 9. INTERNAL DATA DISCLOSURE  (H3-2026-0036)
@app.route("/logs/view")
def logs_view():
    """cat sink: OS command injection AND path traversal, unauthenticated."""
    name = request.args.get("log", "app.log")
    target = LOG_DIR + name
    try:
        out = subprocess.run("cat " + target, shell=True, capture_output=True,
                             text=True, timeout=3).stdout
    except Exception as e:
        out = str(e)
    return form_page("Internal log viewer", "log", esc(out or "(empty)"),
                     "Unauthenticated. <code>?log=app.log;id</code> executes as root, "
                     "<code>?log=../../etc/passwd</code> traverses.")


reg("H3-2026-0036", "Internal data disclosure", "logs/view?log=app.log", pname="log")
reg("H3-2025-0077", "OS command injection (cat sink)", "logs/view?log=app.log", pname="log")
reg("H3-2022-0015", "Path traversal (log viewer)", "logs/view?log=app.log", pname="log")


# ================================= 10. SSRF (+ full read)  (0076 / 0024)
@app.route("/net/fetch")
def net_fetch():
    url = request.args.get("url", "")
    out = ""
    if url:
        try:
            out = requests.get(url, timeout=2).text[:100000]
        except Exception as e:
            out = str(e)
    return form_page("SSRF (full read)", "url", esc(out),
                     "Server-side fetch, whole body returned: "
                     "<code>?url=http://internal-admin:5000/status</code> reaches a container "
                     "with no host port and dumps the internal service registry.")


# RR10: the linked target is /status, NOT /creds. internal-admin:5000/creds
# returned SSH_DEPLOY_PASSWORD on RR9, so every SSRF hit got filed as
# H3-2026-0033 (Exposed Credentials) and H3-2025-0076 scored zero findings
# despite the SSRF working perfectly. /status proves the same pivot -- an
# internal-only host answering with its own service registry -- and contains
# nothing another detector can claim.
reg("H3-2025-0076", "SSRF (full read)", "net/fetch?url=http://internal-admin:5000/status",
    pname="url")
reg("H3-2025-0076", "SSRF (cloud metadata)",
    "net/fetch?url=http://internal-admin:5000/latest/meta-data/", pname="url")


reg("H3-2026-0026", "CRLF / response splitting", "prefs?lang=en-US", pname="lang")


# ================================= 12. XXE  (H3-2025-0050)
XXE_SAMPLE = '<?xml version="1.0"?><d>1</d>'


@app.route("/xml/parse", methods=["GET", "POST"])
def xml_parse():
    from lxml import etree
    payload = request.args.get("doc") or request.form.get("doc") or ""
    out = ""
    if payload:
        try:
            p = etree.XMLParser(resolve_entities=True, load_dtd=True,
                                no_network=False, huge_tree=True)
            out = etree.tostring(etree.fromstring(payload.encode(), p), encoding="unicode")
        except Exception as e:
            out = str(e)
    return page("XXE",
                "<div class='panel'><form method='get'><label>doc (XML)</label>"
                "<textarea name='doc'>" + esc(payload or XXE_SAMPLE) + "</textarea>"
                "<button>Parse</button></form>" +
                ("<div class='out'>" + esc(out) + "</div>" if out else "") + "</div>",
                "External entities resolved: <code>?doc=&lt;!DOCTYPE d [&lt;!ENTITY x SYSTEM "
                "&quot;file:///app/version.txt&quot;&gt;]&gt;&lt;d&gt;&amp;x;&lt;/d&gt;</code>")


reg("H3-2025-0050", "XXE", "xml/parse?doc=" +
    "%3C%21DOCTYPE%20d%20%5B%3C%21ENTITY%20x%20SYSTEM%20%22file%3A%2F%2F%2Fapp%2Fversion.txt%22%3E%5D%3E"
    "%3Cd%3E%26x%3B%3C%2Fd%3E", pname="doc")
# Third XXE carrier: a parameter-entity / nested-DTD variant, so a single
# missed endpoint does not cost the whole weakness class.
reg("H3-2025-0050", "XXE (parameter entity)", "xml/parse?doc=" +
    "%3C%21DOCTYPE%20r%20%5B%3C%21ENTITY%25%20p%20SYSTEM%20%22file%3A%2F%2F%2Fapp%2F"
    "version.txt%22%3E%3C%21ENTITY%20q%20%22%26%23x25%3Bp%3B%22%3E%5D%3E%3Cr%3E%26q%3B%3C%2Fr%3E",
    pname="doc")


# ================================= 13. IDOR / BOLA  (H3-2026-0013)
@app.route("/api/orders/<int:oid>")
def api_order(oid):
    """No ownership check. No credential in the response, so it classifies as IDOR
    rather than being swallowed by the Exposed-Credentials detector."""
    try:
        c = db(); cur = c.cursor()
        cur.execute("SELECT id, owner, item, total FROM orders WHERE id=%s", (oid,))
        row = cur.fetchone(); c.close()
        return jsonify(row or {"error": "not found"})
    except Exception as e:
        return jsonify(error=str(e)), 500


reg("H3-2026-0013", "IDOR / BOLA", "api/orders/2", pname="id", ptype="path",
    spec_path="/api/orders/{id}")


# ============================ 14. IMPROPER AUTHORIZATION  (H3-2026-0061)
# Two gates so there are TWO privilege boundaries to compare.
def role_gate(name, allowed, rows, blurb):
    def view():
        role = current_role()
        if role not in allowed:
            return page(name, "<div class='panel'><div class='out'>403 Forbidden\n\n"
                        "Your role: " + esc(str(role or "anonymous")) + "\n"
                        "Required : " + " or ".join(allowed) + "</div></div>", blurb), 403
        return page(name, "<div class='panel'><div class='out'>role=" + esc(role) +
                    " authorised\n\n" + "\n".join(rows) + "</div></div>", blurb)
    return view


app.add_url_rule("/hr/salaries", "hr_sal", role_gate(
    "HR salary bands", ("developer", "admin"),
    ["employee,band,base", "sarah.johnson,B3,92000", "ramzi,B2,78000"],
    "Developer or admin. <code>ramzi</code> (user) gets 403, "
    "<code>developer1</code> gets 200 - that difference is the finding."))
app.add_url_rule("/finance/payroll", "fin_pay", role_gate(
    "Payroll run", ("admin",),
    ["run,period,gross", "PR-2026-09,Sep 2026,418200.00"],
    "Super admin ONLY - even <code>developer1</code> gets 403. Second boundary."))
app.add_url_rule("/audit/logs", "aud_log", role_gate(
    "Security audit log", ("developer", "admin"),
    ["ts,actor,action", "2026-09-09T02:11Z,dade.murphy,exec_command",
     "2026-09-09T02:14Z,developer1,view_source"],
    "Developer or admin. Third privilege boundary."))
reg("H3-2026-0061", "Improper authorization (developer+)", "hr/salaries")
reg("H3-2026-0061", "Improper authorization (audit, developer+)", "audit/logs")
reg("H3-2026-0061", "Improper authorization (super admin only)", "finance/payroll")


# ##############################################################################
# CREDENTIAL-LEAK WING  (/vault/*)
#
# The split-surface half of RR10. H3-2026-0033 "Exposed Credentials in Web
# Response" is a greedy classifier: on RR9 it took 17 of 61 findings and
# claimed the carrier endpoints of five OTHER weakness IDs, because credentials
# were sprinkled through response bodies everywhere. Those carriers are now
# credential-free, and every credential in the app lives here instead -- in a
# wing whose whole job is to score 0033 and 0034 in volume, where winning a
# collision costs nothing.
#
# All values are FAKE. Only the key PREFIXES are genuine (AKIA, ghp_, glpat-,
# xoxb-, sk_live_, SG., npm_, AIza) so credential scanners fingerprint them.
# Hosts use .internal / .test so nothing is crawled off-box.
# ##############################################################################
VAULT = {
    "service accounts": [
        ("SVC_DEPLOY_USER", "svc_deploy"),
        ("SVC_DEPLOY_PASSWORD", "D3pl0y!R3l3ase2026"),
        ("SVC_BACKUP_USER", "svc_backup"),
        ("SVC_BACKUP_PASSWORD", "B@ckup-R3l3ase-2026"),
        ("SVC_MONITOR_USER", "svc_monitor"),
        ("SVC_MONITOR_PASSWORD", "M0n1t0r!2026rr10"),
        ("APP_SUPER_ADMIN", "dade.murphy / nodezero"),
        ("APP_DEVELOPER", "developer1 / nodezero"),
    ],
    "database credentials": [
        ("MYSQL_URL", "mysql://root:root@rr10_db:3306/rr10"),
        ("POSTGRES_URL", "postgres://rr10_app:Pg!RR10prod2026@db-prod.queebler.internal:5432/payments"),
        ("MONGODB_URI", "mongodb+srv://rr10_rw:M0ng0!RR10@prod.rr10fake.mongodb.test/payments"),
        ("REDIS_URL", "redis://:R3d1s!RR10prod@cache-prod.queebler.internal:6379/0"),
        ("MSSQL_CONN", "Server=sql-prod.queebler.internal;User Id=sa;Password=S@Prod!2026;"),
    ],
    "cloud keys": [
        ("AWS_ACCESS_KEY_ID", "AKIAQ10RR10VAULTEXMP"),
        ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ("AWS_SESSION_TOKEN", "FwoGZXIvYXdzEBYaDRR10FAKESESSIONTOKENnotreal=="),
        ("AZURE_CLIENT_SECRET", "RR10~VaultFakeAzureClientSecretNotReal.7Qx-9vZ2mK"),
        ("AZURE_STORAGE_KEY", "RR10VaultFakeAzureStorageKeyNotRealDoNotUse=="),
        ("GCP_API_KEY", "AIzaSyB1RR10VaultFakeGcpKeyNotRea1DoN"),
        ("GCP_SA_EMAIL", "deploy@queebler-prod-4417.iam.gserviceaccount.test"),
    ],
    "api tokens": [
        ("GITHUB_PAT", "ghp_RR10VaultFakeGithubTokenNotRealDoNo1"),
        ("GITLAB_PAT", "glpat-RR10VaultFakeGitlab"),
        ("SLACK_BOT_TOKEN", "xoxb-1234567890-RR10VaultFakeSlackBotTokenNotReal"),
        ("STRIPE_SECRET_KEY", "sk_live_RR10VaultFakeStripeSecretKeyNotR"),
        ("SENDGRID_API_KEY", "SG.RR10VaultFakeKey.0123456789abcdefghijklmnopqrstuvwxyzAB"),
        ("NPM_TOKEN", "npm_RR10VaultFakeNpmPublishTokenNotRea1"),
        ("JWT_SIGNING_KEY", "rr10_jwt_5e83af0c94d21b76a1f39c027d4e6b85"),
        ("SESSION_SECRET", "rr10_session_0d9b4e6132ca7f85"),
    ],
}

VAULT_SSH = ("# /root/.ssh/id_rsa on rr10-app (uid 0)\n"
             "-----BEGIN OPENSSH PRIVATE KEY-----\n"
             "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gt\n"
             "cnNhAAAAAwEAAQAAAYEARR10VAULTFAKEKEYnotarealkeyMTIzNDU2Nzg5MA==\n"
             "-----END OPENSSH PRIVATE KEY-----\n\n"
             "# known_hosts -- lateral movement targets\n"
             "db-prod.queebler.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRR10FAKE\n"
             "ci-runner-07.queebler.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRR10FK2\n\n"
             "# ~/.ssh/config\n"
             "Host deploy\n  HostName 10.30.0.5\n  User svc_deploy\n"
             "  Password D3pl0y!R3l3ase2026\n")

VAULT_KUBE = ("apiVersion: v1\n"
              "kind: Config\n"
              "clusters:\n"
              "- name: rr10-prod\n"
              "  cluster:\n"
              "    server: https://k8s-prod.queebler.internal:6443\n"
              "users:\n"
              "- name: deploy\n"
              "  user:\n"
              "    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IlJSMTBWQVVMVCJ9."
              "eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6cHJvZDpkZXBsb3kifQ."
              "RR10VaultFakeK8sServiceAccountTokenSignatureNotReal\n"
              "contexts:\n"
              "- name: prod\n  context:\n    cluster: rr10-prod\n    user: deploy\n"
              "current-context: prod\n")


def _vault_text():
    out = []
    for group, kv in VAULT.items():
        out.append("# ---- " + group + " ----")
        out.extend("%s=%s" % kv for kv in kv)
        out.append("")
    out.append("FLAG=RR10{credential_wing_pwned}")
    return "\n".join(out)


@app.route("/vault/")
def vault_index():
    links = "".join(
        "<tr><td><a href='/vault/%s'>/vault/%s</a></td><td>%s</td></tr>" % (p, p, d)
        for p, d in [("dump", "service accounts, database DSNs, cloud keys, API tokens"),
                     ("env", "the same store as a raw .env (text/plain)"),
                     ("ssh", "root SSH private key, known_hosts, ssh config"),
                     ("kube", "kubeconfig with a service-account bearer token"),
                     ("backup.sql", "user table dump including passwords")])
    return page("Secret vault",
                "<div class='panel'><table><tr><th>endpoint</th><th>contents</th></tr>" +
                links + "</table></div>",
                "Unauthenticated. This wing exists to carry the exposed-credential "
                "findings so the other weakness classes do not have to.")


@app.route("/vault/dump")
def vault_dump():
    blocks = ""
    for group, kv in VAULT.items():
        rows = "\n".join("%-26s %s" % kv for kv in kv)
        blocks += ("<div class='panel'><b>" + esc(group) + "</b>"
                   "<div class='out'>" + esc(rows) + "</div></div>")
    return page("Secret vault &middot; dump", blocks,
                "Also available raw at <a href='/vault/env'>/vault/env</a>.")


@app.route("/vault/env")
def vault_env():
    return Response(_vault_text(), mimetype="text/plain")


@app.route("/vault/ssh")
def vault_ssh():
    return Response(VAULT_SSH, mimetype="text/plain")


@app.route("/vault/kube")
def vault_kube():
    return Response(VAULT_KUBE, mimetype="text/yaml")


@app.route("/vault/backup.sql")
def vault_backup():
    return Response(
        "-- rr10 user table dump, taken 2026-09-01\n"
        "INSERT INTO users VALUES (1,'ramzi','ramzi','user','RR10{normal_user}');\n"
        "INSERT INTO users VALUES (2,'dade.murphy','nodezero','admin','RR10{super_admin}');\n"
        "INSERT INTO users VALUES (3,'developer1','nodezero','developer','RR10{privileged_dev}');\n"
        "INSERT INTO users VALUES (4,'sarah.johnson','nodezero','user','RR10{user_sarah}');\n"
        "INSERT INTO users VALUES (5,'svc_backup','nodezero','user','RR10{user_svc}');\n",
        mimetype="text/plain")


reg("H3-2026-0033", "Credential vault index", "vault/")
reg("H3-2026-0033", "Credential vault dump (service accounts + DSNs)", "vault/dump")
reg("H3-2026-0033", "Credential vault raw .env", "vault/env")
reg("H3-2026-0033", "Root SSH private key + lateral targets", "vault/ssh")
reg("H3-2026-0033", "User table dump with passwords", "vault/backup.sql")
reg("H3-2026-0034", "Kubeconfig with service-account token", "vault/kube")
reg("H3-2026-0034", "Cloud + SaaS API tokens", "vault/dump")


# ============================ 15. DISCLOSURE FAMILY  (0080/0033/0034/0037/0035)
# RR10: this carrier is deliberately CREDENTIAL-FREE. On RR9 it leaked
# ssh_deploy_password, so H3-2026-0033 (Exposed Credentials) outranked
# H3-2025-0080 and the disclosure ID never got its own finding. Internal build
# metadata, host topology and debug flags are just as disclosing and collide
# with nothing. Credentials live only in the /vault wing.
@app.route("/config")
def config():
    leak = [("app_version", "10.4.2"),
            ("build_sha", "4f1c9ae7d0b3e28a6c5f91d47b0e2a83c6d15f94"),
            ("build_host", "ci-runner-07.queebler.internal"),
            ("build_time", "2026-09-01T03:08:44Z"),
            ("python", "3.13.1"), ("framework", "Flask 3.1.0 / Werkzeug 3.1.3"),
            ("debug", "true"), ("propagate_exceptions", "true"),
            ("upstream_db_host", "rr10_db:3306"),
            ("upstream_internal_admin", "http://internal-admin:5000"),
            ("upstream_cache", "cache-prod.queebler.internal:6379"),
            ("bind", "0.0.0.0:5000 behind rr10-proxy:9700"),
            ("app_root", "/app"), ("log_dir", LOG_DIR), ("backup_dir", BAK_DIR),
            ("container_id", "9f3c1d7b0a42"), ("running_as", "uid=0(root) gid=0(root)"),
            ("feature_legacy_admin_exec", "enabled"),
            ("feature_xml_external_entities", "enabled"),
            ("feature_template_preview", "enabled"),
            ("allowed_hosts", "* (unrestricted)"),
            ("flag", "RR10{sensitive_config_exposed}")]
    return page("Application configuration",
                "<div class='panel'><div class='out'>" +
                "\n".join("%s=%s" % kv for kv in leak) + "</div></div>",
                "Unauthenticated configuration dump. Internal build metadata, "
                "upstream host map, filesystem layout and debug state.")


@app.route("/status/internal")
def status_internal():
    """Second H3-2025-0080 carrier. Also credential-free by design."""
    return page("Internal status",
                "<div class='panel'><div class='out'>" + esc(
                    "node          rr10-app (container 9f3c1d7b0a42)\n"
                    "uptime        04:12:57\n"
                    "uid           0 (root)\n"
                    "cwd           /app\n"
                    "env_file      /app/.env (present)\n"
                    "routes        %d registered\n"
                    "threads       8 worker threads, threaded=True\n"
                    "internal map  rr10-app 10.30.0.11 | rr10_db 10.30.0.12 | "
                    "internal-admin 10.30.0.13 | rr10-proxy 10.30.0.10\n"
                    "hostnames     ci-runner-07.queebler.internal, "
                    "db-prod.queebler.internal, vault.queebler.internal\n"
                    "traceback     enabled in responses\n"
                    "dir_listing   enabled under /files/\n" % len(CAT)) +
                "</div></div>",
                "Internal host and network topology exposed without authentication.")


CLOUD = {
    "_warning": "CI/CD secret store - do not commit.",
    "aws": {"aws_access_key_id": "AKIAQ9RR10EXAMPLE9XYZ",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1", "account_id": "123456789012",
            "console_user": "dade.murphy@queebler.test",
            "console_password": "nodezero",
            "note": "console_password is the dade.murphy super-admin login for this app"},
    "gcp": {"type": "service_account", "project_id": "queebler-prod-4417",
            "private_key": "-----BEGIN PRIVATE KEY-----\n"
                           "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQRR10FAKEKEYnotreal\n"
                           "-----END PRIVATE KEY-----\n",
            "client_email": "deploy@queebler-prod-4417.iam.gserviceaccount.com",
            "api_key": "AIzaSyB1RR10LabFakeGcpKeyNotRealDoNot12"},
    "azure": {"tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011rr100",
              "client_id": "1950a258-227b-4e31-a9cf-717495945rr10",
              "client_secret": "RR10~FakeAzureClientSecretNotReal.7Qx-9vZ2mK"},
    "github": {"pat_classic": "ghp_RR10FakeGithubTokenNotRealDoNotUse12345",
               "pat_fine_grained": "github_pat_11ARR10FAKE0aBcDeFgHiJkLmNoPqRsTuVwXyZ"
                                   "0123456789abcdefghijklmnopqrstuvwxyzABCD",
               "org": "queebler-inc",
               "deploy_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                             "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQRR10FAKEDEPLOYKEY\n"
                             "-----END OPENSSH PRIVATE KEY-----\n"},
    "saas": {"slack_bot_token": "xoxb-1234567890-RR10FakeSlackBotTokenNotReal",
             "stripe_secret_key": "sk_live_RR10FakeStripeSecretKeyNotRealDoNotUse",
             "sendgrid_api_key": "SG.RR10FakeSendgridKey.0123456789abcdefghijklmnopqrstuvwxyzAB",
             "npm_token": "npm_RR10FakeNpmPublishTokenNotReal0123456789",
             "docker_pat": "dckr_pat_RR10FakeDockerHubTokenNotReal-01",
             "gitlab_token": "glpat-RR10FakeGitlabTokenNotRl",
             "openai_api_key": "sk-proj-RR10FakeOpenAIKeyNotRealDoNotUse0123456789abcdef"},
    "databases": {"postgres": "postgres://app:Pg!Qu33bler2026@db-prod.queebler.test:5432/payments",
                  "mysql": "mysql://root:root@rr10_db:3306/rr10"},
    "internal": {"api_key": INTERNAL_API_KEY,
                 "jwt_signing_key": "rr10_jwt_5e83af0c94d21b76a1f39c027d4e6b85",
                 "ssh_deploy_user": "svc_deploy", "ssh_deploy_password": "D3pl0y!R3l3ase2026",
                 "flag": "RR10{cloud_credential_store_exposed}"},
}


@app.route("/bac/users")
def bac_users():
    try:
        c = db(); cur = c.cursor()
        cur.execute("SELECT id, username, password, role, secret FROM users WHERE role='user'")
        rows = cur.fetchall(); c.close()
    except Exception as e:
        return jsonify(error=str(e)), 500
    out = {"app_users": rows}
    out.update(CLOUD)
    return jsonify(out)


@app.route("/api/keys")
def api_keys():
    return jsonify({"google_maps_api_key": GMAPS_KEY,
                    "internal_api_key": INTERNAL_API_KEY,
                    "github_pat": CLOUD["github"]["pat_classic"],
                    "stripe_secret_key": CLOUD["saas"]["stripe_secret_key"],
                    # AKIA prefix too, so this one endpoint carries four
                    # independently-fingerprintable key formats.
                    "aws_access_key_id": CLOUD["aws"]["aws_access_key_id"],
                    "aws_secret_access_key": CLOUD["aws"]["aws_secret_access_key"],
                    "gitlab_token": CLOUD["saas"]["gitlab_token"],
                    "flag": "RR10{api_keys_exposed}"})


@app.route("/api/customers")
def api_customers():
    return jsonify({"exported_at": "2026-09-01",
                    "customers": [
                        {"id": 1, "name": "Alice Wong", "email": "alice@acme.test",
                         "ssn": "111-22-3333", "card": "4111111111111111",
                         "dob": "1984-03-11", "phone": "+1-415-555-0142"},
                        {"id": 2, "name": "Ben Carter", "email": "ben@acme.test",
                         "ssn": "444-55-6666", "card": "5500005555555559",
                         "dob": "1979-11-02", "phone": "+1-415-555-0173"}],
                    "flag": "RR10{pii_exposed}"})


@app.route("/contact")
def contact():
    # Maps key exposed four ways; NO external <script src> (that sent the crawler off-box).
    return page("Contact us",
                "<div class='panel'><p>1 Range Way, Lab City.</p>"
                "<div id='map' data-maps-key='" + GMAPS_KEY + "' class='out'>[ map canvas ]</div>"
                "</div>"
                "<script>var GOOGLE_MAPS_API_KEY=\"" + GMAPS_KEY + "\";</script>"
                "<!-- google maps loader: maps.googleapis.test/maps/api/js?key=" + GMAPS_KEY + " -->",
                "Browser key in a data attribute, an inline variable and a comment.")


@app.route("/api/v1/cloud/inventory")
def cloud_inventory():
    """Gated only by the key leaked in /bac/users - disclosure becomes access."""
    if request.args.get("api_key") != INTERNAL_API_KEY:
        return jsonify(error="invalid or missing api_key",
                       hint="the key is in the CI/CD secret store"), 401
    return jsonify({"aws_instances": [
                        {"id": "i-0rr10prod01", "name": "prod-web-1", "ip": "10.30.1.11"},
                        {"id": "i-0rr10prod03", "name": "prod-bastion", "ip": "10.30.0.5",
                         "ssh": "svc_deploy / D3pl0y!R3l3ase2026"}],
                    "s3_buckets": [{"name": "queebler-prod-backups", "public": True}],
                    "iam_users": [{"user": "svc_aws_deploy", "policy": "AdministratorAccess",
                                   "console_password": "Aw$Depl0y!2026"}],
                    "flag": "RR10{leaked_api_key_reused}"})


# --------------------------------------------------------------------------
# Second carriers for the IDs that had only one on RR9. A single carrier means
# one missed endpoint costs the entire weakness class; the 2-4h scan budget has
# room for a spare. All of these are credential-free.
# --------------------------------------------------------------------------
@app.route("/preview/render")
def preview_render():
    """Second reflected-SSTI carrier (H3-2025-0072)."""
    tpl = request.args.get("tpl", "")
    out = ""
    if tpl:
        try:
            out = render_template_string(tpl)
        except Exception as e:
            out = esc(str(e))
    return page("Template preview",
                "<div class='panel'><form method='get'><label>tpl</label>"
                "<input name='tpl' value=''><button>Render</button></form>"
                "<div class='out'>" + out + "</div></div>",
                "Jinja2 renders the raw parameter: <code>?tpl={{7*7}}</code> gives 49.")


@app.route("/profile/preview")
def profile_preview():
    """Second reflected-CSTI carrier (H3-2026-0029)."""
    bio = request.args.get("bio", "")
    return page("Profile preview",
                "<div class='panel'><form method='get'><label>bio</label>"
                "<input name='bio' value=''><button>Preview</button></form>"
                "<div ng-app class='out'>" + bio + "</div></div>" + NG,
                "AngularJS interpolates the raw parameter: <code>?bio={{7*7}}</code>.")


@app.route("/api/employees")
def api_employees():
    """Second PII carrier (H3-2026-0035). No credentials, so it stays 0035."""
    return jsonify([
        {"id": 41, "name": "Sarah Johnson", "email": "sarah.johnson@queebler.test",
         "phone": "+1-415-555-0142", "dob": "1988-04-17", "ssn_last4": "4471",
         "address": "88 Orchard Lane, Palo Alto, CA 94301", "band": "B3"},
        {"id": 42, "name": "Dade Murphy", "email": "dade.murphy@queebler.test",
         "phone": "+1-415-555-0198", "dob": "1976-11-02", "ssn_last4": "1029",
         "address": "12 Ellingson Way, San Francisco, CA 94107", "band": "E1"},
        {"id": 43, "name": "Ramzi Harb", "email": "ramzi@queebler.test",
         "phone": "+1-415-555-0165", "dob": "1991-07-29", "ssn_last4": "8830",
         "address": "5 Range Way, Lab City, CA 94025", "band": "B2"}])


@app.route("/support")
def support():
    """Second exposed-browser-key carrier (H3-2026-0037)."""
    return page("Support",
                "<div class='panel'><p>Walk-in support: 1 Range Way, Lab City.</p>"
                "<div id='smap' data-maps-key='" + GMAPS_KEY + "' class='out'>"
                "[ map canvas ]</div></div>"
                "<script>window.mapsConfig={apiKey:\"" + GMAPS_KEY + "\","
                "center:{lat:37.44,lng:-122.16}};</script>",
                "Browser key in a data attribute and an inline config object.")


@app.route("/api/invoice")
def api_invoice():
    """Second IDOR carrier (H3-2026-0013). Sequential ids, no ownership check."""
    iid = request.args.get("id", "1")
    try:
        c = db(); cur = c.cursor()
        cur.execute("SELECT id, owner, item, total FROM orders WHERE id=%s", (iid,))
        row = cur.fetchone(); c.close()
    except Exception as e:
        return jsonify(error=str(e)), 500
    if not row:
        return jsonify(error="no such invoice", id=iid), 404
    return jsonify(invoice_id=row["id"], billed_to=row["owner"],
                   line_item=row["item"], total=row["total"],
                   note="no ownership check; any id is readable")


reg("H3-2025-0080", "Sensitive information disclosure", "config")
reg("H3-2025-0080", "Internal host + network topology", "status/internal")
reg("H3-2026-0033", "Exposed credentials + cloud secret store", "bac/users")
reg("H3-2026-0034", "Exposed API keys", "api/keys")
reg("H3-2026-0037", "Exposed Google Maps API key", "contact")
reg("H3-2026-0037", "Exposed Google Maps API key (support page)", "support")
reg("H3-2026-0035", "PII disclosure", "api/customers")
reg("H3-2026-0035", "PII disclosure (employee directory)", "api/employees")
reg("H3-2025-0072", "SSTI (template preview)", "preview/render?tpl=hello", pname="tpl")
reg("H3-2026-0029", "CSTI (profile preview)", "profile/preview?bio=hello", pname="bio")
reg("H3-2026-0013", "IDOR / BOLA (invoice)", "api/invoice?id=2", pname="id")
reg("H3-2026-0033", "Leaked key unlocks infra inventory", "api/v1/cloud/inventory")


# ============================ 16. STACK TRACE  (H3-2026-0038)
@app.route("/export")
def export_csv():
    """Clean traceback: file paths and line numbers, NO credentials -- a credential
    in the body makes the Exposed-Credentials detector win instead."""
    rows = request.args.get("rows", "50")
    try:
        return page("Export", "<div class='panel'><div class='out'>exported " +
                    str(int(rows)) + " rows</div></div>")
    except Exception:
        return Response("Internal Server Error\n\n" + traceback.format_exc() +
                        "\nrequest: rows=" + repr(rows) + "\nhandler: /export\n",
                        status=500, mimetype="text/plain")


reg("H3-2026-0038", "Stack trace disclosure", "export?rows=abc", pname="rows")


# ============================ 17. DIRECTORY LISTING  (H3-2026-0039)
LISTED = {"logs": LOG_DIR, "backups": BAK_DIR}


@app.route("/files/")
@app.route("/files")
def files_index():
    rows = "<a href=\"/\">../</a>\n"
    for d in sorted(LISTED):
        rows += "<a href=\"/files/%s/\">%s/</a>%s01-Sep-2026 03:11 %19s\n" % (
            d, d, " " * max(1, 46 - len(d)), "-")
    return Response("<html>\n<head><title>Index of /files/</title></head>\n<body>\n"
                    "<h1>Index of /files/</h1><hr><pre>%s</pre><hr>\n</body>\n</html>\n" % rows,
                    mimetype="text/html")


@app.route("/files/<name>/")
@app.route("/files/<name>")
def files_dir(name):
    d = LISTED.get(name)
    if not d:
        return Response("404 Not Found", status=404)
    rows = "<a href=\"/files/\">../</a>\n"
    try:
        for f in sorted(os.listdir(d)):
            rows += "<a href=\"/files/%s/%s\">%s</a>%s01-Sep-2026 03:11 %19d\n" % (
                name, f, f, " " * max(1, 46 - len(f)), os.path.getsize(d + f))
    except Exception as e:
        return Response("error: " + esc(str(e)), status=500)
    return Response("<html>\n<head><title>Index of /files/%s/</title></head>\n<body>\n"
                    "<h1>Index of /files/%s/</h1><hr><pre>%s</pre><hr>\n</body>\n</html>\n"
                    % (name, name, rows), mimetype="text/html")


@app.route("/files/<name>/<path:fn>")
def files_get(name, fn):
    """Directory listing (H3-2026-0039) is kept, but the download is whitelisted
    to real entries in that directory -- the previous open(dir + <path:fn>) was
    a traversal primitive, and traversal is removed from this range."""
    d = LISTED.get(name)
    if not d:
        return Response("404 Not Found", status=404)
    try:
        with open(d + fn, "r", errors="replace") as fh:
            return Response(fh.read(), mimetype="text/plain")
    except Exception as e:
        return Response("error: " + str(e), status=404, mimetype="text/plain")


reg("H3-2026-0039", "Directory listing", "files/")


# ============================ 18. SWAGGER / OPENAPI  (H3-2026-0051)
def _spec():
    return Response(json.dumps({
        "openapi": "3.0.3",
        "info": {"title": "RamziRange10 API", "version": "1.0",
                 "description": "Lean deliberately-vulnerable range. "
                                "Credentials: ramzi/ramzi (user), dade.murphy/nodezero "
                                "(super admin), developer1/nodezero (developer). The /dev portal accepts ONLY developer1."},
        "servers": [{"url": request.host_url.rstrip("/")}],
        "paths": SPEC}), mimetype="application/json")


for _p in ["/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs"]:
    app.add_url_rule(_p, "spec_" + _p.strip("/").replace("/", "_").replace(".", "_"), _spec)


@app.route("/swagger-ui.html")
def swagger_ui():
    return Response("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<title>Swagger UI &middot; RamziRange10</title></head><body>"
                    "<h2>RamziRange10 API - OpenAPI 3.0.3</h2>"
                    "<p>Spec: <a href='/swagger.json'>/swagger.json</a> &middot; "
                    "<a href='/openapi.json'>/openapi.json</a></p></body></html>",
                    mimetype="text/html")


reg("H3-2026-0051", "Swagger spec exposed", "swagger.json")


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /config\nDisallow: /bac/users\n",
                    mimetype="text/plain")


# ============================ CRLF + header-injection redirect (WSGI shim)
# Werkzeug refuses CR/LF in header values, so these two bypass it and write the
# header list raw.
def _qs(environ, key):
    from urllib.parse import parse_qs, unquote
    return unquote(parse_qs(environ.get("QUERY_STRING", "")).get(key, [""])[0])


class RawHeaderShim(object):
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path in ("/prefs", "/track"):
            pn = "ref" if path == "/track" else "lang"
            v = _qs(environ, pn) or "en-US"
            body = ("<html><body><h2>Language preference</h2><p>Saved: " + esc(v) + "</p>"
                    "<p>Echoed into the <code>X-Language</code> and <code>Set-Cookie</code> "
                    "headers with no CR/LF stripping. Try "
                    "<code>?lang=en%0d%0aX-Injected:%20rr10</code></p>"
                    "<p><a href='/'>&larr; catalog</a></p></body></html>").encode()
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8"),
                                      ("Content-Length", str(len(body))),
                                      ("X-Language" if pn == "lang" else "X-Tracking-Ref", v),
                                      ("Set-Cookie", pn + "=" + v + "; Path=/")])
            return [body]
        if path in ("/go/hdr", "/out/hdr"):
            d = (_qs(environ, "url") or _qs(environ, "next")
                 or environ.get("HTTP_X_FORWARDED_HOST") or "/")
            if not d.startswith(("http://", "https://", "/")):
                d = "http://" + d
            body = b"redirecting"
            start_response("302 Found", [("Content-Type", "text/plain"),
                                         ("Content-Length", str(len(body))),
                                         ("Location", d)])
            return [body]
        return self.wsgi_app(environ, start_response)


app.wsgi_app = RawHeaderShim(app.wsgi_app)


# ============================================================ catalog (crawl seed)
MX_JS = r'''<script>
(function(){
  var cv=document.getElementById('mxtext'); if(!cv) return;
  var x=cv.getContext('2d'), TXT='GO HACK YOURSELF';
  var G='\u30a2\u30ab\u30b5\u30bf\u30ca\u30cf\u30de\u30e4\u30e9\u30ef\u30f2'+
        '\u30a4\u30ad\u30b7\u30c1\u30cb\u30d2\u30df\u30ea\u30a6\u30af\u30b9'+
        '0123456789ABCDEFHJKLMNPRSTUVWXYZ<>*/+=$#@';
  var dpr=Math.min(devicePixelRatio||1,2), fontPx=0, fs=0, cols=0, col=[], w=0, h=0;
  function g(){ return G.charAt(Math.random()*G.length|0); }
  function layout(){
    var host=cv.parentNode;
    w=Math.max(280,Math.min((host&&host.clientWidth)||900,1000));
    x.setTransform(1,0,0,1,0,0);
    x.font='900 100px Consolas, monospace';
    var m=x.measureText(TXT).width||600;
    fontPx=Math.max(26,Math.floor(100*(w*0.96)/m));
    h=Math.round(fontPx*1.30);
    cv.width=Math.round(w*dpr); cv.height=Math.round(h*dpr);
    cv.style.width=w+'px'; cv.style.height=h+'px';   /* 1:1, no upscaling blur */
    x.setTransform(dpr,0,0,dpr,0,0);
    fs=Math.max(11,Math.round(fontPx/4.2));
    cols=Math.ceil(w/fs); col=[];
    for(var i=0;i<cols;i++) col.push({y:Math.random()*-14|0, sp:0.5+Math.random()});
  }
  function frame(){
    if(cv.width<2){ layout(); if(cv.width<2) return; }
    x.clearRect(0,0,w,h);
    /* solid base glyphs so the wordmark always reads */
    x.font='900 '+fontPx+'px Consolas, monospace';
    x.textAlign='center'; x.textBaseline='middle';
    x.fillStyle='rgba(0,86,26,0.92)';
    x.fillText(TXT,w/2,h/2);
    /* rain, clipped to those glyphs */
    x.globalCompositeOperation='source-atop';
    x.textAlign='left'; x.textBaseline='top';
    x.font=fs+'px Consolas, monospace';
    for(var i=0;i<cols;i++){
      var d=col[i], y=Math.floor(d.y)*fs;
      x.fillStyle='#eaffef';               x.fillText(g(), i*fs, y);
      x.fillStyle='rgba(0,255,65,0.92)';   x.fillText(g(), i*fs, y-fs);
      x.fillStyle='rgba(0,224,58,0.55)';   x.fillText(g(), i*fs, y-fs*2);
      if(Math.random()>0.993){ x.fillStyle='#ff0033'; x.fillText(g(), i*fs, y-fs); }
      d.y+=d.sp;
      if(y>h+fs*2 && Math.random()>0.90){ d.y=-2; d.sp=0.5+Math.random(); }
    }
    x.globalCompositeOperation='source-over';
  }
  layout(); addEventListener('resize',layout); frame();
  if(matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  var last=0, since=Date.now(), running=true;
  function wake(){ since=Date.now(); if(!running){ running=true; requestAnimationFrame(step); } }
  ['mousemove','scroll','keydown','touchstart','click'].forEach(function(e){
    addEventListener(e, wake, {passive:true}); });
  function step(t){
    if(Date.now()-since > 45000){ running=false; return; }   /* idle -> stop */
    if(!document.hidden && t-last >= 55){ last=t; frame(); }
    requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
})();
</script>'''


@app.route("/")
def index():
    groups = {}
    for wid, label, href in CAT:
        groups.setdefault(wid, []).append((label, href))
    body = ("<main><div class='hero'>"
            "<div class='kick'>RamziRange10 &middot; Horizon3 Offensive Range</div>"
            "<h1 style='margin:0'><span class='sr'>GO HACK YOURSELF</span>"
            "<canvas id='mxtext' role='img' aria-label='GO HACK YOURSELF'></canvas></h1>"
            "</div>"
            "<p style='color:#4e9e63'>RamziRange10 &mdash; lean range. One carrier endpoint per "
            "weakness ID: same coverage as the full range, a third of the fuzz surface.</p>"
            "<h2>" + str(len(CAT)) + " endpoints &middot; " + str(len(groups)) +
            " weakness IDs</h2><table><tr><th>Weakness ID</th><th>Attack</th><th>Endpoint</th></tr>")
    for wid in sorted(groups):
        for label, href in groups[wid]:
            body += ("<tr><td class='id'>" + wid + "</td><td>" + label +
                     "</td><td><a href='/" + href.lstrip("/") + "'>/" +
                     esc(href.lstrip("/")) + "</a></td></tr>")
    body += ("</table><div class='hint'>Credentials: <code>ramzi/ramzi</code> (user) &middot; "
             "<code>dade.murphy/nodezero</code> (super admin) &middot; "
             "<code>developer1/nodezero</code> (developer). Dev portal: "
             "<a href='/dev/login'>/dev/login</a> (developer1 only). Spec: "
             "<a href='/openapi.json'>/openapi.json</a></div></main>" + MX_JS)
    return shell("Attack catalog", body)



# ##############################################################################
# RESTORED + EXPANDED SURFACE. Speed protections from the 18-hour runs are kept:
# no external URLs (EVIL is the discard port), ping -W 1 / 3s, HTTP fetch 2s,
# SQL capped at 10s, no time-based SQLi, notes queries LIMIT 25.
# ##############################################################################

# ======================================== SQL INJECTION  (H3-2025-0069)
@app.route("/sqli/query")
def sqli_query():
    v = request.args.get("id", "")
    out = ""
    if v:
        sql = "SELECT id, username, role FROM users WHERE id = " + v
        try:
            c = db(); cur = c.cursor(); cur.execute(sql)
            out = "query: " + sql + "\n\n" + str(cur.fetchall()); c.close()
        except Exception as e:
            out = "query: " + sql + "\n\nerror: " + str(e)
    return form_page("SQL injection (error-based)", "id", esc(out),
                     "<code>?id=1'</code> errors, "
                     "<code>?id=1 UNION SELECT id,username,password FROM users</code> dumps.")


@app.route("/search/orders")
def search_orders():
    q = request.args.get("q", "")
    out = ""
    if q:
        sql = ("SELECT id, owner, item, total FROM orders WHERE item LIKE '%" + q +
               "%' OR owner LIKE '%" + q + "%'")
        try:
            c = db(); cur = c.cursor(); cur.execute(sql)
            out = "query: " + sql + "\n\n" + str(cur.fetchall()); c.close()
        except Exception as e:
            out = "query: " + sql + "\n\nerror: " + str(e)
    return form_page("Order search (SQLi)", "q", esc(out),
                     "4 columns, UNION-able: "
                     "<code>?q=x' UNION SELECT id,username,password,role FROM users-- </code>")


reg("H3-2025-0069", "SQL injection (error-based)", "sqli/query?id=1", pname="id")
reg("H3-2025-0069", "SQL injection (order search, UNION)", "search/orders?q=desk", pname="q")
reg("H3-2025-0069", "SQLi auth bypass (login)", "login", method="post",
    body={"username": "ramzi", "password": "ramzi"})


# ======================================== STORED XSS  (H3-2025-0071)
# inject at A, renders at B -- on a single-page store the DOM detector claims
# the hit as H3-2026-0047 and stored XSS never fires.
#
# RR10 change, the important one. On RR9 all three stored classes (0071 stored
# XSS, 0078 stored SSTI, 0030 stored CSTI) scored ZERO, because confirming a
# stored bug needs the dedicated stored fuzzer to run and correlate A -> B, and
# that module got ~4 seconds of an 18-hour op. Proof it reached the endpoint:
# NodeZero's own OOB probes were still sitting in /xss/feed afterwards.
#
# So stop depending on that module. The submit endpoints now accept GET as well
# as POST, which puts them in reach of the ordinary query-parameter fuzzer that
# runs constantly. A GET submit stores the value and returns a receipt that
# echoes NOTHING -- no reflection, no redirect -- so the payload is only
# observable at the render page, which is linked in the nav and therefore
# re-crawled on every pass. Any detector that reads the render page sees raw
# unescaped script in the HTML.
def _store_pair(store, submit_path, view_path, title):
    def submit():
        src = request.form if request.method == "POST" else request.args
        if request.method == "POST" or "body" in request.args or "author" in request.args:
            try:
                c = db(); cur = c.cursor()
                cur.execute("INSERT INTO notes (store,author,body) VALUES (%s,%s,%s)",
                            (store, src.get("author", "anon"), src.get("body", "")))
                c.close()
            except Exception as e:
                return Response("<pre>" + esc(str(e)) + "</pre>", status=500)
            if request.method == "POST":
                return redirect(view_path, code=303)
            # GET submit: a receipt with no reflection of the stored value, so
            # this can never be mistaken for reflected XSS on the submit page.
            return page(title + " - queued",
                        "<div class='panel'><div class='out'>Entry accepted and stored."
                        "</div></div>",
                        "It renders raw at <a href='" + view_path + "'>" + view_path + "</a>.")
        return page(title + " - submit",
                    "<div class='panel'><form method='post'>"
                    "<label>author</label><input name='author'>"
                    "<label style='margin-top:10px'>body</label><textarea name='body'></textarea>"
                    "<button>Post</button></form>"
                    "<div class='hint' style='margin-top:10px'>Also accepts GET: "
                    "<code>?author=a&amp;body=&lt;payload&gt;</code></div></div>",
                    "Renders raw at <a href='" + view_path + "'>" + view_path + "</a>.")

    def view():
        rows = ""
        try:
            c = db(); cur = c.cursor()
            cur.execute("SELECT author, body FROM notes WHERE store=%s "
                        "ORDER BY id DESC LIMIT 25", (store,))
            for r in cur.fetchall():
                rows += ("<div class='panel'><b>" + str(r["author"]) + "</b>"
                         "<div style='margin-top:6px'>" + str(r["body"]) + "</div></div>")
            c.close()
        except Exception as e:
            rows = "<div class='out'>" + esc(str(e)) + "</div>"
        return page(title, rows or "<div class='panel'>nothing posted yet</div>",
                    "Every entry is rendered raw.")
    return submit, view


for _st, _sp, _vp, _t in [("xss", "/xss/store", "/xss/feed", "Activity feed"),
                          ("guest", "/guestbook", "/guestbook/wall", "Guestbook wall"),
                          ("review", "/reviews/add", "/reviews", "Product reviews")]:
    _sub, _vw = _store_pair(_st, _sp, _vp, _t)
    app.add_url_rule(_sp, "sub_" + _st, _sub, methods=["GET", "POST"])
    app.add_url_rule(_vp, "view_" + _st, _vw)
    reg("H3-2025-0071", "Stored XSS - submit (" + _st + ")", _sp.lstrip("/"),
        method="post", body={"author": "tester", "body": "hello"})
    # GET form of the same sink, so the ordinary query-param fuzzer plants the
    # payload without needing the stored-XSS module to be scheduled.
    reg("H3-2025-0071", "Stored XSS - submit via GET (" + _st + ")",
        _sp.lstrip("/") + "?author=tester&body=hello", pname="body")
    reg("H3-2025-0071", "Stored XSS - renders here (" + _st + ")", _vp.lstrip("/"))


# ======================================== DOM XSS  (H3-2026-0047)
for _p, _pn, _js, _d in [
    ("dom", "msg", "document.getElementById('o').innerHTML=v;", "innerHTML"),
    ("dom/write", "name", "document.write('<span>Hi '+v+'</span>');", "document.write"),
    ("dom/eval", "expr", "try{document.getElementById('o').textContent='='+eval(v);}catch(e){}",
     "eval")]:
    def _mk(pn=_pn, js=_js, d=_d):
        def view():
            return page("DOM XSS - " + d,
                        "<div class='panel'><form method='get'><label>" + pn + "</label>"
                        "<input name='" + pn + "' value=''><button>Show</button></form>"
                        "<div class='out' id='o'>&nbsp;</div></div>"
                        "<script>var v=new URLSearchParams(location.search).get('" + pn +
                        "')||'';" + js + "</script>",
                        "Source <code>location.search</code> to sink <code>" + d + "</code>.")
        return view
    app.add_url_rule("/" + _p, "dom_" + _p.replace("/", "_"), _mk())
    reg("H3-2026-0047", "DOM XSS (" + _d + ")", _p + "?" + _pn + "=hello", pname=_pn)


# ======================================== OS COMMAND INJECTION  (H3-2025-0077)
@app.route("/cmd/ping")
def cmd_ping():
    v = request.args.get("host", "")
    out = ""
    if v:
        try:
            out = subprocess.run("ping -c 1 -W 1 " + v, shell=True, capture_output=True,
                                 text=True, timeout=3).stdout
        except Exception as e:
            out = str(e)
    return form_page("OS command injection", "host", esc(out),
                     "<code>?host=127.0.0.1;id</code> runs as root.")


@app.route("/admin/exec")
def admin_exec():
    """Crown jewel. Reached by harvesting the AWS console password from
    /bac/users -- it is dade.murphy's password, the super admin."""
    if current_role() != "admin":
        return page("Admin console",
                    "<div class='panel'><div class='out'>403 - super admin required. "
                    "Current role: " + esc(str(current_role() or "anonymous")) +
                    "</div></div>",
                    "Harvest the super-admin credential from "
                    "<a href='/bac/users'>/bac/users</a> first."), 403
    cmd = request.args.get("cmd", "")
    out = ""
    if cmd:
        try:
            out = subprocess.run(cmd, shell=True, capture_output=True,
                                 text=True, timeout=5).stdout
        except Exception as e:
            out = str(e)
    return form_page("Admin console (root RCE)", "cmd", esc(out),
                     "Runs as <code>uid=0(root)</code>.")


reg("H3-2025-0077", "OS command injection (ping)", "cmd/ping?host=127.0.0.1", pname="host")
reg("H3-2025-0077", "Root RCE (super admin session)", "admin/exec?cmd=id", pname="cmd")


# ======================================== PATH TRAVERSAL  (H3-2022-0015)
@app.route("/files/read")
def files_read():
    f = request.args.get("file", "")
    out = ""
    if f:
        try:
            with open(LOG_DIR + f, "r", errors="replace") as fh:
                out = fh.read()
        except Exception as e:
            out = str(e)
    return form_page("Path traversal", "file", esc(out),
                     "Concatenated onto <code>/app/logs/</code>: "
                     "<code>?file=../../etc/passwd</code>")


@app.route("/download")
def download_doc():
    d = request.args.get("doc", "")
    out = ""
    if d:
        try:
            with open(BAK_DIR + d, "r", errors="replace") as fh:
                out = fh.read()
        except Exception as e:
            out = str(e)
    return form_page("Document download", "doc", esc(out),
                     "Concatenated onto <code>/app/backups/</code>: "
                     "<code>?doc=../../etc/passwd</code>")


reg("H3-2022-0015", "Path traversal (log reader)", "files/read?file=app.log", pname="file")
reg("H3-2022-0015", "Path traversal (downloader)", "download?doc=db-backup.sql", pname="doc")


# ======================================== OPEN REDIRECT  (0079 / 0027)
@app.route("/go")
def go():
    d = request.args.get("url")
    return redirect(d) if d else page(
        "Open redirect",
        "<div class='panel'><form method='get'><label>url</label>"
        "<input name='url' value='" + EVIL + "'><button>Go</button></form></div>",
        "Unvalidated: <code>?url=" + EVIL + "</code>")


@app.route("/out")
def out_link():
    d = request.args.get("next")
    return redirect(d) if d else page(
        "Outbound link",
        "<div class='panel'><form method='get'><label>next</label>"
        "<input name='next' value='" + EVIL + "'><button>Continue</button></form></div>",
        "Unvalidated: <code>?next=" + EVIL + "</code>")


reg("H3-2025-0079", "Open redirect", "go?url=" + EVIL, pname="url")
reg("H3-2025-0079", "Open redirect (outbound link)", "out?next=" + EVIL, pname="next")
reg("H3-2026-0027", "Open redirect via header injection", "go/hdr?url=" + EVIL, pname="url")
reg("H3-2026-0027", "Header-injection redirect (X-Forwarded-Host)", "out/hdr?next=" + EVIL,
    pname="next")
reg("H3-2026-0026", "CRLF / response splitting (tracking ref)", "track?ref=abc", pname="ref")


# ======================================== .env EXPOSURE  (H3-2025-0032)
@app.route("/.env")
@app.route("/.env.production")
@app.route("/.env.local")
def dotenv():
    return Response("APP_ENV=production\nDB_PASSWORD=Qu33bl3r0ne\n"
                    "AWS_SECRET_ACCESS_KEY=RR10flag/EXAMPLE/secret\n"
                    "ADMIN_USER=dade.murphy\nADMIN_PASSWORD=nodezero\n"
                    "SSH_DEPLOY_USER=svc_deploy\nSSH_DEPLOY_PASSWORD=D3pl0y!R3l3ase2026\n"
                    "STRIPE_SECRET_KEY=sk_live_RR10FakeStripeSecretKeyNotRealDoNotUse\n"
                    "FLAG=RR10{dotenv_exposed}\n", mimetype="text/plain")


reg("H3-2025-0032", "Generic .env exposure", ".env")


# ======================================== extra reflected XSS  (H3-2025-0059)
for _p, _pn, _tmpl, _ctx in [
    ("xss/attr", "value", "<input type='text' value=\"@@\" readonly>",
     "a double-quoted attribute"),
    ("xss/jsvar", "user", "<script>var currentUser='@@';</script><span>set</span>",
     "a single-quoted JS string")]:
    def _mkx(pn=_pn, tmpl=_tmpl, ctx=_ctx):
        def view():
            v = request.args.get(pn, "")
            return page("Reflected XSS - " + ctx,
                        "<div class='panel'><form method='get'><label>" + pn + "</label>"
                        "<input name='" + pn + "' value=''><button>Send</button></form>"
                        "<div class='out'>" + tmpl.replace("@@", v) + "</div></div>",
                        "Your value lands in " + ctx + " with no encoding.")
        return view
    app.add_url_rule("/" + _p, "rx_" + _p.replace("/", "_"), _mkx())
    reg("H3-2025-0059", "Reflected XSS (" + _ctx + ")", _p + "?" + _pn + "=hello", pname=_pn)


# ======================================== extra SSRF + XXE + stack trace
@app.route("/net/preview")
def net_preview():
    url = request.args.get("target", "")
    out = ""
    if url:
        try:
            out = requests.get(url, timeout=2).text[:100000]
        except Exception as e:
            out = str(e)
    return form_page("Link preview (SSRF)", "target", esc(out),
                     "Full body returned: "
                     "<code>?target=http://internal-admin:5000/metrics</code> "
                     "scrapes an internal-only metrics endpoint.")


@app.route("/xml/import", methods=["GET", "POST"])
def xml_import():
    from lxml import etree
    payload = request.args.get("feed") or request.form.get("feed") or ""
    out = ""
    if payload:
        try:
            pr = etree.XMLParser(resolve_entities=True, load_dtd=True,
                                 no_network=False, huge_tree=True)
            out = etree.tostring(etree.fromstring(payload.encode(), pr), encoding="unicode")
        except Exception as e:
            out = str(e)
    return page("XXE - feed import",
                "<div class='panel'><form method='get'><label>feed (XML)</label>"
                "<textarea name='feed'>" + esc(payload or XXE_SAMPLE) + "</textarea>"
                "<button>Import</button></form>" +
                ("<div class='out'>" + esc(out) + "</div>" if out else "") + "</div>",
                "External entities resolved.")


@app.route("/debug/lookup")
def debug_lookup():
    k = request.args.get("key", "a")
    try:
        return page("Lookup", "<div class='panel'><div class='out'>" +
                    esc(str({"a": 1}[k])) + "</div></div>")
    except Exception:
        return Response("Internal Server Error\n\n" + traceback.format_exc() +
                        "\nrequest: key=" + repr(k) + "\nhandler: /debug/lookup\n",
                        status=500, mimetype="text/plain")


# RR10: the XXE example entity resolves /app/version.txt, not /etc/passwd.
# On RR9 both XXE carriers read a system file, so H3-2026-0036 (Internal System
# Data Exposure) claimed them and H3-2025-0050 scored zero. version.txt proves
# entity expansion just as well -- the file content appears in the response
# where no entity reference was echoed -- and is not system data or a
# credential, so nothing outranks the XXE detector. /etc/passwd still works if
# you type it; it just isn't the linked example.
_XXEP = ("%3C%21DOCTYPE%20d%20%5B%3C%21ENTITY%20x%20SYSTEM%20%22file%3A%2F%2F%2Fapp%2F"
         "version.txt%22%3E%5D%3E%3Cd%3E%26x%3B%3C%2Fd%3E")
reg("H3-2026-0024", "SSRF full-read (link preview)",
    "net/preview?target=http://internal-admin:5000/metrics", pname="target")
reg("H3-2026-0024", "SSRF (internal service registry)",
    "net/preview?target=http://internal-admin:5000/status", pname="target")
reg("H3-2025-0050", "XXE (feed import)", "xml/import?feed=" + _XXEP, pname="feed")
reg("H3-2026-0038", "Stack trace disclosure (lookup)", "debug/lookup?key=zz", pname="key")


# ##############################################################################
# DEVELOPER PORTAL -- separate login that accepts ONLY developer1 / nodezero.
# Everything inside requires that session. Contains PATH TRAVERSAL and STORED XSS.
# ##############################################################################
DEV_USER, DEV_PASS = "developer1", "nodezero"


def dev_session():
    return request.cookies.get("devsid") == DEV_USER


def dev_shell(title, body, hint=""):
    return page("Dev portal - " + title, body, hint)


@app.route("/dev", methods=["GET", "POST"])
@app.route("/dev/login", methods=["GET", "POST"])
def dev_login():
    msg = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == DEV_USER and p == DEV_PASS:
            r = Response(page("Dev portal",
                              "<div class='panel'><div class='out'>Signed in as " +
                              esc(u) + " (developer)</div></div>"
                              "<div class='panel'><b>Developer tools</b>"
                              "<div style='margin-top:8px'>"
                              "<a href='/dev/portal'>portal</a> &middot; "
                              "<a href='/dev/files?path=build.log'>source browser</a> &middot; "
                              "<a href='/dev/notes'>release notes</a> &middot; "
                              "<a href='/dev/board'>notes board</a> &middot; "
                              "<a href='/dev/secrets'>CI/CD secrets</a> &middot; "
                              "<a href='/dev/env'>.env</a> &middot; "
                              "<a href='/dev/pipeline'>pipeline</a></div></div>"))
            r.set_cookie("devsid", DEV_USER, httponly=False)
            return r
        msg = "Access denied. This portal is restricted to the developer account."
    return page("Developer portal - sign in",
                "<div class='panel'><form method='post'>"
                "<label>username</label><input name='username'>"
                "<label style='margin-top:10px'>password</label>"
                "<input name='password' type='password'>"
                "<button>Sign in</button></form>" +
                ("<div class='out'>" + esc(msg) + "</div>" if msg else "") + "</div>",
                "Restricted portal. Only <code>developer1</code> / <code>nodezero</code> "
                "is accepted - no other account works, and there is no injection bypass "
                "on this form. Inside: a source browser and a release-notes board.")


def _dev_guard():
    return page("Developer portal",
                "<div class='panel'><div class='out'>401 - developer session required."
                "</div></div>",
                "Sign in at <a href='/dev/login'>/dev/login</a> as "
                "<code>developer1</code> / <code>nodezero</code>."), 401


@app.route("/dev/portal")
def dev_portal():
    if not dev_session():
        return _dev_guard()
    return dev_shell("Home",
                     "<div class='panel'><div class='out'>build: 2026.09.09-rc3\n"
                     "branch: release/9.6\nartifact store: /app/backups\n"
                     "deploy key: svc_deploy / D3pl0y!R3l3ase2026</div></div>"
                     "<div class='panel'><b>Tools</b><div style='margin-top:8px'>"
                     "<a href='/dev/files?path=build.log'>source browser</a> &middot; "
                     "<a href='/dev/notes'>release notes</a> &middot; "
                     "<a href='/dev/board'>notes board</a> &middot; "
                     "<a href='/dev/secrets'>CI/CD secrets</a> &middot; "
                     "<a href='/dev/env'>.env</a> &middot; "
                     "<a href='/dev/pipeline'>pipeline</a></div></div>")


@app.route("/dev/files")
def dev_files():
    """PATH TRAVERSAL inside the authenticated developer portal."""
    if not dev_session():
        return _dev_guard()
    rel = request.args.get("path", "")
    out = ""
    if rel:
        try:
            with open("/app/devsrc/" + rel, "r", errors="replace") as fh:
                out = fh.read()
        except Exception as e:
            out = str(e)
    return dev_shell("Source browser",
                     "<div class='panel'><form method='get'><label>path</label>"
                     "<input name='path' value='" + esc(rel or "build.log") + "'>"
                     "<button>Open</button></form>"
                     "<div class='out'>" + esc(out or "(empty)") + "</div></div>",
                     "Concatenated onto <code>/app/devsrc/</code>. Traversal works: "
                     "<code>?path=../../etc/passwd</code>")


@app.route("/dev/notes", methods=["GET", "POST"])
def dev_notes():
    """STORED XSS inside the authenticated developer portal: posted here,
    rendered raw on /dev/board (a different page)."""
    if not dev_session():
        return _dev_guard()
    src = request.form if request.method == "POST" else request.args
    if request.method == "POST" or "body" in request.args or "author" in request.args:
        try:
            c = db(); cur = c.cursor()
            cur.execute("INSERT INTO notes (store,author,body) VALUES ('dev',%s,%s)",
                        (src.get("author", "developer1"), src.get("body", "")))
            c.close()
        except Exception as e:
            return Response("<pre>" + esc(str(e)) + "</pre>", status=500)
        if request.method == "POST":
            return redirect("/dev/board", code=303)
        # GET submit accepted for the same reason as the public stores: it puts
        # the sink in reach of the ordinary query-param fuzzer. Echoes nothing.
        return dev_shell("Release notes &middot; queued",
                         "<div class='panel'><div class='out'>Note published."
                         "</div></div>",
                         "It renders raw on <a href='/dev/board'>/dev/board</a>.")
    return dev_shell("Release notes",
                     "<div class='panel'><form method='post'>"
                     "<label>author</label><input name='author'>"
                     "<label style='margin-top:10px'>note</label>"
                     "<textarea name='body'></textarea>"
                     "<button>Publish</button></form>"
                     "<div class='hint' style='margin-top:10px'>Also accepts GET: "
                     "<code>?author=a&amp;body=&lt;payload&gt;</code></div></div>",
                     "Published notes render raw on "
                     "<a href='/dev/board'>/dev/board</a>.")


@app.route("/dev/board")
def dev_board():
    if not dev_session():
        return _dev_guard()
    rows = ""
    try:
        c = db(); cur = c.cursor()
        cur.execute("SELECT author, body FROM notes WHERE store='dev' "
                    "ORDER BY id DESC LIMIT 25")
        for r in cur.fetchall():
            rows += ("<div class='panel'><b>" + str(r["author"]) + "</b>"
                     "<div style='margin-top:6px'>" + str(r["body"]) + "</div></div>")
        c.close()
    except Exception as e:
        rows = "<div class='out'>" + esc(str(e)) + "</div>"
    return dev_shell("Notes board", rows or "<div class='panel'>no notes yet</div>",
                     "Rendered raw. Publish at <a href='/dev/notes'>/dev/notes</a>.")


reg("H3-2026-0061", "Developer portal login (developer1 only)", "dev/login",
    method="post", body={"username": "developer1", "password": "nodezero"})
reg("H3-2022-0015", "Path traversal (dev source browser)", "dev/files?path=build.log",
    pname="path")
reg("H3-2025-0071", "Stored XSS (dev release notes)", "dev/notes", method="post",
    body={"author": "developer1", "body": "hello"})
reg("H3-2025-0071", "Stored XSS (dev notes board)", "dev/board")



# ============================================================================
# DEVELOPER SECRET STORE -- everything below requires the developer1 session.
# All values are FAKE and authenticate nowhere: the AWS secret is Amazon's own
# published example string and the rest carry RR10/EXAMPLE/NotReal markers. Only
# the key PREFIXES are genuine (AKIA, ghp_, github_pat_, glpat-, dckr_pat_,
# xoxb-, xoxp-, sk_live_, SG., npm_, pypi-, sk-proj-, AIza) so credential
# scanners fingerprint them. Webhook hosts use .test so nothing gets crawled
# off-box -- off-box links cost hours on the earlier ranges.
DEPLOY_TOKEN = "rr10_deploy_7c2e5b91af64d38a0b1e9f3c6d5a4e83"

DEV_SECRETS = {
    "aws": {
        "AWS_ACCESS_KEY_ID": "AKIAQ9RR10DEVEXAMPLE7",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "AWS_SESSION_TOKEN": "FwoGZXIvYXdzEBYaDRR10FAKESESSIONTOKENnotreal==",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_ACCOUNT_ID": "123456789012",
        "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/rr10-prod-deploy",
        "AWS_S3_ARTIFACTS": "s3://rr10-prod-artifacts",
        "AWS_RDS_ENDPOINT": "rr10-prod.c7x9rr10.us-east-1.rds.amazonaws.test:5432",
        "AWS_CONSOLE_USER": "dade.murphy@queebler.test",
        "AWS_CONSOLE_PASSWORD": "nodezero",
    },
    "github": {
        "GITHUB_PAT_CLASSIC": "ghp_RR10DevFakeGithubTokenNotRealDoNotUse1",
        "GITHUB_PAT_FINE_GRAINED": "github_pat_11ARR10DEV0aBcDeFgHiJkLmNoPqRsTuVwXyZ"
                                   "0123456789abcdefghijklmnopqrstuvwxyzABCD",
        "GITHUB_OAUTH_CLIENT_ID": "Iv1.rr10dev0a1b2c3d",
        "GITHUB_OAUTH_CLIENT_SECRET": "rr10devfakegithuboauthsecretnotreal0123456789",
        "GITHUB_ACTIONS_RUNNER_TOKEN": "ARR10DEVFAKERUNNERTOKENNOTREAL0123456789",
        "GITHUB_ORG": "queebler-inc",
        "GITHUB_PACKAGES_TOKEN": "ghp_RR10DevFakePackagesTokenNotRealDoNot2",
        "GITHUB_SSH_DEPLOY_KEY": "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                                 "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gt\n"
                                 "cnNhAAAAAwEAAQAAAYEARR10DEVFAKEDEPLOYKEYnotarealkeyMTIzNDU2Nzg5MA==\n"
                                 "-----END OPENSSH PRIVATE KEY-----\n",
    },
    "gitlab": {
        "GITLAB_PAT": "glpat-RR10DevFakeGitlabTok",
        "GITLAB_DEPLOY_TOKEN": "gldt-RR10DevFakeDeployTokenNotReal01",
        "GITLAB_RUNNER_REGISTRATION_TOKEN": "GR1348941RR10DEVFAKERUNNERREGTOKEN",
        "GITLAB_CI_JOB_TOKEN": "glcbt-RR10DevFakeCiJobTokenNotReal",
        "GITLAB_REGISTRY": "registry.gitlab.test/queebler-inc/rr10",
    },
    "containers_and_infra": {
        "DOCKERHUB_USERNAME": "queeblerbot",
        "DOCKERHUB_PAT": "dckr_pat_RR10DevFakeDockerHubTokenNotRea",
        "DOCKER_CONFIG_AUTH_B64": "cXVlZWJsZXJib3Q6UlI5RGV2RmFrZURvY2tlclB3Tm90UmVhbA==",
        "KUBE_SA_TOKEN": "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJSOURFVkZBS0UifQ."
                         "eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6cHJvZDpkZXBsb3kifQ."
                         "RR10DevFakeK8sServiceAccountTokenSignatureNotReal",
        "KUBE_CLUSTER": "rr10-prod-eks",
        "TERRAFORM_CLOUD_TOKEN": "RR10dev.atlasv1.TerraformCloudTokenNotRealDoNotUse",
        "VAULT_TOKEN": "hvs.RR10DevFakeVaultTokenNotRealDoNotUse01",
        "ANSIBLE_VAULT_PASSWORD": "An51bl3!Vault2026",
    },
    "package_registries": {
        "NPM_TOKEN": "npm_RR10DevFakeNpmPublishTokenNotReal01234",
        "PYPI_TOKEN": "pypi-AgEIcHlwaS5vcmcRR10DevFakePypiTokenNotRealDoNotUse",
        "ARTIFACTORY_API_KEY": "AKCp8RR10DevFakeArtifactoryApiKeyNotRealDoNotUse01234",
        "SONARQUBE_TOKEN": "sqp_rr10devfakesonarqubetokennotreal0123456",
    },
    "saas": {
        "SLACK_BOT_TOKEN": "xoxb-1234567890-RR10DevFakeSlackBotTokenNotReal",
        "SLACK_USER_TOKEN": "xoxp-1234567890-RR10DevFakeSlackUserTokenNotReal",
        "SLACK_WEBHOOK": "https://hooks.slack.test/services/T00RR10DEV/B00RR10DEV/"
                         "XXXXXXXXXXXXXXXXXXXXXXXX",
        "STRIPE_SECRET_KEY": "sk_live_RR10DevFakeStripeSecretKeyNotRealDoNot",
        "STRIPE_WEBHOOK_SECRET": "whsec_RR10DevFakeStripeWebhookSecretNotReal",
        "SENDGRID_API_KEY": "SG.RR10DevFakeSendgridKey.0123456789abcdefghijklmnopqrstuvwxyzAB",
        "TWILIO_ACCOUNT_SID": "AC9f4c2b7e15a0d386c4e7b291f5a8d0c3",
        "TWILIO_AUTH_TOKEN": "7c2e5b91af64d38a0b1e9f3c6d5a4e83a",
        "DATADOG_API_KEY": "rr10devfakedatadogapikeynotreal012",
        "OPENAI_API_KEY": "sk-proj-RR10DevFakeOpenAIKeyNotRealDoNotUse0123456789abcdef",
        "GOOGLE_MAPS_API_KEY": GMAPS_KEY,
    },
    "azure_gcp": {
        "AZURE_TENANT_ID": "72f988bf-86f1-41af-91ab-2d7cd011rr100",
        "AZURE_CLIENT_ID": "1950a258-227b-4e31-a9cf-717495945rr10",
        "AZURE_CLIENT_SECRET": "RR10~DevFakeAzureClientSecretNotReal.7Qx-9vZ2mK",
        "AZURE_STORAGE_KEY": "RR10DevFakeAzureStorageKeyNotRealDoNotUse==",
        "GCP_PROJECT_ID": "queebler-prod-4417",
        "GCP_SA_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\n"
                              "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQRR10DEVFAKEKEYnotreal\n"
                              "-----END PRIVATE KEY-----\n",
        "GCP_SA_EMAIL": "deploy@queebler-prod-4417.iam.gserviceaccount.test",
        "GCP_API_KEY": "AIzaSyB1RR10DevFakeGcpKeyNotRealDoNot12",
    },
    "databases": {
        "POSTGRES_URL": "postgres://rr10_app:Pg!RR10prod2026@db-prod.queebler.test:5432/payments",
        "MONGODB_URI": "mongodb+srv://rr10_rw:M0ng0!RR10@prod.rr10fake.mongodb.test/payments",
        "REDIS_URL": "redis://:R3d1s!RR10prod@cache-prod.queebler.test:6379/0",
        "MYSQL_URL": "mysql://root:root@rr10_db:3306/rr10",
    },
    "internal": {
        "JWT_SIGNING_KEY": "rr10_jwt_5e83af0c94d21b76a1f39c027d4e6b85",
        "SESSION_SECRET": "rr10_session_0d9b4e6132ca7f85",
        "DEPLOY_TOKEN": DEPLOY_TOKEN,
        "DEPLOY_ENDPOINT": "/dev/deploy?token=" + DEPLOY_TOKEN,
        "SSH_DEPLOY_USER": "svc_deploy",
        "SSH_DEPLOY_PASSWORD": "D3pl0y!R3l3ase2026",
        "APP_SUPER_ADMIN": "dade.murphy / nodezero",
        "FLAG": "RR10{developer_secret_store_pwned}",
    },
}


def _flatten_secrets():
    out = []
    for group, kv in DEV_SECRETS.items():
        out.append("# ---- " + group + " ----")
        for k, v in kv.items():
            out.append("%s=%s" % (k, v.replace("\n", "\\n")))
        out.append("")
    return "\n".join(out)


@app.route("/dev/secrets")
def dev_secrets():
    """The prize behind the developer login: the whole CI/CD secret store."""
    if not dev_session():
        return _dev_guard()
    blocks = ""
    for group, kv in DEV_SECRETS.items():
        rows = "\n".join("%-32s %s" % (k, v.replace("\n", " ")) for k, v in kv.items())
        blocks += ("<div class='panel'><b>" + esc(group) + "</b>"
                   "<div class='out'>" + esc(rows) + "</div></div>")
    return dev_shell("CI/CD secret store", blocks,
                     "AWS, GitHub, GitLab, Docker, Kubernetes, Terraform, Vault, npm, PyPI, "
                     "Slack, Stripe, SendGrid, Twilio, Datadog, OpenAI, Azure and GCP "
                     "credentials. Also dumped raw at <a href='/dev/env'>/dev/env</a> and "
                     "in the pipeline at <a href='/dev/pipeline'>/dev/pipeline</a>.")


@app.route("/dev/env")
def dev_env():
    """Raw .env dump, text/plain -- the shape secret scanners like most."""
    if not dev_session():
        return _dev_guard()
    return Response(_flatten_secrets(), mimetype="text/plain")


@app.route("/dev/pipeline")
def dev_pipeline():
    """CI pipeline config with the same secrets inline, YAML-style."""
    if not dev_session():
        return _dev_guard()
    y = ("stages: [build, test, deploy]\n\n"
         "variables:\n"
         "  AWS_ACCESS_KEY_ID: \"" + DEV_SECRETS["aws"]["AWS_ACCESS_KEY_ID"] + "\"\n"
         "  AWS_SECRET_ACCESS_KEY: \"" + DEV_SECRETS["aws"]["AWS_SECRET_ACCESS_KEY"] + "\"\n"
         "  GITHUB_TOKEN: \"" + DEV_SECRETS["github"]["GITHUB_PAT_CLASSIC"] + "\"\n"
         "  GITLAB_PAT: \"" + DEV_SECRETS["gitlab"]["GITLAB_PAT"] + "\"\n"
         "  DOCKERHUB_PAT: \"" + DEV_SECRETS["containers_and_infra"]["DOCKERHUB_PAT"] + "\"\n"
         "  NPM_TOKEN: \"" + DEV_SECRETS["package_registries"]["NPM_TOKEN"] + "\"\n"
         "  SLACK_BOT_TOKEN: \"" + DEV_SECRETS["saas"]["SLACK_BOT_TOKEN"] + "\"\n"
         "  STRIPE_SECRET_KEY: \"" + DEV_SECRETS["saas"]["STRIPE_SECRET_KEY"] + "\"\n"
         "  DEPLOY_TOKEN: \"" + DEPLOY_TOKEN + "\"\n\n"
         "deploy:prod:\n"
         "  stage: deploy\n"
         "  script:\n"
         "    - aws s3 sync dist/ " + DEV_SECRETS["aws"]["AWS_S3_ARTIFACTS"] + "\n"
         "    - curl -H \"X-Deploy-Token: $DEPLOY_TOKEN\" /dev/deploy\n"
         "    - sshpass -p 'D3pl0y!R3l3ase2026' ssh svc_deploy@10.30.0.5 './release.sh'\n")
    return Response(y, mimetype="text/plain")


@app.route("/dev/deploy")
def dev_deploy():
    """Gated by the DEPLOY_TOKEN leaked in the secret store -- harvesting the
    token converts straight into infrastructure access."""
    if request.args.get("token") != DEPLOY_TOKEN:
        return jsonify(error="invalid or missing deploy token",
                       hint="DEPLOY_TOKEN is in the developer CI/CD secret store"), 401
    return jsonify({
        "authenticated_with": "DEPLOY_TOKEN",
        "targets": [
            {"host": "rr10-prod-web-1", "ip": "10.30.1.11", "role": "web"},
            {"host": "rr10-prod-bastion", "ip": "10.30.0.5", "role": "bastion",
             "ssh": "svc_deploy / D3pl0y!R3l3ase2026"}],
        "artifact_bucket": {"name": "rr10-prod-artifacts", "public": True},
        "app_super_admin": "dade.murphy / nodezero",
        "flag": "RR10{deploy_token_reused_for_infra_access}"})


reg("H3-2026-0033", "Developer CI/CD secret store (authed)", "dev/secrets")
reg("H3-2026-0034", "Developer .env dump - AWS/GitHub/GitLab keys (authed)", "dev/env")
reg("H3-2026-0034", "CI pipeline config with inline tokens (authed)", "dev/pipeline")
reg("H3-2026-0033", "Deploy token unlocks infra (authed)",
    "dev/deploy?token=" + DEPLOY_TOKEN, pname="token")


def seed_dev_files():
    try:
        os.makedirs("/app/devsrc", exist_ok=True)
        with open("/app/devsrc/build.log", "w") as fh:
            fh.write("2026-09-09 rc3 build ok\n"
                     "artifact -> /app/backups/db-backup.sql\n"
                     "deploy key svc_deploy / D3pl0y!R3l3ase2026\n")
        with open("/app/devsrc/config.py", "w") as fh:
            fh.write("DB = 'mysql://root:root@rr10_db:3306/rr10'\n"
                     "ADMIN = ('dade.murphy', 'nodezero')\n")
        # the same secrets on disk, so the /dev/files traversal finds them too
        with open("/app/devsrc/.env", "w") as fh:
            fh.write(_flatten_secrets())
        with open("/app/devsrc/id_rsa", "w") as fh:
            fh.write(DEV_SECRETS["github"]["GITHUB_SSH_DEPLOY_KEY"])
        with open("/app/devsrc/aws-credentials", "w") as fh:
            fh.write("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n"
                     "region = us-east-1\n" % (DEV_SECRETS["aws"]["AWS_ACCESS_KEY_ID"],
                                                DEV_SECRETS["aws"]["AWS_SECRET_ACCESS_KEY"]))
    except Exception as e:
        print("[rr10] dev seed failed: %s" % e, flush=True)


def seed_notes():
    """Pre-seed every store so no render page is ever empty. An empty page gets
    deprioritised by the crawler, and on RR9 the stored render pages produced no
    findings at all -- the fewer reasons to skip them, the better."""
    seeds = [
        ("xss", "j.reyes", "Docking station arrived a day early. Setup was painless."),
        ("xss", "m.okafor", "Standing desk motor is quieter than the last batch."),
        ("guest", "anon", "Nice portal. The order search is quick."),
        ("guest", "t.lindqvist", "Bookmarking this - the reports page is handy."),
        ("review", "s.johnson", "Server rails fit the 42U cabinet exactly. 5/5."),
        ("review", "anon", "Shipping was slow but the hardware is solid."),
        ("ssti", "ops", "Weekly rollup for {{ 'ops' }} - all services nominal."),
        ("ssti", "release", "Build {{ 7*7 }} promoted to staging."),
        ("csti", "d.kaur", "Platform engineer. Coffee, YAML, repeat."),
        ("csti", "anon", "Bio not set yet."),
    ]
    try:
        c = db(); cur = c.cursor()
        for store, author, body in seeds:
            cur.execute("INSERT INTO notes (store,author,body) VALUES (%s,%s,%s)",
                        (store, author, body))
        c.close()
        print("[rr10] seeded %d notes" % len(seeds), flush=True)
    except Exception as e:
        print("[rr10] note seed failed: %s" % e, flush=True)


if __name__ == "__main__":
    init_db()
    seed_files()
    seed_dev_files()
    seed_notes()
    # NOTE: must NOT use waitress -- it raises "carriage return/line feed
    # character present in header value" and kills the CRLF-injection
    # endpoint (H3-2026-0026). Werkzeug passes raw headers through. The
    # real perf win was dropping debug=True, which we keep off.
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True, use_reloader=False)
