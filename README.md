<h1 align="center">🕶️ RamziRange10</h1>

<p align="center">
  <b>A deliberately vulnerable web application engineered so that every weakness class a scanner looks for gets its <i>own</i>, correctly-classified finding — and so the whole scan finishes in hours, not a day.</b>
</p>

<p align="center">
  <img alt="weaknesses" src="https://img.shields.io/badge/weakness_IDs-28-00ff41?style=for-the-badge&labelColor=000000">
  <img alt="endpoints" src="https://img.shields.io/badge/endpoints-83-00ff41?style=for-the-badge&labelColor=000000">
  <img alt="stack" src="https://img.shields.io/badge/Flask_%2B_MariaDB_%2B_nginx-black?style=for-the-badge&labelColor=000000&color=ff0033">
  <img alt="deploy" src="https://img.shields.io/badge/one_command-53_seconds-00ff41?style=for-the-badge&labelColor=000000">
</p>

<p align="center"><code>GO HACK YOURSELF</code></p>

---

## ⛔ Read this first

> [!CAUTION]
> **This application is intentionally, comprehensively insecure.** It ships remote code
> execution as root, SQL injection, path traversal, XXE, SSRF and an entire wing of
> exposed credentials — *on purpose*. It exists so that scanners and analysts have
> something real to find.
>
> - 🔒 **Run it on an isolated lab network only.** Never on a corporate LAN, never
>   internet-facing, never on a host you care about.
> - 🧪 **Authorized testing and training only.** Point tooling at it because you own it.
> - 🐳 **Treat the container as compromised by design.** `/admin/exec` gives `uid=0`.
> - 🚫 **Do not reuse a single line of this code** in anything real. Every pattern in
>   here is an anti-pattern, deliberately.

---

## 🎯 What makes this one different

Most vulnerable-app projects give you a grab bag of bugs and call it a day. The
problem that motivates *this* repo is subtler and much more annoying:

> **A vulnerability can work perfectly and still not show up in your report.**

Its predecessor registered 28 weakness classes. A full authenticated-capable op
reported **19**. Nothing was broken — every one of the 28 primitives was verified
working by hand afterwards. The nine that vanished were lost to three specific,
reproducible failure modes, and this entire codebase is the fix list for them.

| | |
|---|---|
| 🎖️ **28 weakness classes** | Injection, XSS ×3 flavours, template injection ×4, traversal, SSRF, XXE, CRLF, authz, and the whole disclosure family |
| 🪓 **Split attack surface** | Credential leaks quarantined into one wing so they stop cannibalising other findings |
| 🎣 **GET-fuzzable stored sinks** | Stored XSS/SSTI/CSTI that don't depend on a specialised scanner module being scheduled |
| 🧬 **3 exploit chains** | Credential discovery that converts into super-admin and then into root |
| 🔐 **A gated developer portal** | A second login only one account can pass, hiding a full CI/CD secret store |
| 📜 **A valid OpenAPI 3.0.3 spec** | 71 paths, self-describing, working example values for every parameter |
| 🐳 **4 containers, one command** | No setup, no seeding, no fixtures to load |

---

## ⚡ Deploy it

### Prerequisites

| Need | Why |
|---|---|
| 🐳 **Docker + Compose v2** | `docker compose version` should print v2.x. Compose v1 (`docker-compose`) won't parse the healthcheck conditions. |
| 🌐 **Internet for the first build only** | The images pull base layers, `pip install`, and vendor AngularJS. After that the range is fully self-contained and makes no outbound calls. |
| 🔌 **Port 9700 free** | The only published port. Change the left-hand side of `"9700:9700"` in `docker-compose.yml` if it clashes. |
| 🧱 **An isolated network** | See the warning at the top. This is not optional. |

### Two commands

```bash
git clone https://github.com/<you>/<repo>.git
cd <repo>
docker compose up -d --build --wait
```

That's it. `--wait` blocks until the healthchecks pass, so when the command
returns the range is genuinely ready. Measured cold-clone to serving: **53 seconds**.

> [!TIP]
> **If you omit `--wait`, give it ~40 seconds.** The app deliberately blocks
> until MariaDB has finished its first-boot initialisation and the schema is
> seeded, so nginx will answer **502** until then. That's expected, not a fault.

If your user isn't in the `docker` group, prefix with `sudo`.

### Confirm it's up

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:9700/     # expect 200
docker compose ps                                                    # all healthy
```

Then open **`http://<host>:9700/`** — the landing page is a live catalog of every
endpoint, grouped by weakness ID, each one a working link.

### Prove it's actually vulnerable

```bash
# SQL injection - throws a real MySQL syntax error
curl -s "http://localhost:9700/sqli/query?id=1'" | grep -o 'error in your SQL'

# OS command injection - runs as root
curl -s --get --data-urlencode 'host=127.0.0.1;id' \
     http://localhost:9700/cmd/ping | grep -o 'uid=0(root)'

# SSRF into a container with no published port
curl -s --get --data-urlencode 'url=http://internal-admin:5000/status' \
     http://localhost:9700/net/fetch | grep -o 'rr10-prod-internal'

# XXE - the external entity really expands
curl -s --get --data-urlencode \
     'doc=<!DOCTYPE d [<!ENTITY x SYSTEM "file:///app/version.txt">]><d>&x;</d>' \
     http://localhost:9700/xml/parse | grep -o '4f1c9ae7d0b3e28a'

# Stored XSS in two steps: plant via GET, then read it back somewhere else
curl -s -o /dev/null "http://localhost:9700/xss/store?author=t&body=<script>alert(1)</script>"
curl -s http://localhost:9700/xss/feed | grep -o '<script>alert(1)</script>'

# CRLF injection - the injected header lands on the wire
curl -sD- -o /dev/null \
     "http://localhost:9700/prefs?lang=en%0d%0aX-Injected:%20yes" | grep -i x-injected

# The developer-only portal (nothing else gets in)
curl -si -d 'username=developer1&password=nodezero' \
     http://localhost:9700/dev/login | grep -i 'set-cookie: devsid'
```

### Shut it down

```bash
docker compose down -v      # -v also drops the database volume
```

```
┌─────────────────────────────────────────────────────────┐
│  rr10_   Catalog Login Secrets Config Files Vault  …    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│        ▓▓  ▓▓▓      ▓▓ ▓▓  ▓▓▓   ▓▓▓▓ ▓▓  ▓▓            │
│        ▓   ▓ ▓      ▓▓▓▓▓ ▓▓▓▓▓ ▓     ▓▓▓▓              │
│        ▓▓▓ ▓▓▓      ▓▓ ▓▓ ▓▓ ▓▓  ▓▓▓▓ ▓▓  ▓▓            │
│              G O   H A C K   Y O U R S E L F            │
│                                                         │
│   83 endpoints · 28 weakness IDs                        │
└─────────────────────────────────────────────────────────┘
```

---

## 🔑 Credentials

### Main application — `/login`

| Username | Password | Role | Notes |
|---|---|---|---|
| `ramzi` | `ramzi` | `user` | Normal user. Baseline for privilege comparison. |
| `dade.murphy` | `nodezero` | `admin` | 👑 **Super admin.** Reaches root RCE. |
| `developer1` | `nodezero` | `developer` | 🛠️ Privileged. The only account the dev portal accepts. |

Session is a plain unsigned cookie: `sid=<username>` — trivially forgeable, which is
the point.

### Developer portal — `/dev/login`

A **completely separate login** with its own hardcoded check and its own cookie
(`devsid`). Only `developer1` / `nodezero` gets in — *the super admin cannot*.

> [!IMPORTANT]
> **Supply all three credentials to your scanner.** This is not optional, and it is
> the single biggest lever on your results. On the run that motivated this rebuild,
> the op was unauthenticated, and *every* endpoint returning 401/403 was absent from
> the findings — a perfectly clean split. That alone cost the improper-authorization
> class and the entire developer portal.

---

## 🩻 The post-mortem this range is built from

Three failure modes, nine lost weakness IDs. Each one is worth understanding
because they generalise well beyond this app.

### 1. Classifier collision — cost 5 IDs

One detector, **Exposed Credentials in Web Response**, took **17 of 61 findings**
and swallowed the carrier endpoints belonging to five other weakness classes.

The cause was self-inflicted. The SSRF endpoint pointed at an internal service whose
response was a credential dump. So the SSRF *worked* — it reached a container with no
published port and read its contents — and then got filed as a credential leak,
because a credential in the body outranks everything else. Same story for the config
page. The XXE endpoints lost the same way to a different detector: they read
`/etc/passwd`, so **Internal System Data Exposure** claimed them instead.

> **The rule:** a credential anywhere in a response body wins. If a payload proves
> weakness X but the response also contains a secret, you get a finding for the
> secret and nothing for X.

**The fix — a split surface.** Every non-credential carrier is now credential-free:

| Carrier | Before | After |
|---|---|---|
| `/net/fetch`, `/net/preview` | fetched an internal `/creds` endpoint | fetch `/status`, `/metrics`, `/latest/meta-data/` — credential-free by design |
| `/config` | leaked an SSH deploy password | build SHA, upstream host map, `uid=0(root)`, feature flags |
| `/xml/parse`, `/xml/import` | entity read `/etc/passwd` | entity reads `/app/version.txt`, a benign build stamp |
| `app.log` | contained a plaintext admin password | internal topology and SQL statements only |

…and every credential in the application moved into a dedicated **`/vault/*` wing**
whose entire job is to score credential findings in volume, where winning a collision
costs nothing.

### 2. Module starvation — cost 3 IDs

Stored XSS, stored SSTI and stored CSTI all scored **zero**. Confirming a stored bug
requires the scanner's dedicated stored-injection module to run *and* correlate
inject-at-A with render-at-B. In an 18-hour op, that module ran for about four
seconds.

It definitely reached the endpoint, though — the proof was sitting in the database
afterwards, in the form of the scanner's own out-of-band callback probes rendered on
the feed page.

**The fix — stop depending on that module.** The submit endpoints now accept **GET as
well as POST**, which puts the sink in reach of the ordinary query-parameter fuzzer
that runs constantly. Two details make this work rather than backfire:

- The GET receipt **echoes nothing** — no reflection of the submitted value, no
  redirect. If it echoed the payload, the finding would be misfiled as *reflected*
  XSS and you'd be back where you started.
- The render pages are **nav items**, so they're re-crawled on every pass and any
  accumulated payload is visible in the HTML.

Every store is also pre-seeded, because an empty page gets deprioritised by crawlers.

### 3. Crawl reachability — cost 1 ID

The page carrying the exposed Google Maps browser key was linked *only* from a
catalog card. It never appeared in the results at all — not as a miss, but as a page
the crawler simply never visited. Card-only links have always been hit-or-miss.

**The fix:** anything that must be reached is in the nav. Boring, and it works.

---

## 🎖️ Weakness coverage

Every row is verified working against a live deployment, not aspirational.

| Class | ID | Carrier endpoints |
|---|---|---|
| 💉 **SQL Injection** | `H3-2025-0069` | `/sqli/query?id=` · `/search/orders?q=` (UNION) · `/login` (auth bypass) |
| 🔁 **Reflected XSS** | `H3-2025-0059` | `/xss/reflect?q=` · `/xss/attr?value=` (attribute ctx) · `/xss/jsvar?user=` (JS string ctx) |
| 💾 **Stored XSS** | `H3-2025-0071` | `/xss/store`→`/xss/feed` · `/guestbook`→`/guestbook/wall` · `/reviews/add`→`/reviews` · `/dev/notes`→`/dev/board` — all GET **and** POST |
| 🌐 **DOM XSS** | `H3-2026-0047` | `/dom?msg=` (innerHTML) · `/dom/write?name=` · `/dom/eval?expr=` |
| 🧩 **SSTI — reflected** | `H3-2025-0072` | `/ssti/query?tpl=` · `/preview/render?tpl=` — `{{7*7}}` → `49` |
| 🧩 **SSTI — stored** | `H3-2025-0078` | `/ssti/store` → `/ssti/report` (evaluated per row on view) |
| 🖥️ **CSTI — reflected** | `H3-2026-0029` | `/csti/query?bio=` · `/profile/preview?bio=` (AngularJS, vendored locally) |
| 🖥️ **CSTI — stored** | `H3-2026-0030` | `/csti/store` → `/csti/profile` |
| 💥 **OS Command Injection** | `H3-2025-0077` | `/cmd/ping?host=` · `/logs/view?log=` (cat sink) · `/admin/exec?cmd=` (root, admin session) |
| 📂 **Path Traversal** | `H3-2022-0015` | `/files/read?file=` · `/download?doc=` · `/logs/view?log=` · `/dev/files?path=` |
| 🛰️ **SSRF** | `H3-2025-0076` | `/net/fetch?url=` → internal-only container `/status`, `/latest/meta-data/` |
| 🛰️ **SSRF — full read** | `H3-2026-0024` | `/net/preview?target=` → internal `/metrics`, `/status` |
| 📄 **XXE** | `H3-2025-0050` | `/xml/parse?doc=` · `/xml/import?feed=` · parameter-entity variant |
| ↪️ **Open Redirect** | `H3-2025-0079` | `/go?url=` · `/out?next=` |
| ↪️ **Redirect via header injection** | `H3-2026-0027` | `/go/hdr?url=` · `/out/hdr?next=` (raw `Location`, bypasses the framework) |
| ✂️ **CRLF / Response Splitting** | `H3-2026-0026` | `/prefs?lang=` · `/track?ref=` |
| 🚪 **Improper Authorization** | `H3-2026-0061` | `/hr/salaries` · `/audit/logs` (developer+) · `/finance/payroll` (admin only) · `/dev/login` |
| 🔓 **IDOR / BOLA** | `H3-2026-0013` | `/api/orders/{id}` · `/api/invoice?id=` |
| 🗝️ **Exposed Credentials** | `H3-2026-0033` | `/vault/dump` · `/vault/env` · `/vault/ssh` · `/vault/backup.sql` · `/bac/users` |
| 🔑 **Exposed API Keys** | `H3-2026-0034` | `/api/keys` (4 key formats) · `/vault/kube` · `/dev/env` · `/dev/pipeline` |
| 🗺️ **Exposed browser key** | `H3-2026-0037` | `/contact` · `/support` (data attribute + inline config + comment) |
| 📋 **Sensitive Info Disclosure** | `H3-2025-0080` | `/config` · `/status/internal` |
| 👤 **PII Disclosure** | `H3-2026-0035` | `/api/customers` · `/api/employees` |
| 🏢 **Internal System Data** | `H3-2026-0036` | `/logs/view?log=app.log` |
| 🧯 **Stack Trace Disclosure** | `H3-2026-0038` | `/debug/lookup?key=zz` · `/export?rows=abc` |
| 📁 **Directory Listing** | `H3-2026-0039` | `/files/` · `/files/logs/` · `/files/backups/` |
| 📗 **Swagger Spec Exposed** | `H3-2026-0051` | `/openapi.json` · `/swagger.json` |
| 🧾 **.env Exposure** | `H3-2025-0032` | `/.env` |

**2–3 carriers per class.** One is too few — a single missed endpoint costs the whole
weakness class. Many more is worse: it inflates the fuzz surface without adding a
single distinct ID, which is exactly how an earlier range in this series took 18 hours.

---

## 🔐 The developer portal

A second, independent authentication boundary at `/dev/login`. Its check is
hardcoded and accepts exactly one account. The **super admin cannot get in** —
that asymmetry is itself the finding.

Behind it:

| Endpoint | What it gives up |
|---|---|
| `/dev/secrets` | The full CI/CD secret store, grouped by provider |
| `/dev/env` | The same store as a raw `.env` (`text/plain` — the shape secret scanners like most) |
| `/dev/pipeline` | A CI pipeline YAML with tokens inline |
| `/dev/files?path=` | A source browser with path traversal |
| `/dev/notes` → `/dev/board` | Stored XSS inside the authenticated area |
| `/dev/deploy?token=` | A deploy endpoint gated by a token found in the store |

AWS, GitHub (classic + fine-grained + SSH deploy key), GitLab, Docker Hub,
Kubernetes, Terraform, Vault, npm, PyPI, Slack, Stripe, SendGrid, Twilio, Datadog,
OpenAI, Azure and GCP. All fake — see [SECURITY.md](SECURITY.md).

---

## 🚪 The authorization matrix

Three tiers, verified live. The *difference* between rows is the finding, which is
why the op needs more than one credential:

| | `/hr/salaries` | `/audit/logs` | `/finance/payroll` | `/dev/*` |
|---|:---:|:---:|:---:|:---:|
| unauthenticated | 403 | 403 | 403 | 401 |
| `ramzi` (user) | 403 | 403 | 403 | 401 |
| `developer1` (developer) | **200** | **200** | 403 | **200** |
| `dade.murphy` (admin) | **200** | **200** | **200** | 401 |

---

## 🧬 Attack chains

```
  CHAIN 1 — disclosure becomes access
  /bac/users ──leaks──> internal_api_key ──unlocks──> /api/v1/cloud/inventory
      └─> cloud inventory leaks a bastion credential and an admin IAM user

  CHAIN 2 — credential harvest becomes root
  /vault/dump ──leaks──> dade.murphy / nodezero ──login──> admin session
      └─> /admin/exec?cmd=id ──> uid=0(root) ──> host compromise

  CHAIN 3 — the developer track
  /dev/login (developer1 only) ──> /dev/secrets ──> CI/CD secret store
      └─> /dev/deploy?token=… ──> infra access
      └─> /dev/files?path=../../etc/passwd ──> traversal inside the authed area
```

---

## ⚙️ Tuning notes — how to keep the scan short

Accumulated the hard way, mostly by watching an 18-hour op and reading its
action logs afterwards.

- **Zero external URLs.** An earlier range used a real hostname as an example
  parameter value. The fuzzer cross-mutated it into ~50 bogus hostnames and the
  open-redirect module alone burned **3.45 hours** at 40s per DNS timeout. The only
  "attacker" host here is `127.0.0.1:9` — the discard port, which refuses instantly
  with no lookup.
- **AngularJS is vendored at build time.** Pulling it from a CDN sends the crawler
  off-box and drags in a dozen third-party hosts.
- **Bound every blocking call.** `ping -W 1`, HTTP fetch timeout 2s,
  `SET SESSION max_statement_time=10`.
- **No time-based SQL injection.** Each probe costs ~10 seconds and carries the same
  weakness ID as the error-based one, which is free.
- **`LIMIT 25` on stored renders, plus an index on `(store, id)`.** Without it, a
  notes table grew to 26,000 rows mid-scan and the SSTI report re-rendered every row
  on every view — page cost climbed all scan long.
- **The theme is pure CSS.** A perpetual canvas animation costs real CPU on every one
  of thousands of page loads.
- **Werkzeug, not waitress.** Waitress validates header values and raises on CR/LF,
  which silently deletes the CRLF-injection finding. Werkzeug passes raw headers
  through a small WSGI shim. It also measured faster.

---

## 🏗️ Architecture

```
                        ┌──────────────────────────────┐
   you ───── :9700 ────▶│  rr10-proxy   (nginx 1.27)   │
                        └──────────────┬───────────────┘
                                       │ proxy_pass, Host: $http_host
                        ┌──────────────▼───────────────┐
                        │  rr10-app     (Flask, root)  │
                        │  83 endpoints · 28 IDs       │
                        └───────┬──────────────┬───────┘
                                │              │
                ┌───────────────▼──┐    ┌──────▼──────────────────────┐
                │ rr10-db          │    │ rr10-internal-admin         │
                │ MariaDB 10.5     │    │ NO published port           │
                └──────────────────┘    │ the SSRF payoff             │
                                        └─────────────────────────────┘
```

`internal-admin` has no host port at all. It is reachable *only* from inside the
Docker network, which is what makes `/net/fetch` a genuine SSRF finding rather than
a reflected URL. Its `/status`, `/metrics` and `/latest/meta-data/` endpoints are
deliberately credential-free so the SSRF finding doesn't get outranked.

> [!NOTE]
> `proxy_set_header Host $http_host` — **not** `$host`. `$host` drops the port, which
> makes the OpenAPI `servers[].url` resolve to port 80 and quietly breaks spec-driven
> scanning.

---

## 📁 Layout

```
.
├── docker-compose.yml        healthchecks + depends_on so --wait is deterministic
├── app/
│   ├── app.py                the whole application, one file
│   └── Dockerfile            vendors AngularJS at build time
├── internal-admin/
│   ├── app.py                internal-only SSRF target, credential-free
│   └── Dockerfile
├── proxy/
│   └── nginx.conf            single entrypoint on :9700
├── README.md
├── SECURITY.md               why secret scanners will flag this repo
└── LICENSE
```

---

## 🔌 Pointing a scanner at it

1. Scope: `http://<host>:9700`
2. Load **all three** credentials (see the ⚠️ note above — this is the biggest lever).
3. Feed it the spec: `http://<host>:9700/openapi.json` — 71 paths, valid 3.0.3.
4. Enable out-of-band / callback confirmation if your tooling supports it.
5. Expect a couple of hours, not a day.

---

<details>
<summary><b>🩺 Troubleshooting</b></summary>

**`502 Bad Gateway` right after starting.** The app blocks until MariaDB finishes
first-boot init. Use `--wait`, or wait ~40 seconds.

**`docker compose up --wait` exits 1.** Check `docker compose ps` for which service
is unhealthy. Note the proxy deliberately has *no* healthcheck — it raced its own
retry budget and reported a false `unhealthy`, and `depends_on: service_healthy` on
the app already sequences it correctly.

**Findings appear under the wrong weakness ID.** That's the whole subject of the
post-mortem section above. If you add an endpoint, keep credentials out of its
response body unless you *want* a credential finding.

**Stored payloads don't show up.** Check the render page, not the submit page —
they're deliberately different URLs. The submit receipt echoes nothing on purpose.

**A rebuilt backend 404s through the proxy.** nginx resolves the upstream hostname
once at startup, so after recreating the app container run
`docker compose restart proxy`.

**Port clash.** Change both sides of `"9700:9700"` in `docker-compose.yml` and the
`listen` directive in `proxy/nginx.conf`.

</details>

---

## 🧾 What's fake

Everything sensitive. No key in this repository authenticates anywhere, no hostname
resolves to infrastructure anyone owns, and no account exists on any real machine.
Only the key *prefixes* are genuine, so that credential scanners fingerprint them —
which is the entire point of a credential-exposure test target.

Read [SECURITY.md](SECURITY.md) before you file an issue about a leaked secret.

---

## 📜 License

MIT — see [LICENSE](LICENSE). Use it to test things you are authorized to test.
