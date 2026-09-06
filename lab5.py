#!/usr/bin/env python3
"""
lab5.py - Gokstad Akademiet, Emne 3, Lesson 5
HTTP, status codes, headers, cookies, sessions and APIs.

A deliberately flawed web application for teaching use.

    python3 lab5.py

Then open http://127.0.0.1:8080/ in Kali.

Standard library only. No install, no accounts, no containers.
Binds to 127.0.0.1 by default, so it answers inside this machine and
nowhere else. That is on purpose: this application is broken by design
and must never be reachable from a network.

Options:
    --port N        listen on another port (default 8080)
    --reset         clear the access log before starting
    --log PATH      access log location (default ./lab5_access.log)
    --expose        bind 0.0.0.0. Do not use this on any real network.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

SERVER_BANNER = "gokstad-lab/1.0"
JWT_SECRET = b"lab5-signing-key"
LOG_PATH = "lab5_access.log"

# ---------------------------------------------------------------------------
# State. All in memory, so restarting the process resets everything.
# ---------------------------------------------------------------------------

USERS = {
    "student": {
        "password": "student123",
        "name": "Student Bruker",
        "email": "student@lab.local",
        "role": "customer",
        "customer_id": 1041,
        "credit_limit": 5000,
        "internal_note": "trial account, do not refund",
        "password_reset_token": "prt_7f3a9c21",
        "flagged_for_review": False,
    },
    "kari": {
        "password": "vaarsol2019",
        "name": "Kari Nordmann",
        "email": "kari@lab.local",
        "role": "customer",
        "customer_id": 1042,
        "credit_limit": 25000,
        "internal_note": "escalated complaint 2026-03, handle carefully",
        "password_reset_token": "prt_be14d0f8",
        "flagged_for_review": True,
    },
    "drift": {
        "password": "Sommer2026!",
        "name": "Drift Konto",
        "email": "drift@lab.local",
        "role": "admin",
        "customer_id": 9001,
        "credit_limit": 0,
        "internal_note": "service account, shared password",
        "password_reset_token": "prt_00000001",
        "flagged_for_review": False,
    },
}

ORDERS = [
    {"order_id": 5001, "customer_id": 1041, "item": "Nettverkskabel Cat6 5m",
     "price_nok": 149, "status": "sendt", "internal_margin_pct": 62,
     "warehouse_note": "billigste leverandoer, byttet uten aa si fra"},
    {"order_id": 5002, "customer_id": 1041, "item": "USB-hub 4 port",
     "price_nok": 399, "status": "pakkes", "internal_margin_pct": 41,
     "warehouse_note": "returrate hoey paa denne"},
    {"order_id": 5003, "customer_id": 1042, "item": "Skjermarm dobbel",
     "price_nok": 1290, "status": "levert", "internal_margin_pct": 55,
     "warehouse_note": "kunde klaget, gitt 20 pct avslag"},
]

VAULT_FILES = {
    "rapport-2026-q1.pdf": "kari",
    "loennsliste.xlsx": "drift",
}

_sessions = {}          # weak session store, no rotation
_sessions_v2 = {}       # correct session store
_counter_lock = threading.Lock()
_session_counter = 1000
_rate_lock = threading.Lock()
_rate_buckets = {}
_log_lock = threading.Lock()

RATE_WINDOW = 10.0
RATE_LIMIT_GENERAL = 200
RATE_LIMIT_LOGIN = 25


def next_session_id():
    """Predictable by design. Structure is visible after base64 decoding."""
    global _session_counter
    with _counter_lock:
        _session_counter += 1
        n = _session_counter
    raw = "s{0}:{1}".format(n, int(time.time()))
    return base64.b64encode(raw.encode()).decode().rstrip("=")


# ---------------------------------------------------------------------------
# JWT, HS256, hand rolled so the file stays stdlib only
# ---------------------------------------------------------------------------

def b64url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(text):
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def jwt_encode(payload):
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = "{0}.{1}".format(h, p).encode()
    sig = hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest()
    return "{0}.{1}.{2}".format(h, p, b64url(sig))


def jwt_decode(token):
    """Returns (payload, error). Verifies the signature and the expiry."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, "malformed token"
    h, p, s = parts
    signing_input = "{0}.{1}".format(h, p).encode()
    expected = b64url(hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest())
    if not hmac.compare_digest(expected, s):
        return None, "signature check failed"
    try:
        payload = json.loads(b64url_decode(p))
    except Exception:
        return None, "payload is not JSON"
    if payload.get("exp", 0) < time.time():
        return None, "token expired"
    return payload, None


# ---------------------------------------------------------------------------
# Page templates. Deliberately plain: the protocol is the subject, not the CSS.
# ---------------------------------------------------------------------------

PAGE = """<!doctype html>
<html lang="nb"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} - Kontorlageret</title>
<link rel="stylesheet" href="/style.css"></head>
<body><header><a class="mark" href="/">Kontorlageret</a>
<nav><a href="/shop/">Butikk</a><a href="/account">Min side</a>
<a href="/vault/">Dokumenter</a><a href="/login">Logg inn</a>
<a href="/logout">Logg ut</a></nav></header>
<main><h1>{title}</h1>{body}</main>
<footer>Kontorlageret AS, org. 918 273 645. Kundeservice 33 44 55 66.</footer>
</body></html>
"""

STYLESHEET = """:root{--ink:#1c2330;--muted:#5b6472;--rule:#dfe3e8;--brand:#2f5d8a;
--bg:#fff;--soft:#f5f7f9}
*{box-sizing:border-box}
body{margin:0;color:var(--ink);background:var(--bg);
font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{display:flex;align-items:baseline;gap:2rem;flex-wrap:wrap;
padding:1.1rem 1.5rem;border-bottom:1px solid var(--rule)}
.mark{font-size:1.15rem;font-weight:600;letter-spacing:-.02em;
color:var(--ink);text-decoration:none}
nav{display:flex;gap:1.25rem;flex-wrap:wrap}
nav a{color:var(--muted);text-decoration:none;font-size:.9rem}
nav a:hover,nav a:focus{color:var(--brand);text-decoration:underline}
main{max-width:44rem;margin:0 auto;padding:2rem 1.5rem 3rem}
h1{font-size:1.5rem;font-weight:600;letter-spacing:-.01em;margin:0 0 1.25rem}
p{margin:0 0 .85rem;max-width:38rem}
ul{list-style:none;margin:0;padding:0;border-top:1px solid var(--rule)}
li{display:flex;justify-content:space-between;gap:1rem;align-items:baseline;
padding:.8rem 0;border-bottom:1px solid var(--rule)}
li a{color:var(--brand);text-decoration:none}
li a:hover{text-decoration:underline}
.price{color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}
.rows{border-top:1px solid var(--rule);margin:0 0 1.25rem}
.row{display:flex;justify-content:space-between;gap:1rem;
padding:.7rem 0;border-bottom:1px solid var(--rule)}
.row span:first-child{color:var(--muted)}
form{background:var(--soft);border:1px solid var(--rule);border-radius:3px;
padding:1.25rem;max-width:22rem}
label{display:block;font-size:.85rem;color:var(--muted);margin-bottom:.3rem}
input{width:100%;padding:.5rem .6rem;border:1px solid #c3cad3;border-radius:2px;
font:inherit;font-size:.95rem;margin-bottom:.9rem;background:#fff}
input:focus{outline:2px solid var(--brand);outline-offset:1px;border-color:var(--brand)}
button{background:var(--brand);color:#fff;border:0;border-radius:2px;
padding:.55rem 1.1rem;font:inherit;font-size:.95rem;cursor:pointer}
button:hover{background:#26496c}
.note{color:var(--muted);font-size:.88rem}
footer{max-width:44rem;margin:0 auto;padding:1.25rem 1.5rem 2.5rem;
color:var(--muted);font-size:.82rem;border-top:1px solid var(--rule)}
@media(max-width:34rem){header{gap:.6rem}main{padding:1.5rem 1.1rem 2rem}}
"""

LOGIN_FORM = """<form method="post" action="{action}">
<label for="u">Brukernavn</label><input id="u" name="username">
<label for="p">Passord</label><input id="p" name="password" type="password">
<button type="submit">Logg inn</button></form>
<p class="note">{note}</p>"""


def page(title, body):
    return PAGE.format(title=title, body=body).encode("utf-8")


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = SERVER_BANNER
    sys_version = ""

    # -- plumbing ----------------------------------------------------------

    def version_string(self):
        return SERVER_BANNER

    def log_message(self, fmt, *args):
        pass  # replaced by write_access_log so the format is under our control

    def write_access_log(self, status, size):
        """Apache combined log format, so the round 4 comparison is realistic."""
        stamp = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
        line = '{ip} - - [{ts}] "{req}" {status} {size} "{ref}" "{ua}"\n'.format(
            ip=self.client_address[0],
            ts=stamp,
            req="{0} {1} {2}".format(self.command, self.path, self.request_version),
            status=status,
            size=size,
            ref=self.headers.get("Referer", "-"),
            ua=self.headers.get("User-Agent", "-"),
        )
        with _log_lock:
            try:
                with open(self.server.log_path, "a", encoding="utf-8") as fh:
                    fh.write(line)
            except OSError:
                pass
        sys.stdout.write(line)
        sys.stdout.flush()

    def send(self, status, body=b"", ctype="text/html; charset=utf-8",
             extra=None, cookies=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        for cookie in (cookies or []):
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.write_access_log(status, len(body))

    def send_json(self, status, obj, extra=None):
        body = json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")
        self.send(status, body, "application/json; charset=utf-8", extra)

    # -- request helpers ---------------------------------------------------

    def cookies(self):
        jar = {}
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                jar[k.strip()] = unquote(v.strip())
        return jar

    def body_params(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype == "application/json":
            try:
                return json.loads(raw) if raw else {}
            except ValueError:
                return {}
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def current_user(self):
        sid = self.cookies().get("sid")
        return _sessions.get(sid)

    def current_user_v2(self):
        sid = self.cookies().get("sid2")
        return _sessions_v2.get(sid)

    def rate_ok(self, path):
        limit = RATE_LIMIT_LOGIN if path.startswith("/api/login") else RATE_LIMIT_GENERAL
        key = (self.client_address[0], "login" if limit == RATE_LIMIT_LOGIN else "general")
        now = time.time()
        with _rate_lock:
            hits = [t for t in _rate_buckets.get(key, []) if now - t < RATE_WINDOW]
            hits.append(now)
            _rate_buckets[key] = hits
            return len(hits) <= limit

    # -- entry points ------------------------------------------------------

    def do_GET(self):
        self.route()

    def do_HEAD(self):
        self.route()

    def do_POST(self):
        self.route()

    def route(self):
        # RFC 9112: an HTTP/1.1 request without a Host header is a bad request.
        if self.request_version == "HTTP/1.1" and not self.headers.get("Host"):
            self.send(400, page("400 Bad Request",
                                "<p>HTTP/1.1 krever en Host-header.</p>"))
            return

        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if not self.rate_ok(path):
            self.send(429, page("For mange foresporsler",
                                "<p>Ta det litt roligere. Vinduet er "
                                "{0:.0f} sekunder.</p>".format(RATE_WINDOW)),
                      extra={"Retry-After": str(int(RATE_WINDOW))})
            return

        host = (self.headers.get("Host") or "").split(":")[0].lower()

        for pattern, methods, fn in ROUTES:
            match = re.match(pattern, path)
            if match:
                if self.command not in methods:
                    self.send(405, page("Metoden er ikke tillatt",
                                        "<p>Tillatt her: {0}</p>".format(", ".join(methods))),
                              extra={"Allow": ", ".join(methods)})
                    return
                fn(self, match, query, host)
                return

        self.send(404, page("Siden finnes ikke",
                            "<p>Fant ingen side paa {0}.</p>".format(path)))


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def h_index(rq, m, q, host):
    # Virtual hosting: the Host header selects the site, not the IP address.
    if host in ("admin.lab", "internal.lab"):
        rq.send(200, page("Internportal",
                          "<p>Intern bygg. Ikke for kunder.</p>"
                          "<p class='note'>Deploy-notat: /vault/</p>"),
                extra={"X-Vhost": "internal"})
        return
    body = ("<p>Kontorrekvisita og datautstyr til bedrifter. "
            "Fri frakt paa ordre over 500 kr.</p>"
            "<p class='note'>Kontoen du skal bruke staar i oppgavearket.</p>")
    cookies = [
        # A deliberately mixed set, so the flag matrix has something to find.
        "prefs=lang%3Dnb; Path=/; Max-Age=86400",
        "tracking=t_88213; Path=/; SameSite=Lax",
        "consent=yes; Path=/; Secure",
    ]
    rq.send(200, page("Velkommen", body), extra={"X-Vhost": "public"}, cookies=cookies)


def h_shop(rq, m, q, host):
    items = "".join(
        "<li><a href='/shop/item?id={0}'>{1}</a>"
        "<span class='price'>{2} kr</span></li>".format(
            o["order_id"], o["item"], o["price_nok"]) for o in ORDERS)
    rq.send(200, page("Butikk", "<ul>{0}</ul>".format(items)))


def h_shop_item(rq, m, q, host):
    try:
        wanted = int((q.get("id") or ["0"])[0])
    except ValueError:
        wanted = 0
    for o in ORDERS:
        if o["order_id"] == wanted:
            rq.send(200, page(o["item"],
                              "<div class='rows'>"
                              "<div class='row'><span>Pris</span><span>{0} kr</span></div>"
                              "<div class='row'><span>Status</span><span>{1}</span></div>"
                              "</div>".format(o["price_nok"], o["status"])))
            return
    rq.send(404, page("Fant ikke varen",
                      "<p>Denne varen finnes ikke i sortimentet.</p>"))


def h_login(rq, m, q, host):
    """Broken on purpose: the session id does not change when you log in."""
    if rq.command in ("GET", "HEAD"):
        sid = rq.cookies().get("sid")
        cookies = []
        if not sid:
            sid = next_session_id()
            _sessions[sid] = None                      # anonymous session
            cookies = ["sid={0}; Path=/".format(sid)]  # no HttpOnly, no SameSite
        user = _sessions.get(sid)
        note = "Logged in as {0}.".format(user) if user else "Not logged in."
        rq.send(200, page("Logg inn", LOGIN_FORM.format(action="/login", note=note)),
                cookies=cookies)
        return

    params = rq.body_params()
    username = (params.get("username") or "").strip()
    password = params.get("password") or ""
    record = USERS.get(username)

    # Timing leak: only a real account reaches the password check.
    if record:
        time.sleep(0.35)
    if not record or record["password"] != password:
        rq.send(401, page("Logg inn", LOGIN_FORM.format(
            action="/login", note="Feil brukernavn eller passord.")))
        return

    sid = rq.cookies().get("sid")
    if not sid:
        sid = next_session_id()
    _sessions[sid] = username          # same id, new privileges
    rq.send(303, page("Logget inn", "<p>Sender deg videre.</p>"),
            extra={"Location": "/account"},
            cookies=["sid={0}; Path=/".format(sid)])


def h_login2(rq, m, q, host):
    """The same flow done correctly, for comparison."""
    if rq.command in ("GET", "HEAD"):
        user = rq.current_user_v2()
        note = "Logged in as {0}.".format(user) if user else "Not logged in."
        rq.send(200, page("Logg inn", LOGIN_FORM.format(action="/login2", note=note)))
        return

    params = rq.body_params()
    username = (params.get("username") or "").strip()
    password = params.get("password") or ""
    record = USERS.get(username)
    time.sleep(0.35)                                   # constant cost either way
    if not record or record["password"] != password:
        rq.send(401, page("Logg inn", LOGIN_FORM.format(
            action="/login2", note="Feil brukernavn eller passord.")))
        return

    old = rq.cookies().get("sid2")
    _sessions_v2.pop(old, None)                        # rotate on privilege change
    sid = secrets.token_hex(16)                        # unpredictable
    _sessions_v2[sid] = username
    rq.send(303, page("Logget inn", "<p>Sender deg videre.</p>"),
            extra={"Location": "/account"},
            cookies=["sid2={0}; Path=/; HttpOnly; SameSite=Strict".format(sid)])


def h_logout(rq, m, q, host):
    """v1 clears the browser only. v2 also drops the server side record."""
    sid2 = rq.cookies().get("sid2")
    if sid2:
        _sessions_v2.pop(sid2, None)
    rq.send(200, page("Logget ut",
                      "<p>Du er logget ut.</p>"),
            cookies=["sid=; Path=/; Max-Age=0",
                     "sid2=; Path=/; Max-Age=0"])


def h_account(rq, m, q, host):
    username = rq.current_user() or rq.current_user_v2()
    account_body = ""
    if username:
        u = USERS[username]
        account_body = ("<div class='rows'>"
                        "<div class='row'><span>Navn</span><span>{0}</span></div>"
                        "<div class='row'><span>E-post</span><span>{1}</span></div>"
                        "<div class='row'><span>Kundenummer</span><span>{2}</span></div>"
                        "</div>").format(u["name"], u["email"], u["customer_id"])
    if not username:
        # The redirect is issued, but the body was rendered first and is sent anyway.
        hidden = page("Min side",
                      "<div class='rows'>"
                      "<div class='row'><span>Navn</span><span>Student Bruker</span></div>"
                      "<div class='row'><span>E-post</span><span>student@lab.local</span></div>"
                      "<div class='row'><span>Kundenummer</span><span>1041</span></div>"
                      "</div>")
        rq.send(302, hidden, extra={"Location": "/login"})
        return
    rq.send(200, page("Min side", account_body))


def h_vault_index(rq, m, q, host):
    username = rq.current_user() or rq.current_user_v2()
    if not username:
        rq.send(403, page("Ingen tilgang",
                          "<p>Logg inn for aa se dokumentene.</p>"))
        return
    items = "".join("<li><a href='/vault/{0}'>{0}</a>"
                    "<span class='price'>PDF</span></li>".format(f)
                    for f in VAULT_FILES)
    rq.send(200, page("Dokumenter", "<ul>{0}</ul>".format(items)))


def h_vault_file(rq, m, q, host):
    """Same status code, different body length. That difference is the leak."""
    name = m.group("name")
    owner = VAULT_FILES.get(name)
    if owner:
        rq.send(403, page("Ingen tilgang",
                          "<p>Du har ikke tilgang til <b>{0}</b>. "
                          "Eier: {1}. Be eier om tilgang, eller kontakt "
                          "drift.</p>".format(name, owner)))
    else:
        rq.send(403, page("Ingen tilgang", "<p>Du har ikke tilgang.</p>"))


def h_api_login(rq, m, q, host):
    params = rq.body_params()
    username = (params.get("username") or "").strip()
    password = params.get("password") or ""
    record = USERS.get(username)
    if not record or record["password"] != password:
        rq.send_json(401, {"error": "invalid credentials"})
        return
    now = int(time.time())
    token = jwt_encode({
        "sub": username,
        "role": record["role"],
        "customer_id": record["customer_id"],
        "iat": now,
        "exp": now + 3600,
        "internal_note": record["internal_note"],
    })
    rq.send_json(200, {"authentication": {"token": token, "expires_in": 3600}})


def bearer_user(rq):
    """Returns (payload, error_response_tuple)."""
    raw = rq.headers.get("Authorization")
    if not raw:
        return None, (401, {"error": "missing Authorization header"})
    parts = raw.split(" ", 1)
    if len(parts) != 2:
        return None, (401, {"error": "malformed Authorization header"})
    scheme, token = parts
    if scheme.lower() != "bearer":
        return None, (401, {"error": "unsupported scheme: {0}".format(scheme)})
    payload, err = jwt_decode(token.strip())
    if err:
        return None, (401, {"error": err})
    return payload, None


def h_api_me(rq, m, q, host):
    payload, bad = bearer_user(rq)
    if bad:
        rq.send_json(bad[0], bad[1])
        return
    u = USERS[payload["sub"]]
    # Returns considerably more than /account renders.
    rq.send_json(200, dict(u, username=payload["sub"], password="[redacted]"))


def h_api_orders(rq, m, q, host):
    payload, bad = bearer_user(rq)
    if bad:
        rq.send_json(bad[0], bad[1])
        return
    mine = [o for o in ORDERS if o["customer_id"] == payload["customer_id"]]
    rq.send_json(200, {"orders": mine})


def h_api_admin(rq, m, q, host):
    payload, bad = bearer_user(rq)
    if bad:
        rq.send_json(bad[0], bad[1])
        return
    if payload.get("role") != "admin":
        rq.send_json(403, {"error": "role 'admin' required, token carries '{0}'".format(
            payload.get("role"))})
        return
    rq.send_json(200, {"users": list(USERS)})


def h_slow(rq, m, q, host):
    time.sleep(1.2)
    rq.send(200, page("Treg side", "<p>Det tok en stund.</p>"))


def h_status(rq, m, q, host):
    code = int(m.group("code"))
    rq.send(code, page("{0}".format(code), "<p>Du ba om status {0}.</p>".format(code)))


def h_style(rq, m, q, host):
    rq.send(200, STYLESHEET, "text/css; charset=utf-8",
            extra={"Cache-Control": "max-age=60"})


def h_robots(rq, m, q, host):
    rq.send(200, "User-agent: *\nDisallow: /vault/\nDisallow: /api/\n",
            "text/plain; charset=utf-8")


ROUTES = [
    (r"^/$",                            ("GET", "HEAD"),         h_index),
    (r"^/style\.css$",                  ("GET", "HEAD"),         h_style),
    (r"^/robots\.txt$",                 ("GET", "HEAD"),         h_robots),
    (r"^/shop/?$",                      ("GET", "HEAD"),         h_shop),
    (r"^/shop/item$",                   ("GET", "HEAD"),         h_shop_item),
    (r"^/login$",                       ("GET", "HEAD", "POST"), h_login),
    (r"^/login2$",                      ("GET", "HEAD", "POST"), h_login2),
    (r"^/logout$",                      ("GET", "HEAD"),         h_logout),
    (r"^/account$",                     ("GET", "HEAD"),         h_account),
    (r"^/vault/?$",                     ("GET", "HEAD"),         h_vault_index),
    (r"^/vault/(?P<name>[^/]+)$",       ("GET", "HEAD"),         h_vault_file),
    (r"^/api/login$",                   ("POST",),               h_api_login),
    (r"^/api/me$",                      ("GET", "HEAD"),         h_api_me),
    (r"^/api/orders$",                  ("GET", "HEAD"),         h_api_orders),
    (r"^/api/admin/users$",             ("GET", "HEAD"),         h_api_admin),
    (r"^/slow$",                        ("GET", "HEAD"),         h_slow),
    (r"^/status/(?P<code>\d{3})$",      ("GET", "HEAD"),         h_status),
]


def main():
    ap = argparse.ArgumentParser(description="Lesson 5 teaching lab")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--log", default=LOG_PATH)
    ap.add_argument("--reset", action="store_true", help="clear the access log")
    ap.add_argument("--expose", action="store_true",
                    help="bind 0.0.0.0. Do not use on a real network.")
    args = ap.parse_args()

    if args.reset and os.path.exists(args.log):
        os.remove(args.log)

    bind = "0.0.0.0" if args.expose else "127.0.0.1"
    httpd = ThreadingHTTPServer((bind, args.port), LabHandler)
    httpd.log_path = args.log

    print("lab5 listening on http://{0}:{1}/".format(
        "127.0.0.1" if not args.expose else bind, args.port))
    print("access log: {0}".format(os.path.abspath(args.log)))
    if args.expose:
        print("WARNING: bound to all interfaces. This application is "
              "vulnerable by design.")
    print("stop with Ctrl-C")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
