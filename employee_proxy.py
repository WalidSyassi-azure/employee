"""
Employee Proxy for Render (simplified & production-ready)
- Uses env vars for all secrets
- Secure session settings for Render
- Browser-like headers for Odoo (avoids WAF/bot filters)
- Optional ODOO_DB support for multi-DB Odoo
- Public /health for Render health checks
"""

import os
import json
import re
import unicodedata
from typing import Dict, Any
from functools import lru_cache, wraps
from datetime import datetime, timedelta

import requests
from flask import Flask, request, Response, redirect, render_template_string, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode

# =========================
# Configuration (ENV-based)
# =========================
PROXY_EMAIL    = os.environ.get("PROXY_EMAIL", "")
PROXY_PASSWORD = os.environ.get("PROXY_PASSWORD", "")

ODOO_BASE_URL  = os.environ.get("ODOO_BASE_URL", "https://example.com/")
ODOO_USERNAME  = os.environ.get("ODOO_USERNAME", "")
ODOO_PASSWORD  = os.environ.get("ODOO_PASSWORD", "")
ODOO_DB        = os.environ.get("ODOO_DB", "")  # optional

SANITIZE = True
TIMEOUT = (10, 30)

def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{ts}] [{level}] {msg}")

# =========================
# Flask app & session setup
# =========================
ODOO_BASE_URL = ODOO_BASE_URL.rstrip("/")
parsed_base = urlparse(ODOO_BASE_URL)
BASE_ROOT = f"{parsed_base.scheme}://{parsed_base.netloc}"
BASE_QS = dict(parse_qsl(parsed_base.query or ""))

app = Flask(__name__)

# Make Flask respect Render's reverse proxy headers
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Secret key (Render: set SECRET_KEY env or we generate one at boot)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

# Session config (secure-by-default on Render)
app.config.update(
    SESSION_COOKIE_NAME='session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,      # HTTPS only on Render
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    SESSION_REFRESH_EACH_REQUEST=True,
    PREFERRED_URL_SCHEME='https'
)

log("=" * 80)
log("🚀 Employee Proxy - Render build")
log("=" * 80)

# Upstream session that looks like a real browser (helps avoid WAF blocks)
odoo_session = requests.Session()
odoo_session.headers.update({
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/122.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
})

_view_cache: Dict[str, str] = {}

# =========================
# Login page (simple)
# =========================
LOGIN_PAGE = """
<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connexion</title>
<style>
 body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#f6f7fb;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
 .card{background:#fff;max-width:380px;width:100%;padding:28px;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.08)}
 h1{margin:0 0 18px;color:#4c5bd4;font-size:22px}
 label{display:block;margin:10px 0 6px;font-weight:600}
 input{width:100%;padding:12px;border:1px solid #ddd;border-radius:8px;font-size:14px}
 button{width:100%;margin-top:14px;padding:12px 14px;border:0;border-radius:8px;background:#4c5bd4;color:#fff;font-weight:700;cursor:pointer}
 .error{background:#fee;border:1px solid #fcc;color:#c33;padding:10px;border-radius:8px;margin:0 0 12px}
</style></head>
<body><div class="card">
<h1>🔐 Connexion</h1>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="POST">
<label>Email</label><input type="email" name="email" required autofocus>
<label>Mot de passe</label><input type="password" name="password" required>
<button type="submit">Se connecter</button>
</form></div></body></html>
"""

# =========================
# Auth decorator
# =========================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            log(f"[AUTH] Access denied to {request.path} - Not logged in", "WARN")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return wrapper

# =========================
# Utilities
# =========================
@lru_cache(maxsize=512)
def _norm(s: str) -> str:
    s = (s or "").strip()
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.lower()
    return re.sub(r"[\s_\-]+", " ", s)

REMOVED_FIELDS = {
    _norm("frais"), _norm("fees"),
    _norm("crbt"), _norm("crbt récupéré"), _norm("crbt recupere"),
    _norm("cod"), _norm("cod amount"), _norm("cod_amount"),
    _norm("is_crbt_client_paid"),
    _norm("montant dû"), _norm("montant du"), _norm("montant_du"),
    _norm("amount due"), _norm("amount_due"),
}

def _real(path: str) -> str:
    if path.startswith(("http://", "https://")):
        return path
    if not path.startswith("/"):
        path = "/" + path
    url = urljoin(BASE_ROOT, path)
    if BASE_QS:
        q = urlencode(BASE_QS, doseq=True)
        url += ("&" if "?" in url else "?") + q
    return url

# =========================
# Odoo login (with optional DB)
# =========================
def _ensure_odoo_login() -> None:
    try:
        r = odoo_session.get(_real("/web"), allow_redirects=True, timeout=TIMEOUT)
        if "/web/login" not in r.url:
            return

        log("Connexion Odoo...", "INFO")

        r_login = odoo_session.get(_real("/web/login"), allow_redirects=True, timeout=TIMEOUT)

        token = ""
        m = re.search(r'name=["\']csrf_token["\'].*?value=["\']([^"\']+)', r_login.text or "")
        if m:
            token = m.group(1)

        payload = {
            "login": ODOO_USERNAME,
            "password": ODOO_PASSWORD,
            "redirect": "/web",
        }
        if ODOO_DB:
            payload["db"] = ODOO_DB
        if token:
            payload["csrf_token"] = token

        r_post = odoo_session.post(
            _real("/web/login"),
            data=payload,
            headers={"Referer": _real("/web/login")},
            allow_redirects=True,
            timeout=TIMEOUT
        )

        if "/web/login" in r_post.url:
            raise RuntimeError("Odoo login failed")

        log("✓ Odoo connected", "INFO")

    except Exception as e:
        log(f"Odoo error: {e}", "ERROR")
        raise

# =========================
# Sanitization helpers
# =========================
def _detect_view_type(arch_xml: str) -> str:
    if not arch_xml:
        return "unknown"
    a = arch_xml.lower()
    if "<tree" in a or "<list" in a:
        return "list"
    if "<kanban" in a:
        return "kanban"
    if "<form" in a:
        return "form"
    return "unknown"

def _strip_fields_dict(fields_dict: Dict[str, Any], is_list_view: bool = True) -> None:
    if not is_list_view:
        return
    for k in list(fields_dict.keys()):
        if _norm(k) in REMOVED_FIELDS:
            fields_dict.pop(k, None)

def _strip_arch_fields_and_dashboard(arch_xml: str, view_type: str = "unknown") -> str:
    is_list_view = view_type in ("list", "tree", "kanban")
    cache_key = hash(arch_xml + view_type)
    if cache_key in _view_cache:
        return _view_cache[cache_key]
    try:
        soup = BeautifulSoup(arch_xml, "xml")
        if is_list_view:
            for fld in soup.find_all("field"):
                if _norm(fld.get("name", "")) in REMOVED_FIELDS:
                    fld.decompose()
        for node in soup.find_all(True):
            for attr in ("js_class", "js_classes"):
                if node.has_attr(attr):
                    val = " ".join(node.get(attr, []) if isinstance(node.get(attr), list) else [node.get(attr) or ""])
                    if "balance_dashboard_customer" in val or "dashboard" in val:
                        del node[attr]
        result = str(soup)
        _view_cache[cache_key] = result
        return result
    except Exception:
        return arch_xml

def _sanitize_view_payload(res: Dict[str, Any]) -> None:
    vt = "unknown"
    if isinstance(res.get("arch"), str):
        vt = _detect_view_type(res["arch"])
    is_list = vt in ("list", "tree", "kanban")
    if isinstance(res.get("fields"), dict):
        _strip_fields_dict(res["fields"], is_list)
    if isinstance(res.get("arch"), str):
        res["arch"] = _strip_arch_fields_and_dashboard(res["arch"], vt)
    fv = res.get("fields_views")
    if isinstance(fv, dict):
        for _, v in fv.items():
            if isinstance(v, dict):
                svt = "unknown"
                if isinstance(v.get("arch"), str):
                    svt = _detect_view_type(v["arch"])
                sub_is_list = svt in ("list", "tree", "kanban")
                if isinstance(v.get("fields"), dict):
                    _strip_fields_dict(v["fields"], sub_is_list)
                if isinstance(v.get("arch"), str):
                    v["arch"] = _strip_arch_fields_and_dashboard(v["arch"], svt)

def _sanitize_records_payload(res: Any, is_search_read: bool = True) -> Any:
    if isinstance(res, dict) and isinstance(res.get("records"), list):
        if is_search_read:
            res["records"] = [
                {k: v for k, v in r.items() if _norm(k) not in REMOVED_FIELDS} if isinstance(r, dict) else r
                for r in res["records"]
            ]
        return res
    if isinstance(res, list) and res and isinstance(res[0], dict):
        if len(res) == 1 or not is_search_read:
            return res
        return [
            {k: v for k, v in r.items() if _norm(k) not in REMOVED_FIELDS} if isinstance(r, dict) else r
            for r in res
        ]
    return res

def _sanitize_json(body: Dict[str, Any], request_path: str = "") -> Dict[str, Any]:
    if not isinstance(body, dict) or "result" not in body:
        return body
    try:
        if isinstance(body.get("result"), dict):
            if "unpaid_fees" in body["result"]:
                body["result"]["unpaid_fees"] = 0
            if "unpaid_crbt" in body["result"]:
                body["result"]["unpaid_crbt"] = 0
    except Exception:
        pass
    is_search_read = True
    try:
        if "search_read" in request_path or "search_read" in str(body):
            is_search_read = True
        elif "/call_kw/" in request_path and "read" in request_path:
            is_search_read = False
        elif isinstance(body.get("result"), list) and len(body["result"]) == 1:
            is_search_read = False
    except Exception:
        pass
    body["result"] = _sanitize_records_payload(body["result"], is_search_read)
    if isinstance(body["result"], dict):
        _sanitize_view_payload(body["result"])
    return body

CSS_INJECTION = """
<style>
.o_list_view th[data-name="frais"],.o_list_view td[data-name="frais"],
.o_list_view th[data-name="fees"],.o_list_view td[data-name="fees"],
.o_list_view th[data-name="crbt"],.o_list_view td[data-name="crbt"],
.o_list_view th[data-name="crbt_recupere"],.o_list_view td[data-name="crbt_recupere"],
.o_list_view th[data-name="cod"],.o_list_view td[data-name="cod"],
.o_list_view th[data-name="montant_du"],.o_list_view td[data-name="montant_du"],
.o_list_view th[data-name="amount_due"],.o_list_view td[data-name="amount_due"]{display:none!important}
</style>
"""

def _sanitize_html_fast(html: str) -> str:
    if "</head>" in html:
        html = html.replace("</head>", f"{CSS_INJECTION}</head>")
    return html

# =========================
# Proxy handler
# =========================
def _is_json_response(resp: requests.Response) -> bool:
    return "application/json" in resp.headers.get("Content-Type", "")

def _forward_upstream(path: str) -> Response:
    try:
        _ensure_odoo_login()
    except Exception as e:
        return Response(f"Odoo Error: {e}", status=500)

    method = request.method
    upstream = _real(path)

    headers = {}
    for key, value in request.headers:
        if key.lower() not in {
            'host', 'content-length', 'cookie', 'connection',
            'keep-alive', 'proxy-authenticate', 'proxy-authorization',
            'te', 'trailers', 'transfer-encoding', 'upgrade'
        }:
            headers[key] = value

    body = request.get_data()

    try:
        resp = odoo_session.request(
            method, upstream,
            params=request.args, data=body, headers=headers,
            stream=True, allow_redirects=False, timeout=TIMEOUT
        )
        log(f"Upstream {method} {upstream} -> {resp.status_code} {resp.headers.get('Content-Type','')}", "DEBUG")
    except Exception as e:
        return Response(f"Proxy Error: {e}", status=502)

    if 300 <= resp.status_code < 400 and "Location" in resp.headers:
        loc = resp.headers["Location"]
        if loc.startswith(BASE_ROOT):
            loc = loc.replace(BASE_ROOT, "")
        return redirect(loc, code=resp.status_code)

    if _is_json_response(resp):
        try:
            data = resp.json()
            if SANITIZE:
                data = _sanitize_json(data, path)
            return Response(json.dumps(data, separators=(',', ':')),
                            status=resp.status_code,
                            content_type="application/json")
        except Exception:
            return Response(resp.content, status=resp.status_code, content_type="application/json")

    if "text/html" in resp.headers.get("Content-Type", ""):
        try:
            html = resp.text
            if SANITIZE:
                html = _sanitize_html_fast(html)
            html = html.replace(BASE_ROOT, "")
            return Response(html, status=resp.status_code, content_type="text/html; charset=utf-8")
        except Exception:
            pass

    excluded = {
        "content-encoding", "transfer-encoding", "connection", "content-length",
        "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "upgrade"
    }
    headers_out = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
    return Response(resp.content, status=resp.status_code, headers=headers_out)

# =========================
# Routes
# =========================
@app.route("/health")
def health():
    return Response("ok", status=200, headers={"Content-Type": "text/plain"})

@app.before_request
def before_request():
    session.permanent = True
    log(f"[REQUEST] {request.method} {request.path} - Session ID: {session.get('_id', 'none')}", "DEBUG")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        log("[LOGIN] Already logged in, redirecting", "INFO")
        return redirect(url_for('proxy', path='web'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        log(f"[LOGIN] Attempt from {email}", "INFO")
        if email == PROXY_EMAIL and password == PROXY_PASSWORD:
            session.clear()
            session['logged_in'] = True
            session['user_email'] = email
            session['login_time'] = datetime.now().isoformat()
            session.permanent = True
            log(f"[LOGIN] ✓ Success for {email}", "INFO")
            return redirect(url_for('proxy', path='web'))
        else:
            log(f"[LOGIN] ✗ Failed for {email}", "WARN")
            return render_template_string(LOGIN_PAGE, error="Email ou mot de passe incorrect"), 401

    return render_template_string(LOGIN_PAGE, error=None)

@app.route('/logout')
def logout():
    session.clear()
    log("[LOGOUT] User logged out", "INFO")
    return redirect(url_for('login'))

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
@login_required
def proxy(path: str):
    if path == "":
        path = "web"
    if not path.startswith("/"):
        path = "/" + path
    return _forward_upstream(path)

@app.route("/_status")
@login_required
def status():
    return Response(
        f"Status: OK\nUser: {session.get('user_email')}\nLogin: {session.get('login_time')}\n",
        200, {"Content-Type": "text/plain"}
    )

@app.errorhandler(404)
def not_found(e):
    return Response("Not Found", status=404)

@app.errorhandler(500)
def server_error(e):
    log(f"Error 500: {e}", "ERROR")
    return Response("Server Error", status=500)

# =========================
# Local dev entrypoint
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    log("=" * 80)
    log("🚀 Employee Proxy - Local run")
    log(f"Port: {port}")
    log(f"Session Lifetime: {app.config['PERMANENT_SESSION_LIFETIME']}")
    log(f"Session Secure: {app.config['SESSION_COOKIE_SECURE']}")
    log(f"Session SameSite: {app.config['SESSION_COOKIE_SAMESITE']}")
    log("=" * 80)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
