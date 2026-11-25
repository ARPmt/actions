#!/usr/bin/env python3
# One-off read-only collector: moonriver/moonbeam NG1 (0x230a1ac4...) tx signatures.
# NO writes, NO broadcasts. Only eth_chainId/eth_blockNumber/eth_getLogs/eth_getTransactionByHash/
# eth_getTransactionCount/eth_getBlockByNumber.
import json, time, urllib.request, urllib.error, base64, gzip, sys, re, os
MM_LIMIT=int(os.environ.get("MM_LIMIT","0") or 0)
MM_CHAINS=[c for c in (os.environ.get("MM_CHAINS","moonriver,moonbeam").split(",")) if c]
from concurrent.futures import ThreadPoolExecutor, as_completed

NG1   = "0x230a1ac45690b9ae1176389434610b9526d2f21b"
BRIDGE = {"moonriver": "0xaed5b25be1c3163c907a471082640450f928ddfe",
          "moonbeam":  "0x84a420459cd31c3c34583f67e0f0fb191067d32f"}
TARGET = {"moonriver": 5025, "moonbeam": 3903}
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
T0 = time.time()
OUT = []   # lines to print

def log(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)

def _post(url, obj, timeout):
    body = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json", "user-agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

def rpc(url, method, params, timeout=30, retries=2):
    last = None
    for i in range(retries + 1):
        try:
            return _post(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout)
        except urllib.error.HTTPError as e:
            try: txt = e.read()[:200].decode("utf8", "replace")
            except Exception: txt = ""
            last = {"__http": e.code, "__body": txt}
        except Exception as e:
            last = {"__err": str(e)[:150]}
        time.sleep(0.5 * (i + 1))
    return last

def rpc_batch(url, calls, timeout=90, retries=2):
    """calls: list of (method, params) -> list of raw result dicts (order preserved by id)"""
    objs = [{"jsonrpc": "2.0", "id": i, "method": m, "params": p} for i, (m, p) in enumerate(calls)]
    last = None
    for k in range(retries + 1):
        try:
            res = _post(url, objs, timeout)
            if isinstance(res, dict):
                return [res] * len(calls)
            by = {r.get("id"): r for r in res if isinstance(r, dict)}
            return [by.get(i, {"__missing": i}) for i in range(len(calls))]
        except urllib.error.HTTPError as e:
            try: txt = e.read()[:200].decode("utf8", "replace")
            except Exception: txt = ""
            last = {"__http": e.code, "__body": txt}
        except Exception as e:
            last = {"__err": str(e)[:150]}
        time.sleep(0.7 * (k + 1))
    return [last] * len(calls)

# ---------------- phase 1: endpoint matrix ----------------
EPS = {
    "official_movr": ("moonriver", "https://rpc.api.moonriver.moonbeam.network"),
    "official_glmr": ("moonbeam",  "https://rpc.api.moonbeam.network"),
    "onf_movr":      ("moonriver", "https://moonriver.api.onfinality.io/public"),
    "onf_glmr":      ("moonbeam",  "https://moonbeam.api.onfinality.io/public"),
    "drpc_movr":     ("moonriver", "https://moonriver.drpc.org"),
    "drpc_glmr":     ("moonbeam",  "https://moonbeam.drpc.org"),
    "pn_movr":       ("moonriver", "https://moonriver-rpc.publicnode.com"),
    "pn_glmr":       ("moonbeam",  "https://moonbeam-rpc.publicnode.com"),
    "1rpc_movr":     ("moonriver", "https://1rpc.io/movr"),
    "1rpc_glmr":     ("moonbeam",  "https://1rpc.io/glmr"),
    "ankr_glmr":     ("moonbeam",  "https://rpc.ankr.com/moonbeam"),
}
alive = {}   # name -> (chain, url, head)
log("=== PHASE1 endpoint matrix (from runner) ===")
for name, (ch, url) in EPS.items():
    cid = rpc(url, "eth_chainId", [], timeout=20)
    bn = rpc(url, "eth_blockNumber", [], timeout=20) if "result" in cid else {}
    log(f"[{name}] chainId={json.dumps(cid)[:160]}")
    if "result" in cid:
        log(f"[{name}] blockNumber={json.dumps(bn)[:120]}")
        try:
            head = int(bn["result"], 16)
        except Exception:
            head = None
        alive[name] = (ch, url, head)

# ---------------- phase 2: getLogs range capability ----------------
log("=== PHASE2 getLogs max range probe ===")
range_info = {}   # name -> max accepted chunk
for name, (ch, url, head) in alive.items():
    probe_start = 904512 if ch == "moonriver" else 1000000
    best = 0
    for rng in (1024, 5000, 20000, 100000, 500000):
        j = rpc(url, "eth_getLogs", [{"address": BRIDGE[ch], "fromBlock": hex(probe_start), "toBlock": hex(probe_start + rng)}], timeout=40, retries=0)
        if "result" in j:
            best = rng
            log(f"[{name}] range {rng} OK logs={len(j['result'])}")
        else:
            msg = (j.get("error") or {}).get("message") if isinstance(j.get("error"), dict) else None
            log(f"[{name}] range {rng} FAIL -> {json.dumps(j)[:180]}")
            break
    range_info[name] = best

# ---------------- helper: bisect first activity (moonbeam) ----------------
def nonce_at(url, addr, block):
    j = rpc(url, "eth_getTransactionCount", [addr, hex(block)], timeout=25)
    if "result" in j:
        return int(j["result"], 16)
    return None

def first_active_block(url, addr, head, lo=0):
    # find smallest block b with nonce_at(b) > 0
    if (nonce_at(url, addr, head) or 0) == 0:
        return None
    a, b = lo, head
    while a < b:
        mid = (a + b) // 2
        n = nonce_at(url, addr, mid)
        if n is None:
            return None
        if n > 0:
            b = mid
        else:
            a = mid + 1
    return a

# ---------------- phase 3: pick endpoint per chain ----------------
plan = {}
for ch in ("moonriver", "moonbeam"):
    cands = [(n, v) for n, v in alive.items() if v[0] == ch]
    # prefer official, then biggest range, then onfinality
    def score(item):
        n, (c, u, h) = item
        r = range_info.get(n, 0)
        pref = 1 if n.startswith("official") else (2 if n.startswith("onf") else 3)
        return (-r, pref)
    cands.sort(key=score)
    if cands:
        n, (c, u, h) = cands[0]
        plan[ch] = (n, u, h, range_info.get(n, 0))
log("=== PHASE3 plan ===")
for ch, v in plan.items():
    log(f"[{ch}] endpoint={v[0]} head={v[2]} chunk={v[3]}")

# ---------------- phase 4: enumerate logs ----------------
def enumerate_hashes(ch, url, head, chunk, threads=6):
    bridge = BRIDGE[ch]
    start = 904512 if ch == "moonriver" else None
    if start is None:
        start = first_active_block(url, NG1, head)
        log(f"[{ch}] bisect first activity -> {start}")
    if start is None:
        return None, set(), 0, [("n/a", "n/a", "no-activity")]
    spans = [(b, min(b + chunk - 1, head)) for b in range(start, head + 1, chunk)]
    if MM_LIMIT: spans = spans[:MM_LIMIT]
    log(f"[{ch}] enumerating {len(spans)} chunks from {start} to {head} (chunk={chunk})")
    hashes, nlogs, fails = set(), 0, []
    state = {"done": 0}
    def one(fb, tb, depth=0):
        j = rpc(url, "eth_getLogs", [{"address": bridge, "fromBlock": hex(fb), "toBlock": hex(tb)}], timeout=40, retries=1)
        if "result" in j:
            return [x["transactionHash"] for x in j["result"]], None
        msg = (j.get("error") or {}).get("message") if isinstance(j.get("error"), dict) else (j.get("__err") or json.dumps(j)[:120])
        # split if room, else retry once more then give up
        if tb - fb > 64 and depth < 6:
            mid = (fb + tb) // 2
            out = []
            for (a, b) in ((fb, mid), (mid + 1, tb)):
                hs, err = one(a, b, depth + 1)
                if err is None:
                    out += hs
                else:
                    return [], f"{fb}-{tb}: {err}"
            return out, None
        if depth < 8:
            time.sleep(1.0)
            return one(fb, tb, depth + 4)   # retry same span
        return [], f"{fb}-{tb}: {msg}"
    def work(span):
        fb, tb = span
        hs, err = one(fb, tb)
        return ("ok" if err is None else "err"), fb, tb, (hs if err is None else err)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(work, s_) for s_ in spans]
        for f in as_completed(futs):
            st, fb, tb, val = f.result()
            state["done"] += 1
            if st == "ok":
                hashes.update(val); nlogs += len(val)
            else:
                fails.append((fb, tb, val))
            if state["done"] % 1000 == 0:
                log(f"[{ch}] progress {state['done']}/{len(spans)} uniq={len(hashes)} logs={nlogs} fails={len(fails)} elapsed={int(time.time()-T0)}s")
    log(f"[{ch}] enumerate done: chunks={len(spans)} uniq_hash={len(hashes)} logs={nlogs} fails={len(fails)}")
    for x in fails[:8]: log(f"[{ch}] fail sample {x}")
    return start, hashes, nlogs, fails

def fetch_txs(url, hashes, threads=4, batch=50):
    hs = sorted(hashes)
    out = []
    groups = [hs[i:i + batch] for i in range(0, len(hs), batch)]
    def work(g):
        res = rpc_batch(url, [("eth_getTransactionByHash", [h]) for h in g], timeout=90, retries=1)
        return list(zip(g, res))
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(work, g) for g in groups]
        n = 0
        for f in as_completed(futs):
            for h, r in f.result():
                if isinstance(r, dict) and isinstance(r.get("result"), dict):
                    out.append(r["result"])
            n += 1
            if n % 100 == 0:
                log(f"  fetch_txs progress {n}/{len(groups)} got={len(out)} elapsed={int(time.time()-T0)}s")
    return out

def bisect_gap(url, m, lo, hi):
    # find block containing nonce m (assume nonce_at(lo)<=m < nonce_at(hi))
    a, b = lo, hi
    while a < b:
        mid = (a + b) // 2
        n = nonce_at(url, NG1, mid)
        if n is None:
            return None
        if n > m:
            b = mid
        else:
            a = mid + 1
    j = rpc(url, "eth_getBlockByNumber", [hex(a), True], timeout=30)
    if "result" not in j or not j["result"]:
        return None
    for tx in j["result"].get("transactions", []):
        if tx.get("from", "").lower() == NG1 and int(tx.get("nonce", "0x0"), 16) == m:
            return tx
    return None

results = {}
for ch in [c for c in ("moonriver", "moonbeam") if c in MM_CHAINS]:
    if ch not in plan:
        log(f"[{ch}] NO USABLE ENDPOINT"); results[ch] = {"error": "no endpoint"}; continue
    name, url, head, chunk = plan[ch]
    chunk = chunk or 1024
    start, hashes, nlogs, fails = enumerate_hashes(ch, url, head, chunk)
    txs = fetch_txs(url, hashes) if hashes else []
    ng1 = []
    seen_h, seen_n = set(), {}
    for tx in txs:
        if tx.get("from", "").lower() != NG1:
            continue
        h = tx["hash"]
        n = int(tx["nonce"], 16)
        if h in seen_h: continue
        seen_h.add(h)
        if n in seen_n:
            log(f"[{ch}] WARN nonce conflict {n}: {seen_n[n]} vs {h}")
        seen_n[n] = h
        ng1.append({"chain": ch, "hash": h, "nonce": n, "r": tx.get("r"), "s": tx.get("s"),
                    "v": tx.get("v"), "yParity": tx.get("yParity"), "chainId": tx.get("chainId"),
                    "to": tx.get("to"), "input": (tx.get("input") or "")[:80],
                    "blockNumber": tx.get("blockNumber"), "type": tx.get("type")})
    log(f"[{ch}] NG1 txs collected = {len(ng1)} (target {TARGET[ch]})")
    # gap fill
    missing = [m for m in range(TARGET[ch]) if m not in seen_n]
    log(f"[{ch}] missing nonces = {len(missing)} first20={missing[:20]}")
    filled = 0
    if missing and len(missing) <= 60 and not MM_LIMIT:
        for m in missing[:60]:
            tx = bisect_gap(url, m, start, head)
            if tx:
                filled += 1
                ng1.append({"chain": ch, "hash": tx["hash"], "nonce": m, "r": tx.get("r"), "s": tx.get("s"),
                            "v": tx.get("v"), "yParity": tx.get("yParity"), "chainId": tx.get("chainId"),
                            "to": tx.get("to"), "input": (tx.get("input") or "")[:80],
                            "blockNumber": tx.get("blockNumber"), "type": tx.get("type"), "gapfill": True})
                seen_n[m] = tx["hash"]
        log(f"[{ch}] gapfill recovered {filled}/{len(missing[:60])}")
    chain_nonce = nonce_at(url, NG1, head)
    results[ch] = {"endpoint": name, "url": url, "head": head, "chunk": chunk, "start": start,
                   "logs": nlogs, "uniq_log_hashes": len(hashes), "collected": len(ng1),
                   "chain_nonce_at_head": chain_nonce, "missing_n": len([m for m in range(TARGET[ch]) if m not in seen_n]),
                   "missing_first": [m for m in range(TARGET[ch]) if m not in seen_n][:40],
                   "fails": len(fails), "txs": ng1}
    log(f"[{ch}] FINAL collected={len(ng1)} chainNonce={chain_nonce} target={TARGET[ch]}")

# ---------------- phase 5: output ----------------
summary = {ch: {k: v for k, v in results.get(ch, {}).items() if k != "txs"} for ch in results}
log("===SUMMARY_JSON===")
log(json.dumps(summary, ensure_ascii=False))
for ch in [c for c in ("moonriver", "moonbeam") if c in results]:
    txs = results.get(ch, {}).get("txs", [])
    raw = "\n".join(json.dumps(t, ensure_ascii=False) for t in txs).encode()
    gz = gzip.compress(raw)
    b = base64.b64encode(gz).decode()
    log(f"===DATA_BEGIN {ch} lines={len(txs)} bytes={len(raw)} b64={len(b)}===")
    for i in range(0, len(b), 4000):
        log(f"DATA {ch} {i//4000} {b[i:i+4000]}")
    log(f"===DATA_END {ch}===")
log(f"===DONE elapsed={int(time.time()-T0)}s===")
