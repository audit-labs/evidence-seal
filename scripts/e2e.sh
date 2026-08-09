#!/usr/bin/env bash
#
# End-to-end demonstration of every evidence-seal feature, run against the CLI.
#
# Exercises seal, verify, chain, keygen, sign, and RFC 3161 timestamping —
# including the adversarial cases that must fail — and prints a pass/fail tally.
# Exits non-zero if any check does not behave as expected.
#
# The timestamp tokens are minted by a local self-signed TSA (scripts/_local_tsa.py)
# so the full flow, including signature verification, runs offline. Needs the
# optional extras: pip install -e ".[sign,timestamp]"
#
# Usage: scripts/e2e.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"

# Prefer the project venv; fall back to whatever is on PATH.
if [[ -x "$REPO/.venv/bin/python" ]]; then
  PY="$REPO/.venv/bin/python"
else
  PY="$(command -v python3 || command -v python)"
fi
ES="$PY -m evidence_seal"
TSA="$PY $SCRIPT_DIR/_local_tsa.py"

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

pass=0; fail=0
step() { printf '\n\033[1m━━━ %s\033[0m\n' "$*"; }
run()  { printf '$ %s\n' "$*"; eval "$*"; }
# assert_exit <expected-code> <label> <command...>
assert_exit() {
  local exp="$1" label="$2"; shift 2
  printf '$ %s\n' "$*"
  eval "$*" >"$W/out" 2>&1; local rc=$?
  sed 's/^/   /' "$W/out"
  if [[ "$rc" == "$exp" ]]; then
    printf '   \033[32m✓ PASS\033[0m — %s (exit %s)\n' "$label" "$rc"; pass=$((pass+1))
  else
    printf '   \033[31m✗ FAIL\033[0m — %s (exit %s, expected %s)\n' "$label" "$rc" "$exp"; fail=$((fail+1))
  fi
}

step "0. Version + command surface"
run "$ES --version"

step "1. SEAL a realistic evidence package (with provenance metadata)"
mkdir -p "$W/pkg/logs"
printf 'user,mfa_enabled\nalice,true\nbob,false\n' > "$W/pkg/iam_users.csv"
printf 'repo,branch,protected\napp,main,true\n' > "$W/pkg/branch_protections.csv"
printf 'GitHub Audit — acme\n' > "$W/pkg/summary.txt"
printf 'scratch\n' > "$W/pkg/logs/debug.tmp"
assert_exit 0 "seal writes a manifest" \
  "$ES seal $W/pkg --out $W/m.json --ignore 'logs/*.tmp' --meta engagement=ACME-2026 --meta collector='Christian Cleberg'"

step "2. VERIFY — intact package"
assert_exit 0 "verify clean" "$ES verify $W/pkg --manifest $W/m.json"

step "3. TAMPER — modify a sealed file"
printf 'alice,true\nbob,flipped\n' >> "$W/pkg/iam_users.csv"
assert_exit 1 "verify catches modification" "$ES verify $W/pkg --manifest $W/m.json"
printf 'user,mfa_enabled\nalice,true\nbob,false\n' > "$W/pkg/iam_users.csv"

step "4. TAMPER — added + removed files"
printf 'oops\n' > "$W/pkg/rogue.csv"; rm "$W/pkg/summary.txt"
assert_exit 1 "verify catches add+remove" "$ES verify $W/pkg --manifest $W/m.json"
rm "$W/pkg/rogue.csv"; printf 'GitHub Audit — acme\n' > "$W/pkg/summary.txt"

step "5. IGNORE globs — excluded file never flags"
assert_exit 0 "ignored file does not break verify" "$ES verify $W/pkg --manifest $W/m.json"

step "6. MANIFEST TAMPER — edit a recorded hash in the manifest itself"
"$PY" - "$W/m.json" "$W/m_bad.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); m["files"][0]["sha256"] = "0" * 64
json.dump(m, open(sys.argv[2], "w"), indent=2, sort_keys=True)
PY
assert_exit 1 "verify catches a doctored manifest" "$ES verify $W/pkg --manifest $W/m_bad.json"

step "7. CHAIN OF CUSTODY — three sequential seals link"
mkdir -p "$W/chain"
printf 'v1\n' > "$W/pkg/state.csv"; $ES seal "$W/pkg" --out "$W/chain/jan.json" >/dev/null 2>&1
printf 'v2\n' > "$W/pkg/state.csv"; $ES seal "$W/pkg" --out "$W/chain/feb.json" --prev "$W/chain/jan.json" >/dev/null 2>&1
printf 'v3\n' > "$W/pkg/state.csv"; $ES seal "$W/pkg" --out "$W/chain/mar.json" --prev "$W/chain/feb.json" >/dev/null 2>&1
rm "$W/pkg/state.csv"
assert_exit 0 "chain in order is intact" "$ES chain $W/chain/jan.json $W/chain/feb.json $W/chain/mar.json"

step "8. CHAIN — reordered links are detected"
assert_exit 1 "reordered chain is broken" "$ES chain $W/chain/mar.json $W/chain/jan.json $W/chain/feb.json"

step "9. CHAIN — a spliced-out link is detected"
assert_exit 1 "missing middle seal is broken" "$ES chain $W/chain/jan.json $W/chain/mar.json"

step "10. SIGNING — generate an ed25519 keypair"
assert_exit 0 "keygen" "$ES keygen --private $W/acme.key --public $W/acme.pub"

step "11. SIGN and VERIFY with the matching public key"
assert_exit 0 "seal + sign" "$ES seal $W/pkg --out $W/signed.json --sign $W/acme.key"
assert_exit 0 "verify requires correct signer" "$ES verify $W/pkg --manifest $W/signed.json --pubkey $W/acme.pub"

step "12. SIGN — a wrong public key is rejected"
$ES keygen --private "$W/other.key" --public "$W/other.pub" >/dev/null 2>&1
assert_exit 1 "wrong signer rejected" "$ES verify $W/pkg --manifest $W/signed.json --pubkey $W/other.pub"

step "13. TIMESTAMP — build an RFC 3161 request (.tsq)"
assert_exit 0 "timestamp request" "$ES timestamp request $W/signed.json --out $W/req.tsq"

step "14. TIMESTAMP — apply a TSA token and verify the binding"
MID=$("$PY" -c "import json;print(json.load(open('$W/signed.json'))['id'])")
$TSA "$MID" "$W/tsa_ok" >/dev/null 2>&1
assert_exit 0 "apply token" "$ES timestamp apply $W/signed.json --token $W/tsa_ok/resp.tsr --out $W/stamped.json"
assert_exit 0 "verify timestamp binding" "$ES timestamp verify $W/stamped.json"

step "15. TIMESTAMP — full CMS signature verification with --tsa-cert"
assert_exit 0 "full TSA signature verify" "$ES timestamp verify $W/stamped.json --tsa-cert $W/tsa_ok/tsa.pem"

step "16. TIMESTAMP — wrong TSA certificate is rejected"
$TSA "$MID" "$W/tsa_wrong" >/dev/null 2>&1
assert_exit 1 "wrong TSA cert rejected" "$ES timestamp verify $W/stamped.json --tsa-cert $W/tsa_wrong/tsa.pem"

step "17. TIMESTAMP — cert lacking the timeStamping EKU is rejected"
$TSA "$MID" "$W/tsa_noeku" --no-eku >/dev/null 2>&1
$ES timestamp apply "$W/signed.json" --token "$W/tsa_noeku/resp.tsr" --out "$W/stamped_noeku.json" >/dev/null 2>&1
assert_exit 1 "cert without timeStamping EKU rejected" "$ES timestamp verify $W/stamped_noeku.json --tsa-cert $W/tsa_noeku/tsa.pem"

step "18. COMPOSITION — sealed + signed + timestamped, verified together"
$ES seal "$W/pkg" --out "$W/full.json" --sign "$W/acme.key" --meta engagement=ACME-2026 >/dev/null 2>&1
FID=$("$PY" -c "import json;print(json.load(open('$W/full.json'))['id'])")
$TSA "$FID" "$W/tsa_full" >/dev/null 2>&1
$ES timestamp apply "$W/full.json" --token "$W/tsa_full/resp.tsr" >/dev/null 2>&1
assert_exit 0 "integrity + signature + timestamp all verify at once" \
  "$ES verify $W/pkg --manifest $W/full.json --pubkey $W/acme.pub --tsa-cert $W/tsa_full/tsa.pem"

echo
printf '\033[1m════════════════════════════════════════════\033[0m\n'
printf '\033[1m  E2E RESULT: %s passed, %s failed\033[0m\n' "$pass" "$fail"
printf '\033[1m════════════════════════════════════════════\033[0m\n'
exit $fail
