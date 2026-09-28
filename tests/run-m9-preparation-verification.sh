#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${M9_PYTHON_BIN:-python3}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/m9-prep-verify.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
printf '===== M9 PROOF-HARNESS PREPARATION VERIFICATION =====\n'
M9_SYNTHETIC_TEST_MODE=1 bash "$ROOT/tests/run-static-verification.sh"
"$PYTHON" "$ROOT/scripts/verify-m9-targeted-vitest.py" --report "$ROOT/tests/fixtures/vitest-targeted-good.json" --map "$ROOT/scripts/lib/m9-targeted-test-map.json" --web-root /candidate/apps/web --expected-tests 113 --expect-candidate-sha 91f5cb3ee951e253b8d97e6f5fa4f719c75b22d3 --expect-candidate-tree e734b357d60364faccb428efd78202099f414aa1 --json-out "$TMP/good.json"
grep -Fq '"status": "PASS"' "$TMP/good.json"
"$PYTHON" - "$ROOT/tests/fixtures/vitest-targeted-good.json" "$TMP/missing.json" <<'PY'
import json,sys
src,out=sys.argv[1:3]
with open(src,encoding="utf-8") as h:d=json.load(h)
d["testResults"][0]["assertionResults"][0]["title"]="MISSING-G-01"
with open(out,"w",encoding="utf-8") as h:json.dump(d,h)
PY
if "$PYTHON" "$ROOT/scripts/verify-m9-targeted-vitest.py" --report "$TMP/missing.json" --map "$ROOT/scripts/lib/m9-targeted-test-map.json" --web-root /candidate/apps/web --expected-tests 113 --expect-candidate-sha 91f5cb3ee951e253b8d97e6f5fa4f719c75b22d3 --expect-candidate-tree e734b357d60364faccb428efd78202099f414aa1 --json-out "$TMP/missing-out.json" >/dev/null 2>&1; then
  printf 'FAIL: missing semantic title was accepted\n' >&2; exit 1
fi
"$PYTHON" - "$ROOT/tests/fixtures/vitest-targeted-good.json" "$TMP/failed.json" <<'PY'
import json,sys
src,out=sys.argv[1:3]
with open(src,encoding="utf-8") as h:d=json.load(h)
d["testResults"][0]["assertionResults"][0]["status"]="failed";d["numPassedTests"]=112;d["numFailedTests"]=1;d["success"]=False
with open(out,"w",encoding="utf-8") as h:json.dump(d,h)
PY
if "$PYTHON" "$ROOT/scripts/verify-m9-targeted-vitest.py" --report "$TMP/failed.json" --map "$ROOT/scripts/lib/m9-targeted-test-map.json" --web-root /candidate/apps/web --expected-tests 113 --expect-candidate-sha 91f5cb3ee951e253b8d97e6f5fa4f719c75b22d3 --expect-candidate-tree e734b357d60364faccb428efd78202099f414aa1 --json-out "$TMP/failed-out.json" >/dev/null 2>&1; then
  printf 'FAIL: failed targeted assertion was accepted\n' >&2; exit 1
fi
CORE="$ROOT/scripts/run-m9-proof-core.sh"
PREFLIGHT="$ROOT/scripts/preflight-m9-alibaba-ecs.sh"
grep -Fq "readonly APP_BRANCH='m9-grapheme-safe-native-selection-capture'" "$CORE"
grep -Fq "readonly APP_SHA='91f5cb3ee951e253b8d97e6f5fa4f719c75b22d3'" "$CORE"
grep -Fq "readonly APP_TREE='e734b357d60364faccb428efd78202099f414aa1'" "$CORE"
grep -Fq "readonly APP_PARENT='6dc5c84fb90b9f09e9f59a7b43c1f2b7d9c205a1'" "$CORE"
grep -Fq "readonly MAIN_SHA='e752d2c3358217770ee7029ace07687a15cf927a'" "$CORE"
grep -Fq "readonly EXPECTED_PYTEST_PASSED='602'" "$CORE"
grep -Fq "readonly EXPECTED_VITEST_PASSED='561'" "$CORE"
grep -Fq "readonly EXPECTED_PLAYWRIGHT_PASSED='35'" "$CORE"
grep -Fq "readonly EXPECTED_M9_TARGETED_PASSED='113'" "$CORE"
grep -Fq "readonly PRODUCT_BRANCH='m9-grapheme-safe-native-selection-capture'" "$PREFLIGHT"
if grep -Fq "m9-alignment-connector-obstacle-avoiding-routing" "$PREFLIGHT"; then
  printf 'FAIL: stale M8-derived Product branch survived in M9 preflight\n' >&2; exit 1
fi
if grep -R -Fq "M9-M9-GATE2" "$ROOT/scripts" "$ROOT/tests" "$ROOT/README.md"; then
  printf 'FAIL: stale duplicated M9 Gate 2 label survived preparation\n' >&2; exit 1
fi
grep -Fq "readonly M9_PROVIDER_BINDING_READY='NO'" "$ROOT/scripts/lib/m9-provider-identity.sh"
if env -u M9_SYNTHETIC_TEST_MODE bash -c 'source "$1"; m9_provider_binding_ready' _ "$ROOT/scripts/lib/m9-provider-identity.sh" >/dev/null 2>&1; then
  printf 'FAIL: formally unbound provider was accepted\n' >&2; exit 1
fi
printf 'M9_PREPARATION_STATIC_VERIFY=PASS\n'
printf 'PROVIDER_BINDING=UNBOUND_FAIL_CLOSED\n'
printf 'HOSTED_PROOF_EXECUTED=NO\n'
