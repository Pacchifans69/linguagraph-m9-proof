#!/usr/bin/env bash
# LinguaGraph M9 Gate 2 formal proof wrapper.
#
# This is the ONE AND ONLY formal M9 entrypoint:
#
#   scripts/run-m9-proof.sh
#
# Lifecycle:
#
#   pre-claim guards   local proof/executor/token syntax, frozen static binding,
#                      proof checkout, ossutil capability, bucket versioning
#                      (read-only), durable issued.json retrieval + validation,
#                      read-only provider identity verification
#   claim              atomic create-if-absent single-use claim.json
#   PHASE A execution  formal adapter invocation + RC capture and cross-check
#   PHASE B seal       deterministic manifest, exactly one canonical archive,
#                      locally generated package-index.json (frozen)
#   PHASE C durability create-if-absent uploads + byte-exact read-back
#   PHASE D commit     canonical closure-receipt.json, exact read-back, terminal
#                      M9_FORMAL_RUN_COMMAND_RC=0 marker
#
# run-m9-proof-alibaba-ecs.sh is NOT an independent formal runner: without the
# wrapper-issued context and the durable claim it refuses to consume any
# authorization and never invokes the semantic core.
#
# The semantic core scripts/run-m9-proof-core.sh never writes core-exit-code.txt;
# only the adapter captures that child RC, and only the wrapper captures the
# adapter child RC as formal-execution-rc.txt.
#
# Never run this without separate Human approval of the exact proof commit and a
# fresh single-use authorization. The file is sourceable so that offline
# synthetic verification can exercise individual phases: sourcing it only
# defines functions and mutates nothing.
set -Eeuo pipefail

M9_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/lib" && pwd)"
# shellcheck source=lib/m9-synthetic-seams.sh
source "$M9_LIB_DIR/m9-synthetic-seams.sh"
# shellcheck source=lib/m9-provider-identity.sh
source "$M9_LIB_DIR/m9-provider-identity.sh"
# shellcheck source=lib/m9-oss.sh
source "$M9_LIB_DIR/m9-oss.sh"
# shellcheck source=lib/m9-manifest.sh
source "$M9_LIB_DIR/m9-manifest.sh"

readonly M9_FORMAL_RC_MARKER='M9_FORMAL_RUN_COMMAND_RC'
readonly M9_PROOF_ORIGIN_URL='https://github.com/Pacchifans69/linguagraph-m9-proof.git'
readonly M9_PROOF_BRANCH='main'

# Frozen Product bindings are owned by the semantic core and read back through
# its --emit-static-binding mode, so there is exactly one copy of each pin.
readonly M9_APP_SHA='91f5cb3ee951e253b8d97e6f5fa4f719c75b22d3'
readonly M9_APP_TREE='e734b357d60364faccb428efd78202099f414aa1'
readonly M9_APP_PARENT='6dc5c84fb90b9f09e9f59a7b43c1f2b7d9c205a1'
readonly M9_MAIN_SHA='e752d2c3358217770ee7029ace07687a15cf927a'

readonly M9_AUTH_SCHEMA='linguagraph-m9-run-authorization/v1'
readonly M9_RETRY_SCHEMA='linguagraph-m9-durability-retry-authorization/v1'
readonly M9_CLAIM_SCHEMA='linguagraph-m9-claim/v1'
readonly M9_PACKAGE_INDEX_SCHEMA='linguagraph-m9-package-index/v1'
readonly M9_RECEIPT_SCHEMA='linguagraph-m9-closure-receipt/v1'
readonly M9_CONTEXT_SCHEMA='linguagraph-m9-formal-invocation-context/v1'
readonly M9_PACKAGE_INDEX_OBJECT_NAME='package-index.json'
readonly M9_RECEIPT_OBJECT_NAME='closure-receipt.json'
readonly M9_EFFECTIVE_RETRIES_CONTENT='PLAYWRIGHT_EFFECTIVE_RETRIES=0'

# --- populated by m9_wrapper_init / m9_load_authorization -------------------
# Sourcing this file must never clobber an already-provided value, so that
# offline synthetic verification can inject paths into individual phases.
M9_PROOF_ROOT="${M9_PROOF_ROOT:-}"
M9_EVIDENCE="${M9_EVIDENCE:-}"
M9_HOST_STATE="${M9_HOST_STATE:-}"
M9_PRECLAIM_DIR="${M9_PRECLAIM_DIR:-}"
M9_SEAL_DIR="${M9_SEAL_DIR:-}"
M9_ARCHIVE_DIR="${M9_ARCHIVE_DIR:-}"
M9_ARCHIVE_LOCAL="${M9_ARCHIVE_LOCAL:-}"
M9_PACKAGE_INDEX_LOCAL="${M9_PACKAGE_INDEX_LOCAL:-}"
M9_CORE_SCRIPT="${M9_CORE_SCRIPT:-}"
M9_ADAPTER_SCRIPT="${M9_ADAPTER_SCRIPT:-}"
M9_WRAPPER_FAILURE="${M9_WRAPPER_FAILURE:-}"

AUTHORIZATION_KIND=''
AUTHORIZATION_SHA256=''
SEMANTIC_AUTH_SHA256=''
RETRY_AUTH_SHA256='null'
ISSUED_OBJECT=''
ISSUED_DOCUMENT_SHA256=''
# --- R2I-C4 / B03 OSS trust target (all values derived at runtime) ----------
OSS_TRUST_PROFILE_SHA256=''
OSSUTIL_ABSOLUTE_PATH=''
OSSUTIL_VERSION=''
OSSUTIL_BINARY_SHA256=''
ECS_ROLE_NAME=''
ENVIRONMENT_GUARD_STATE='NOT_RUN'
ISSUED_PROFILE_SHA256=''
CLAIM_OBJECT=''
CLAIM_SHA256=''
RUN_PREFIX=''
ARCHIVE_NAME=''
ARCHIVE_OBJECT=''
PACKAGE_INDEX_OBJECT=''
RECEIPT_OBJECT=''
ISSUED_ARCHIVE_SHA256=''
ISSUED_PACKAGE_INDEX_SHA256=''
EXECUTION_STARTED_UTC=''
FORMAL_EXECUTION_RC=''
EXPECTED_RECEIPT_SHA256=''
RECEIPT_VERIFIED_SHA256=''

# --- freeze-at-seal values --------------------------------------------------
SEALED_ARCHIVE_SHA256=''
SEALED_ARCHIVE_SIZE=''
SEALED_MANIFEST_SHA256=''
SEALED_EMBEDDED_MANIFEST_SHA256=''
SEALED_PACKAGE_INDEX_SHA256=''
SEALED_CORE_RC=''
SEALED_ADAPTER_RC=''
SEALED_FORMAL_RC=''

m9_die() { printf 'FAIL: %s\n' "$*" >&2; return 1; }
m9_expect() { [[ "$1" == "$2" ]] || m9_die "Mismatch: $3 (expected $2; got $1)"; }
m9_synthetic() { [[ "${M9_SYNTHETIC_TEST_MODE:-0}" == '1' ]]; }

# Authorization identity. The Human-issued authorization input is the exact
# secret/capability TOKEN string; authorization_sha256 is its SHA-256. The token
# itself is never printed, persisted, recorded, uploaded or placed in evidence.
m9_sha256_token() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

# Post-claim bookkeeping is host-local so that the sealed evidence tree is never
# written to after its manifest has been frozen.
m9_record() {
  [[ -n "$M9_SEAL_DIR" && -d "$M9_SEAL_DIR" ]] || return 0
  printf '%s=%s\n' "$1" "$2" >>"$M9_SEAL_DIR/wrapper-records.txt"
}

# ---------------------------------------------------------------------------
# Initialisation and environment guards.
# ---------------------------------------------------------------------------
m9_wrapper_init() {
  if m9_synthetic; then
    # Synthetic mode exists only for offline verification against a stub
    # object-store client; it must never be pointed at the provisioned binary.
    [[ -n "${M9_OSSUTIL_BIN:-}" ]] ||
      { m9_die 'M9_SYNTHETIC_TEST_MODE=1 requires an explicit M9_OSSUTIL_BIN override'; return 1; }
    M9_PROOF_ROOT="${M9_PROOF_ROOT:-$(git rev-parse --show-toplevel)}"
    M9_EVIDENCE="${M9_PROOF_EVIDENCE_DIR:-$M9_PROOF_ROOT/proof-artifacts}"
    M9_HOST_STATE="${M9_PROOF_HOST_STATE:-$M9_PROOF_ROOT/.m9-host-state}"
  else
    M9_PROOF_ROOT="$(git rev-parse --show-toplevel)"
    local account_home inherited_home inherited_evidence inherited_state
    inherited_home="${HOME:-}"
    account_home="$(getent passwd "$(id -u)" | awk -F: 'NR == 1 { print $6 }')" || return 1
    [[ -n "$account_home" ]] || { m9_die 'resolved account home is empty'; return 1; }
    [[ "$inherited_home" == "$account_home" ]] ||
      { m9_die "HOME must exactly match account home $account_home"; return 1; }
    inherited_evidence="${M9_PROOF_EVIDENCE_DIR:-}"
    [[ -z "$inherited_evidence" || "$inherited_evidence" == "$M9_PROOF_ROOT/proof-artifacts" ]] ||
      { m9_die "M9_PROOF_EVIDENCE_DIR must be unset or exactly $M9_PROOF_ROOT/proof-artifacts"; return 1; }
    inherited_state="${M9_PROOF_HOST_STATE:-}"
    [[ -z "$inherited_state" || "$inherited_state" == "$account_home/.local/state/linguagraph-m9-proof" ]] ||
      { m9_die "M9_PROOF_HOST_STATE must be unset or exactly $account_home/.local/state/linguagraph-m9-proof"; return 1; }
    M9_EVIDENCE="$M9_PROOF_ROOT/proof-artifacts"
    M9_HOST_STATE="$account_home/.local/state/linguagraph-m9-proof"
  fi

  M9_CORE_SCRIPT="$M9_PROOF_ROOT/scripts/run-m9-proof-core.sh"
  M9_ADAPTER_SCRIPT="${M9_ADAPTER_SCRIPT_OVERRIDE:-$M9_PROOF_ROOT/scripts/run-m9-proof-alibaba-ecs.sh}"
  M9_ARCHIVE_DIR="$M9_HOST_STATE/artifacts"

  case "$M9_HOST_STATE" in
    "$M9_PROOF_ROOT" | "$M9_PROOF_ROOT"/*)
      m9_die 'Host state directory must be outside the git worktree'
      return 1
      ;;
  esac
  [[ -f "$M9_CORE_SCRIPT" ]] || { m9_die "semantic core is missing: $M9_CORE_SCRIPT"; return 1; }
  [[ -f "$M9_ADAPTER_SCRIPT" ]] || { m9_die "adapter is missing: $M9_ADAPTER_SCRIPT"; return 1; }
  return 0
}

m9_guard_environment() {
  local name
  for name in CIRCLE_PROJECT_USERNAME CIRCLE_PROJECT_REPONAME CIRCLE_BRANCH \
    CIRCLE_SHA1 CIRCLE_WORKFLOW_ID CIRCLE_BUILD_NUM; do
    [[ -z "${!name:-}" ]] ||
      { m9_die "CircleCI identity variable $name is set; hosted proof identity must not be spoofed"; return 1; }
  done
  return 0
}

m9_guard_local_syntax() {
  local run_auth="${M9_PROOF_RUN_AUTHORIZATION:-}"
  local retry_auth="${M9_PROOF_RETRY_AUTHORIZATION:-}"
  local token executor

  if [[ -n "$run_auth" && -n "$retry_auth" ]]; then
    m9_die 'present exactly one of M9_PROOF_RUN_AUTHORIZATION or M9_PROOF_RETRY_AUTHORIZATION'
    return 1
  fi
  if [[ -z "$run_auth" && -z "$retry_auth" ]]; then
    m9_die 'missing single-use authorization (M9_PROOF_RUN_AUTHORIZATION or M9_PROOF_RETRY_AUTHORIZATION)'
    return 1
  fi
  if [[ -n "$run_auth" ]]; then
    AUTHORIZATION_KIND='SEMANTIC'
    token="$run_auth"
  else
    AUTHORIZATION_KIND='DURABILITY_RETRY'
    token="$retry_auth"
  fi
  # The presented value is the exact Human-issued TOKEN, not a hash. It must be
  # a single non-empty line; it is hashed locally and never echoed.
  [[ -n "$token" ]] || { m9_die 'authorization token is empty'; return 1; }
  [[ "$token" != *$'\n'* && "$token" != *$'\r'* ]] ||
    { m9_die 'authorization token must be a single line'; return 1; }
  AUTHORIZATION_SHA256="$(m9_sha256_token "$token")"
  token=''
  run_auth=''
  retry_auth=''
  [[ "$AUTHORIZATION_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    { m9_die 'authorization identity could not be derived'; return 1; }

  [[ "${APPROVED_PROOF_SHA:-}" =~ ^[0-9a-f]{40}$ ]] ||
    { m9_die 'APPROVED_PROOF_SHA must be a full 40-character SHA'; return 1; }
  [[ "${APPROVED_PROOF_TREE:-}" =~ ^[0-9a-f]{40}$ ]] ||
    { m9_die 'APPROVED_PROOF_TREE must be a full 40-character tree SHA'; return 1; }

  executor="${M9_EXECUTOR_ID:-}"
  [[ -n "$executor" ]] || { m9_die 'M9_EXECUTOR_ID is not configured'; return 1; }
  [[ "$executor" =~ ^alibaba-ecs:i-[a-z0-9]+$ ]] ||
    { m9_die "M9_EXECUTOR_ID is not a canonical executor identity: $executor"; return 1; }
  m9_expect "$executor" "$(m9_provider_identity_executor_id)" configured_executor_id || return 1

  m9_oss_require_config || return 1
  return 0
}

m9_core_static_binding() {
  bash "$M9_CORE_SCRIPT" --emit-static-binding
}

m9_guard_static_binding() {
  local binding='' key value expected
  binding="$(m9_core_static_binding)" ||
    { m9_die 'semantic core refused to emit its static binding'; return 1; }
  [[ -n "$binding" ]] || { m9_die 'semantic core emitted an empty static binding'; return 1; }
  while IFS='=' read -r key value; do
    [[ -n "$key" ]] || continue
    case "$key" in
      candidate_sha) expected="$M9_APP_SHA" ;;
      candidate_tree) expected="$M9_APP_TREE" ;;
      candidate_parent) expected="$M9_APP_PARENT" ;;
      frozen_main) expected="$M9_MAIN_SHA" ;;
      *) continue ;;
    esac
    m9_expect "$value" "$expected" "core_static_binding_$key" || return 1
  done <<<"$binding"
  return 0
}

m9_guard_proof_checkout() {
  m9_expect "$(git -C "$M9_PROOF_ROOT" remote get-url origin 2>/dev/null || printf '')" \
    "$M9_PROOF_ORIGIN_URL" proof_origin_url || return 1
  m9_expect "$(git -C "$M9_PROOF_ROOT" rev-parse --abbrev-ref HEAD)" \
    "$M9_PROOF_BRANCH" proof_branch || return 1
  m9_expect "$(git -C "$M9_PROOF_ROOT" rev-parse HEAD)" \
    "$APPROVED_PROOF_SHA" approved_proof_head || return 1
  m9_expect "$(git -C "$M9_PROOF_ROOT" rev-parse HEAD^{tree})" \
    "$APPROVED_PROOF_TREE" approved_proof_tree || return 1
  m9_expect "$(git -C "$M9_PROOF_ROOT" status --porcelain=v1 --untracked-files=all)" \
    '' proof_worktree_clean || return 1
  m9_expect "$(git -C "$M9_PROOF_ROOT" ls-remote origin "refs/heads/$M9_PROOF_BRANCH" | awk '{print $1}')" \
    "$APPROVED_PROOF_SHA" approved_proof_remote_main || return 1
  return 0
}

m9_guard_clean_start() {
  if [[ "$AUTHORIZATION_KIND" == 'DURABILITY_RETRY' ]]; then
    # A durability retry deliberately runs on the host that already holds the
    # failed semantic run's evidence and sealed artifacts. It must never create,
    # rewrite or delete that evidence tree, and it never invokes the core.
    [[ ! -e "$M9_HOST_STATE/preclaim/$AUTHORIZATION_SHA256" ]] ||
      { m9_die "pre-claim staging already exists for this retry authorization"; return 1; }
    return 0
  fi
  [[ ! -e "$M9_EVIDENCE" ]] ||
    { m9_die "pre-existing formal evidence path: $M9_EVIDENCE"; return 1; }
  [[ ! -e "$M9_PROOF_ROOT/candidate" ]] ||
    { m9_die "pre-existing candidate checkout path: $M9_PROOF_ROOT/candidate"; return 1; }
  return 0
}

# ---------------------------------------------------------------------------
# Durable authorization retrieval + validation.
# ---------------------------------------------------------------------------
m9_validate_authorization_structure() {
  local file=$1 kind=$2
  "$(m9_python_bin)" - "$file" "$kind" <<'PY' || return 1
import json
import re
import sys

path, kind = sys.argv[1], sys.argv[2]
with open(path, "rb") as handle:
    raw = handle.read()
try:
    doc = json.loads(raw.decode("utf-8"))
except Exception as exc:  # noqa: BLE001
    sys.stderr.write("FAIL: issued.json is not valid JSON: %s\n" % exc)
    sys.exit(1)

if not isinstance(doc, dict):
    sys.stderr.write("FAIL: issued.json must be a JSON object\n")
    sys.exit(1)
if doc.get("authorization_kind") != kind:
    sys.stderr.write(
        "FAIL: issued.json authorization_kind is %r, expected %r\n"
        % (doc.get("authorization_kind"), kind)
    )
    sys.exit(1)

common = [
    "schema", "authorization_kind", "authorization_id",
    "authorization_sha256", "oss_trust_profile_sha256", "proof_sha", "proof_tree",
    "candidate_sha", "candidate_tree", "candidate_parent", "frozen_main",
    "provider_identity", "authorized_executor_id", "single_use", "issued_utc",
]
retry_only = [
    "semantic_auth_sha256", "archive_name", "archive_sha256",
    "package_index_sha256", "run_prefix",
]
required = common + (retry_only if kind == "DURABILITY_RETRY" else [])
missing = [key for key in required if key not in doc]
if missing:
    sys.stderr.write("FAIL: issued.json is missing fields: %s\n" % ", ".join(sorted(missing)))
    sys.exit(1)

sha64 = re.compile(r"^[0-9a-f]{64}$")
sha40 = re.compile(r"^[0-9a-f]{40}$")

def require_sha(field, pattern, label):
    value = doc.get(field)
    if not isinstance(value, str) or not pattern.match(value):
        sys.stderr.write("FAIL: %s is not a canonical %s: %r\n" % (field, label, value))
        sys.exit(1)

for field in ("proof_sha", "candidate_sha", "candidate_parent", "frozen_main"):
    require_sha(field, sha40, "40-hex commit SHA")
require_sha("proof_tree", sha40, "40-hex tree SHA")
require_sha("candidate_tree", sha40, "40-hex tree SHA")

# authorization_sha256 is the SHA-256 of the Human-issued authorization TOKEN.
# It is required, and it is NOT a digest of this document: a document can never
# contain a correct digest of its own bytes, so there is no self-reference and
# no issued-document digest is accepted from inside the document.
require_sha("authorization_sha256", sha64, "64-hex SHA-256")

# R2I-C4/B03: every issued authorization must ALSO bind the OSS trust profile.
require_sha("oss_trust_profile_sha256", sha64, "64-hex OSS trust-profile SHA-256")

if kind == "DURABILITY_RETRY":
    for field in ("semantic_auth_sha256", "archive_sha256", "package_index_sha256"):
        require_sha(field, sha64, "64-hex SHA-256")

identity = doc.get("provider_identity")
identity_fields = (
    "instance_id", "region_id", "zone_id", "instance_type", "image_id",
    "identity_document_sha256", "identity_pkcs7_sha256",
)
if not isinstance(identity, dict):
    sys.stderr.write("FAIL: provider_identity must be an object\n")
    sys.exit(1)
for field in identity_fields:
    value = identity.get(field)
    if not isinstance(value, str) or not value:
        sys.stderr.write("FAIL: provider_identity.%s is missing or empty\n" % field)
        sys.exit(1)
for field in ("identity_document_sha256", "identity_pkcs7_sha256"):
    if not sha64.match(identity[field]):
        sys.stderr.write("FAIL: provider_identity.%s is not a SHA-256\n" % field)
        sys.exit(1)

if doc.get("single_use") is not True:
    sys.stderr.write("FAIL: issued.json must declare single_use=true\n")
    sys.exit(1)

for field in ("authorization_id", "authorized_executor_id", "issued_utc"):
    value = doc.get(field)
    if not isinstance(value, str) or not value.strip():
        sys.stderr.write("FAIL: issued.json field %s is missing or empty\n" % field)
        sys.exit(1)

expected_schema = (
    "linguagraph-m9-durability-retry-authorization/v1"
    if kind == "DURABILITY_RETRY"
    else "linguagraph-m9-run-authorization/v1"
)
if doc.get("schema") != expected_schema:
    sys.stderr.write(
        "FAIL: issued.json schema is %r, expected %r\n" % (doc.get("schema"), expected_schema)
    )
    sys.exit(1)
PY
}

m9_load_authorization() {
  local issued_local="$M9_PRECLAIM_DIR/issued.json"
  local field expected_value proof_tree

  mkdir -p "$M9_PRECLAIM_DIR" || { m9_die "cannot create $M9_PRECLAIM_DIR"; return 1; }
  ISSUED_OBJECT="authorizations/$AUTHORIZATION_SHA256/issued.json"

  if ! m9_oss_get_object "$ISSUED_OBJECT" "$issued_local" "$M9_PRECLAIM_DIR/oss-preclaim.log"; then
    m9_die "issued.json could not be read from $ISSUED_OBJECT (FAIL CLOSED)"
    return 1
  fi

  m9_validate_authorization_structure "$issued_local" "$AUTHORIZATION_KIND" || return 1

  # R2I-C4/B03: the Human-issued authorization binds the exact OSS trust profile.
  # Missing, malformed or mismatched => FAIL CLOSED before claim creation.
  ISSUED_PROFILE_SHA256="$(m9_json_get "$issued_local" oss_trust_profile_sha256)"
  [[ "$ISSUED_PROFILE_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    { m9_die 'issued.json oss_trust_profile_sha256 is not a SHA-256'; return 1; }
  [[ -n "$OSS_TRUST_PROFILE_SHA256" ]] ||
    { m9_die 'local OSS trust profile digest has not been established'; return 1; }
  m9_expect "$ISSUED_PROFILE_SHA256" "$OSS_TRUST_PROFILE_SHA256" issued_oss_trust_profile_sha256 || return 1

  # The authorization identity is SHA256(exact Human-issued TOKEN); it is NOT a
  # digest of the issued document. There is no self-reference: the document must
  # BIND the identity, and that binding is what is verified here.
  m9_expect "$(m9_json_get "$issued_local" authorization_sha256)" \
    "$AUTHORIZATION_SHA256" issued_authorization_sha256 || return 1

  # Exact issued-document byte identity is recorded as a separate, semantically
  # distinct receipt field. It is computed by this wrapper over the retrieved
  # bytes; it is never demanded from inside the document, because a document can
  # never contain a correct digest of its own bytes.
  ISSUED_DOCUMENT_SHA256="$(m9_sha256_file "$issued_local")"

  proof_tree="$(git -C "$M9_PROOF_ROOT" rev-parse HEAD^{tree})"
  m9_expect "$(m9_json_get "$issued_local" proof_sha)" "$APPROVED_PROOF_SHA" issued_proof_sha || return 1
  m9_expect "$(m9_json_get "$issued_local" proof_tree)" "$proof_tree" issued_proof_tree || return 1
  m9_expect "$(m9_json_get "$issued_local" candidate_sha)" "$M9_APP_SHA" issued_candidate_sha || return 1
  m9_expect "$(m9_json_get "$issued_local" candidate_tree)" "$M9_APP_TREE" issued_candidate_tree || return 1
  m9_expect "$(m9_json_get "$issued_local" candidate_parent)" "$M9_APP_PARENT" issued_candidate_parent || return 1
  m9_expect "$(m9_json_get "$issued_local" frozen_main)" "$M9_MAIN_SHA" issued_frozen_main || return 1

  for field in instance_id region_id zone_id instance_type image_id \
    identity_document_sha256 identity_pkcs7_sha256; do
    expected_value="$(m9_provider_identity_expected_lines | sed -n "s/^${field}=//p")"
    m9_expect "$(m9_json_get "$issued_local" "provider_identity.$field")" \
      "$expected_value" "issued_provider_identity_$field" || return 1
  done

  m9_expect "$(m9_json_get "$issued_local" authorized_executor_id)" \
    "$(m9_provider_identity_executor_id)" issued_authorized_executor_id || return 1
  m9_expect "$(m9_json_get "$issued_local" single_use)" 'true' issued_single_use || return 1

  if [[ "$AUTHORIZATION_KIND" == 'SEMANTIC' ]]; then
    SEMANTIC_AUTH_SHA256="$AUTHORIZATION_SHA256"
  else
    SEMANTIC_AUTH_SHA256="$(m9_json_get "$issued_local" semantic_auth_sha256)"
    [[ "$SEMANTIC_AUTH_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
      { m9_die 'retry semantic_auth_sha256 is not a SHA-256'; return 1; }
    [[ "$SEMANTIC_AUTH_SHA256" != "$AUTHORIZATION_SHA256" ]] ||
      { m9_die 'retry authorization must be distinct from the semantic authorization'; return 1; }
    RETRY_AUTH_SHA256="$AUTHORIZATION_SHA256"
    ISSUED_ARCHIVE_SHA256="$(m9_json_get "$issued_local" archive_sha256)"
    ISSUED_PACKAGE_INDEX_SHA256="$(m9_json_get "$issued_local" package_index_sha256)"
  fi

  # Canonical object model is derived, never supplied by the caller.
  RUN_PREFIX="runs/$APPROVED_PROOF_SHA/$SEMANTIC_AUTH_SHA256"
  ARCHIVE_NAME="m9-proof-artifacts-$APPROVED_PROOF_SHA-$SEMANTIC_AUTH_SHA256.tar.gz"
  ARCHIVE_OBJECT="$RUN_PREFIX/$ARCHIVE_NAME"
  PACKAGE_INDEX_OBJECT="$RUN_PREFIX/$M9_PACKAGE_INDEX_OBJECT_NAME"
  RECEIPT_OBJECT="$RUN_PREFIX/$M9_RECEIPT_OBJECT_NAME"
  CLAIM_OBJECT="authorizations/$AUTHORIZATION_SHA256/claim.json"

  if [[ "$AUTHORIZATION_KIND" == 'DURABILITY_RETRY' ]]; then
    m9_expect "$(m9_json_get "$issued_local" run_prefix)" "$RUN_PREFIX" retry_run_prefix || return 1
    m9_expect "$(m9_json_get "$issued_local" archive_name)" "$ARCHIVE_NAME" retry_archive_name || return 1
  fi

  M9_SEAL_DIR="$M9_HOST_STATE/sealed/$SEMANTIC_AUTH_SHA256"
  M9_ARCHIVE_LOCAL="$M9_SEAL_DIR/$ARCHIVE_NAME"
  M9_PACKAGE_INDEX_LOCAL="$M9_SEAL_DIR/$M9_PACKAGE_INDEX_OBJECT_NAME"
  return 0
}

# ---------------------------------------------------------------------------
# One-shot refusal when the authorization is already committed (section 12).
# ---------------------------------------------------------------------------
m9_validate_receipt_against_authorization() {
  local receipt=$1
  "$M9_PROOF_ROOT/scripts/verify-m9-closure-receipt.py" \
    --receipt "$receipt" \
    --expect-proof-sha "$APPROVED_PROOF_SHA" \
    --expect-candidate-sha "$M9_APP_SHA" \
    --expect-authorization-sha "$AUTHORIZATION_SHA256" \
    --expect-oss-trust-profile-sha256 "$OSS_TRUST_PROFILE_SHA256" >/dev/null 2>&1
}

m9_already_committed_check() {
  local probe_rc=0 receipt_local=''
  probe_rc=0
  m9_oss_object_probe "$RECEIPT_OBJECT" "$M9_PRECLAIM_DIR/oss-preclaim.log" || probe_rc=$?
  case "$probe_rc" in
    "$M9_OSS_ABSENT") return 0 ;;
    "$M9_OSS_OK") ;;
    *)
      m9_die "cannot determine whether $RECEIPT_OBJECT already exists (FAIL CLOSED)"
      return 1
      ;;
  esac

  receipt_local="$M9_PRECLAIM_DIR/existing-closure-receipt.json"
  if ! m9_oss_get_object "$RECEIPT_OBJECT" "$receipt_local" "$M9_PRECLAIM_DIR/oss-preclaim.log"; then
    m9_die 'existing closure receipt could not be read; refusing to re-execute'
    return 1
  fi
  if m9_validate_receipt_against_authorization "$receipt_local"; then
    m9_die "ALREADY_COMMITTED: authorization $AUTHORIZATION_SHA256 already has a valid closure receipt at $RECEIPT_OBJECT; the formal wrapper is one-shot and will not re-execute, will not re-emit $M9_FORMAL_RC_MARKER, and will not return a synthetic success"
    return 1
  fi
  m9_die "ALREADY_COMMITTED: a closure receipt object exists at $RECEIPT_OBJECT but does not validate; refusing to overwrite or re-execute (Human reconciliation required)"
  return 1
}

# ---------------------------------------------------------------------------
# Single-use claim (section 8).
# ---------------------------------------------------------------------------
m9_kv_set() {
  printf '%s=%s\n' "$1" "$2" >>"$3"
}

m9_build_claim() {
  local out=$1 kv="$M9_PRECLAIM_DIR/claim-inputs.txt"
  : >"$kv"
  m9_kv_set schema "$M9_CLAIM_SCHEMA" "$kv"
  m9_kv_set authorization_kind "$AUTHORIZATION_KIND" "$kv"
  m9_kv_set authorization_sha256 "$AUTHORIZATION_SHA256" "$kv"
  m9_kv_set semantic_auth_sha256 "$SEMANTIC_AUTH_SHA256" "$kv"
  m9_kv_set proof_sha "$APPROVED_PROOF_SHA" "$kv"
  m9_kv_set proof_tree "$(git -C "$M9_PROOF_ROOT" rev-parse HEAD^{tree})" "$kv"
  m9_kv_set candidate_sha "$M9_APP_SHA" "$kv"
  m9_kv_set candidate_tree "$M9_APP_TREE" "$kv"
  m9_kv_set candidate_parent "$M9_APP_PARENT" "$kv"
  m9_kv_set frozen_main "$M9_MAIN_SHA" "$kv"
  m9_kv_set authorized_executor_id "$(m9_provider_identity_executor_id)" "$kv"
  m9_kv_set executor_id "${M9_EXECUTOR_ID:-}" "$kv"
  m9_kv_set run_prefix "$RUN_PREFIX" "$kv"
  m9_kv_set claim_object "$CLAIM_OBJECT" "$kv"
  m9_kv_set issued_object "$ISSUED_OBJECT" "$kv"
  m9_kv_set oss_trust_profile_sha256 "$OSS_TRUST_PROFILE_SHA256" "$kv"
  m9_kv_set single_use true "$kv"
  m9_kv_set instance_id "$EXPECTED_INSTANCE_ID" "$kv"
  m9_kv_set region_id "$EXPECTED_REGION_ID" "$kv"
  m9_kv_set zone_id "$EXPECTED_ZONE_ID" "$kv"
  m9_kv_set instance_type "$EXPECTED_INSTANCE_TYPE" "$kv"
  m9_kv_set image_id "$EXPECTED_IMAGE_ID" "$kv"
  m9_kv_set identity_document_sha256 "$EXPECTED_IDENTITY_DOCUMENT_SHA256" "$kv"
  m9_kv_set identity_pkcs7_sha256 "$EXPECTED_IDENTITY_PKCS7_SHA256" "$kv"

  "$(m9_python_bin)" - "$kv" "$out" <<'PY' || return 1
import datetime
import json
import sys

kv_path, out = sys.argv[1], sys.argv[2]
values = {}
with open(kv_path, "r", encoding="utf-8") as handle:
    for line in handle:
        line = line.rstrip("\n")
        if not line:
            continue
        key, _, value = line.partition("=")
        values[key] = value

document = {
    "schema": values["schema"],
    "authorization_kind": values["authorization_kind"],
    "authorization_sha256": values["authorization_sha256"],
    "semantic_auth_sha256": values["semantic_auth_sha256"],
    "proof_sha": values["proof_sha"],
    "proof_tree": values["proof_tree"],
    "candidate_sha": values["candidate_sha"],
    "candidate_tree": values["candidate_tree"],
    "candidate_parent": values["candidate_parent"],
    "frozen_main": values["frozen_main"],
    "authorized_executor_id": values["authorized_executor_id"],
    "executor_id": values["executor_id"],
    "run_prefix": values["run_prefix"],
    "claim_object": values["claim_object"],
    "issued_object": values["issued_object"],
    "oss_trust_profile_sha256": values["oss_trust_profile_sha256"],
    "single_use": values["single_use"] == "true",
    "provider_identity": {
        "instance_id": values["instance_id"],
        "region_id": values["region_id"],
        "zone_id": values["zone_id"],
        "instance_type": values["instance_type"],
        "image_id": values["image_id"],
        "identity_document_sha256": values["identity_document_sha256"],
        "identity_pkcs7_sha256": values["identity_pkcs7_sha256"],
    },
    "claimed_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(out, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
PY
}

m9_claim_create() {
  local claim_local="$M9_PRECLAIM_DIR/claim.json" rc=0
  m9_build_claim "$claim_local" || return 1
  CLAIM_SHA256="$(m9_sha256_file "$claim_local")"

  m9_oss_put_object_no_overwrite "$CLAIM_OBJECT" "$claim_local" \
    "$M9_PRECLAIM_DIR/oss-preclaim.log" || rc=$?
  case "$rc" in
    "$M9_OSS_OK") ;;
    "$M9_OSS_EXISTS")
      m9_die "claim already exists at $CLAIM_OBJECT; the authorization is single-use and cannot be re-consumed, taken over, leased or renewed (INDETERMINATE if no closure receipt exists)"
      return 1
      ;;
    *)
      m9_die "claim could not be created atomically at $CLAIM_OBJECT (FAIL CLOSED)"
      return 1
      ;;
  esac

  m9_oss_verify_object "$CLAIM_OBJECT" "$claim_local" "$M9_PRECLAIM_DIR/oss-preclaim.log" || {
    m9_die 'claim read-back did not match the locally created claim (FAIL CLOSED)'
    return 1
  }
  return 0
}

m9_provider_identity_preclaim() {
  m9_provider_identity_verify "$M9_PRECLAIM_DIR/provider-identity" primary || {
    m9_die 'read-only provider identity verification failed; refusing to claim the authorization'
    return 1
  }
  return 0
}

# ---------------------------------------------------------------------------
# R2I-C4 / B03: OSS trust-target establishment.
# ---------------------------------------------------------------------------

# Step 11: observe the attached ECS instance RAM role NAME read-only. Only the
# role-name LIST endpoint is queried; the per-role endpoint returns temporary
# credentials and is never requested. The observed name is a non-secret live
# value that the Human-issued trust profile later binds.
m9_oss_observe_ecs_role_name() {
  local role
  role=$(m9_provider_identity_observe_ecs_role_name) || {
    m9_die 'read-only ECS RAM role-name observation failed; refusing any OSS access'
    return 1
  }
  [[ -n "$role" ]] || { m9_die 'observed ECS RAM role name is empty'; return 1; }
  ECS_ROLE_NAME="$role"
  export M9_OSS_ECS_ROLE_NAME="$role"
  export ECS_ROLE_NAME
  # The read-only observation NEVER creates host state. The wrapper has already
  # created the pre-claim staging directory before step 8; if it is absent (for
  # example in an offline fixture that drives the phase functions directly) the
  # provenance record is simply skipped. Manufacturing the directory here would
  # defeat the "pre-claim staging already exists" retry guard.
  if [[ -n "${M9_PRECLAIM_DIR:-}" && -d "$M9_PRECLAIM_DIR" ]]; then
    {
      printf 'ecs_role_name_observed=%s\n' "$role"
      printf 'ecs_role_name_observation_utc=%s\n' "$(date -u +%FT%TZ)"
      printf 'ecs_role_name_endpoint=meta-data/ram/security-credentials/\n'
      printf 'note=role-name list endpoint only; no credential payload was requested or read\n'
    } >> "$M9_PRECLAIM_DIR/oss-preclaim.log" 2>/dev/null || true
  fi
  return 0
}

# Step 12: build the exact 18-field trust profile from the frozen constants plus
# the observed live values, and record its digest. The digest is derived here and
# is never a caller-supplied environment variable.
m9_prepare_oss_trust_profile() {
  m9_oss_trust_profile_assert_canonical || return 1
  OSS_TRUST_PROFILE_SHA256="$(m9_oss_trust_profile_sha256)" || return 1
  [[ "$OSS_TRUST_PROFILE_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    { m9_die 'derived OSS trust profile digest is not a SHA-256'; return 1; }
  OSSUTIL_ABSOLUTE_PATH="${M9_OSSUTIL_ABSOLUTE_PATH:-}"
  OSSUTIL_VERSION="${M9_OSSUTIL_VERSION:-}"
  OSSUTIL_BINARY_SHA256="${M9_OSSUTIL_BINARY_SHA256:-}"
  export OSS_TRUST_PROFILE_SHA256 OSSUTIL_ABSOLUTE_PATH OSSUTIL_VERSION OSSUTIL_BINARY_SHA256
  if [[ -n "${M9_PRECLAIM_DIR:-}" ]]; then
    m9_oss_trust_profile_values > "$M9_PRECLAIM_DIR/oss-trust-profile.txt" 2>/dev/null || true
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Evidence initialisation after a successful claim.
# ---------------------------------------------------------------------------
m9_write_invocation_context() {
  local target=$1 nonce nonce_sha256 proof_tree
  proof_tree="$(git -C "$M9_PROOF_ROOT" rev-parse HEAD^{tree})"
  nonce="$(head -c 32 /dev/urandom | sha256sum | cut -d' ' -f1)"
  # R2I-C14: the runtime nonce stays process-local and is never persisted. Only
  # SHA256(nonce) is written to the context, which is exactly what the adapter
  # verifies: SHA256(M9_FORMAL_RUN_NONCE) == invocation_nonce_sha256. Persisting
  # the raw nonce in a field named "_sha256" made every formal invocation fail
  # context_invocation_nonce.
  nonce_sha256="$(printf '%s' "$nonce" | sha256sum | cut -d' ' -f1)"
  M9_FORMAL_RUN_NONCE="$nonce"
  export M9_FORMAL_RUN_NONCE

  {
    printf 'schema=%s\n' "$M9_CONTEXT_SCHEMA"
    printf 'formal_entrypoint=scripts/run-m9-proof.sh\n'
    printf 'authorization_kind=%s\n' "$AUTHORIZATION_KIND"
    printf 'authorization_sha256=%s\n' "$AUTHORIZATION_SHA256"
    printf 'semantic_auth_sha256=%s\n' "$SEMANTIC_AUTH_SHA256"
    printf 'proof_sha=%s\n' "$APPROVED_PROOF_SHA"
    printf 'proof_tree=%s\n' "$proof_tree"
    printf 'candidate_sha=%s\n' "$M9_APP_SHA"
    printf 'candidate_tree=%s\n' "$M9_APP_TREE"
    printf 'candidate_parent=%s\n' "$M9_APP_PARENT"
    printf 'frozen_main=%s\n' "$M9_MAIN_SHA"
    printf 'authorized_executor_id=%s\n' "$(m9_provider_identity_executor_id)"
    printf 'executor_id=%s\n' "${M9_EXECUTOR_ID:-}"
    printf 'run_prefix=%s\n' "$RUN_PREFIX"
    printf 'claim_object=%s\n' "$CLAIM_OBJECT"
    printf 'claim_sha256=%s\n' "$CLAIM_SHA256"
    printf 'invocation_nonce_sha256=%s\n' "$nonce_sha256"
  } >"$target/formal-invocation-context.txt"

  M9_FORMAL_WRAPPER_CONTEXT="$target/formal-invocation-context.txt"
  export M9_FORMAL_WRAPPER_CONTEXT
}

m9_write_wrapper_provenance() {
  local target=$1 proof_tree
  proof_tree="$(git -C "$M9_PROOF_ROOT" rev-parse HEAD^{tree})"
  {
    printf 'wrapper=scripts/run-m9-proof.sh\n'
    printf 'authorization_kind=%s\n' "$AUTHORIZATION_KIND"
    printf 'authorization_sha256=%s\n' "$AUTHORIZATION_SHA256"
    printf 'semantic_auth_sha256=%s\n' "$SEMANTIC_AUTH_SHA256"
    printf 'proof_sha=%s\n' "$APPROVED_PROOF_SHA"
    printf 'proof_tree=%s\n' "$proof_tree"
    printf 'oss_bucket=%s\n' "$(m9_oss_bucket)"
    printf 'ossutil_bin=%s\n' "$(m9_ossutil_bin)"
    printf 'imds_base_url=%s\n' "$(m9_imds_base_url)"
    printf 'synthetic_test_mode=%s\n' "${M9_SYNTHETIC_TEST_MODE:-0}"
    printf 'started_utc=%s\n' "$(date -u +%FT%TZ)"
    # --- R2I-C4/B03: field-level durable record of the effective OSS trust
    # target. Together with the frozen constants this is sufficient to
    # reconstruct the exact 18 serialized trust-profile bytes. No credential,
    # token or temporary-credential material is ever recorded here.
    printf 'oss_trust_profile_sha256=%s\n' "${OSS_TRUST_PROFILE_SHA256:-}"
    printf 'ossutil_absolute_path=%s\n' "${OSSUTIL_ABSOLUTE_PATH:-}"
    printf 'bucket_location_observed=%s\n' "${M9_OSS_BUCKET_LOCATION_OBSERVED:-}"
    printf 'environment_guard=%s\n' "${ENVIRONMENT_GUARD_STATE:-NOT_RUN}"
    printf 'oss_trust_profile_field_count=18\n'
    printf 'oss_trust_profile_serialization=UTF-8 key=value LF records, field_01..field_18, exactly one final LF\n'
    m9_oss_trust_profile_values
  } >"$target/wrapper-provenance.txt"
}

m9_copy_authorization_records() {
  local target=$1
  cp -f "$M9_PRECLAIM_DIR/issued.json" "$target/issued.json" || return 1
  cp -f "$M9_PRECLAIM_DIR/claim.json" "$target/claim.json" || return 1
  [[ -f "$M9_PRECLAIM_DIR/oss-preclaim.log" ]] &&
    cp -f "$M9_PRECLAIM_DIR/oss-preclaim.log" "$target/oss-preclaim.log"
  [[ -f "$M9_PRECLAIM_DIR/ossutil-capability.txt" ]] &&
    cp -f "$M9_PRECLAIM_DIR/ossutil-capability.txt" "$target/ossutil-capability.txt"
  [[ -f "$M9_PRECLAIM_DIR/oss-versioning-guard.txt" ]] &&
    cp -f "$M9_PRECLAIM_DIR/oss-versioning-guard.txt" "$target/oss-versioning-guard.txt"
  return 0
}

m9_evidence_initialize() {
  if [[ "$AUTHORIZATION_KIND" == 'DURABILITY_RETRY' ]]; then
    # A retry never creates or writes the sealed semantic evidence tree: its own
    # records live under the host seal directory for this retry authorization.
    local retry_records="$M9_SEAL_DIR/retry/$AUTHORIZATION_SHA256"
    mkdir -p "$retry_records" || { m9_die "cannot create $retry_records"; return 1; }
    m9_copy_authorization_records "$retry_records" || return 1
    m9_write_invocation_context "$retry_records"
    m9_write_wrapper_provenance "$retry_records"
    m9_record wrapper_mode DURABILITY_RETRY
    return 0
  fi

  mkdir -p "$M9_EVIDENCE" || { m9_die "cannot create $M9_EVIDENCE"; return 1; }
  # The host-local seal directory receives PHASE A validation output and the
  # PHASE B/C/D seal, index and receipt artifacts, so it must exist before the
  # execution phase runs.
  mkdir -p "$M9_SEAL_DIR" || { m9_die "cannot create $M9_SEAL_DIR"; return 1; }
  cp -a "$M9_PRECLAIM_DIR/provider-identity" "$M9_EVIDENCE/provider-identity" || return 1
  m9_copy_authorization_records "$M9_EVIDENCE" || return 1
  m9_write_invocation_context "$M9_EVIDENCE"
  m9_write_wrapper_provenance "$M9_EVIDENCE"

  EXECUTION_STARTED_UTC="$(date -u +%FT%TZ)"
  return 0
}

# ---------------------------------------------------------------------------
# PHASE A — execution.
# ---------------------------------------------------------------------------
# Reads the two independent RC records and requires them to be present,
# numeric, and exactly equal. Absent/empty/non-numeric/mismatch => FAIL CLOSED.
m9_rc_crosscheck() {
  local adapter_rc='' execution_rc=''
  adapter_rc="$(cat "$M9_EVIDENCE/adapter-exit-code.txt" 2>/dev/null || printf '')"
  execution_rc="$(cat "$M9_EVIDENCE/formal-execution-rc.txt" 2>/dev/null || printf '')"

  [[ -n "$adapter_rc" ]] ||
    { m9_die 'adapter-exit-code.txt is absent or empty; RC contract violated (FAIL CLOSED)'; return 1; }
  [[ -n "$execution_rc" ]] ||
    { m9_die 'formal-execution-rc.txt is absent or empty; RC contract violated (FAIL CLOSED)'; return 1; }
  [[ "$adapter_rc" =~ ^[0-9]+$ ]] ||
    { m9_die "adapter-exit-code.txt is not numeric: $adapter_rc"; return 1; }
  [[ "$execution_rc" =~ ^[0-9]+$ ]] ||
    { m9_die "formal-execution-rc.txt is not numeric: $execution_rc"; return 1; }
  [[ "$adapter_rc" == "$execution_rc" ]] ||
    { m9_die "adapter-exit-code.txt ($adapter_rc) != formal-execution-rc.txt ($execution_rc); FAIL CLOSED"; return 1; }
  FORMAL_EXECUTION_RC="$execution_rc"
  return 0
}

m9_phase_a_invoke_adapter() {
  local rc=0
  # Capture the adapter child process RC immediately after it returns, before
  # any other work.
  printf 'invoking formal adapter: %s\n' "$M9_ADAPTER_SCRIPT"
  bash "$M9_ADAPTER_SCRIPT" >>"$M9_EVIDENCE/adapter-raw.log" 2>&1 || rc=$?
  printf '%s\n' "$rc" >"$M9_EVIDENCE/formal-execution-rc.txt"
  m9_rc_crosscheck || return 1
  return 0
}

# Independently re-check a captured read-only identity observation against the
# reviewed tuple. The adapter performs the live verification; the wrapper
# verifies the captured evidence so a broken adapter cannot pass silently.
m9_verify_identity_capture() {
  local dir=$1 label=$2 observed='' field expected=''
  for field in instance_id region_id zone_id instance_type image_id; do
    case "$field" in
      instance_id) expected="$EXPECTED_INSTANCE_ID" ;;
      region_id) expected="$EXPECTED_REGION_ID" ;;
      zone_id) expected="$EXPECTED_ZONE_ID" ;;
      instance_type) expected="$EXPECTED_INSTANCE_TYPE" ;;
      image_id) expected="$EXPECTED_IMAGE_ID" ;;
    esac
    [[ -f "$dir/${field//_/-}.txt" ]] ||
      { m9_die "$label identity capture is missing ${field//_/-}.txt"; return 1; }
    observed="$(cat "$dir/${field//_/-}.txt")"
    m9_expect "$observed" "$expected" "$label $field" || return 1
  done
  [[ -f "$dir/instance-identity-document.sha256" && -f "$dir/instance-identity-pkcs7.sha256" ]] ||
    { m9_die "$label identity digests are missing"; return 1; }
  m9_expect "$(cat "$dir/instance-identity-document.sha256")" \
    "$EXPECTED_IDENTITY_DOCUMENT_SHA256" "$label identity document sha256" || return 1
  m9_expect "$(cat "$dir/instance-identity-pkcs7.sha256")" \
    "$EXPECTED_IDENTITY_PKCS7_SHA256" "$label identity pkcs7 sha256" || return 1
  return 0
}

m9_phase_a_validate() {
  # Strict set closure: the actual regular files in the evidence root, minus the
  # seal-phase artifact manifest, must equal the canonical required artifact set
  # exactly. A missing required file and an unexpected/unclassified file are both
  # fatal, so a PHASE A tree is only acceptable when it is fully classified.
  "$M9_PROOF_ROOT/scripts/verify-m9-artifact-completeness.py" \
    --root "$M9_EVIDENCE" \
    --required "$M9_LIB_DIR/m9-required-artifacts.txt" \
    --json-out "$M9_SEAL_DIR/artifact-completeness.json" || {
    m9_die 'required execution artifacts are incomplete or unclassified (FAIL CLOSED)'
    return 1
  }
  local effective=''
  effective="$(cat "$M9_EVIDENCE/playwright-effective-retries.txt" 2>/dev/null || printf '')"
  m9_expect "$effective" "$M9_EFFECTIVE_RETRIES_CONTENT" playwright_effective_retries || return 1
  m9_verify_identity_capture "$M9_EVIDENCE/provider-identity/primary" preclaim || return 1
  m9_verify_identity_capture "$M9_EVIDENCE/provider-identity/reexec" postclaim || return 1
  return 0
}

m9_phase_a_outcome_gate() {
  local first_line=''
  first_line="$(head -n1 "$M9_EVIDENCE/outcome.txt" 2>/dev/null || printf '')"
  if [[ "$FORMAL_EXECUTION_RC" != '0' || "$first_line" != 'PASS' ]]; then
    printf 'M9_INDETERMINATE: claim exists, closure receipt absent (adapter rc=%s outcome=%s)\n' \
      "$FORMAL_EXECUTION_RC" "${first_line:-missing}" >&2
    m9_die 'semantic execution did not pass; no closure receipt will be materialized'
    return 1
  fi
  return 0
}

m9_phase_a_execute() {
  m9_phase_a_invoke_adapter || return 1
  m9_phase_a_outcome_gate || return 1
  m9_phase_a_validate || return 1
  return 0
}

# ---------------------------------------------------------------------------
# PHASE B — seal.
# ---------------------------------------------------------------------------
m9_write_artifact_inventory() {
  local manifest=$1 out=$2
  "$(m9_python_bin)" - "$manifest" "$out" "$M9_EVIDENCE" <<'PY' || return 1
import json
import os
import sys

manifest, out, root = sys.argv[1], sys.argv[2], sys.argv[3]
entries = []
with open(manifest, "r", encoding="utf-8") as handle:
    for line in handle:
        line = line.rstrip("\n")
        if not line:
            continue
        digest, _, rel = line.partition("  ")
        rel = rel[2:] if rel.startswith("./") else rel
        path = os.path.join(root, rel)
        entries.append(
            {
                "path": rel,
                "sha256": digest,
                "size_bytes": os.path.getsize(path) if os.path.exists(path) else None,
            }
        )
entries.sort(key=lambda item: item["path"])
with open(out, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(entries, indent=2, sort_keys=True) + "\n")
PY
}

m9_build_package_index() {
  local out=$1 kv="$M9_SEAL_DIR/package-index-inputs.txt"
  m9_write_artifact_inventory "$M9_EVIDENCE/artifact-manifest.sha256" \
    "$M9_SEAL_DIR/artifact-inventory.json" || return 1

  : >"$kv"
  m9_kv_set schema "$M9_PACKAGE_INDEX_SCHEMA" "$kv"
  m9_kv_set authorization_kind "$AUTHORIZATION_KIND" "$kv"
  m9_kv_set authorization_sha256 "$AUTHORIZATION_SHA256" "$kv"
  m9_kv_set semantic_auth_sha256 "$SEMANTIC_AUTH_SHA256" "$kv"
  m9_kv_set retry_auth_sha256 "$RETRY_AUTH_SHA256" "$kv"
  m9_kv_set oss_trust_profile_sha256 "$OSS_TRUST_PROFILE_SHA256" "$kv"
  m9_kv_set proof_sha "$APPROVED_PROOF_SHA" "$kv"
  m9_kv_set proof_tree "$(git -C "$M9_PROOF_ROOT" rev-parse HEAD^{tree})" "$kv"
  m9_kv_set candidate_sha "$M9_APP_SHA" "$kv"
  m9_kv_set candidate_tree "$M9_APP_TREE" "$kv"
  m9_kv_set candidate_parent "$M9_APP_PARENT" "$kv"
  m9_kv_set frozen_main "$M9_MAIN_SHA" "$kv"
  m9_kv_set authorized_executor_id "$(m9_provider_identity_executor_id)" "$kv"
  m9_kv_set executor_id "${M9_EXECUTOR_ID:-}" "$kv"
  m9_kv_set run_prefix "$RUN_PREFIX" "$kv"
  m9_kv_set archive_name "$ARCHIVE_NAME" "$kv"
  m9_kv_set archive_object "$ARCHIVE_OBJECT" "$kv"
  m9_kv_set archive_sha256 "$SEALED_ARCHIVE_SHA256" "$kv"
  m9_kv_set archive_size_bytes "$SEALED_ARCHIVE_SIZE" "$kv"
  m9_kv_set manifest_name 'artifact-manifest.sha256' "$kv"
  m9_kv_set manifest_sha256 "$SEALED_MANIFEST_SHA256" "$kv"
  m9_kv_set execution_started_utc "$EXECUTION_STARTED_UTC" "$kv"
  m9_kv_set core_exit_code "$SEALED_CORE_RC" "$kv"
  m9_kv_set adapter_exit_code "$SEALED_ADAPTER_RC" "$kv"
  m9_kv_set formal_execution_rc "$SEALED_FORMAL_RC" "$kv"
  m9_kv_set playwright_effective_retries 0 "$kv"
  m9_kv_set instance_id "$EXPECTED_INSTANCE_ID" "$kv"
  m9_kv_set region_id "$EXPECTED_REGION_ID" "$kv"
  m9_kv_set zone_id "$EXPECTED_ZONE_ID" "$kv"
  m9_kv_set instance_type "$EXPECTED_INSTANCE_TYPE" "$kv"
  m9_kv_set image_id "$EXPECTED_IMAGE_ID" "$kv"
  m9_kv_set identity_document_sha256 "$EXPECTED_IDENTITY_DOCUMENT_SHA256" "$kv"
  m9_kv_set identity_pkcs7_sha256 "$EXPECTED_IDENTITY_PKCS7_SHA256" "$kv"
  m9_kv_set inventory_path "$M9_SEAL_DIR/artifact-inventory.json" "$kv"

  "$(m9_python_bin)" - "$kv" "$out" <<'PY' || return 1
import datetime
import json
import sys

kv_path, out = sys.argv[1], sys.argv[2]
values = {}
with open(kv_path, "r", encoding="utf-8") as handle:
    for line in handle:
        line = line.rstrip("\n")
        if not line:
            continue
        key, _, value = line.partition("=")
        values[key] = value

with open(values["inventory_path"], "r", encoding="utf-8") as handle:
    artifacts = json.load(handle)

document = {
    "schema": values["schema"],
    "authorization_kind": values["authorization_kind"],
    "authorization_sha256": values["authorization_sha256"],
    "semantic_auth_sha256": values["semantic_auth_sha256"],
    "retry_auth_sha256": None if values["retry_auth_sha256"] == "null" else values["retry_auth_sha256"],
    "oss_trust_profile_sha256": values["oss_trust_profile_sha256"],
    "proof_sha": values["proof_sha"],
    "proof_tree": values["proof_tree"],
    "candidate_sha": values["candidate_sha"],
    "candidate_tree": values["candidate_tree"],
    "candidate_parent": values["candidate_parent"],
    "frozen_main": values["frozen_main"],
    "authorized_executor_id": values["authorized_executor_id"],
    "executor_id": values["executor_id"],
    "run_prefix": values["run_prefix"],
    "provider_identity": {
        "instance_id": values["instance_id"],
        "region_id": values["region_id"],
        "zone_id": values["zone_id"],
        "instance_type": values["instance_type"],
        "image_id": values["image_id"],
        "identity_document_sha256": values["identity_document_sha256"],
        "identity_pkcs7_sha256": values["identity_pkcs7_sha256"],
    },
    "archive": {
        "name": values["archive_name"],
        "object": values["archive_object"],
        "sha256": values["archive_sha256"],
        "size_bytes": int(values["archive_size_bytes"]),
    },
    "artifact_manifest": {
        "name": values["manifest_name"],
        "sha256": values["manifest_sha256"],
    },
    "exit_codes": {
        "core": int(values["core_exit_code"]),
        "adapter": int(values["adapter_exit_code"]),
        "formal_execution": int(values["formal_execution_rc"]),
    },
    "playwright_effective_retries": int(values["playwright_effective_retries"]),
    "artifacts": artifacts,
    "execution_started_utc": values["execution_started_utc"],
    "sealed_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(out, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
PY
}

m9_phase_b_seal_semantic() {
  local rc=0
  mkdir -p "$M9_ARCHIVE_DIR" "$M9_SEAL_DIR" ||
    { m9_die 'cannot create seal directories'; return 1; }

  m9_manifest_generate "$M9_EVIDENCE" || return 1
  SEALED_MANIFEST_SHA256="$(m9_sha256_file "$M9_EVIDENCE/artifact-manifest.sha256")"

  # The sealed manifest is the authoritative inventory: its entry set must equal
  # the exact required artifact set, every path must be normalized/relative/
  # non-traversing/non-duplicated, and every recorded digest must match the file
  # on disk. The manifest never hashes itself. Manifest mismatch => FAIL CLOSED.
  "$M9_PROOF_ROOT/scripts/verify-m9-artifact-completeness.py" \
    --root "$M9_EVIDENCE" \
    --required "$M9_LIB_DIR/m9-required-artifacts.txt" \
    --manifest "$M9_EVIDENCE/artifact-manifest.sha256" \
    --json-out "$M9_SEAL_DIR/artifact-manifest-check.json" || {
    m9_die 'sealed artifact manifest does not exactly cover the required execution artifacts (FAIL CLOSED)'
    return 1
  }

  m9_archive_build "$M9_PROOF_ROOT" "$(basename "$M9_EVIDENCE")" "$M9_ARCHIVE_LOCAL" || rc=$?
  if (( rc == 2 )); then
    m9_die "canonical archive already exists and will not be rebuilt: $M9_ARCHIVE_LOCAL"
    return 1
  fi
  if (( rc != 0 )); then
    m9_die 'canonical archive creation failed'
    return 1
  fi

  SEALED_ARCHIVE_SHA256="$(m9_sha256_file "$M9_ARCHIVE_LOCAL")"
  SEALED_ARCHIVE_SIZE="$(m9_size_bytes "$M9_ARCHIVE_LOCAL")"
  SEALED_EMBEDDED_MANIFEST_SHA256="$(m9_archive_embedded_manifest "$M9_ARCHIVE_LOCAL" \
    "$(basename "$M9_EVIDENCE")" | sha256sum | cut -d' ' -f1)"
  m9_expect "$SEALED_EMBEDDED_MANIFEST_SHA256" "$SEALED_MANIFEST_SHA256" embedded_artifact_manifest_sha256 || return 1

  SEALED_CORE_RC="$(cat "$M9_EVIDENCE/core-exit-code.txt")"
  SEALED_ADAPTER_RC="$(cat "$M9_EVIDENCE/adapter-exit-code.txt")"
  SEALED_FORMAL_RC="$FORMAL_EXECUTION_RC"

  [[ ! -e "$M9_PACKAGE_INDEX_LOCAL" ]] ||
    { m9_die "package-index already exists and is generated exactly once: $M9_PACKAGE_INDEX_LOCAL"; return 1; }
  m9_build_package_index "$M9_PACKAGE_INDEX_LOCAL" || return 1
  SEALED_PACKAGE_INDEX_SHA256="$(m9_sha256_file "$M9_PACKAGE_INDEX_LOCAL")"

  # The sealed set must be internally consistent immediately after sealing.
  m9_manifest_verify "$M9_EVIDENCE" || return 1
  m9_record archive_sha256 "$SEALED_ARCHIVE_SHA256"
  m9_record archive_size_bytes "$SEALED_ARCHIVE_SIZE"
  m9_record artifact_manifest_sha256 "$SEALED_MANIFEST_SHA256"
  m9_record package_index_sha256 "$SEALED_PACKAGE_INDEX_SHA256"
  m9_record sealed_utc "$(date -u +%FT%TZ)"
  return 0
}

m9_phase_b_seal_retry() {
  local scratch='' embedded_sha='' index_manifest_sha='' index_size=''
  [[ -f "$M9_PACKAGE_INDEX_LOCAL" ]] ||
    { m9_die 'durability retry is NOT eligible: local package-index.json is missing and regeneration is not authorized (Human reconciliation required)'; return 1; }
  m9_expect "$(m9_sha256_file "$M9_PACKAGE_INDEX_LOCAL")" \
    "$ISSUED_PACKAGE_INDEX_SHA256" retry_package_index_sha256 || return 1
  SEALED_PACKAGE_INDEX_SHA256="$ISSUED_PACKAGE_INDEX_SHA256"

  index_manifest_sha="$(m9_json_get "$M9_PACKAGE_INDEX_LOCAL" artifact_manifest.sha256)"
  index_size="$(m9_json_get "$M9_PACKAGE_INDEX_LOCAL" archive.size_bytes)"
  # R2I-C4/B03: a durability retry must target the same OSS trust profile that
  # the pre-existing sealed package index was written under.
  m9_expect "$(m9_json_get "$M9_PACKAGE_INDEX_LOCAL" oss_trust_profile_sha256)" \
    "$OSS_TRUST_PROFILE_SHA256" retry_package_index_oss_trust_profile || return 1
  EXECUTION_STARTED_UTC="$(m9_json_get "$M9_PACKAGE_INDEX_LOCAL" execution_started_utc)"
  SEALED_CORE_RC="$(m9_json_get "$M9_PACKAGE_INDEX_LOCAL" exit_codes.core)"
  SEALED_ADAPTER_RC="$(m9_json_get "$M9_PACKAGE_INDEX_LOCAL" exit_codes.adapter)"
  SEALED_FORMAL_RC="$(m9_json_get "$M9_PACKAGE_INDEX_LOCAL" exit_codes.formal_execution)"
  SEALED_MANIFEST_SHA256="$index_manifest_sha"
  SEALED_ARCHIVE_SHA256="$ISSUED_ARCHIVE_SHA256"
  SEALED_ARCHIVE_SIZE="$index_size"

  if [[ -f "$M9_ARCHIVE_LOCAL" ]]; then
    m9_expect "$(m9_sha256_file "$M9_ARCHIVE_LOCAL")" \
      "$ISSUED_ARCHIVE_SHA256" retry_local_archive_sha256 || return 1
    m9_expect "$(m9_size_bytes "$M9_ARCHIVE_LOCAL")" "$index_size" retry_local_archive_size || return 1
    embedded_sha="$(m9_archive_embedded_manifest "$M9_ARCHIVE_LOCAL" \
      "$(basename "$M9_EVIDENCE")" | sha256sum | cut -d' ' -f1)"
  else
    scratch="$(mktemp "${TMPDIR:-/tmp}/m9-retry-archive.XXXXXX")"
    if ! m9_oss_get_object "$ARCHIVE_OBJECT" "$scratch" "$M9_SEAL_DIR/oss-retry.log"; then
      rm -f "$scratch"
      m9_die 'durability retry is NOT eligible: sealed archive is absent locally and not durably present (Human reconciliation required)'
      return 1
    fi
    if ! m9_expect "$(m9_sha256_file "$scratch")" "$ISSUED_ARCHIVE_SHA256" retry_remote_archive_sha256; then
      rm -f "$scratch"
      return 1
    fi
    m9_expect "$(m9_size_bytes "$scratch")" "$index_size" retry_remote_archive_size || return 1
    embedded_sha="$(m9_archive_embedded_manifest "$scratch" \
      "$(basename "$M9_EVIDENCE")" | sha256sum | cut -d' ' -f1)"
    rm -f "$scratch"
  fi
  m9_expect "$embedded_sha" "$index_manifest_sha" retry_embedded_manifest_sha256 || return 1
  SEALED_EMBEDDED_MANIFEST_SHA256="$embedded_sha"
  m9_record retry_semantic_auth_sha256 "$SEMANTIC_AUTH_SHA256"
  m9_record retry_archive_sha256 "$ISSUED_ARCHIVE_SHA256"
  m9_record retry_package_index_sha256 "$ISSUED_PACKAGE_INDEX_SHA256"
  return 0
}

m9_phase_b_seal() {
  case "$AUTHORIZATION_KIND" in
    SEMANTIC) m9_phase_b_seal_semantic ;;
    DURABILITY_RETRY) m9_phase_b_seal_retry ;;
    *) m9_die "unknown authorization kind: $AUTHORIZATION_KIND"; return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# PHASE C — durability.
# ---------------------------------------------------------------------------
m9_upload_or_verify() {
  local key=$1 local_file=$2 rc=0
  m9_oss_put_object_no_overwrite "$key" "$local_file" "$M9_SEAL_DIR/oss-durability.log" || rc=$?
  case "$rc" in
    "$M9_OSS_OK") ;;
    "$M9_OSS_EXISTS") m9_record "durability_object_preexisting" "$key" ;;
    *)
      m9_die "durability upload failed for $key (FAIL CLOSED)"
      return 1
      ;;
  esac
  m9_oss_verify_object "$key" "$local_file" "$M9_SEAL_DIR/oss-durability.log" || {
    m9_die "durability read-back verification failed for $key (FAIL CLOSED)"
    return 1
  }
  return 0
}

# Fetch the durable archive and require size, SHA-256 and the embedded artifact
# manifest to match the sealed values. ETag is never used as a digest.
m9_verify_durable_archive() {
  local scratch='' fetched_sha='' fetched_size='' embedded_sha=''
  scratch="$(mktemp "${TMPDIR:-/tmp}/m9-durable-archive.XXXXXX")"
  if ! m9_oss_get_object "$ARCHIVE_OBJECT" "$scratch" "$M9_SEAL_DIR/oss-durability.log"; then
    rm -f "$scratch"
    m9_die 'durable canonical archive could not be read back (FAIL CLOSED)'
    return 1
  fi
  fetched_sha="$(m9_sha256_file "$scratch")"
  fetched_size="$(m9_size_bytes "$scratch")"
  if [[ "$fetched_sha" != "$SEALED_ARCHIVE_SHA256" ]]; then
    rm -f "$scratch"
    m9_die "durable archive SHA-256 mismatch (expected $SEALED_ARCHIVE_SHA256; got $fetched_sha) (FAIL CLOSED)"
    return 1
  fi
  if [[ "$fetched_size" != "$SEALED_ARCHIVE_SIZE" ]]; then
    rm -f "$scratch"
    m9_die "durable archive size mismatch (expected $SEALED_ARCHIVE_SIZE; got $fetched_size) (FAIL CLOSED)"
    return 1
  fi
  embedded_sha="$(m9_archive_embedded_manifest "$scratch" "$(basename "$M9_EVIDENCE")" \
    | sha256sum | cut -d' ' -f1)"
  if ! m9_expect "$embedded_sha" "$SEALED_MANIFEST_SHA256" durable_embedded_artifact_manifest; then
    rm -f "$scratch"
    return 1
  fi
  rm -f "$scratch"
  return 0
}

m9_phase_c_durability() {
  local fetched_index='' fetched_index_sha='' index_archive_sha='' index_manifest_sha='' index_profile_sha=''

  m9_oss_versioning_guard "$M9_SEAL_DIR" || {
    m9_die 'bucket versioning is not eligible immediately before durability writes (FAIL CLOSED)'
    return 1
  }

  # Upload the canonical archive create-if-absent. A durability retry may have no
  # local archive at all: the exact object was already verified as durably
  # present during sealing.
  if [[ -f "$M9_ARCHIVE_LOCAL" ]]; then
    m9_upload_or_verify "$ARCHIVE_OBJECT" "$M9_ARCHIVE_LOCAL" || return 1
    m9_expect "$(m9_sha256_file "$M9_ARCHIVE_LOCAL")" "$SEALED_ARCHIVE_SHA256" archive_frozen_after_digest || return 1
    m9_expect "$(m9_size_bytes "$M9_ARCHIVE_LOCAL")" "$SEALED_ARCHIVE_SIZE" archive_size_frozen_after_digest || return 1
  else
    local probe_rc=0
    m9_oss_object_probe "$ARCHIVE_OBJECT" "$M9_SEAL_DIR/oss-durability.log" || probe_rc=$?
    [[ "$probe_rc" == "$M9_OSS_OK" ]] ||
      { m9_die "durability retry requires the pre-existing sealed archive at $ARCHIVE_OBJECT"; return 1; }
  fi

  # Upload the exact pre-generated package-index.json create-if-absent.
  m9_upload_or_verify "$PACKAGE_INDEX_OBJECT" "$M9_PACKAGE_INDEX_LOCAL" || return 1
  m9_expect "$(m9_sha256_file "$M9_PACKAGE_INDEX_LOCAL")" \
    "$SEALED_PACKAGE_INDEX_SHA256" package_index_frozen_after_digest || return 1

  # Read-back and verify: object size, archive SHA-256, embedded manifest.
  m9_verify_durable_archive || return 1

  # Read back the package index and cross-bind it to the archive digest.
  fetched_index="$(mktemp "${TMPDIR:-/tmp}/m9-index-readback.XXXXXX")"
  if ! m9_oss_get_object "$PACKAGE_INDEX_OBJECT" "$fetched_index" "$M9_SEAL_DIR/oss-durability.log"; then
    rm -f "$fetched_index"
    m9_die 'durable package-index.json could not be read back (FAIL CLOSED)'
    return 1
  fi
  fetched_index_sha="$(m9_sha256_file "$fetched_index")"
  if ! m9_expect "$fetched_index_sha" "$SEALED_PACKAGE_INDEX_SHA256" durable_package_index_sha256; then
    rm -f "$fetched_index"
    return 1
  fi
  index_archive_sha="$(m9_json_get "$fetched_index" archive.sha256)"
  index_manifest_sha="$(m9_json_get "$fetched_index" artifact_manifest.sha256)"
  index_profile_sha="$(m9_json_get "$fetched_index" oss_trust_profile_sha256)"
  rm -f "$fetched_index"
  m9_expect "$index_archive_sha" "$SEALED_ARCHIVE_SHA256" package_index_archive_binding || return 1
  m9_expect "$index_manifest_sha" "$SEALED_MANIFEST_SHA256" package_index_manifest_binding || return 1
  # R2I-C4/B03: the durable package index must carry the exact current profile.
  m9_expect "$index_profile_sha" "$OSS_TRUST_PROFILE_SHA256" \
    package_index_oss_trust_profile_binding || return 1
  return 0
}

# ---------------------------------------------------------------------------
# PHASE D — commit.
# ---------------------------------------------------------------------------
m9_build_receipt() {
  local out=$1 kv="$M9_SEAL_DIR/receipt-inputs.txt"
  : >"$kv"
  m9_kv_set schema "$M9_RECEIPT_SCHEMA" "$kv"
  m9_kv_set closure_outcome 'PASS' "$kv"
  m9_kv_set authorization_kind "$AUTHORIZATION_KIND" "$kv"
  m9_kv_set authorization_sha256 "$AUTHORIZATION_SHA256" "$kv"
  m9_kv_set semantic_auth_sha256 "$SEMANTIC_AUTH_SHA256" "$kv"
  m9_kv_set retry_auth_sha256 "$RETRY_AUTH_SHA256" "$kv"
  m9_kv_set claim_sha256 "$CLAIM_SHA256" "$kv"
  m9_kv_set claim_object "$CLAIM_OBJECT" "$kv"
  m9_kv_set issued_object "$ISSUED_OBJECT" "$kv"
  m9_kv_set issued_document_sha256 "$ISSUED_DOCUMENT_SHA256" "$kv"
  m9_kv_set oss_trust_profile_sha256 "$OSS_TRUST_PROFILE_SHA256" "$kv"
  m9_kv_set proof_sha "$APPROVED_PROOF_SHA" "$kv"
  m9_kv_set proof_tree "$(git -C "$M9_PROOF_ROOT" rev-parse HEAD^{tree})" "$kv"
  m9_kv_set candidate_sha "$M9_APP_SHA" "$kv"
  m9_kv_set candidate_tree "$M9_APP_TREE" "$kv"
  m9_kv_set candidate_parent "$M9_APP_PARENT" "$kv"
  m9_kv_set frozen_main "$M9_MAIN_SHA" "$kv"
  m9_kv_set executor_id "${M9_EXECUTOR_ID:-}" "$kv"
  m9_kv_set authorized_executor_id "$(m9_provider_identity_executor_id)" "$kv"
  m9_kv_set run_prefix "$RUN_PREFIX" "$kv"
  m9_kv_set archive_name "$ARCHIVE_NAME" "$kv"
  m9_kv_set archive_object "$ARCHIVE_OBJECT" "$kv"
  m9_kv_set archive_sha256 "$SEALED_ARCHIVE_SHA256" "$kv"
  m9_kv_set archive_size_bytes "$SEALED_ARCHIVE_SIZE" "$kv"
  m9_kv_set artifact_manifest_sha256 "$SEALED_MANIFEST_SHA256" "$kv"
  m9_kv_set package_index_sha256 "$SEALED_PACKAGE_INDEX_SHA256" "$kv"
  m9_kv_set package_index_object "$PACKAGE_INDEX_OBJECT" "$kv"
  m9_kv_set core_exit_code "$SEALED_CORE_RC" "$kv"
  m9_kv_set adapter_exit_code "$SEALED_ADAPTER_RC" "$kv"
  m9_kv_set formal_execution_rc "$SEALED_FORMAL_RC" "$kv"
  m9_kv_set playwright_effective_retries 0 "$kv"
  m9_kv_set formal_command_rc 0 "$kv"
  m9_kv_set execution_started_utc "$EXECUTION_STARTED_UTC" "$kv"
  m9_kv_set instance_id "$EXPECTED_INSTANCE_ID" "$kv"
  m9_kv_set region_id "$EXPECTED_REGION_ID" "$kv"
  m9_kv_set zone_id "$EXPECTED_ZONE_ID" "$kv"
  m9_kv_set instance_type "$EXPECTED_INSTANCE_TYPE" "$kv"
  m9_kv_set image_id "$EXPECTED_IMAGE_ID" "$kv"
  m9_kv_set identity_document_sha256 "$EXPECTED_IDENTITY_DOCUMENT_SHA256" "$kv"
  m9_kv_set identity_pkcs7_sha256 "$EXPECTED_IDENTITY_PKCS7_SHA256" "$kv"

  "$(m9_python_bin)" - "$kv" "$out" <<'PY' || return 1
import datetime
import json
import sys

kv_path, out = sys.argv[1], sys.argv[2]
values = {}
with open(kv_path, "r", encoding="utf-8") as handle:
    for line in handle:
        line = line.rstrip("\n")
        if not line:
            continue
        key, _, value = line.partition("=")
        values[key] = value

document = {
    "schema": values["schema"],
    "closure_outcome": values["closure_outcome"],
    "authorization_kind": values["authorization_kind"],
    "authorization_sha256": values["authorization_sha256"],
    "semantic_auth_sha256": values["semantic_auth_sha256"],
    "retry_auth_sha256": None if values["retry_auth_sha256"] == "null" else values["retry_auth_sha256"],
    "oss_trust_profile_sha256": values["oss_trust_profile_sha256"],
    "claim_sha256": values["claim_sha256"],
    "claim_object": values["claim_object"],
    "issued_object": values["issued_object"],
    "issued_document_sha256": values["issued_document_sha256"],
    "proof_sha": values["proof_sha"],
    "proof_tree": values["proof_tree"],
    "candidate_sha": values["candidate_sha"],
    "candidate_tree": values["candidate_tree"],
    "candidate_parent": values["candidate_parent"],
    "frozen_main": values["frozen_main"],
    "executor_id": values["executor_id"],
    "authorized_executor_id": values["authorized_executor_id"],
    "provider_identity": {
        "instance_id": values["instance_id"],
        "region_id": values["region_id"],
        "zone_id": values["zone_id"],
        "instance_type": values["instance_type"],
        "image_id": values["image_id"],
        "identity_document_sha256": values["identity_document_sha256"],
        "identity_pkcs7_sha256": values["identity_pkcs7_sha256"],
    },
    "run_prefix": values["run_prefix"],
    "archive_name": values["archive_name"],
    "archive_object": values["archive_object"],
    "archive_sha256": values["archive_sha256"],
    "archive_size_bytes": int(values["archive_size_bytes"]),
    "artifact_manifest_sha256": values["artifact_manifest_sha256"],
    "package_index_sha256": values["package_index_sha256"],
    "package_index_object": values["package_index_object"],
    "core_exit_code": int(values["core_exit_code"]),
    "adapter_exit_code": int(values["adapter_exit_code"]),
    "formal_execution_rc": int(values["formal_execution_rc"]),
    "playwright_effective_retries": int(values["playwright_effective_retries"]),
    "formal_command_rc": int(values["formal_command_rc"]),
    "execution_started_utc": values["execution_started_utc"],
    "committed_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "cross_binding": {
        "sealed_archive_sha256": values["archive_sha256"],
        "package_index_archive_sha256": values["archive_sha256"],
        "manifest_sha256": values["artifact_manifest_sha256"],
        "issued_document_sha256": values["issued_document_sha256"],
        "oss_trust_profile_sha256": values["oss_trust_profile_sha256"],
        "claim_object_sha256": values["claim_sha256"],
    },
}
with open(out, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
PY
}

m9_phase_d_commit() {
  local receipt_local="$M9_SEAL_DIR/closure-receipt.json" rc=0 fetched='' fetched_sha=''

  mkdir -p "$M9_SEAL_DIR" || { m9_die "cannot create $M9_SEAL_DIR"; return 1; }

  # The seal must not be disturbed by the commit phase.
  if [[ "$AUTHORIZATION_KIND" == 'SEMANTIC' ]]; then
    m9_manifest_verify "$M9_EVIDENCE" || return 1
    m9_expect "$(m9_sha256_file "$M9_ARCHIVE_LOCAL")" "$SEALED_ARCHIVE_SHA256" archive_unchanged_before_commit || return 1
  fi

  m9_build_receipt "$receipt_local" || return 1
  EXPECTED_RECEIPT_SHA256="$(m9_sha256_file "$receipt_local")"

  # The closure receipt is the LAST mutating commit object.
  m9_oss_put_object_no_overwrite "$RECEIPT_OBJECT" "$receipt_local" \
    "$M9_SEAL_DIR/oss-commit.log" || rc=$?
  case "$rc" in
    "$M9_OSS_OK") ;;
    "$M9_OSS_EXISTS")
      m9_die "ALREADY_COMMITTED: a closure receipt appeared at $RECEIPT_OBJECT during commit; refusing to overwrite (FAIL CLOSED, no formal RC)"
      return 1
      ;;
    *)
      m9_die "closure receipt could not be committed at $RECEIPT_OBJECT (FAIL CLOSED)"
      return 1
      ;;
  esac

  # Exact byte/SHA-256 read-back is required before any formal RC is claimed.
  fetched="$M9_SEAL_DIR/closure-receipt.readback.json"
  if ! m9_oss_get_object "$RECEIPT_OBJECT" "$fetched" "$M9_SEAL_DIR/oss-commit.log"; then
    m9_die 'closure receipt could not be read back (FAIL CLOSED)'
    return 1
  fi
  fetched_sha="$(m9_sha256_file "$fetched")"
  if [[ "$fetched_sha" != "$EXPECTED_RECEIPT_SHA256" ]]; then
    m9_die "closure receipt read-back SHA-256 mismatch (expected $EXPECTED_RECEIPT_SHA256; got $fetched_sha); FAIL CLOSED, no formal RC"
    return 1
  fi

  "$M9_PROOF_ROOT/scripts/verify-m9-closure-receipt.py" \
    --receipt "$fetched" \
    --expect-sha256 "$EXPECTED_RECEIPT_SHA256" \
    --expect-proof-sha "$APPROVED_PROOF_SHA" \
    --expect-candidate-sha "$M9_APP_SHA" \
    --expect-authorization-sha "$AUTHORIZATION_SHA256" \
    --expect-archive-sha256 "$SEALED_ARCHIVE_SHA256" \
    --expect-oss-trust-profile-sha256 "$OSS_TRUST_PROFILE_SHA256" \
    --json-out "$M9_SEAL_DIR/closure-receipt-check.json" || {
    m9_die 'read-back closure receipt failed validation (FAIL CLOSED, no formal RC)'
    return 1
  }

  m9_expect "$(m9_json_get "$fetched" formal_command_rc)" '0' receipt_formal_command_rc || return 1
  m9_expect "$(m9_json_get "$fetched" closure_outcome)" 'PASS' receipt_closure_outcome || return 1
  RECEIPT_VERIFIED_SHA256="$fetched_sha"
  return 0
}

# Pure formatter for the terminal marker. It refuses to print unless the exact
# verified receipt digest and a zero formal RC are supplied.
m9_emit_formal_rc_marker() {
  local verified_receipt_sha=$1 verified_rc=$2
  [[ "$verified_rc" == '0' ]] || return 1
  [[ -n "$verified_receipt_sha" && "$verified_receipt_sha" == "$EXPECTED_RECEIPT_SHA256" ]] || return 1
  printf '%s=0\n' "$M9_FORMAL_RC_MARKER"
  return 0
}

m9_terminal_success() {
  local marker=''
  marker="$(m9_emit_formal_rc_marker "${RECEIPT_VERIFIED_SHA256:-}" "${FORMAL_EXECUTION_RC:-}")" || {
    m9_die 'refusing to emit the formal RC marker without an exactly verified closure receipt'
    return 1
  }
  printf '%s\n' "$marker"
  m9_record formal_run_command_rc 0
  m9_record receipt_sha256 "${RECEIPT_VERIFIED_SHA256:-}"
  return 0
}

# ---------------------------------------------------------------------------
# Failure bookkeeping and main.
# ---------------------------------------------------------------------------
m9_record_failure() {
  [[ -n "$M9_SEAL_DIR" && -d "$M9_SEAL_DIR" ]] || return 0
  {
    printf 'wrapper_outcome=FAIL\n'
    printf 'failure_utc=%s\n' "$(date -u +%FT%TZ)"
    [[ -n "$AUTHORIZATION_KIND" ]] &&
      printf 'authorization_state=INDETERMINATE claim_exists=yes receipt=absent\n'
  } >>"$M9_SEAL_DIR/wrapper-failure.txt" || true
  return 0
}

m9_wrapper_run() {
  # Formal eligibility guard: this is the canonical production entrypoint, so any
  # non-empty offline synthetic seam makes the invocation FAIL CLOSED before any
  # external I/O or host-state mutation. Offline tests exercise the phase
  # functions directly and never reach this guard.
  m9_reject_synthetic_overrides || return 1
  # R2I-C4/B03: the OSS trust-target environment is closed. This runs immediately
  # after the seam guard and before wrapper init, authorization processing,
  # provider access, OSS access, host-state or evidence creation.
  m9_reject_oss_trust_environment || return 1
  ENVIRONMENT_GUARD_STATE='PASS'
  m9_wrapper_init || return 1
  m9_guard_environment || return 1
  m9_guard_local_syntax || return 1
  m9_guard_static_binding || return 1
  m9_guard_proof_checkout || return 1
  m9_guard_clean_start || return 1

  M9_PRECLAIM_DIR="$M9_HOST_STATE/preclaim/$AUTHORIZATION_SHA256"
  [[ ! -e "$M9_PRECLAIM_DIR" ]] ||
    { m9_die "pre-claim staging already exists: $M9_PRECLAIM_DIR"; return 1; }
  mkdir -p "$M9_PRECLAIM_DIR" || return 1

  # --- OSS trust-target establishment (all read-only, all before any write) ---
  # Ordering invariant: no PutObject may occur anywhere below until every step
  # 8-19 has succeeded. Steps 14/15 are read-only; the first permitted mutating
  # call is the atomic claim at step 20.
  m9_oss_canonical_config_guard "$M9_PRECLAIM_DIR" || return 1   # 8
  m9_ossutil_identity_guard "$M9_PRECLAIM_DIR" || return 1       # 9
  m9_provider_identity_preclaim || return 1                      # 10
  m9_oss_observe_ecs_role_name || return 1                       # 11
  m9_prepare_oss_trust_profile || return 1                       # 12
  m9_oss_capability_guard "$M9_PRECLAIM_DIR" || return 1         # 13
  m9_oss_bucket_location_guard "$M9_PRECLAIM_DIR" || return 1    # 14
  m9_oss_versioning_guard "$M9_PRECLAIM_DIR" || return 1         # 15
  m9_load_authorization || return 1                             # 16-18
  m9_already_committed_check || return 1                        # 19
  m9_claim_create || return 1                                   # 20
  m9_evidence_initialize || return 1                            # 21

  case "$AUTHORIZATION_KIND" in
    SEMANTIC) m9_phase_a_execute || return 1 ;;
    DURABILITY_RETRY) : ;; # a durability retry never reruns core or adapter
    *) m9_die "unknown authorization kind: $AUTHORIZATION_KIND"; return 1 ;;
  esac

  m9_phase_b_seal || return 1
  m9_phase_c_durability || return 1
  m9_phase_d_commit || return 1

  if m9_synthetic; then
    printf 'M9_SYNTHETIC_TEST_MODE=1\n'
    printf 'M9_SYNTHETIC_OUTCOME=OK\n'
    return 0
  fi
  m9_terminal_success || return 1
  return 0
}

m9_main() {
  local rc=0
  m9_wrapper_run || rc=$?
  if (( rc != 0 )); then
    m9_record_failure
    return "$rc"
  fi
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  m9_main
fi
