#!/usr/bin/env bash
# lib/common.sh — shared helpers for all exploit scripts.
# Source this file; do not execute directly.

# ---------------------------------------------------------------------------
# Service base URLs (override via env for non-default setups)
# ---------------------------------------------------------------------------
WEB_BASE="${WEB_BASE:-http://localhost:3000}"
MCP_BASE="${MCP_BASE:-http://localhost:8788}"

# The URL containers use to reach the mock server running on the Docker host.
# On Linux, --add-host=host.docker.internal:host-gateway maps this name.
# isPrivateHost() in og/route.ts only blocks literal RFC-1918 IPs and
# localhost — DNS names such as host.docker.internal pass the check, which
# is exactly the bypass class being demonstrated for C1.
MOCK_HOST_FROM_CONTAINER="http://host.docker.internal:9099"

# The URL scripts on the host use to reach the mock server.
MOCK_HOST_FROM_SCRIPT="http://localhost:9099"

# Pinned constants — must match setup.sh and the audit report.
PINNED_COMMIT="268499068810586495ba5bd4773f8c5786d9fc97"
AUDIT_STATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.audit_state"

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
_RED='\033[0;31m'
_GREEN='\033[0;32m'
_YELLOW='\033[1;33m'
_CYAN='\033[0;36m'
_BOLD='\033[1m'
_RESET='\033[0m'

pass() { echo -e "${_GREEN}${_BOLD}RESULT: PASS${_RESET}  $*"; }
fail() { echo -e "${_RED}${_BOLD}RESULT: FAIL${_RESET}  $*"; }
info() { echo -e "${_CYAN}[INFO]${_RESET} $*"; }
warn() { echo -e "${_YELLOW}[WARN]${_RESET} $*"; }
header() {
    echo ""
    echo -e "${_BOLD}${_CYAN}================================================================${_RESET}"
    echo -e "${_BOLD}${_CYAN}  $*${_RESET}"
    echo -e "${_BOLD}${_CYAN}================================================================${_RESET}"
    echo ""
}

# ---------------------------------------------------------------------------
# Canary helpers
# ---------------------------------------------------------------------------
read_canary() {
    local canary_file="${AUDIT_STATE_DIR}/canary.txt"
    if [[ ! -f "${canary_file}" ]]; then
        echo "CANARY-NOT-FOUND"
        return 1
    fi
    cat "${canary_file}"
}

# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

# assert_status <expected> <actual> <label>
assert_status() {
    local expected="$1"
    local actual="$2"
    local label="${3:-status check}"
    if [[ "${actual}" == "${expected}" ]]; then
        info "  ${label}: status ${actual} == ${expected} (OK)"
        return 0
    else
        warn "  ${label}: status ${actual} != ${expected} (FAIL)"
        return 1
    fi
}

# assert_contains <haystack> <needle> <label>
assert_contains() {
    local haystack="$1"
    local needle="$2"
    local label="${3:-contains check}"
    if echo "${haystack}" | grep -qF "${needle}"; then
        info "  ${label}: found '${needle}' (OK)"
        return 0
    else
        warn "  ${label}: '${needle}' NOT found (FAIL)"
        return 1
    fi
}

# assert_not_contains <haystack> <needle> <label>
assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local label="${3:-not-contains check}"
    if echo "${haystack}" | grep -qF "${needle}"; then
        warn "  ${label}: '${needle}' WAS found but should not be (FAIL)"
        return 1
    else
        info "  ${label}: '${needle}' absent (OK)"
        return 0
    fi
}

# ---------------------------------------------------------------------------
# Mock hit query
# ---------------------------------------------------------------------------
# mock_hits_since <unix_timestamp>
# Returns JSON array of recorded hits from the mock server since timestamp.
mock_hits_since() {
    local since="${1:-0}"
    curl -sf "${MOCK_HOST_FROM_SCRIPT}/__hits?since=${since}" 2>/dev/null || echo "[]"
}

# ---------------------------------------------------------------------------
# Proof capture
# ---------------------------------------------------------------------------
# save_proof <exploit_id> <content>
save_proof() {
    local exploit_id="$1"
    local content="$2"
    mkdir -p "${AUDIT_STATE_DIR}"
    printf '%s\n' "${content}" > "${AUDIT_STATE_DIR}/${exploit_id}.proof"
    info "  Proof saved to ${AUDIT_STATE_DIR}/${exploit_id}.proof"
}

# ---------------------------------------------------------------------------
# Print a request block before sending it (for transparency)
# ---------------------------------------------------------------------------
print_request() {
    echo -e "${_BOLD}--- REQUEST ---${_RESET}"
    echo "$@"
    echo -e "${_BOLD}---------------${_RESET}"
}
