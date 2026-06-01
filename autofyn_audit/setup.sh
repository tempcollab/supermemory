#!/usr/bin/env bash
# setup.sh — Build the audit image, start the web+mcp containers, and start
# the mock server on the host.
#
# Prerequisites: docker, git, python3, curl
#
# Usage: bash autofyn_audit/setup.sh
#        bash autofyn_audit/setup.sh --no-cache   (force image rebuild)
#
# Host-port overrides (use when ports 3000/8788 are already taken on the host):
#        WEB_HOST_PORT=3001 MCP_HOST_PORT=8789 bash autofyn_audit/setup.sh
#   The container-internal app ports stay 3000/8788; only the host-side
#   published ports change. Run the exploits with matching bases:
#        WEB_BASE=http://localhost:3001 MCP_BASE=http://localhost:8789 \
#            bash autofyn_audit/run_exploits.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Constants — must match lib/common.sh and the spec
# ---------------------------------------------------------------------------
PINNED_COMMIT="268499068810586495ba5bd4773f8c5786d9fc97"
PINNED_IMAGE="oven/bun:1.3.6@sha256:f20d9cf365ab35529384f1717687c739c92e6f39157a35a95ef06f4049a10e4a"
IMAGE_TAG="autofyn-audit:pinned"

WEB_CONTAINER="autofyn-web"
MCP_CONTAINER="autofyn-mcp"
# Container-internal app ports (fixed — the apps listen on these inside the container).
WEB_PORT=3000
MCP_PORT=8788
MOCK_PORT=9099
# Host-side published ports (overridable to avoid conflicts with other workloads).
WEB_HOST_PORT="${WEB_HOST_PORT:-3000}"
MCP_HOST_PORT="${MCP_HOST_PORT:-8788}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
AUDIT_STATE_DIR="${SCRIPT_DIR}/.audit_state"

WEB_READY_TIMEOUT=180   # seconds — next dev first build is slow
MCP_READY_TIMEOUT=120   # seconds

NO_CACHE_FLAG=""
for arg in "$@"; do
    [[ "${arg}" == "--no-cache" ]] && NO_CACHE_FLAG="--no-cache"
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_RED='\033[0;31m'
_GREEN='\033[0;32m'
_YELLOW='\033[1;33m'
_CYAN='\033[0;36m'
_BOLD='\033[1m'
_RESET='\033[0m'

die()  { echo -e "${_RED}${_BOLD}[FATAL]${_RESET} $*" >&2; exit 1; }
ok()   { echo -e "${_GREEN}[OK]${_RESET} $*"; }
info() { echo -e "${_CYAN}[INFO]${_RESET} $*"; }
warn() { echo -e "${_YELLOW}[WARN]${_RESET} $*"; }

# ---------------------------------------------------------------------------
# Step 0 — Commit pin check (AUTHORITATIVE; must pass before docker build)
# ---------------------------------------------------------------------------
info "Checking pinned app source…"
command -v git >/dev/null 2>&1 || die "git is not installed."
ACTUAL_COMMIT="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null)" || \
    die "Could not run 'git rev-parse HEAD' in ${REPO_ROOT}. Is this a git repo?"

# The audit pins the *application source* under test to ${PINNED_COMMIT}.
# The audit deliverables themselves (autofyn_audit/) may be committed on top of
# that pin across audit rounds, advancing HEAD. Reproducibility therefore means
# "the audited app code is identical to the pin", NOT "HEAD == pin". We verify
# that no tracked app/package source has changed since the pinned commit.
git -C "${REPO_ROOT}" cat-file -e "${PINNED_COMMIT}^{commit}" 2>/dev/null || \
    die "Pinned commit ${PINNED_COMMIT} not found in this repo. Cannot verify app source."

APP_SOURCE_PATHS=(apps packages package.json bun.lock turbo.json biome.json tsconfig.json)
if ! git -C "${REPO_ROOT}" diff --quiet "${PINNED_COMMIT}" HEAD -- "${APP_SOURCE_PATHS[@]}" 2>/dev/null; then
    echo "" >&2
    git -C "${REPO_ROOT}" diff --stat "${PINNED_COMMIT}" HEAD -- "${APP_SOURCE_PATHS[@]}" >&2
    die "APP SOURCE MISMATCH — audited app code differs from pinned commit ${PINNED_COMMIT}.
     The above paths changed since the pin. Re-pin the audit or revert the changes
     before running setup, otherwise exploit results are not reproducible."
fi
ok "App source pin verified: identical to ${PINNED_COMMIT} (HEAD=${ACTUAL_COMMIT})"

# ---------------------------------------------------------------------------
# Step 1 — Idempotent teardown of existing containers
# ---------------------------------------------------------------------------
info "Removing any existing audit containers…"
docker rm -f "${WEB_CONTAINER}" "${MCP_CONTAINER}" 2>/dev/null || true
ok "Existing containers removed (or did not exist)."

# ---------------------------------------------------------------------------
# Step 1b — Pre-flight host-port availability check (clear error, not a cryptic
#           docker bind failure mid-run).
# ---------------------------------------------------------------------------
port_in_use() {
    # Returns 0 if something is already listening on the given host TCP port.
    curl -s -o /dev/null --max-time 2 "http://localhost:${1}/" 2>/dev/null && return 0
    # Also catch ports that accept connections but return nothing parseable.
    (exec 3<>"/dev/tcp/localhost/${1}") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
    return 1
}
for p in "${WEB_HOST_PORT}" "${MCP_HOST_PORT}"; do
    if port_in_use "${p}"; then
        die "Host port ${p} is already in use by another process/container.
     Pick free host ports and re-run, e.g.:
       WEB_HOST_PORT=3001 MCP_HOST_PORT=8789 bash autofyn_audit/setup.sh
     then run the exploits against them:
       WEB_BASE=http://localhost:3001 MCP_BASE=http://localhost:8789 bash autofyn_audit/run_exploits.sh"
    fi
done

# ---------------------------------------------------------------------------
# Step 2 — Build audit image (reuse if already present and --no-cache not given)
# ---------------------------------------------------------------------------
info "Building audit image: ${IMAGE_TAG}  (base: ${PINNED_IMAGE})"
info "Build context: ${REPO_ROOT}  — see autofyn_audit/.dockerignore for exclusions"
info "Expected first-build time: 3-6 minutes (bun install on full monorepo)"
docker build \
    ${NO_CACHE_FLAG} \
    --build-arg "EXPECTED_COMMIT=${PINNED_COMMIT}" \
    -t "${IMAGE_TAG}" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    "${REPO_ROOT}"
ok "Image built: ${IMAGE_TAG}"

# ---------------------------------------------------------------------------
# Step 3 — Start the mock server on the host
# ---------------------------------------------------------------------------
mkdir -p "${AUDIT_STATE_DIR}"

# Kill any existing mock server
if [[ -f "${AUDIT_STATE_DIR}/mock.pid" ]]; then
    OLD_PID="$(cat "${AUDIT_STATE_DIR}/mock.pid")"
    if kill -0 "${OLD_PID}" 2>/dev/null; then
        info "Killing existing mock server (PID ${OLD_PID})…"
        kill "${OLD_PID}" 2>/dev/null || true
        sleep 1
    fi
    rm -f "${AUDIT_STATE_DIR}/mock.pid"
fi

# Fresh hit log per setup so SSRF proofs are unambiguous.
rm -f "${AUDIT_STATE_DIR}/mock_hits.log"

info "Starting mock server on host port ${MOCK_PORT}…"
python3 "${SCRIPT_DIR}/mock_server.py" &>"${AUDIT_STATE_DIR}/mock_server.log" &
MOCK_PID=$!

# Wait for mock to be ready (writes PID file when up)
MOCK_WAIT=0
until curl -sf "http://localhost:${MOCK_PORT}/__hits" >/dev/null 2>&1; do
    MOCK_WAIT=$((MOCK_WAIT + 1))
    [[ ${MOCK_WAIT} -gt 15 ]] && die "Mock server did not start within 15s — check ${AUDIT_STATE_DIR}/mock_server.log"
    sleep 1
done
ok "Mock server ready on port ${MOCK_PORT} (PID ${MOCK_PID})"

# ---------------------------------------------------------------------------
# Step 4 — Start web container (next dev on port 3000)
# ---------------------------------------------------------------------------
info "Starting ${WEB_CONTAINER} (next dev, host port ${WEB_HOST_PORT} -> container ${WEB_PORT})…"
info "  Note: WRANGLER_SEND_METRICS=false CI=1 are set; no XAI/EXA keys injected by default."
info "  If you have XAI_API_KEY or EXA_API_KEY, export them before running setup.sh."

WEB_ENV_FLAGS=""
[[ -n "${XAI_API_KEY:-}" ]] && WEB_ENV_FLAGS="${WEB_ENV_FLAGS} -e XAI_API_KEY=${XAI_API_KEY}"
[[ -n "${EXA_API_KEY:-}" ]] && WEB_ENV_FLAGS="${WEB_ENV_FLAGS} -e EXA_API_KEY=${EXA_API_KEY}"

# shellcheck disable=SC2086
docker run -d \
    --name "${WEB_CONTAINER}" \
    --add-host=host.docker.internal:host-gateway \
    -p "${WEB_HOST_PORT}:${WEB_PORT}" \
    -e PORT="${WEB_PORT}" \
    -e WRANGLER_SEND_METRICS=false \
    -e CI=1 \
    -e NODE_ENV=development \
    ${WEB_ENV_FLAGS} \
    "${IMAGE_TAG}" \
    bash -c "cd /app/apps/web && bun run dev:app"

ok "${WEB_CONTAINER} started."

# ---------------------------------------------------------------------------
# Step 5 — Start MCP container (wrangler dev on port 8788)
# ---------------------------------------------------------------------------
info "Starting ${MCP_CONTAINER} (wrangler dev --local, host port ${MCP_HOST_PORT} -> container ${MCP_PORT})…"
info "  MCP_URL is intentionally UNSET so C4 (host-header injection) is live-reproducible."

# shellcheck disable=SC2086
docker run -d \
    --name "${MCP_CONTAINER}" \
    --add-host=host.docker.internal:host-gateway \
    -p "${MCP_HOST_PORT}:${MCP_PORT}" \
    -e PORT="${MCP_PORT}" \
    -e WRANGLER_SEND_METRICS=false \
    -e WRANGLER_LOG=error \
    -e CI=1 \
    "${IMAGE_TAG}" \
    bash -c "cd /app/apps/mcp && bun run dev:app"

ok "${MCP_CONTAINER} started."

# ---------------------------------------------------------------------------
# Step 6 — Health-check web (up to WEB_READY_TIMEOUT seconds)
# ---------------------------------------------------------------------------
info "Waiting for web app on host port ${WEB_HOST_PORT} (timeout ${WEB_READY_TIMEOUT}s)…"
WEB_ELAPSED=0
WEB_READY=false
until curl -sf -o /dev/null "http://localhost:${WEB_HOST_PORT}/login"; do
    WEB_ELAPSED=$((WEB_ELAPSED + 2))
    if [[ ${WEB_ELAPSED} -ge ${WEB_READY_TIMEOUT} ]]; then
        echo ""
        docker logs --tail=50 "${WEB_CONTAINER}" >&2
        die "${WEB_CONTAINER} did NOT become ready within ${WEB_READY_TIMEOUT}s.
     See logs above. Common causes: bun install incomplete, port conflict.
     Re-run with --no-cache if dependencies changed."
    fi
    printf '.'
    sleep 2
done
echo ""
WEB_READY=true
ok "${WEB_CONTAINER} READY on http://localhost:${WEB_HOST_PORT}"

# ---------------------------------------------------------------------------
# Step 7 — Health-check MCP (up to MCP_READY_TIMEOUT seconds)
# ---------------------------------------------------------------------------
info "Waiting for MCP server on host port ${MCP_HOST_PORT} (timeout ${MCP_READY_TIMEOUT}s)…"
MCP_ELAPSED=0
MCP_READY=false
until curl -sf -o /dev/null "http://localhost:${MCP_HOST_PORT}/"; do
    MCP_ELAPSED=$((MCP_ELAPSED + 2))
    if [[ ${MCP_ELAPSED} -ge ${MCP_READY_TIMEOUT} ]]; then
        echo ""
        docker logs --tail=50 "${MCP_CONTAINER}" >&2
        die "${MCP_CONTAINER} did NOT become ready within ${MCP_READY_TIMEOUT}s.
     See logs above. Common causes: vite build failed, wrangler requires --local flag,
     or port conflict. Check that wrangler runs in local mode (no --remote flag in dev:app)."
    fi
    printf '.'
    sleep 2
done
echo ""
MCP_READY=true
ok "${MCP_CONTAINER} READY on http://localhost:${MCP_HOST_PORT}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${_BOLD}${_GREEN}================================================================${_RESET}"
echo -e "${_BOLD}${_GREEN}  SETUP COMPLETE — READY${_RESET}"
echo -e "${_BOLD}${_GREEN}================================================================${_RESET}"
echo "  Pinned commit : ${PINNED_COMMIT}"
echo "  Pinned image  : ${PINNED_IMAGE}"
echo "  Web           : http://localhost:${WEB_HOST_PORT}   (${WEB_CONTAINER})"
echo "  MCP           : http://localhost:${MCP_HOST_PORT}   (${MCP_CONTAINER})"
echo "  Mock server   : http://localhost:${MOCK_PORT}  (host, PID ${MOCK_PID})"
echo "  Canary token  : $(cat "${AUDIT_STATE_DIR}/canary.txt" 2>/dev/null || echo 'NOT YET WRITTEN')"
echo ""
if [[ "${WEB_HOST_PORT}" != "3000" || "${MCP_HOST_PORT}" != "8788" ]]; then
echo "  NON-DEFAULT PORTS — run exploits with matching bases:"
echo "    WEB_BASE=http://localhost:${WEB_HOST_PORT} MCP_BASE=http://localhost:${MCP_HOST_PORT} bash autofyn_audit/run_exploits.sh"
else
echo "  Run exploits  : bash autofyn_audit/run_exploits.sh"
fi
echo "  Teardown      : bash autofyn_audit/teardown.sh"
echo -e "${_BOLD}${_GREEN}================================================================${_RESET}"
