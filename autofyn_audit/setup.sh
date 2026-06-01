#!/usr/bin/env bash
# setup.sh — Resolve the pre-built audit image, create the shared network,
# start mock + web + mcp containers, and health-check all three.
#
# This script does NOT build the Docker image. Build it once (and only once)
# before the first run with:
#   bash autofyn_audit/build_image.sh
#
# After that, setup.sh reuses the pinned local image autofyn-audit:pinned
# without rebuilding. To use a registry image instead, set AUDIT_IMAGE:
#   AUDIT_IMAGE=ghcr.io/your-org/autofyn-audit:pinned bash autofyn_audit/setup.sh
#
# Prerequisites: docker, git, curl
#
# Usage: bash autofyn_audit/setup.sh
#
# Reachability: all containers communicate over ${AUDIT_NET} by container name.
# No published host port is required for exploit reproducibility. Published ports
# (-p flags) are kept as optional convenience for humans on a real Docker host
# but are NOT load-bearing. Exploit scripts reach services as:
#   http://autofyn-web:3000   (autofyn-web)
#   http://autofyn-mcp:8788   (autofyn-mcp)
#   http://audit-mock:9099    (audit-mock)
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Constants — must match lib/common.sh and the spec
# ---------------------------------------------------------------------------
PINNED_COMMIT="268499068810586495ba5bd4773f8c5786d9fc97"
PINNED_IMAGE="oven/bun:1.3.6@sha256:f20d9cf365ab35529384f1717687c739c92e6f39157a35a95ef06f4049a10e4a"
IMAGE_TAG="autofyn-audit:pinned"

# Mock image: python:3.12-slim pinned by digest (resolved from python:3.12-slim).
# To re-resolve: docker buildx imagetools inspect python:3.12-slim
MOCK_IMAGE="python@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203"

AUDIT_NET="autofyn-audit-net"
WEB_CONTAINER="autofyn-web"
MCP_CONTAINER="autofyn-mcp"
MOCK_CONTAINER="audit-mock"

# Container-internal app ports (fixed — the apps listen on these inside the container).
WEB_PORT=3000
MCP_PORT=8788
MOCK_PORT=9099
# Host-side published ports (overridable to avoid conflicts; NOT load-bearing).
WEB_HOST_PORT="${WEB_HOST_PORT:-3000}"
MCP_HOST_PORT="${MCP_HOST_PORT:-8788}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
AUDIT_STATE_DIR="${SCRIPT_DIR}/.audit_state"

WEB_READY_TIMEOUT=180   # seconds — next dev first build is slow
MCP_READY_TIMEOUT=120   # seconds
MOCK_READY_TIMEOUT=15   # seconds

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
docker rm -f "${WEB_CONTAINER}" "${MCP_CONTAINER}" "${MOCK_CONTAINER}" 2>/dev/null || true
ok "Existing containers removed (or did not exist)."

# ---------------------------------------------------------------------------
# Step 2 — Resolve the pre-built audit image (NO inline build)
# ---------------------------------------------------------------------------
# Two paths:
#   a) AUDIT_IMAGE env set  → pull that registry image and use it.
#   b) AUDIT_IMAGE unset    → use the local autofyn-audit:pinned image; fail
#      with an actionable message if it is not present.
# ---------------------------------------------------------------------------
RUN_IMAGE=""
if [[ -n "${AUDIT_IMAGE:-}" ]]; then
    info "AUDIT_IMAGE set — pulling registry image: ${AUDIT_IMAGE}"
    docker pull "${AUDIT_IMAGE}" || \
        die "Failed to pull AUDIT_IMAGE='${AUDIT_IMAGE}'. Check the reference and your credentials."
    RUN_IMAGE="${AUDIT_IMAGE}"
    ok "Pulled registry image: ${RUN_IMAGE}"
else
    if ! docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
        die "Pinned image ${IMAGE_TAG} not found locally.
     Build it once with:
       bash autofyn_audit/build_image.sh
     (or set AUDIT_IMAGE=<registry-ref> to pull a pre-published image)."
    fi
    # Verify the OCI revision label if it exists (back-compat: warn if absent).
    EXISTING_REVISION="$(docker image inspect \
        --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
        "${IMAGE_TAG}" 2>/dev/null || true)"
    if [[ -n "${EXISTING_REVISION}" ]]; then
        if [[ "${EXISTING_REVISION}" != "${PINNED_COMMIT}" ]]; then
            die "Image ${IMAGE_TAG} revision label '${EXISTING_REVISION}' does not match
     pinned commit '${PINNED_COMMIT}'. Rebuild with:
       bash autofyn_audit/build_image.sh --force"
        fi
        ok "Image revision label verified: ${EXISTING_REVISION}"
    else
        warn "Image ${IMAGE_TAG} has no org.opencontainers.image.revision label (older build). Proceeding."
    fi
    RUN_IMAGE="${IMAGE_TAG}"
    ok "Using local pinned image: ${RUN_IMAGE}"
fi

# ---------------------------------------------------------------------------
# Step 2b — Create the shared docker network (idempotent)
# ---------------------------------------------------------------------------
info "Ensuring docker network '${AUDIT_NET}' exists…"
docker network inspect "${AUDIT_NET}" >/dev/null 2>&1 || docker network create "${AUDIT_NET}"
ok "Network '${AUDIT_NET}' ready."

# ---------------------------------------------------------------------------
# Step 3 — Start the mock server as a container on the shared network
#
# File sharing strategy: docker cp (portable across bind-mount and named-volume
# backed driver containers; avoids "Mounts denied" in gVisor/named-volume setups).
#   - mock_server.py is copied IN to the container after create.
#   - canary.txt is copied OUT to the driver fs after the health-check passes.
# ---------------------------------------------------------------------------
mkdir -p "${AUDIT_STATE_DIR}"
rm -f "${AUDIT_STATE_DIR}/mock_hits.log"   # fresh hit log per run

info "Creating mock container '${MOCK_CONTAINER}' on network '${AUDIT_NET}'…"
info "  Mock image: ${MOCK_IMAGE}"
info "  File sharing: docker cp (no bind-mount — portable across host and named-volume topologies)"

# Create (not run yet) so we can docker cp the script in before starting.
# The entrypoint copies /tmp/mock_server.py → /mock/mock_server.py and runs it,
# so docker cp only needs to reach /tmp (which always exists in the image).
docker create \
    --name "${MOCK_CONTAINER}" \
    --network "${AUDIT_NET}" \
    "${MOCK_IMAGE}" \
    sh -c "mkdir -p /mock && cp /tmp/mock_server.py /mock/mock_server.py && python3 /mock/mock_server.py"

# Copy mock_server.py into /tmp inside the (stopped) container.
# docker cp works on stopped/created containers — no bind mount needed.
docker cp "${SCRIPT_DIR}/mock_server.py" "${MOCK_CONTAINER}:/tmp/mock_server.py"

docker start "${MOCK_CONTAINER}"
ok "${MOCK_CONTAINER} started."

# Health-check the mock from a runner container on the network (not localhost).
# Uses `if ...; then` so a down mock yields the retry loop, not a pipefail abort.
info "Waiting for mock server to be ready (up to ${MOCK_READY_TIMEOUT}s)…"
MOCK_ELAPSED=0
until docker run --rm --network "${AUDIT_NET}" "${RUN_IMAGE}" \
        curl -sf --max-time 5 "http://${MOCK_CONTAINER}:${MOCK_PORT}/__hits" >/dev/null 2>&1; do
    MOCK_ELAPSED=$((MOCK_ELAPSED + 1))
    if [[ ${MOCK_ELAPSED} -gt ${MOCK_READY_TIMEOUT} ]]; then
        echo ""
        docker logs --tail=50 "${MOCK_CONTAINER}" >&2
        die "Mock container did NOT start within ${MOCK_READY_TIMEOUT}s — see logs above."
    fi
    printf '.'
    sleep 1
done
echo ""
ok "Mock server ready (http://${MOCK_CONTAINER}:${MOCK_PORT})."

# Pull canary.txt from the mock container to the driver filesystem via docker cp.
# mock_server.py writes canary.txt in setup_state_dir() before serve_forever(),
# so once /__hits answers, canary.txt is already present inside the container.
docker cp "${MOCK_CONTAINER}:/mock/.audit_state/canary.txt" "${AUDIT_STATE_DIR}/canary.txt" 2>/dev/null || true

if [[ ! -f "${AUDIT_STATE_DIR}/canary.txt" ]]; then
    die "canary.txt NOT found at ${AUDIT_STATE_DIR}/canary.txt after mock health-check passed.
     docker cp from ${MOCK_CONTAINER}:/mock/.audit_state/canary.txt failed.
     Check mock_server.py writes canary.txt to /mock/.audit_state/ on startup.
     Container logs: docker logs ${MOCK_CONTAINER}"
fi
ok "Canary copied from mock container: ${AUDIT_STATE_DIR}/canary.txt"
info "  Canary token: $(cat "${AUDIT_STATE_DIR}/canary.txt")"

# ---------------------------------------------------------------------------
# Step 4 — Start web container (next dev on port 3000) on the shared network
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
    --network "${AUDIT_NET}" \
    --add-host=host.docker.internal:host-gateway \
    -p "${WEB_HOST_PORT}:${WEB_PORT}" \
    -e PORT="${WEB_PORT}" \
    -e WRANGLER_SEND_METRICS=false \
    -e CI=1 \
    -e NODE_ENV=development \
    ${WEB_ENV_FLAGS} \
    "${RUN_IMAGE}" \
    bash -c "cd /app/apps/web && bunx next dev -H 0.0.0.0 --port ${WEB_PORT}"

ok "${WEB_CONTAINER} started."

# ---------------------------------------------------------------------------
# Step 5 — Start MCP container (wrangler dev on port 8788) on the shared network
# ---------------------------------------------------------------------------
info "Starting ${MCP_CONTAINER} (wrangler dev --local, host port ${MCP_HOST_PORT} -> container ${MCP_PORT})…"
info "  MCP_URL is intentionally UNSET so C4 (host-header injection) is live-reproducible."

# shellcheck disable=SC2086
docker run -d \
    --name "${MCP_CONTAINER}" \
    --network "${AUDIT_NET}" \
    --add-host=host.docker.internal:host-gateway \
    -p "${MCP_HOST_PORT}:${MCP_PORT}" \
    -e PORT="${MCP_PORT}" \
    -e WRANGLER_SEND_METRICS=false \
    -e WRANGLER_LOG=error \
    -e CI=1 \
    "${RUN_IMAGE}" \
    bash -c "cd /app/apps/mcp && bun run build:ui && bunx wrangler dev --ip 0.0.0.0 --port ${MCP_PORT}"

ok "${MCP_CONTAINER} started."

# ---------------------------------------------------------------------------
# Step 6 — Health-check web from a runner container on the network
# (not localhost — localhost is unreachable from the gVisor sandbox sibling)
# --max-time 20 accommodates Next.js on-demand route compilation (10–15s first req)
# ---------------------------------------------------------------------------
info "Waiting for web app on network (timeout ${WEB_READY_TIMEOUT}s)…"
WEB_ELAPSED=0
until docker run --rm --network "${AUDIT_NET}" "${RUN_IMAGE}" \
        curl -sf -o /dev/null --max-time 20 "http://${WEB_CONTAINER}:${WEB_PORT}/login"; do
    WEB_ELAPSED=$((WEB_ELAPSED + 2))
    if [[ ${WEB_ELAPSED} -ge ${WEB_READY_TIMEOUT} ]]; then
        echo ""
        docker logs --tail=50 "${WEB_CONTAINER}" >&2
        die "${WEB_CONTAINER} did NOT become ready within ${WEB_READY_TIMEOUT}s.
     See logs above. Common causes: bun install incomplete, port conflict.
     If the image seems stale, rebuild with: bash autofyn_audit/build_image.sh --force"
    fi
    printf '.'
    sleep 2
done
echo ""
ok "${WEB_CONTAINER} READY (http://${WEB_CONTAINER}:${WEB_PORT} on ${AUDIT_NET})"

# ---------------------------------------------------------------------------
# Step 7 — Health-check MCP from a runner container on the network
# ---------------------------------------------------------------------------
info "Waiting for MCP server on network (timeout ${MCP_READY_TIMEOUT}s)…"
MCP_ELAPSED=0
until docker run --rm --network "${AUDIT_NET}" "${RUN_IMAGE}" \
        curl -sf -o /dev/null --max-time 20 "http://${MCP_CONTAINER}:${MCP_PORT}/"; do
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
ok "${MCP_CONTAINER} READY (http://${MCP_CONTAINER}:${MCP_PORT} on ${AUDIT_NET})"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${_BOLD}${_GREEN}================================================================${_RESET}"
echo -e "${_BOLD}${_GREEN}  SETUP COMPLETE — READY${_RESET}"
echo -e "${_BOLD}${_GREEN}================================================================${_RESET}"
echo "  Pinned commit : ${PINNED_COMMIT}"
echo "  Pinned image  : ${PINNED_IMAGE}"
echo "  Mock image    : ${MOCK_IMAGE}"
echo "  Run image     : ${RUN_IMAGE}"
echo "  Image id      : $(docker image inspect --format '{{.Id}}' "${RUN_IMAGE}" 2>/dev/null || echo 'unknown')"
echo "  Network       : ${AUDIT_NET}"
echo "  Web           : http://autofyn-web:3000   (${WEB_CONTAINER})"
echo "  MCP           : http://autofyn-mcp:8788   (${MCP_CONTAINER})"
echo "  Mock server   : http://audit-mock:9099     (${MOCK_CONTAINER})"
echo "  Canary token  : $(cat "${AUDIT_STATE_DIR}/canary.txt" 2>/dev/null || echo 'NOT YET WRITTEN')"
echo ""
echo "  Run exploits  : bash autofyn_audit/run_exploits.sh"
echo "  Teardown      : bash autofyn_audit/teardown.sh"
echo -e "${_BOLD}${_GREEN}================================================================${_RESET}"
