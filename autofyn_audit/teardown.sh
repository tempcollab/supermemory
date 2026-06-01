#!/usr/bin/env bash
# teardown.sh — Stop and remove audit containers, kill mock server, clean temp.
#
# Usage:
#   bash autofyn_audit/teardown.sh            # stop containers + mock
#   bash autofyn_audit/teardown.sh --purge    # also remove image + .audit_state/
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_STATE_DIR="${SCRIPT_DIR}/.audit_state"
IMAGE_TAG="autofyn-audit:pinned"
WEB_CONTAINER="autofyn-web"
MCP_CONTAINER="autofyn-mcp"

_GREEN='\033[0;32m'
_CYAN='\033[0;36m'
_RESET='\033[0m'

info() { echo -e "${_CYAN}[INFO]${_RESET} $*"; }
ok()   { echo -e "${_GREEN}[OK]${_RESET} $*"; }

PURGE=false
for arg in "$@"; do
    [[ "${arg}" == "--purge" ]] && PURGE=true
done

# ---------------------------------------------------------------------------
# Remove containers (idempotent — ignore errors if not found)
# ---------------------------------------------------------------------------
info "Removing containers: ${WEB_CONTAINER}, ${MCP_CONTAINER}…"
docker rm -f "${WEB_CONTAINER}" "${MCP_CONTAINER}" 2>/dev/null || true
ok "Containers removed (or did not exist)."

# ---------------------------------------------------------------------------
# Kill mock server via PID file
# ---------------------------------------------------------------------------
if [[ -f "${AUDIT_STATE_DIR}/mock.pid" ]]; then
    MOCK_PID="$(cat "${AUDIT_STATE_DIR}/mock.pid")"
    if kill -0 "${MOCK_PID}" 2>/dev/null; then
        info "Killing mock server (PID ${MOCK_PID})…"
        kill "${MOCK_PID}" 2>/dev/null || true
        sleep 1
    else
        info "Mock server (PID ${MOCK_PID}) was not running."
    fi
    rm -f "${AUDIT_STATE_DIR}/mock.pid"
else
    # Fallback: kill any process listening on port 9099
    PIDS="$(lsof -ti tcp:9099 2>/dev/null || true)"
    if [[ -n "${PIDS}" ]]; then
        info "Killing processes on port 9099: ${PIDS}"
        echo "${PIDS}" | xargs kill 2>/dev/null || true
    fi
fi
ok "Mock server stopped."

# ---------------------------------------------------------------------------
# Optional --purge: remove image and state directory
# ---------------------------------------------------------------------------
if [[ "${PURGE}" == "true" ]]; then
    info "Removing image: ${IMAGE_TAG}…"
    docker rmi "${IMAGE_TAG}" 2>/dev/null && ok "Image removed." || info "Image not found (already removed)."

    if [[ -d "${AUDIT_STATE_DIR}" ]]; then
        info "Removing ${AUDIT_STATE_DIR}…"
        rm -rf "${AUDIT_STATE_DIR}"
        ok "State directory removed."
    fi
fi

echo ""
ok "Teardown complete."
