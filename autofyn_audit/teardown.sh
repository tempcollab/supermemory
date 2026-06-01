#!/usr/bin/env bash
# teardown.sh — Stop and remove audit containers + network. Idempotent.
#
# Usage:
#   bash autofyn_audit/teardown.sh            # stop containers + remove network
#   bash autofyn_audit/teardown.sh --purge    # also remove image + .audit_state/
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_STATE_DIR="${SCRIPT_DIR}/.audit_state"
IMAGE_TAG="autofyn-audit:pinned"
AUDIT_NET="autofyn-audit-net"
WEB_CONTAINER="autofyn-web"
MCP_CONTAINER="autofyn-mcp"
MOCK_CONTAINER="audit-mock"

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
info "Removing containers: ${WEB_CONTAINER}, ${MCP_CONTAINER}, ${MOCK_CONTAINER}…"
docker rm -f "${WEB_CONTAINER}" "${MCP_CONTAINER}" "${MOCK_CONTAINER}" 2>/dev/null || true
ok "Containers removed (or did not exist)."

# Clean up the stale mock.pid file if present (it held the in-container PID,
# which is meaningless on the driver; the container removal above already stopped
# the mock process).
rm -f "${AUDIT_STATE_DIR}/mock.pid" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Remove the shared docker network (idempotent)
# docker rm -f above detaches the containers first; if other containers somehow
# remain attached, network rm no-ops with || true.
# ---------------------------------------------------------------------------
info "Removing network '${AUDIT_NET}'…"
docker network rm "${AUDIT_NET}" 2>/dev/null || true
ok "Network '${AUDIT_NET}' removed (or did not exist)."

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
