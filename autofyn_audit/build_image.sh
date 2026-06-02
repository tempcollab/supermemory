#!/usr/bin/env bash
# build_image.sh — Build the audit Docker image ONCE and pin it locally.
#
# This script is idempotent: if the image tagged autofyn-audit:pinned already
# exists AND carries the correct org.opencontainers.image.revision label, it
# exits immediately without rebuilding.
#
# Usage:
#   bash autofyn_audit/build_image.sh            # build only if not yet built
#   bash autofyn_audit/build_image.sh --force    # force full --no-cache rebuild
#
# After the first successful build, setup.sh will reuse the image without
# rebuilding.  You only need to re-run this script if:
#   - The pinned commit changes (new audit target).
#   - The base image changes.
#   - You want to confirm a clean build (--force).
#
set -euo pipefail

# Prefer BuildKit when buildx is available so the Dockerfile-adjacent ignore
# file (autofyn_audit/Dockerfile.dockerignore) is honored. If buildx is missing
# (some minimal daemons), fall back to the legacy builder: the build still
# succeeds, the image just also contains the audit folder, which is harmless.
if docker buildx version >/dev/null 2>&1; then
    export DOCKER_BUILDKIT=1
else
    export DOCKER_BUILDKIT=0
fi

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINNED_COMMIT="268499068810586495ba5bd4773f8c5786d9fc97"
PINNED_IMAGE="oven/bun:1.3.6@sha256:f20d9cf365ab35529384f1717687c739c92e6f39157a35a95ef06f4049a10e4a"
IMAGE_TAG="autofyn-audit:pinned"
COMMIT12="${PINNED_COMMIT:0:12}"
IMAGE_TAG_SHORT="autofyn-audit:${COMMIT12}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

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
# Arg parsing
# ---------------------------------------------------------------------------
FORCE=0
for arg in "$@"; do
    [[ "${arg}" == "--force" ]] && FORCE=1
done

# ---------------------------------------------------------------------------
# Idempotency check
# ---------------------------------------------------------------------------
if [[ "${FORCE}" -eq 0 ]] && docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
    EXISTING_REVISION="$(docker image inspect \
        --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
        "${IMAGE_TAG}" 2>/dev/null || true)"
    if [[ "${EXISTING_REVISION}" == "${PINNED_COMMIT}" ]]; then
        ok "Image already built and revision label matches ${PINNED_COMMIT} — skipping."
        info "Image tag   : ${IMAGE_TAG}"
        info "Image id    : $(docker image inspect --format '{{.Id}}' "${IMAGE_TAG}")"
        exit 0
    else
        warn "Image ${IMAGE_TAG} exists but revision label '${EXISTING_REVISION}' != '${PINNED_COMMIT}'."
        warn "Rebuilding to ensure correctness."
    fi
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
NO_CACHE_FLAG=""
[[ "${FORCE}" -eq 1 ]] && NO_CACHE_FLAG="--no-cache" && info "Force flag set — rebuilding with --no-cache."

info "Building audit image: ${IMAGE_TAG}"
info "  also tagging as  : ${IMAGE_TAG_SHORT}"
info "  base image        : ${PINNED_IMAGE}"
info "  build context     : ${REPO_ROOT}"
info "  Dockerfile        : ${SCRIPT_DIR}/Dockerfile"
info "Expected build time: 3-6 minutes on a cold cache (bun install + Node.js from NodeSource)"

# shellcheck disable=SC2086
docker build \
    ${NO_CACHE_FLAG} \
    --build-arg "EXPECTED_COMMIT=${PINNED_COMMIT}" \
    -t "${IMAGE_TAG}" \
    -t "${IMAGE_TAG_SHORT}" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    "${REPO_ROOT}"

IMAGE_ID="$(docker image inspect --format '{{.Id}}' "${IMAGE_TAG}")"

ok "Image built successfully."
echo ""
echo "  Image tag (pinned) : ${IMAGE_TAG}"
echo "  Image tag (commit) : ${IMAGE_TAG_SHORT}"
echo "  Image id           : ${IMAGE_ID}"
echo ""
info "IMPORTANT: the image id above should match the digest pinned in audit_report.md and run_state.md."
info "Expected : sha256:626536cd69310217a6ac5518696a8b99cd063b103e55cc7ad2616dbbeee49b5d"
if [[ "${IMAGE_ID}" != "sha256:626536cd69310217a6ac5518696a8b99cd063b103e55cc7ad2616dbbeee49b5d" ]]; then
    warn "Image id does NOT match the pinned digest. This may mean the image was rebuilt"
    warn "from a different context or base. If intentional, update the pinned digest in"
    warn "run_state.md and audit_report.md."
fi
