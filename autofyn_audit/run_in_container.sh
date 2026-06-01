#!/usr/bin/env bash
# run_in_container.sh — Inner exploit runner; executes INSIDE the runner container.
#
# This script is NOT invoked directly by the user. It is launched by run_exploits.sh
# via:
#   docker run --rm --network autofyn-audit-net \
#       -v <host-autofyn_audit>:/audit -w /audit \
#       -e WEB_BASE=... -e MCP_BASE=... -e MOCK_BASE=... \
#       autofyn-audit:pinned bash /audit/run_in_container.sh
#
# Inside the container /audit maps to the host autofyn_audit/ directory, so
# .audit_state/*.proof and *.log land on the driver filesystem.
#
# This script does NOT call docker (it is already inside the runner container).
# It is pure bash + curl + node.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

EXPLOITS_DIR="${SCRIPT_DIR}/exploits"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_BOLD='\033[1m'
_RESET='\033[0m'
_GREEN='\033[0;32m'
_RED='\033[0;31m'
_YELLOW='\033[1;33m'

# Severity lookup by exploit filename pattern
severity_for() {
    local name="$1"
    case "${name}" in
        *exploit_01*) echo "MEDIUM"  ;;
        *exploit_02*) echo "REFUTED" ;;
        *exploit_03*) echo "REFUTED" ;;
        *exploit_04*) echo "MEDIUM"  ;;
        *exploit_05*) echo "INFO"    ;;
        *)            echo "UNKNOWN" ;;
    esac
}

title_for() {
    local name="$1"
    case "${name}" in
        *exploit_01*) echo "C1 — SSRF in /api/og" ;;
        *exploit_02*) echo "C2 — REFUTED: /api/onboarding/research is auth-gated" ;;
        *exploit_03*) echo "C3 — REFUTED: /api/onboarding/extract-content is auth-gated" ;;
        *exploit_04*) echo "C4 — MCP host-header OAuth metadata injection" ;;
        *exploit_05*) echo "C5 — Next.js middleware RSC/prefetch auth bypass" ;;
        *)            echo "$(basename "${name}" .sh)" ;;
    esac
}

# ---------------------------------------------------------------------------
# Collect exploit scripts in numeric order
# ---------------------------------------------------------------------------
EXPLOIT_SCRIPTS=()
while IFS= read -r -d '' f; do
    EXPLOIT_SCRIPTS+=("$f")
done < <(find "${EXPLOITS_DIR}" -name 'exploit_*.sh' -print0 | sort -z)

if [[ ${#EXPLOIT_SCRIPTS[@]} -eq 0 ]]; then
    echo -e "${_RED}[FATAL]${_RESET} No exploit_*.sh scripts found in ${EXPLOITS_DIR}" >&2
    exit 1
fi

mkdir -p "${AUDIT_STATE_DIR}"

# Result tracking: parallel arrays (bash 3 compatible)
RESULT_IDS=()
RESULT_TITLES=()
RESULT_SEVERITIES=()
RESULT_STATUSES=()

FAIL_COUNT=0

for script in "${EXPLOIT_SCRIPTS[@]}"; do
    SCRIPT_NAME="$(basename "${script}")"
    LOG_FILE="${AUDIT_STATE_DIR}/${SCRIPT_NAME%.sh}.log"
    SEV="$(severity_for "${SCRIPT_NAME}")"
    TITLE="$(title_for "${SCRIPT_NAME}")"

    header "Running: ${SCRIPT_NAME}"
    info "Logging to: ${LOG_FILE}"
    echo ""

    EXIT_CODE=0
    bash "${script}" 2>&1 | tee "${LOG_FILE}" || EXIT_CODE=$?

    RESULT_IDS+=("${SCRIPT_NAME%.sh}")
    RESULT_TITLES+=("${TITLE}")
    RESULT_SEVERITIES+=("${SEV}")

    if [[ ${EXIT_CODE} -eq 0 ]]; then
        RESULT_STATUSES+=("PASS")
        echo ""
        echo -e "${_GREEN}${_BOLD}>>> ${SCRIPT_NAME}: PASS${_RESET}"
    else
        RESULT_STATUSES+=("FAIL")
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo ""
        echo -e "${_RED}${_BOLD}>>> ${SCRIPT_NAME}: FAIL (exit ${EXIT_CODE})${_RESET}"
    fi
    echo ""
done

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
echo ""
echo -e "${_BOLD}${_YELLOW}================================================================${_RESET}"
echo -e "${_BOLD}${_YELLOW}  EXPLOIT RUN SUMMARY${_RESET}"
echo -e "${_BOLD}${_YELLOW}================================================================${_RESET}"
printf "${_BOLD}%-30s  %-10s  %-8s  %-6s${_RESET}\n" "ID" "TITLE_ABBREV" "SEVERITY" "RESULT"
echo "----------------------------------------------------------------------"

for i in "${!RESULT_IDS[@]}"; do
    ID="${RESULT_IDS[$i]}"
    TITLE_ABBREV="${RESULT_TITLES[$i]}"
    SEV="${RESULT_SEVERITIES[$i]}"
    STATUS="${RESULT_STATUSES[$i]}"

    if [[ "${STATUS}" == "PASS" ]]; then
        STATUS_FMT="${_GREEN}${STATUS}${_RESET}"
    else
        STATUS_FMT="${_RED}${STATUS}${_RESET}"
    fi

    printf "%-30s  %-45s  %-8s  " "${ID}" "${TITLE_ABBREV}" "${SEV}"
    echo -e "${STATUS_FMT}"
done

echo "----------------------------------------------------------------------"
echo ""
TOTAL=${#RESULT_IDS[@]}
PASS_COUNT=$((TOTAL - FAIL_COUNT))
echo -e "  Total: ${TOTAL}   ${_GREEN}PASS: ${PASS_COUNT}${_RESET}   ${_RED}FAIL: ${FAIL_COUNT}${_RESET}"
echo ""
echo -e "  Proof files in: ${AUDIT_STATE_DIR}/"
echo -e "  Log files in:   ${AUDIT_STATE_DIR}/"
echo ""
echo -e "${_BOLD}${_YELLOW}================================================================${_RESET}"

exit "${FAIL_COUNT}"
