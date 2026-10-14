#!/usr/bin/env bash
# =============================================================================
#  AWS Cloud Security Auditor — Quick-Start Shell Launcher
#  v5.0.0 | read-only | Linux / macOS
# =============================================================================
#
#  Usage:
#    chmod +x run_audit.sh
#    ./run_audit.sh
#
#  What this script does (in order):
#    1. Verifies Python 3.11+ is available
#    2. Creates (or reuses) a .venv virtual environment in this directory
#    3. Installs / updates dependencies from requirements.txt
#    4. Asks for the AWS region and (optionally) a named CLI profile
#    5. Runs the audit via  python main.py
#    6. Opens the finished HTML report in the default browser
#
#  No audit logic lives here — this is only a convenience launcher.
#  The actual checks run inside the  auditor/  package.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers (disabled automatically if stdout is not a terminal)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}${BOLD}║      ☁  AWS Cloud Security Auditor  v5.0.0      ║${RESET}"
    echo -e "${CYAN}${BOLD}║            read-only  |  safe to run             ║${RESET}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
    echo ""
}

info()    { echo -e "${GREEN}[✔]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✘]${RESET} $*" >&2; }
section() { echo -e "\n${BOLD}$*${RESET}"; }

# ---------------------------------------------------------------------------
# Step 1 — Find Python 3.11+
# ---------------------------------------------------------------------------
find_python() {
    for cmd in python3 python python3.12 python3.11 python3.10 python3.9 python3.8; do
        if command -v "$cmd" &>/dev/null; then
            ver=$("$cmd" -c 'import sys; print(sys.version_info[:2])' 2>/dev/null || true)
            major=$("$cmd" -c 'import sys; print(sys.version_info[0])' 2>/dev/null || echo 0)
            minor=$("$cmd" -c 'import sys; print(sys.version_info[1])' 2>/dev/null || echo 0)
            if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
                echo "$cmd"
                return 0
            fi
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Step 2 — Open HTML report after the audit finishes
# ---------------------------------------------------------------------------
open_report() {
    local path="$1"
    if [ ! -f "$path" ]; then
        warn "Report file not found: $path"
        return
    fi

    info "Opening report in your default browser…"
    # macOS
    if command -v open &>/dev/null; then
        open "$path" 2>/dev/null || true
    # Linux with xdg-open (most desktops: GNOME, KDE, XFCE …)
    elif command -v xdg-open &>/dev/null; then
        xdg-open "$path" 2>/dev/null || true
    # Windows/WSL fallback
    elif command -v wslview &>/dev/null; then
        wslview "$path" 2>/dev/null || true
    else
        warn "Could not detect a browser opener."
        echo "      Open this file manually:"
        echo "      $path"
    fi
}

# ---------------------------------------------------------------------------
# Resolve the directory that contains this script (handles symlinks)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
banner

# ── Python check ────────────────────────────────────────────────────────────
section "Step 1/4  Checking Python version"
PYTHON=$(find_python || true)
if [ -z "$PYTHON" ]; then
    error "Python 3.11+ or later is required but was not found."
    echo ""
    echo "  macOS:   brew install python   OR   download from https://python.org"
    echo "  Ubuntu:  sudo apt-get install python3 python3-venv"
    echo "  Fedora:  sudo dnf install python3"
    echo ""
    exit 1
fi
info "Using $("$PYTHON" --version)"

# ── Virtual environment ──────────────────────────────────────────────────────
section "Step 2/4  Setting up virtual environment"
VENV_DIR="$SCRIPT_DIR/.venv"
if [ -d "$VENV_DIR" ]; then
    info "Reusing existing virtual environment (.venv/)"
else
    info "Creating virtual environment (.venv/)…"
    "$PYTHON" -m venv "$VENV_DIR"
fi

# Activate
if [ -f "$VENV_DIR/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
elif [ -f "$VENV_DIR/Scripts/activate" ]; then          # Git-Bash / MSYS on Windows
    # shellcheck disable=SC1091
    source "$VENV_DIR/Scripts/activate"
else
    error "Could not activate the virtual environment."
    exit 1
fi
PYTHON="python"   # from here on, use the venv's python

# ── Dependencies ─────────────────────────────────────────────────────────────
section "Step 3/4  Installing dependencies"
if [ -f "requirements.txt" ]; then
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    info "Dependencies ready."
else
    error "requirements.txt not found. Are you running this from the project folder?"
    exit 1
fi

# ── Configuration ────────────────────────────────────────────────────────────
section "Step 4/4  Audit configuration"
echo ""

# Region
echo -e "${BOLD}Common AWS regions:${RESET}"
echo "  eu-central-1   eu-west-1      eu-west-2      eu-west-3"
echo "  us-east-1      us-east-2      us-west-1      us-west-2"
echo "  ap-southeast-1 ap-northeast-1 ap-south-1     ca-central-1"
echo ""
read -rp "$(echo -e "${BOLD}AWS Region${RESET} (e.g. eu-central-1): ")" REGION
REGION="${REGION// /}"    # strip spaces
if [ -z "$REGION" ]; then
    error "Region cannot be empty."
    exit 1
fi

# Profile (optional)
echo ""
read -rp "$(echo -e "${BOLD}AWS Profile${RESET} (press Enter to use 'default'): ")" PROFILE
PROFILE="${PROFILE// /}"

# Output directory
DEFAULT_OUTPUT="$HOME/aws_audit_reports"
echo ""
read -rp "$(echo -e "${BOLD}Output folder${RESET} [${DEFAULT_OUTPUT}]: ")" OUTPUT_DIR
OUTPUT_DIR="${OUTPUT_DIR:-$DEFAULT_OUTPUT}"

echo ""
echo -e "${CYAN}────────────────────────────────────────────────────${RESET}"
echo -e "  Region  : ${BOLD}${REGION}${RESET}"
echo -e "  Profile : ${BOLD}${PROFILE:-default}${RESET}"
echo -e "  Output  : ${BOLD}${OUTPUT_DIR}${RESET}"
echo -e "${CYAN}────────────────────────────────────────────────────${RESET}"
echo ""
warn "Read-only tool. No changes will be made to your AWS account."
echo ""

# ── Run audit ────────────────────────────────────────────────────────────────
ARGS=("--region" "$REGION" "--output-dir" "$OUTPUT_DIR")
if [ -n "$PROFILE" ] && [ "$PROFILE" != "default" ]; then
    ARGS+=("--profile" "$PROFILE")
fi

echo -e "${BOLD}Running audit…${RESET}"
echo ""

# Capture the path of the HTML report from stdout
# main.py prints:  HTML report written → /path/to/report.html
HTML_REPORT=""

set +e    # allow non-zero exit so we can show a friendly message
OUTPUT=$("$PYTHON" main.py "${ARGS[@]}" 2>&1)
EXIT_CODE=$?
set -e

echo "$OUTPUT"

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    error "Audit did not complete successfully (exit code $EXIT_CODE)."
    echo ""
    # Translate the most common errors into plain English
    if echo "$OUTPUT" | grep -q "NoCredentialsError"; then
        echo "  AWS credentials not found."
        echo "  Run:  aws configure  — and enter your Access Key ID and Secret Access Key."
    elif echo "$OUTPUT" | grep -q "ProfileNotFound"; then
        echo "  AWS profile '${PROFILE}' was not found."
        echo "  Check the profile name or press Enter next time to use the default profile."
    elif echo "$OUTPUT" | grep -q "AccessDenied"; then
        echo "  AWS denied access to one or more API calls."
        echo "  Make sure the IAM user has the AWSSecurityAuditorReadOnly policy attached."
        echo "  See:  docs/required-iam-policy.json"
    elif echo "$OUTPUT" | grep -q "InvalidClientTokenId"; then
        echo "  The AWS Access Key ID is not valid."
        echo "  Reconfigure your AWS CLI profile:  aws configure"
    elif echo "$OUTPUT" | grep -q "SignatureDoesNotMatch"; then
        echo "  The AWS Secret Access Key is incorrect."
        echo "  Reconfigure your AWS CLI profile:  aws configure"
    elif echo "$OUTPUT" | grep -q "EndpointResolutionError\|Could not connect"; then
        echo "  Could not reach AWS. Check your internet connection."
    else
        echo "  Review the output above for details."
    fi
    echo ""
    exit $EXIT_CODE
fi

# ── Open report ──────────────────────────────────────────────────────────────
# Extract the HTML report path written by main.py
HTML_REPORT=$(echo "$OUTPUT" | grep -Eo '[^ ]+\.html' | tail -1 || true)

echo ""
info "Audit finished successfully."

if [ -n "$HTML_REPORT" ] && [ -f "$HTML_REPORT" ]; then
    open_report "$HTML_REPORT"
else
    # Fallback: look for most-recently modified report in the output dir
    LATEST=$(find "$OUTPUT_DIR" -name "*.html" -newer "$SCRIPT_DIR/requirements.txt" \
             -print 2>/dev/null | sort -t_ -k5 | tail -1 || true)
    if [ -n "$LATEST" ]; then
        open_report "$LATEST"
    else
        info "Report saved to: $OUTPUT_DIR"
    fi
fi

echo ""
