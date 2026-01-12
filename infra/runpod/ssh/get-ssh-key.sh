#!/usr/bin/env bash
#
# RunPod B200 SSH Key Retrieval via 1Password
# Retrieves SSH private key from 1Password and configures local SSH
#
# Prerequisites:
#   - 1Password CLI (op) installed and authenticated
#   - Account signed in: eval $(op signin)
#
# Usage:
#   ./get-ssh-key.sh [--refresh]
#
set -euo pipefail

# Configuration
readonly SSH_KEY_PATH="${HOME}/.ssh/runpod-b200"
readonly SSH_CONFIG_DIR="${HOME}/.ssh"
readonly OP_VAULT="Private"
readonly OP_ITEM="RunPod-B200-SSH"
readonly OP_FIELD="private_key"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Check 1Password CLI
check_op_cli() {
    if ! command -v op &> /dev/null; then
        log_error "1Password CLI (op) not found. Install from: https://1password.com/downloads/command-line/"
        exit 1
    fi

    # Check if signed in
    if ! op account list &> /dev/null; then
        log_warn "Not signed in to 1Password. Attempting sign-in..."
        eval "$(op signin)"
    fi
}

# Retrieve SSH key from 1Password
retrieve_ssh_key() {
    log_info "Retrieving SSH key from 1Password..."

    local private_key
    private_key=$(op read "op://${OP_VAULT}/${OP_ITEM}/${OP_FIELD}" 2>/dev/null) || {
        log_error "Failed to retrieve SSH key from 1Password"
        log_error "Ensure item '${OP_ITEM}' exists in vault '${OP_VAULT}' with field '${OP_FIELD}'"
        exit 1
    }

    echo "${private_key}"
}

# Setup SSH key locally
setup_ssh_key() {
    local private_key="$1"
    local refresh="${2:-false}"

    # Create .ssh directory if needed
    mkdir -p "${SSH_CONFIG_DIR}"
    chmod 700 "${SSH_CONFIG_DIR}"

    # Check if key already exists
    if [[ -f "${SSH_KEY_PATH}" && "${refresh}" != "true" ]]; then
        log_warn "SSH key already exists at ${SSH_KEY_PATH}"
        read -rp "Overwrite? [y/N]: " confirm
        if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
            log_info "Skipping key write"
            return 0
        fi
    fi

    # Write private key with secure permissions
    echo "${private_key}" > "${SSH_KEY_PATH}"
    chmod 600 "${SSH_KEY_PATH}"

    log_info "SSH key written to ${SSH_KEY_PATH}"
}

# Append SSH config include if needed
setup_ssh_config() {
    local config_file="${SSH_CONFIG_DIR}/config"
    local include_line="Include $(dirname "$0")/config"

    if [[ -f "${config_file}" ]]; then
        if grep -q "runpod" "${config_file}" 2>/dev/null; then
            log_info "RunPod SSH config already referenced"
            return 0
        fi
    fi

    log_info "Adding RunPod config to ${config_file}"
    echo -e "\n# RunPod B200 Configuration\n${include_line}" >> "${config_file}"
}

# Test SSH connection
test_connection() {
    log_info "Testing SSH connection to RunPod..."

    if ssh -o ConnectTimeout=10 -o BatchMode=yes runpod-b200 "nvidia-smi --query-gpu=name,memory.total --format=csv,noheader" 2>/dev/null; then
        log_info "Connection successful! B200 GPUs detected."
    else
        log_warn "Connection test failed - pod may not be running"
        log_info "Start your RunPod pod and try: ssh runpod-b200"
    fi
}

# Main
main() {
    local refresh="false"

    if [[ "${1:-}" == "--refresh" ]]; then
        refresh="true"
    fi

    log_info "RunPod B200 SSH Setup via 1Password"
    echo "========================================="

    check_op_cli

    local private_key
    private_key=$(retrieve_ssh_key)

    setup_ssh_key "${private_key}" "${refresh}"
    setup_ssh_config

    echo ""
    test_connection

    echo ""
    log_info "Setup complete! Connect with: ssh runpod-b200"
}

main "$@"
