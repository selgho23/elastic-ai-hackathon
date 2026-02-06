#!/usr/bin/env bash
#
# Dev tools installer - modular script for installing development tools on Linux
# Supports: docker (more tools can be added)
# Usage: sudo ./install-docker.sh [tool1] [tool2] ... | --all | --list
#        ./install-docker.sh (no args = interactive menu)
#
set -e

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

AVAILABLE_TOOLS=(docker)

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    # --list and --help don't need root
    case "${1:-}" in
        --list)
            echo "Available tools: ${AVAILABLE_TOOLS[*]}"
            exit 0
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
    esac

    require_root
    detect_distro

    local tools_to_install=()
    if [[ "${1:-}" == "--all" ]]; then
        tools_to_install=("${AVAILABLE_TOOLS[@]}")
    elif [[ $# -gt 0 ]]; then
        tools_to_install=("$@")
    else
        interactive_menu || exit 0
        if [[ "$INTERACTIVE_CHOICE" == "all" ]]; then
            tools_to_install=("${AVAILABLE_TOOLS[@]}")
        else
            tools_to_install=()
            for t in $INTERACTIVE_CHOICE; do tools_to_install+=("$t"); done
        fi
        [[ ${#tools_to_install[@]} -eq 0 ]] && { echo "No tools selected."; exit 0; }
    fi

    setup_prerequisites

    for tool in ${tools_to_install[*]}; do
        run_installer "$tool" || echo "Failed to install $tool" >&2
    done

    echo ""
    echo "Done."
}

# -----------------------------------------------------------------------------
# Prerequisites (runs once, shared by all tools)
# -----------------------------------------------------------------------------

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root (use sudo)" >&2
        exit 1
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            ubuntu) DOCKER_DISTRO="ubuntu" ;;
            debian) DOCKER_DISTRO="debian" ;;
            *) echo "Unsupported distro: $ID. Supports Ubuntu and Debian." >&2; exit 1 ;;
        esac
    else
        echo "Cannot detect distribution (no /etc/os-release)" >&2
        exit 1
    fi
}

setup_prerequisites() {
    echo "==> Updating package index..."
    apt-get update
    echo "==> Installing prerequisites..."
    apt-get install -y ca-certificates curl
}

# -----------------------------------------------------------------------------
# Tool installers (add new tools here)
# -----------------------------------------------------------------------------

install_docker() {
    echo ""
    echo "==> Installing Docker Engine..."
    echo "==> Detected: $ID ($VERSION_CODENAME)"

    # Remove conflicting packages (per Docker docs)
    echo "==> Removing conflicting packages (if any)..."
    apt-get remove -y docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc 2>/dev/null || true

    # Add Docker's official GPG key (DEB822 format, docker.asc)
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${DOCKER_DISTRO}/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    # Add repository using DEB822 format (docker.sources)
    local suite="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
    tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/${DOCKER_DISTRO}
Suites: ${suite}
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    systemctl start docker
    systemctl enable docker

    echo "Docker Engine installed: $(docker --version)"
}

# Placeholder for future tools - add install_<toolname> and add to AVAILABLE_TOOLS
# install_kubectl() { ... }
# install_helm() { ... }
# install_terraform() { ... }

interactive_menu() {
    echo "Available tools:"
    local i=1
    for tool in "${AVAILABLE_TOOLS[@]}"; do
        echo "  $i) $tool"
        ((i++))
    done
    echo "  a) Install all"
    echo "  q) Quit"
    echo ""
    read -r -p "Select tools to install (e.g. 1, 1 2, or a): " input

    INTERACTIVE_CHOICE=""
    [[ -z "$input" ]] && return 1

    local result=""
    for sel in $input; do
        case "$sel" in
            [qQ]) return 1 ;;
            [aA]) INTERACTIVE_CHOICE="all"; return 0 ;;
            [0-9]*)
                if (( sel >= 1 && sel <= ${#AVAILABLE_TOOLS[@]} )); then
                    result="${result} ${AVAILABLE_TOOLS[sel-1]}"
                fi
                ;;
        esac
    done
    INTERACTIVE_CHOICE=$result
    [[ -n "$result" ]]
}

show_usage() {
    echo "Usage: $0 [tool1] [tool2] ... | --all | --list"
    echo ""
    echo "Available tools: ${AVAILABLE_TOOLS[*]}"
    echo ""
    echo "  --all   Install all available tools"
    echo "  --list  List available tools and exit"
    echo ""
    echo "  No arguments: interactive menu to choose tools"
}

run_installer() {
    local tool="$1"
    case "$tool" in
        docker) install_docker ;;
        *)
            echo "Unknown tool: $tool" >&2
            return 1
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Script execution
# -----------------------------------------------------------------------------

main "$@"
