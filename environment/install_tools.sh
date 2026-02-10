#!/usr/bin/env bash
#
# Dev tools installer - modular script for installing development tools on Linux
# Supports: docker, k3s, helm, jq (more tools can be added)
# Usage: sudo ./install-docker.sh [tool1] [tool2] ... | --all | --list
#        ./install-docker.sh (no args = interactive menu)
#
set -e

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

AVAILABLE_TOOLS=(docker k3s helm jq python nodejs claude-code)

# Python 3.12 from source: install prefix
PYTHON_PREFIX="/opt/python"
PYTHON_VERSION="3.12.12"
PYTHON_LINK_DIR="/usr/local/bin"  # symlinks here so python/pip are on PATH

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

install_k3s() {
    echo ""
    echo "==> Installing NVIDIA Container Toolkit..."
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
    local arch
    arch=$(dpkg --print-architecture)
    curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
        sed "s#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g; s#\$(ARCH)#${arch}#g" | \
        tee /etc/apt/sources.list.d/nvidia-container-toolkit.list > /dev/null
    apt-get update
    apt-get install -y nvidia-container-toolkit

    echo "==> Installing k3s..."
    curl -sfL https://get.k3s.io | sh -
    systemctl restart k3s 2>/dev/null || systemctl restart k3s-agent 2>/dev/null || true

    echo "==> Installing NVIDIA device plugin..."
    local i=0
    while ! k3s kubectl get nodes &>/dev/null && [[ $i -lt 30 ]]; do
        sleep 2
        ((i++))
    done
    if k3s kubectl get nodes &>/dev/null; then
        k3s kubectl apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.14.0/nvidia-device-plugin.yml
        k3s kubectl patch daemonset nvidia-device-plugin-daemonset -n kube-system -p '{"spec":{"template":{"spec":{"runtimeClassName":"nvidia"}}}}' 2>/dev/null || true
    fi

    echo ""
    echo "k3s installed. Kubeconfig: /etc/rancher/k3s/k3s.yaml"
    echo "Verify GPU: kubectl get nodes -o yaml | grep nvidia.com/gpu"
}

install_helm() {
    echo ""
    echo "==> Installing Helm..."
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    echo "Helm installed: $(helm version --short)"
}

install_jq() {
    echo ""
    echo "==> Installing jq..."
    apt-get install -y jq
    echo "jq installed: $(jq --version)"
}

install_nodejs() {
    echo ""
    echo "==> Installing Node.js and npm (NodeSource 20.x LTS)..."
    local nodesetup="/tmp/nodesource_setup.sh"
    curl -fsSL https://deb.nodesource.com/setup_20.x -o "$nodesetup"
    bash "$nodesetup"
    rm -f "$nodesetup"
    apt-get install -y nodejs
    echo ""
    echo "Node.js installed: $(node --version)"
    echo "npm installed: $(npm --version)"
}

install_claude_code() {
    echo ""
    echo "==> Installing Claude Code globally via npm..."
    if ! command -v npm &>/dev/null; then
        echo "Node.js/npm required. Install with: $0 nodejs" >&2
        return 1
    fi
    npm install -g @anthropic-ai/claude-code
    echo ""
    echo "Claude Code installed (global npm). Run 'claude' from a project directory."
}

install_python() {
    echo ""
    echo "==> Installing Python ${PYTHON_VERSION} from source into ${PYTHON_PREFIX}..."
    apt-get install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev \
        libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev \
        wget xz-utils libbz2-dev libgdbm-compat-dev liblzma-dev

    local tarball="Python-${PYTHON_VERSION}.tar.xz"
    local url="https://www.python.org/ftp/python/${PYTHON_VERSION}/${tarball}"
    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf ${tmpdir}" RETURN

    echo "==> Downloading ${url}..."
    curl -fsSL -o "${tmpdir}/${tarball}" "$url"
    echo "==> Extracting..."
    tar -xJf "${tmpdir}/${tarball}" -C "${tmpdir}"
    local srcdir="${tmpdir}/Python-${PYTHON_VERSION}"

    (
        cd "${srcdir}"
        echo "==> Configuring (prefix=${PYTHON_PREFIX})..."
        ./configure --prefix="${PYTHON_PREFIX}" --enable-optimizations
        echo "==> Building (this may take several minutes)..."
        make -j"$(nproc)"
        echo "==> Installing..."
        make altinstall
    )

    echo "==> Adding symlinks to ${PYTHON_LINK_DIR} (on PATH)..."
    ln -sf "${PYTHON_PREFIX}/bin/python3.12" "${PYTHON_LINK_DIR}/python"
    ln -sf "${PYTHON_PREFIX}/bin/pip3.12" "${PYTHON_LINK_DIR}/pip"

    echo ""
    echo "Python ${PYTHON_VERSION} installed to ${PYTHON_PREFIX}"
    echo "  Symlinks: ${PYTHON_LINK_DIR}/python, ${PYTHON_LINK_DIR}/pip"
    python --version
}

# Placeholder for future tools - add install_<toolname> and add to AVAILABLE_TOOLS
# install_kubectl() { ... }
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
        k3s) install_k3s ;;
        helm) install_helm ;;
        jq) install_jq ;;
        nodejs) install_nodejs ;;
        claude-code) install_claude_code ;;
        python) install_python ;;
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
