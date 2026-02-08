#!/usr/bin/env bash
# Elastic Stack orchestration script
# Usage: ./main.sh [op1] [op2] ... | --all | --list
#        ./main.sh (no args = interactive menu)

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

# Use K3s kubeconfig if KUBECONFIG is not already set (so kubectl/helm always target this cluster)
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ECK_OPERATOR_VALUES="${SCRIPT_DIR}/eck-operator.yaml"
ELASTICSEARCH_VALUES="${SCRIPT_DIR}/eck-elasticsearch.yaml"
KIBANA_VALUES="${SCRIPT_DIR}/eck-kibana.yaml"
# Must match eck-elasticsearch fullnameOverride (secret name is ${ELASTICSEARCH_CLUSTER_NAME}-es-elastic-user)
ELASTICSEARCH_CLUSTER_NAME="${ELASTICSEARCH_CLUSTER_NAME:-hackathon}"
# Kibana resource name (service is ${KIBANA_NAME}-kb-http); match eck-kibana fullnameOverride
KIBANA_NAME="${KIBANA_NAME:-hackathon}"

# Operations included in --all / "Run all" (teardown is excluded)
RUN_ALL_OPS=(namespace context helm-repo eck-operator elasticsearch kibana kibana-access)
AVAILABLE_OPERATIONS=("${RUN_ALL_OPS[@]}" teardown)

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
  case "${1:-}" in
    --list)
      echo "Available operations: ${AVAILABLE_OPERATIONS[*]}"
      exit 0
      ;;
    --help|-h)
      show_usage
      exit 0
      ;;
  esac

  local ops=()
  if [[ "${1:-}" == "--all" ]]; then
    ops=("${RUN_ALL_OPS[@]}")
  elif [[ $# -gt 0 ]]; then
    ops=("$@")
  else
    interactive_menu || exit 0
    if [[ "${INTERACTIVE_CHOICE:-}" == "all" ]]; then
      ops=("${RUN_ALL_OPS[@]}")
    else
      ops=()
      for o in ${INTERACTIVE_CHOICE:-}; do ops+=("$o"); done
    fi
    [[ ${#ops[@]} -eq 0 ]] && { echo "No operations selected."; exit 0; }
  fi

  for op in "${ops[@]}"; do
    run_operation "$op" || echo "Failed: $op" >&2
  done

  echo ""
  echo "Done."
}

# -----------------------------------------------------------------------------
# Namespace
# -----------------------------------------------------------------------------

create_namespace() {
  echo "Creating namespace: elastic"
  kubectl create namespace elastic --dry-run=client -o yaml | kubectl apply -f -
}

set_namespace_context() {
  echo "Setting current context namespace to: elastic"
  kubectl config set-context --current --namespace=elastic
}

# -----------------------------------------------------------------------------
# Helm
# -----------------------------------------------------------------------------

add_elastic_helm_repo() {
  echo "Adding Elastic Helm repo..."
  helm repo add elastic https://helm.elastic.co
  echo "Updating Helm repos..."
  helm repo update
}

install_eck_operator() {
  echo "Installing ECK operator (values: ${ECK_OPERATOR_VALUES})..."
  helm upgrade --install elastic-operator elastic/eck-operator -n elastic -f "${ECK_OPERATOR_VALUES}"
}

install_elasticsearch() {
  echo "Installing Elasticsearch (values: ${ELASTICSEARCH_VALUES})..."
  helm upgrade --install es-quickstart elastic/eck-stack -n elastic \
    -f "${ELASTICSEARCH_VALUES}" \
    --set eck-kibana.enabled=false
}

install_kibana() {
  echo "Installing Kibana (values: ${KIBANA_VALUES})..."
  helm upgrade --install kibana-quickstart elastic/eck-kibana -n elastic \
    -f "${KIBANA_VALUES}" \
    --set eck-elasticsearch.enabled=false
}

show_kibana_access() {
  local password
  password=$(kubectl get secret "${ELASTICSEARCH_CLUSTER_NAME}-es-elastic-user" -n elastic -o json | jq -r .data.elastic | base64 -d)
  local lb
  lb=$(kubectl get svc "${KIBANA_NAME}-kb-http" -n elastic -o json | jq -r '.status.loadBalancer.ingress[0].ip // .status.loadBalancer.ingress[0].hostname // empty')
  local url="https://${lb}:5601"
  echo ""
  echo "--- Kibana access (LoadBalancer) ---"
  echo "  URL:      ${url}"
  echo "  Username: elastic"
  echo "  Password: ${password}"
  echo ""
}

# -----------------------------------------------------------------------------
# Teardown (excluded from --all)
# -----------------------------------------------------------------------------

teardown() {
  echo "Uninstalling Helm releases and deleting namespace..."
  helm uninstall kibana-quickstart -n elastic 2>/dev/null || true
  helm uninstall es-quickstart -n elastic 2>/dev/null || true
  helm uninstall elastic-operator -n elastic 2>/dev/null || true
  kubectl delete namespace elastic --ignore-not-found --timeout=120s
  echo "Teardown complete."
}

# -----------------------------------------------------------------------------
# Menu, usage, dispatcher
# -----------------------------------------------------------------------------

interactive_menu() {
  echo "Available operations:"
  local i=1
  for op in "${AVAILABLE_OPERATIONS[@]}"; do
    echo "  $i) $op"
    ((i++))
  done
  echo "  a) Run all"
  echo "  q) Quit"
  echo ""
  read -r -p "Select operations (e.g. 1, 1 2, or a): " input

  INTERACTIVE_CHOICE=""
  [[ -z "${input:-}" ]] && return 1

  local result=""
  for sel in $input; do
    case "$sel" in
      [qQ]) return 1 ;;
      [aA]) INTERACTIVE_CHOICE="all"; return 0 ;;
      [0-9]*)
        if (( sel >= 1 && sel <= ${#AVAILABLE_OPERATIONS[@]} )); then
          result="${result} ${AVAILABLE_OPERATIONS[sel-1]}"
        fi
        ;;
    esac
  done
  INTERACTIVE_CHOICE=$result
  [[ -n "$result" ]]
}

show_usage() {
  echo "Usage: $0 [op1] [op2] ... | --all | --list"
  echo ""
  echo "Available operations: ${AVAILABLE_OPERATIONS[*]}"
  echo ""
  echo "  --all   Run all operations (excludes teardown)"
  echo "  --list  List available operations and exit"
  echo ""
  echo "  No arguments: interactive menu to choose operations"
}

run_operation() {
  local op="$1"
  case "$op" in
    namespace) create_namespace ;;
    context) set_namespace_context ;;
    helm-repo) add_elastic_helm_repo ;;
    eck-operator) install_eck_operator ;;
    elasticsearch) install_elasticsearch ;;
    kibana) install_kibana ;;
    kibana-access) show_kibana_access ;;
    teardown) teardown ;;
    *)
      echo "Unknown operation: $op" >&2
      return 1
      ;;
  esac
}

# -----------------------------------------------------------------------------
# Script execution
# -----------------------------------------------------------------------------

main "$@"
