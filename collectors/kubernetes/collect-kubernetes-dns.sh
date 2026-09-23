#!/usr/bin/env bash
# Inventorie les noms publiés par les objets Kubernetes Ingress et les envoie
# vers Parralax-DNS via le collecteur DNS personnalisé.
#
# Prérequis : bash 3+, kubectl, jq et curl. Le compte Kubernetes utilisé ne
# requiert que la permission `list` sur networking.k8s.io/ingresses.

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="${0##*/}"
readonly KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
readonly JQ_BIN="${JQ_BIN:-jq}"
readonly CURL_BIN="${CURL_BIN:-curl}"

DRY_RUN=false
TEMP_DIR=""

log() {
    printf '%s: %s\n' "$SCRIPT_NAME" "$*" >&2
}

die() {
    log "ERREUR: $*"
    exit 1
}

cleanup() {
    [[ -z "$TEMP_DIR" || ! -d "$TEMP_DIR" ]] || rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage: collect-kubernetes-dns.sh [--dry-run]

Lit les objets networking.k8s.io/v1 Ingress de tous les espaces de noms. Pour
chaque hôte de règle, le collecteur publie les adresses observées dans le statut
du load balancer (A, AAAA ou CNAME), ainsi que la cible ExternalDNS éventuelle.
Il n'interroge pas CoreDNS et ne modifie jamais le cluster.

Variables requises (sauf avec --dry-run) :
  PARRALAX_API_URL       URL complète de /api/collectors/custom-dns/sync
  PARRALAX_SOURCE        Identifiant du cluster configuré dans Parralax-DNS
  PARRALAX_SOURCE_TOKEN  Jeton associé à cette source

Variables optionnelles :
  KUBECTL_BIN                         Chemin de kubectl (défaut : kubectl)
  KUBECTL_CACHE_DIR                   Cache de découverte kubectl (défaut : /tmp/kubectl-cache)
  JQ_BIN                              Chemin de jq (défaut : jq)
  CURL_BIN                            Chemin de curl (défaut : curl)
  PARRALAX_ALLOW_EMPTY_INVENTORY=true Autorise un push vide qui archive les
                                       hôtes précédemment remontés par la source.

--dry-run écrit le JSON construit sur stdout sans joindre Parralax-DNS.
EOF
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Commande introuvable: $1"
}

parse_arguments() {
    while (($#)); do
        case "$1" in
            --dry-run) DRY_RUN=true ;;
            -h|--help) usage; exit 0 ;;
            *) die "Option inconnue: $1 (utilisez --help)" ;;
        esac
        shift
    done
}

collect_zones() {
    local ingress_file="$1"
    "$JQ_BIN" '
        [
          .items[] as $ingress
          | ($ingress.metadata.namespace // "default") as $namespace
          | ($ingress.metadata.name // "unknown") as $resource_name
          | ($ingress.status.loadBalancer.ingress // []) as $load_balancers
          | ($ingress.metadata.annotations["external-dns.alpha.kubernetes.io/target"] // "") as $external_dns_target
          | $ingress.spec.rules[]?
          | select(.host? and (.host | length > 0))
          | (.host | ascii_downcase | rtrimstr(".")) as $host
          | {
              name: $host,
              external_id: $host,
              remote_status: (if (($load_balancers | length) > 0 or $external_dns_target != "") then "published" else "pending" end),
              zone_type: "kubernetes-ingress",
              records: (
                [
                  $load_balancers[]?
                  | if .ip? and (.ip | length > 0) then
                      {name: "@", type: (if (.ip | contains(":")) then "AAAA" else "A" end), value: .ip}
                    elif .hostname? and (.hostname | length > 0) then
                      {name: "@", type: "CNAME", value: .hostname}
                    else empty end,
                  ($external_dns_target | split(",")[] | gsub("^[[:space:]]+|[[:space:]]+$"; "") | select(length > 0) | {name: "@", type: "CNAME", value: .})
                ] | unique
              ),
              _ingress: ($namespace + "/" + $resource_name)
            }
        ]
        | group_by(.external_id)
        | map({
            name: .[0].name,
            external_id: .[0].external_id,
            remote_status: (if any(.[]; .remote_status == "published") then "published" else "pending" end),
            zone_type: "kubernetes-ingress",
            records: (map(.records[]) | unique)
          })
    ' "$ingress_file"
}

main() {
    parse_arguments "$@"
    require_command "$KUBECTL_BIN"
    require_command "$JQ_BIN"
    if [[ "$DRY_RUN" == false ]]; then
        require_command "$CURL_BIN"
        [[ -n "${PARRALAX_API_URL:-}" ]] || die "PARRALAX_API_URL est requis."
        [[ -n "${PARRALAX_SOURCE:-}" ]] || die "PARRALAX_SOURCE est requis."
        [[ -n "${PARRALAX_SOURCE_TOKEN:-}" ]] || die "PARRALAX_SOURCE_TOKEN est requis."
    fi

    TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/parralax-kubernetes-collector.XXXXXX")"
    chmod 700 "$TEMP_DIR"
    local ingress_file="$TEMP_DIR/ingresses.json"
    local zones_file="$TEMP_DIR/zones.json"
    local payload="$TEMP_DIR/payload.json"

    log "Lecture des Ingress dans tous les espaces de noms..."
    "$KUBECTL_BIN" --cache-dir "${KUBECTL_CACHE_DIR:-/tmp/kubectl-cache}" \
        get ingress --all-namespaces --output json >"$ingress_file"
    collect_zones "$ingress_file" >"$zones_file"

    local count
    count="$($JQ_BIN 'length' "$zones_file")"
    if [[ "$count" == 0 && "${PARRALAX_ALLOW_EMPTY_INVENTORY:-false}" != "true" ]]; then
        die "Aucun hôte Ingress trouvé ; push annulé pour ne pas archiver l'inventaire existant. Définissez PARRALAX_ALLOW_EMPTY_INVENTORY=true uniquement pour confirmer un inventaire vide."
    fi
    log "${count} hôte(s) Ingress collecté(s)."

    "$JQ_BIN" --arg source "${PARRALAX_SOURCE:-kubernetes-dry-run}" '{source: $source, zones: .}' "$zones_file" >"$payload"
    if [[ "$DRY_RUN" == true ]]; then
        cat "$payload"
        return
    fi

    log "Publication vers Parralax-DNS..."
    "$CURL_BIN" --fail-with-body --silent --show-error \
        --request POST "$PARRALAX_API_URL" \
        --header 'Content-Type: application/json' \
        --header "X-Parralax-Source-Token: $PARRALAX_SOURCE_TOKEN" \
        --data-binary "@$payload"
    printf '\n'
    log "Synchronisation terminée."
}

main "$@"
