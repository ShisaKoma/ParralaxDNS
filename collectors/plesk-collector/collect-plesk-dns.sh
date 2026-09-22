#!/usr/bin/env bash
# Collecte les zones DNS d'un Plesk Linux et les publie vers Parralax-DNS.
#
# Prérequis : bash 3+, curl, jq et la commande locale `plesk`.
# Les paramètres sensibles sont fournis uniquement par l'environnement :
#   PARRALAX_API_URL, PARRALAX_SOURCE et PARRALAX_SOURCE_TOKEN.

set -Eeuo pipefail
IFS=$'\n\t'
shopt -s extglob

readonly SCRIPT_NAME="${0##*/}"
readonly PLESK_BIN="${PLESK_BIN:-plesk}"
readonly CURL_BIN="${CURL_BIN:-curl}"
readonly JQ_BIN="${JQ_BIN:-jq}"

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
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf -- "$TEMP_DIR"
    fi
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage: collect-plesk-dns.sh [--dry-run]

Lit l'inventaire Plesk local via `plesk bin domain --list` et
`plesk bin dns --info`, puis prépare le document attendu par Parralax-DNS.

Variables d'environnement requises (sauf avec --dry-run) :
  PARRALAX_API_URL       URL complète de /api/collectors/custom-dns/sync
  PARRALAX_SOURCE        Identifiant de source configuré dans Parralax-DNS
  PARRALAX_SOURCE_TOKEN  Jeton associé à cette source

Variables optionnelles :
  PLESK_BIN           Chemin de l'exécutable plesk (défaut : plesk)
  CURL_BIN            Chemin de curl (défaut : curl)
  JQ_BIN              Chemin de jq (défaut : jq)

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

# Transforme la sortie texte documentée de `plesk bin dns --info` :
#   webmail.example.org. A 192.0.2.42
#   example.org. MX 10 mail.example.org.
#   _sip._tcp.example.org. SRV 10 5 5060 sip.example.org.
#
# Le format ne fournit pas de TTL ; ce champ est donc volontairement omis.
# Toute ligne non vide qui ne ressemble pas à un record annule la collecte :
# l'objectif est de ne jamais transformer une erreur de lecture en inventaire
# incomplet acceptable par l'API.
records_to_json() {
    local domain="$1"
    local input_file="$2"

    "$JQ_BIN" -Rsc --arg domain "$domain" '
        [
          split("\n")[]
          | select(length > 0)
          | split("\t") as $fields
          | if ($fields | length) != 3 then
              error("ligne DNS interne mal normalisée")
            else . end
          | ($fields[0] | rtrimstr(".")) as $owner
          | ($fields[1] | ascii_upcase) as $type
          | $fields[2] as $raw_value
          | (if $owner == $domain then "@"
             elif $owner | endswith("." + $domain) then $owner[0:-(($domain | length) + 1)]
             else $owner
             end) as $name
          | if $type == "MX" then
              ($raw_value | capture("^(?<priority>[0-9]+)[[:space:]]+(?<value>.+)$")) as $mx
              | {name: $name, type: $type, value: $mx.value, priority: ($mx.priority | tonumber)}
            elif $type == "SRV" then
              ($raw_value | capture("^(?<priority>[0-9]+)[[:space:]]+(?<weight>[0-9]+)[[:space:]]+(?<port>[0-9]+)[[:space:]]+(?<value>.+)$")) as $srv
              | {name: $name, type: $type, value: $srv.value, priority: ($srv.priority | tonumber), weight: ($srv.weight | tonumber), port: ($srv.port | tonumber)}
            else
              {name: $name, type: $type, value: $raw_value}
            end
        ]
    ' < "$input_file"
}

collect_zone() {
    local domain="$1"
    local dns_output="$TEMP_DIR/${domain}.dns"
    local normalized="$TEMP_DIR/${domain}.tsv"
    local records

    if ! "$PLESK_BIN" bin dns --info "$domain" >"$dns_output" 2>&1; then
        log "Lecture DNS échouée pour ${domain}:"
        sed 's/^/  /' "$dns_output" >&2 || true
        return 1
    fi

    # On ne saute aucune ligne non vide : un changement de format Plesk ou un
    # message de diagnostic doit bloquer le push, jamais produire un snapshot
    # partiel.
    if ! awk '
        /^[[:space:]]*$/ { next }
        $1 ~ /^#/ { next }
        NF < 3 {
            printf "Ligne DNS non reconnue: %s\n", $0 > "/dev/stderr"
            exit 1
        }
        $2 !~ /^[A-Za-z][A-Za-z0-9-]{0,15}$/ {
            printf "Type DNS non reconnu: %s\n", $0 > "/dev/stderr"
            exit 1
        }
        {
            owner = $1
            type = $2
            $1 = ""
            $2 = ""
            sub(/^[[:space:]]+/, "")
            if ($0 == "") {
                printf "Valeur DNS absente: %s\n", owner " " type > "/dev/stderr"
                exit 1
            }
            printf "%s\t%s\t%s\n", owner, type, $0
        }
    ' "$dns_output" >"$normalized"; then
        return 1
    fi

    if [[ ! -s "$normalized" ]]; then
        log "Aucun record lisible pour ${domain}; push annulé par sécurité."
        return 1
    fi

    if ! records="$(records_to_json "$domain" "$normalized")"; then
        log "Conversion JSON échouée pour ${domain}."
        return 1
    fi

    "$JQ_BIN" -cn \
        --arg name "$domain" \
        --arg external_id "$domain" \
        --argjson records "$records" \
        '{name: $name, external_id: $external_id, remote_status: "active", records: $records}'
}

main() {
    parse_arguments "$@"
    require_command "$PLESK_BIN"
    require_command "$JQ_BIN"
    if [[ "$DRY_RUN" == false ]]; then
        require_command "$CURL_BIN"
        [[ -n "${PARRALAX_API_URL:-}" ]] || die "PARRALAX_API_URL est requis."
        [[ -n "${PARRALAX_SOURCE:-}" ]] || die "PARRALAX_SOURCE est requis."
        [[ -n "${PARRALAX_SOURCE_TOKEN:-}" ]] || die "PARRALAX_SOURCE_TOKEN est requis."
    fi

    TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/parralax-plesk-collector.XXXXXX")"
    chmod 700 "$TEMP_DIR"

    local domains_output="$TEMP_DIR/domains.txt"
    if ! "$PLESK_BIN" bin domain --list >"$domains_output" 2>&1; then
        log "Impossible de lister les domaines Plesk:"
        sed 's/^/  /' "$domains_output" >&2 || true
        die "Push annulé."
    fi

    local -a domains=()
    local domain
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        domain="${domain##+([[:space:]])}"
        domain="${domain%%+([[:space:]])}"
        [[ -z "$domain" ]] && continue
        [[ "$domain" =~ ^[A-Za-z0-9._-]+$ ]] || die "Nom de domaine Plesk inattendu: $domain"
        domains+=("$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]')")
    done < "$domains_output"

    ((${#domains[@]} > 0)) || die "Plesk n'a retourné aucun domaine; push annulé par sécurité."

    local zones_file="$TEMP_DIR/zones.jsonl"
    for domain in "${domains[@]}"; do
        log "Lecture de ${domain}..."
        if ! collect_zone "$domain" >>"$zones_file"; then
            die "Collecte incomplète; aucun inventaire n'a été envoyé."
        fi
    done

    local zones payload
    zones="$("$JQ_BIN" -sc '.' "$zones_file")"
    [[ "$zones" != '[]' ]] || die "Inventaire de zones vide; push annulé par sécurité."

    if [[ "$DRY_RUN" == true ]]; then
        "$JQ_BIN" -n --arg source "${PARRALAX_SOURCE:-plesk-dry-run}" --argjson zones "$zones" '{source: $source, zones: $zones}'
        return
    fi

    payload="$TEMP_DIR/payload.json"
    "$JQ_BIN" -n --arg source "$PARRALAX_SOURCE" --argjson zones "$zones" '{source: $source, zones: $zones}' >"$payload"

    log "Publication de ${#domains[@]} zone(s) vers Parralax-DNS..."
    "$CURL_BIN" --fail-with-body --silent --show-error \
        --request POST "$PARRALAX_API_URL" \
        --header 'Content-Type: application/json' \
        --header "X-Parralax-Source-Token: $PARRALAX_SOURCE_TOKEN" \
        --data-binary "@$payload"
    printf '\n'
    log "Synchronisation terminée."
}

main "$@"
