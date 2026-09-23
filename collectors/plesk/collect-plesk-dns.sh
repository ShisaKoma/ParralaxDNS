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
DEBUG=false
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
        if [[ "$DEBUG" == true ]]; then
            log "Fichiers de diagnostic conservés dans ${TEMP_DIR}"
        else
            rm -rf -- "$TEMP_DIR"
        fi
    fi
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage: collect-plesk-dns.sh [--dry-run] [--debug]

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
--debug affiche les sorties Plesk et conserve les fichiers de diagnostic
        temporaires (lisibles uniquement par l'utilisateur qui lance le script).
EOF
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Commande introuvable: $1"
}

parse_arguments() {
    while (($#)); do
        case "$1" in
            --dry-run) DRY_RUN=true ;;
            --debug) DEBUG=true ;;
            -h|--help) usage; exit 0 ;;
            *) die "Option inconnue: $1 (utilisez --help)" ;;
        esac
        shift
    done
}

file_size() {
    wc -c < "$1" | tr -d '[:space:]'
}

non_empty_line_count() {
    awk 'NF { count++ } END { print count + 0 }' "$1"
}

is_dns_zone_switched_off() {
    awk '
        tolower($0) ~ /dns zone for this domain is switched off/ { found = 1 }
        END { exit !found }
    ' "$1"
}

placeholder_zone_to_json() {
    local domain="$1"
    local remote_status="$2"

    "$JQ_BIN" -cn \
        --arg name "$domain" \
        --arg external_id "$domain" \
        --arg remote_status "$remote_status" \
        '{name: $name, external_id: $external_id, remote_status: $remote_status, records: []}'
}

show_diagnostic_file() {
    local label="$1"
    local file="$2"
    local limit=160
    local lines

    [[ -s "$file" ]] || return 0
    lines="$(wc -l < "$file" | tr -d '[:space:]')"
    log "${label} (${lines} ligne(s), $(file_size "$file") octet(s)) :"
    nl -ba "$file" | sed -n "1,${limit}p" | sed 's/^/  /' >&2
    if (( lines > limit )); then
        log "  … sortie tronquée après ${limit} lignes; le fichier complet est dans ${file}."
    fi
}

show_zone_diagnostics() {
    local domain="$1"
    local stdout_file="$2"
    local stderr_file="$3"
    local normalized_file="${4:-}"

    log "Diagnostic ${domain}: commande: ${PLESK_BIN} bin dns --info ${domain}"
    log "Diagnostic ${domain}: stdout=$(file_size "$stdout_file") octet(s), $(non_empty_line_count "$stdout_file") ligne(s) non vide(s); stderr=$(file_size "$stderr_file") octet(s), $(non_empty_line_count "$stderr_file") ligne(s) non vide(s)."
    show_diagnostic_file "Diagnostic ${domain}: stdout Plesk" "$stdout_file"
    show_diagnostic_file "Diagnostic ${domain}: stderr Plesk" "$stderr_file"
    [[ "$DEBUG" == true || -z "$normalized_file" ]] || return 0
    show_diagnostic_file "Diagnostic ${domain}: records normalisés" "$normalized_file"
}

# Transforme la sortie texte documentée de `plesk bin dns --info` :
#   webmail.example.org. A 192.0.2.42
#   example.org. MX 10 mail.example.org.
#   _sip._tcp.example.org. SRV 10 5 5060 sip.example.org.
#
# Le format ne fournit pas de TTL ; ce champ est donc volontairement omis.
# Toute ligne non vide qui ne ressemble pas à un record invalide uniquement la
# zone concernée : les autres zones peuvent tout de même être publiées.
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
    local dns_stdout="$TEMP_DIR/${domain}.stdout"
    local dns_stderr="$TEMP_DIR/${domain}.stderr"
    local normalized="$TEMP_DIR/${domain}.tsv"
    local normalize_error="$TEMP_DIR/${domain}.normalize-error"
    local json_error="$TEMP_DIR/${domain}.json-error"
    local records_json="$TEMP_DIR/${domain}.records.json"
    local plesk_status=0
    local dns_zone_switched_off=false

    "$PLESK_BIN" bin dns --info "$domain" >"$dns_stdout" 2>"$dns_stderr" || plesk_status=$?
    if is_dns_zone_switched_off "$dns_stderr"; then
        dns_zone_switched_off=true
    fi
    if (( plesk_status != 0 )); then
        if [[ "$dns_zone_switched_off" == true ]]; then
            log "Zone DNS désactivée dans Plesk pour ${domain} (code de sortie Plesk: ${plesk_status}); zone remontée sans records."
            show_zone_diagnostics "$domain" "$dns_stdout" "$dns_stderr"
            placeholder_zone_to_json "$domain" "dns_disabled"
            return 0
        else
            log "Lecture DNS échouée pour ${domain} (code de sortie Plesk: ${plesk_status})."
        fi
        show_zone_diagnostics "$domain" "$dns_stdout" "$dns_stderr"
        return 1
    fi

    if [[ -s "$dns_stderr" ]]; then
        if [[ "$dns_zone_switched_off" == true ]]; then
            log "Zone DNS désactivée dans Plesk pour ${domain}; elle sera remontée sans records."
        else
            log "Plesk a émis des diagnostics sur stderr pour ${domain}."
        fi
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
    ' "$dns_stdout" >"$normalized" 2>"$normalize_error"; then
        log "Format DNS Plesk non reconnu pour ${domain}."
        show_diagnostic_file "Diagnostic ${domain}: erreur de normalisation" "$normalize_error"
        show_zone_diagnostics "$domain" "$dns_stdout" "$dns_stderr" "$normalized"
        return 1
    fi

    if [[ ! -s "$normalized" ]]; then
        if [[ "$dns_zone_switched_off" == true ]]; then
            log "Aucun record collecté pour ${domain}, car sa zone DNS est désactivée dans Plesk; statut dns_disabled envoyé."
            show_zone_diagnostics "$domain" "$dns_stdout" "$dns_stderr" "$normalized"
            placeholder_zone_to_json "$domain" "dns_disabled"
        else
            log "Aucun record lisible pour ${domain}; la commande Plesk a réussi mais stdout ne contient aucun record DNS; statut no_records envoyé."
            show_zone_diagnostics "$domain" "$dns_stdout" "$dns_stderr" "$normalized"
            placeholder_zone_to_json "$domain" "no_records"
        fi
        return 0
    fi

    if ! records_to_json "$domain" "$normalized" >"$records_json" 2>"$json_error"; then
        log "Conversion JSON échouée pour ${domain}."
        show_diagnostic_file "Diagnostic ${domain}: erreur de conversion JSON" "$json_error"
        show_zone_diagnostics "$domain" "$dns_stdout" "$dns_stderr" "$normalized"
        return 1
    fi

    if [[ "$DEBUG" == true && -s "$dns_stderr" ]]; then
        show_diagnostic_file "Diagnostic ${domain}: stderr Plesk" "$dns_stderr"
    fi

    "$JQ_BIN" \
        --arg name "$domain" \
        --arg external_id "$domain" \
        '{name: $name, external_id: $external_id, remote_status: "active", records: .}' \
        "$records_json"
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
    local domains_error="$TEMP_DIR/domains.stderr"
    local domains_status=0
    "$PLESK_BIN" bin domain --list >"$domains_output" 2>"$domains_error" || domains_status=$?
    if (( domains_status != 0 )); then
        log "Impossible de lister les domaines Plesk (code de sortie: ${domains_status})."
        show_diagnostic_file "stdout de plesk bin domain --list" "$domains_output"
        show_diagnostic_file "stderr de plesk bin domain --list" "$domains_error"
        die "Push annulé."
    fi
    if [[ -s "$domains_error" && "$DEBUG" == true ]]; then
        show_diagnostic_file "Diagnostic: stderr de plesk bin domain --list" "$domains_error"
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
    log "${#domains[@]} domaine(s) Plesk trouvé(s)."

    local zones_file="$TEMP_DIR/zones.jsonl"
    local collected_zones=0
    local skipped_zones=0
    for domain in "${domains[@]}"; do
        log "Lecture de ${domain}..."
        if collect_zone "$domain" >>"$zones_file"; then
            (( collected_zones += 1 ))
        else
            (( skipped_zones += 1 ))
            log "Zone ${domain} ignorée; poursuite avec les domaines suivants."
        fi
    done

    local zones_json="$TEMP_DIR/zones.json"
    "$JQ_BIN" -sc '.' "$zones_file" >"$zones_json"
    "$JQ_BIN" -e 'length > 0' "$zones_json" >/dev/null || die "Inventaire de zones vide; push annulé par sécurité."
    log "Collecte terminée: ${collected_zones} zone(s) transmise(s), ${skipped_zones} zone(s) ignorée(s)."

    if [[ "$DRY_RUN" == true ]]; then
        "$JQ_BIN" --arg source "${PARRALAX_SOURCE:-plesk-dry-run}" '{source: $source, zones: .}' "$zones_json"
        return
    fi

    local payload="$TEMP_DIR/payload.json"
    "$JQ_BIN" --arg source "$PARRALAX_SOURCE" '{source: $source, zones: .}' "$zones_json" >"$payload"

    log "Publication de ${collected_zones} zone(s) vers Parralax-DNS..."
    "$CURL_BIN" --fail-with-body --silent --show-error \
        --request POST "$PARRALAX_API_URL" \
        --header 'Content-Type: application/json' \
        --header "X-Parralax-Source-Token: $PARRALAX_SOURCE_TOKEN" \
        --data-binary "@$payload"
    printf '\n'
    log "Synchronisation terminée."
}

main "$@"
