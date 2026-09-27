#!/usr/bin/env bash
# Agent de diagnostic réseau Parralax-DNS, compatible Bash sur Debian et Alpine.

set -euo pipefail

DRY_RUN=false
TEMP_DIR=""
COMPLETE=true
MAX_DOMAINS=360
MAX_OUTPUT_BYTES=16000

log() {
    printf '%s\n' "$*" >&2
}

die() {
    log "Erreur: $*"
    exit 1
}

cleanup() {
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf -- "$TEMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

usage() {
    cat <<'EOF'
Usage: collect-network-diagnostics.sh [--dry-run]

Variables obligatoires :
  PARRALAX_API_URL       URL complète de /api/collectors/network-diagnostics
  PARRALAX_AGENT         Identifiant stable de l'agent
  PARRALAX_AGENT_TOKEN   Jeton propre à cet agent
  PARRALAX_DOMAINS_FILE  Fichier contenant un domaine par ligne

Variables facultatives :
  PARRALAX_DIAGNOSTIC_CHECKS  dig,traceroute,netstat par défaut
  PARRALAX_DIG_TIMEOUT        Délai dig en secondes (3 par défaut)
  PARRALAX_TRACEROUTE_HOPS    Nombre maximal de sauts (12 par défaut)
  PARRALAX_TRACEROUTE_WAIT    Attente par sonde en secondes (2 par défaut)
EOF
}

while (($#)); do
    case "$1" in
        --dry-run) DRY_RUN=true ;;
        -h|--help) usage; exit 0 ;;
        *) die "Option inconnue: $1" ;;
    esac
    shift
done

API_URL="${PARRALAX_API_URL:-}"
AGENT="${PARRALAX_AGENT:-}"
AGENT_TOKEN="${PARRALAX_AGENT_TOKEN:-}"
DOMAINS_FILE="${PARRALAX_DOMAINS_FILE:-}"
CHECKS="${PARRALAX_DIAGNOSTIC_CHECKS:-dig,traceroute,netstat}"
DIG_TIMEOUT="${PARRALAX_DIG_TIMEOUT:-3}"
TRACEROUTE_HOPS="${PARRALAX_TRACEROUTE_HOPS:-12}"
TRACEROUTE_WAIT="${PARRALAX_TRACEROUTE_WAIT:-2}"

[[ -n "$API_URL" ]] || die "PARRALAX_API_URL est obligatoire."
[[ "$API_URL" == http://* || "$API_URL" == https://* ]] || die "PARRALAX_API_URL doit utiliser HTTP ou HTTPS."
[[ -n "$AGENT" && "$AGENT" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die "PARRALAX_AGENT est invalide."
[[ -n "$AGENT_TOKEN" && "$AGENT_TOKEN" =~ ^[A-Za-z0-9._~-]+$ ]] || die "PARRALAX_AGENT_TOKEN doit être un jeton non vide composé de caractères sûrs."
[[ -f "$DOMAINS_FILE" && -r "$DOMAINS_FILE" ]] || die "PARRALAX_DOMAINS_FILE doit désigner un fichier lisible."
[[ "$DIG_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || die "PARRALAX_DIG_TIMEOUT doit être compris entre 1 et 99."
[[ "$TRACEROUTE_HOPS" =~ ^[1-9][0-9]?$ ]] || die "PARRALAX_TRACEROUTE_HOPS doit être compris entre 1 et 99."
[[ "$TRACEROUTE_WAIT" =~ ^[1-9][0-9]?$ ]] || die "PARRALAX_TRACEROUTE_WAIT doit être compris entre 1 et 99."

for dependency in curl jq sort; do
    command -v "$dependency" >/dev/null 2>&1 || die "Commande requise absente: ${dependency}."
done

case ",${CHECKS}," in
    *,dig,*|*,traceroute,*|*,netstat,*) ;;
    *) die "PARRALAX_DIAGNOSTIC_CHECKS ne contient aucun contrôle pris en charge." ;;
esac
IFS=',' read -r -a requested_checks <<< "$CHECKS"
for check in "${requested_checks[@]}"; do
    case "$check" in
        dig|traceroute|netstat) ;;
        *) die "Contrôle non autorisé: ${check}." ;;
    esac
done

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/parralax-network-diagnostics.XXXXXX")"
chmod 0700 "$TEMP_DIR"
NORMALIZED_DOMAINS="$TEMP_DIR/domains"
CHECKS_NDJSON="$TEMP_DIR/checks.ndjson"
: > "$NORMALIZED_DOMAINS"
: > "$CHECKS_NDJSON"

domain_count=0
while IFS= read -r raw_domain || [[ -n "$raw_domain" ]]; do
    raw_domain="${raw_domain%$'\r'}"
    domain="$(printf '%s' "$raw_domain" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$domain" || "${domain:0:1}" == "#" ]] && continue
    [[ "$domain" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$ ]] \
        || die "Domaine invalide dans la liste: ${domain}."
    printf '%s\n' "${domain%.}" | tr '[:upper:]' '[:lower:]' >> "$NORMALIZED_DOMAINS"
    domain_count=$((domain_count + 1))
    ((domain_count <= MAX_DOMAINS)) || die "La liste dépasse ${MAX_DOMAINS} domaines."
done < "$DOMAINS_FILE"

sort -u "$NORMALIZED_DOMAINS" -o "$NORMALIZED_DOMAINS"
domain_count="$(wc -l < "$NORMALIZED_DOMAINS" | tr -d ' ')"
((domain_count > 0)) || die "La liste ne contient aucun domaine valide."

append_check() {
    local domain="$1" check_type="$2" status="$3" exit_code="$4" duration_ms="$5" anomaly_code="$6" output_file="$7"
    local bounded_output="$TEMP_DIR/bounded-output"
    head -c "$MAX_OUTPUT_BYTES" "$output_file" > "$bounded_output"
    jq -cn \
        --arg domain "$domain" \
        --arg check_type "$check_type" \
        --arg status "$status" \
        --argjson exit_code "$exit_code" \
        --argjson duration_ms "$duration_ms" \
        --arg anomaly_code "$anomaly_code" \
        --rawfile output "$bounded_output" \
        '{domain:(if $domain == "" then null else $domain end),check_type:$check_type,status:$status,exit_code:$exit_code,duration_ms:$duration_ms,anomaly_code:(if $anomaly_code == "" then null else $anomaly_code end),output:$output}' \
        >> "$CHECKS_NDJSON"
}

run_dig() {
    local domain="$1" output="$TEMP_DIR/dig-output" started ended exit_code status anomaly
    if ! command -v dig >/dev/null 2>&1; then
        printf 'La commande dig est absente.\n' > "$output"
        append_check "$domain" dig unavailable null null tool_missing "$output"
        COMPLETE=false
        return
    fi
    started="$(date +%s)"
    if dig "+time=${DIG_TIMEOUT}" +tries=1 +noall +comments +answer A "$domain" > "$output" 2>&1; then
        exit_code=0
    else
        exit_code=$?
    fi
    ended="$(date +%s)"
    status=ok
    anomaly=""
    if ((exit_code != 0)); then
        status=error
        anomaly=dns_command_failed
    elif grep -Eq 'status: NXDOMAIN' "$output"; then
        status=anomaly
        anomaly=dns_nxdomain
    elif grep -Eq 'status: (SERVFAIL|REFUSED)' "$output"; then
        status=anomaly
        anomaly=dns_server_error
    elif ! grep -Eq '[[:space:]]IN[[:space:]]+A[[:space:]]' "$output"; then
        status=anomaly
        anomaly=dns_no_a_answer
    fi
    append_check "$domain" dig "$status" "$exit_code" "$(((ended - started) * 1000))" "$anomaly" "$output"
}

run_traceroute() {
    local domain="$1" output="$TEMP_DIR/traceroute-output" started ended exit_code status anomaly
    if ! command -v traceroute >/dev/null 2>&1; then
        printf 'La commande traceroute est absente.\n' > "$output"
        append_check "$domain" traceroute unavailable null null tool_missing "$output"
        COMPLETE=false
        return
    fi
    started="$(date +%s)"
    if traceroute -m "$TRACEROUTE_HOPS" -w "$TRACEROUTE_WAIT" -q 1 "$domain" > "$output" 2>&1; then
        exit_code=0
    else
        exit_code=$?
    fi
    ended="$(date +%s)"
    status=ok
    anomaly=""
    if ((exit_code != 0)); then
        status=error
        anomaly=traceroute_failed
    fi
    append_check "$domain" traceroute "$status" "$exit_code" "$(((ended - started) * 1000))" "$anomaly" "$output"
}

run_netstat() {
    local output="$TEMP_DIR/netstat-output" started ended exit_code status anomaly
    if ! command -v netstat >/dev/null 2>&1; then
        printf 'La commande netstat est absente.\n' > "$output"
        append_check "" netstat unavailable null null tool_missing "$output"
        COMPLETE=false
        return
    fi
    started="$(date +%s)"
    if netstat -rn > "$output" 2>&1; then
        exit_code=0
    else
        exit_code=$?
    fi
    ended="$(date +%s)"
    status=ok
    anomaly=""
    if ((exit_code != 0)); then
        status=error
        anomaly=netstat_failed
    fi
    append_check "" netstat "$status" "$exit_code" "$(((ended - started) * 1000))" "$anomaly" "$output"
}

while IFS= read -r domain; do
    case ",${CHECKS}," in *,dig,*) run_dig "$domain" ;; esac
    case ",${CHECKS}," in *,traceroute,*) run_traceroute "$domain" ;; esac
done < "$NORMALIZED_DOMAINS"
case ",${CHECKS}," in *,netstat,*) run_netstat ;; esac

COLLECTED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
REPORT="$TEMP_DIR/report.json"
jq -s \
    --arg agent "$AGENT" \
    --arg collected_at "$COLLECTED_AT" \
    --argjson complete "$COMPLETE" \
    '{agent:$agent,collected_at:$collected_at,complete:$complete,checks:.}' \
    "$CHECKS_NDJSON" > "$REPORT"

if [[ "$DRY_RUN" == true ]]; then
    jq . "$REPORT"
    exit 0
fi

CURL_CONFIG="$TEMP_DIR/curl-config"
umask 077
printf 'header = "X-Parralax-Agent-Token: %s"\n' "$AGENT_TOKEN" > "$CURL_CONFIG"
curl --config "$CURL_CONFIG" --fail --silent --show-error \
    --connect-timeout 10 \
    --max-time 120 \
    -X POST "$API_URL" \
    -H 'Content-Type: application/json' \
    --data-binary "@${REPORT}"
printf '\n'
