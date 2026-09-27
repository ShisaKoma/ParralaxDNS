#!/usr/bin/env bash
set -Eeuo pipefail

readonly TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly COLLECTOR="$TEST_DIR/../collect-plesk-dns.sh"

payload="$(PLESK_BIN="$TEST_DIR/mock-plesk" "$COLLECTOR" --dry-run)"

jq -e '
  .source == "plesk-dry-run"
  and (.zones | length) == 2
  and (.zones[] | select(.name == "example.org") | .records | length) == 4
  and (.zones[] | select(.name == "example.org") | .records[] | select(.type == "MX") | .priority == 10 and .value == "mail.example.org.")
  and (.zones[] | select(.name == "example.org") | .records[] | select(.type == "SRV") | .priority == 10 and .weight == 5 and .port == 5060)
' <<<"$payload" >/dev/null

temp_dir="$(mktemp -d)"
trap 'rm -rf -- "$temp_dir"' EXIT

PARRALAX_API_URL='https://parralax.example.test/api/collectors/custom-dns/sync' \
PARRALAX_SOURCE='plesk-test' \
PARRALAX_SOURCE_TOKEN='test-token' \
PLESK_BIN="$TEST_DIR/mock-plesk" \
CURL_BIN="$TEST_DIR/mock-curl" \
CURL_CALLED_FILE="$temp_dir/curl-called-after-success" \
"$COLLECTOR" >/dev/null
[[ -e "$temp_dir/curl-called-after-success" ]]

PARRALAX_API_URL='https://parralax.example.test/api/collectors/custom-dns/sync' \
PARRALAX_SOURCE='plesk-test' \
PARRALAX_SOURCE_TOKEN='test-token' \
PLESK_BIN="$TEST_DIR/mock-plesk-partial-failure" \
CURL_BIN="$TEST_DIR/mock-curl" \
CURL_CALLED_FILE="$temp_dir/curl-called" \
"$COLLECTOR" >"$temp_dir/stdout" 2>"$temp_dir/stderr"

[[ -e "$temp_dir/curl-called" ]]
rg -F 'Lecture DNS échouée pour example.net (code de sortie Plesk: 1).' "$temp_dir/stderr" >/dev/null
rg -F 'Diagnostic example.net: stdout=0 octet(s), 0 ligne(s) non vide(s); stderr=28 octet(s), 1 ligne(s) non vide(s).' "$temp_dir/stderr" >/dev/null
rg -F 'Zone example.net ignorée; poursuite avec les domaines suivants.' "$temp_dir/stderr" >/dev/null
rg -F 'Collecte terminée: 1 zone(s) transmise(s), 1 zone(s) ignorée(s).' "$temp_dir/stderr" >/dev/null

set +e
PLESK_BIN="$TEST_DIR/mock-plesk-empty-zone" \
"$COLLECTOR" --dry-run --debug >"$temp_dir/debug-stdout" 2>"$temp_dir/debug-stderr"
status=$?
set -e

[[ $status -eq 0 ]]
 jq -e '(.zones | length) == 2 and (.zones[] | select(.name == "empty.example") | .remote_status == "dns_disabled" and .records == [])' "$temp_dir/debug-stdout" >/dev/null
rg -F 'Zone DNS désactivée dans Plesk pour empty.example; elle sera remontée sans records.' "$temp_dir/debug-stderr" >/dev/null
rg -F 'Aucun record collecté pour empty.example, car sa zone DNS est désactivée dans Plesk; statut dns_disabled envoyé.' "$temp_dir/debug-stderr" >/dev/null
rg -F 'Diagnostic empty.example: stdout=0 octet(s), 0 ligne(s) non vide(s); stderr=61 octet(s), 2 ligne(s) non vide(s).' "$temp_dir/debug-stderr" >/dev/null
rg -F 'Fichiers de diagnostic conservés dans ' "$temp_dir/debug-stderr" >/dev/null
diagnostic_dir="$(sed -n 's/.*Fichiers de diagnostic conservés dans //p' "$temp_dir/debug-stderr")"
[[ -d "$diagnostic_dir" ]]
rm -rf -- "$diagnostic_dir"

printf 'OK: collect-plesk-dns.sh transforme les sorties Plesk attendues.\n'
printf 'OK: un inventaire complet est publié.\n'
printf 'OK: une erreur de zone est ignorée et les zones valides sont publiées.\n'
printf 'OK: une zone DNS désactivée reste inventoriée avec des diagnostics détaillés.\n'
