#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
collector="$project_root/collectors/network-diagnostics/collect-network-diagnostics.sh"
temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/parralax-network-test.XXXXXX")"
trap 'rm -rf -- "$temp_dir"' EXIT

mkdir "$temp_dir/bin"
cat > "$temp_dir/bin/dig" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1'
printf '%s\n' 'example.org. 300 IN A 192.0.2.42'
EOF
cat > "$temp_dir/bin/traceroute" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'traceroute to example.org (192.0.2.42), 12 hops max'
printf '%s\n' ' 1  192.0.2.1  1.0 ms'
EOF
cat > "$temp_dir/bin/netstat" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'Kernel IP routing table'
EOF
chmod +x "$temp_dir/bin/dig" "$temp_dir/bin/traceroute" "$temp_dir/bin/netstat"

cat > "$temp_dir/domains.txt" <<'EOF'
# Commentaire
EXAMPLE.org.
example.org
EOF

PATH="$temp_dir/bin:$PATH" \
PARRALAX_API_URL='https://parralax.example.test/api/collectors/network-diagnostics' \
PARRALAX_AGENT='debian-edge-01' \
PARRALAX_AGENT_TOKEN='test-agent-token' \
PARRALAX_DOMAINS_FILE="$temp_dir/domains.txt" \
"$collector" --dry-run > "$temp_dir/report.json"

jq -e '.agent == "debian-edge-01" and .complete == true and (.checks | length) == 3' "$temp_dir/report.json" >/dev/null
jq -e '[.checks[] | select(.check_type == "dig" and .domain == "example.org" and .status == "ok")] | length == 1' "$temp_dir/report.json" >/dev/null
jq -e '[.checks[] | select(.check_type == "netstat" and .domain == null)] | length == 1' "$temp_dir/report.json" >/dev/null

printf '%s\n' 'not a domain' > "$temp_dir/invalid-domains.txt"
if PATH="$temp_dir/bin:$PATH" \
    PARRALAX_API_URL='https://parralax.example.test/api/collectors/network-diagnostics' \
    PARRALAX_AGENT='debian-edge-01' \
    PARRALAX_AGENT_TOKEN='test-agent-token' \
    PARRALAX_DOMAINS_FILE="$temp_dir/invalid-domains.txt" \
    "$collector" --dry-run > /dev/null 2> "$temp_dir/invalid-error"; then
    printf 'Le collecteur aurait dû refuser un domaine invalide.\n' >&2
    exit 1
fi
grep -F 'Domaine invalide' "$temp_dir/invalid-error" >/dev/null

: > "$temp_dir/too-many-domains.txt"
for index in $(seq 1 361); do
    printf 'host-%s.example.org\n' "$index" >> "$temp_dir/too-many-domains.txt"
done
if PATH="$temp_dir/bin:$PATH" \
    PARRALAX_API_URL='https://parralax.example.test/api/collectors/network-diagnostics' \
    PARRALAX_AGENT='debian-edge-01' \
    PARRALAX_AGENT_TOKEN='test-agent-token' \
    PARRALAX_DOMAINS_FILE="$temp_dir/too-many-domains.txt" \
    "$collector" --dry-run > /dev/null 2> "$temp_dir/too-many-error"; then
    printf 'Le collecteur aurait dû refuser plus de 360 domaines.\n' >&2
    exit 1
fi
grep -F 'La liste dépasse 360 domaines' "$temp_dir/too-many-error" >/dev/null

printf 'OK: collecte réseau bornée et validation de la liste.\n'
