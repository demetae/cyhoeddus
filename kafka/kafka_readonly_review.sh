#!/usr/bin/env bash

set -u
set -o pipefail

TESTSSL="${TESTSSL:-/home/kali/Desktop/testssl_2026-09-17/testssl.sh-3.3dev/testssl.sh}"
OUT_ROOT="${OUT_ROOT:-$PWD/kafka-review-$(date +%Y%m%d-%H%M%S)}"

# Intentionally narrow defaults.
PORTS="${PORTS:-9093}"

TCP_TIMEOUT="${TCP_TIMEOUT:-8}"
OPENSSL_TIMEOUT="${OPENSSL_TIMEOUT:-15}"
KCAT_TIMEOUT="${KCAT_TIMEOUT:-20}"
TESTSSL_TIMEOUT="${TESTSSL_TIMEOUT:-600}"

mkdir -p "$OUT_ROOT"

FINDINGS_MD="$OUT_ROOT/suggested-findings.md"
FINDINGS_CSV="$OUT_ROOT/suggested-findings.csv"
NOTES_MD="$OUT_ROOT/review-notes.md"

cat > "$FINDINGS_MD" <<'EOF'
# Suggested Kafka Findings

These are automated candidate findings only. They require analyst validation and
context before inclusion in a report. In particular, internal topology exposure,
certificate trust, and lack of TLS may have different risk depending on the
network boundary and intended Kafka listener design.

EOF

printf '"Category","Target","Suggested finding","Rationale","Evidence"\n' > "$FINDINGS_CSV"

cat > "$NOTES_MD" <<'EOF'
# Kafka Review Notes

Operational observations and controls detected during the read-only review.

EOF

usage() {
    cat <<'EOF'
Usage:
  kafka_readonly_review.sh targets_fqdn.txt
  kafka_readonly_review.sh targets_fqdn.txt targets_ip.txt

Environment overrides:
  PORTS="9092,9093,9094"
  TESTSSL=/path/to/testssl.sh
  OUT_ROOT=/path/to/output
  TCP_TIMEOUT=8
  OPENSSL_TIMEOUT=15
  KCAT_TIMEOUT=20
  TESTSSL_TIMEOUT=600

Input files contain one hostname or IPv4 address per line.
Comments beginning with # and blank lines are ignored.
EOF
}

have() {
    command -v "$1" >/dev/null 2>&1
}

safe_name() {
    printf '%s' "$1" | tr '/:[] ' '_____'
}

banner() {
    printf '\n============================================================\n'
    printf '%s\n' "$*"
    printf '============================================================\n'
}

csv_escape() {
    local s="${1//\"/\"\"}"
    printf '"%s"' "$s"
}

add_finding() {
    local category="$1"
    local target="$2"
    local title="$3"
    local rationale="$4"
    local evidence="$5"

    {
        echo "## [$category] $title"
        echo
        echo "- **Target:** \`$target\`"
        echo "- **Why it may matter:** $rationale"
        echo "- **Evidence:** \`$evidence\`"
        echo "- **Status:** Candidate finding — analyst validation required"
        echo
    } >> "$FINDINGS_MD"

    {
        csv_escape "$category"; printf ','
        csv_escape "$target"; printf ','
        csv_escape "$title"; printf ','
        csv_escape "$rationale"; printf ','
        csv_escape "$evidence"; printf '\n'
    } >> "$FINDINGS_CSV"
}

add_note() {
    local target="$1"
    local note="$2"
    {
        echo "- **$target:** $note"
    } >> "$NOTES_MD"
}

run_capture() {
    local outfile="$1"
    shift
    {
        printf '$'
        printf ' %q' "$@"
        printf '\n\n'
        "$@"
        rc=$?
        printf '\n[exit-code] %s\n' "$rc"
        return "$rc"
    } >"$outfile" 2>&1
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage
    exit 1
fi

for f in "$@"; do
    if [[ ! -r "$f" ]]; then
        echo "[!] Cannot read input file: $f" >&2
        exit 1
    fi
done

# Core prerequisites
missing=0
for cmd in getent nc nmap openssl kcat timeout awk sed grep sort; do
    if ! have "$cmd"; then
        echo "[!] Missing required command: $cmd" >&2
        missing=1
    fi
done
[[ "$missing" -eq 0 ]] || exit 1

declare -a TARGETS=()

for f in "$@"; do
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | xargs)"
        [[ -z "$line" ]] && continue

        # If someone accidentally supplies host:port, strip the port so this
        # script remains port-discovery driven.
        if [[ "$line" =~ ^[^:]+:[0-9]+$ ]]; then
            line="${line%:*}"
        fi

        TARGETS+=("$line")
    done < "$f"
done

# Deduplicate while preserving a deterministic order.
mapfile -t TARGETS < <(printf '%s\n' "${TARGETS[@]}" | sort -u)

if [[ "${#TARGETS[@]}" -eq 0 ]]; then
    echo "[!] No targets found in supplied file(s)." >&2
    exit 1
fi

{
    echo "Kafka read-only review"
    echo "Started: $(date -Is)"
    echo "Host: $(hostname)"
    echo "Input files: $*"
    echo "Candidate Kafka ports: $PORTS"
    echo
    echo "Tool versions:"
    echo "--------------"
    kcat -V 2>&1 || true
    nmap --version 2>&1 | head -n 2 || true
    openssl version -a 2>&1 | head -n 3 || true
    nc -h 2>&1 | head -n 2 || true
    if have dig; then
        dig -v 2>&1 | head -n 1 || true
    fi
    if [[ -f "$TESTSSL" ]]; then
        bash "$TESTSSL" --version 2>&1 | head -n 5 || true
    fi
} >"$OUT_ROOT/tool-versions.txt"

printf '%s\n' "${TARGETS[@]}" >"$OUT_ROOT/targets-normalised.txt"

echo "[+] Evidence directory: $OUT_ROOT"
echo "[+] Targets: ${#TARGETS[@]}"
echo "[+] Candidate ports: $PORTS"

for host in "${TARGETS[@]}"; do
    banner "Reviewing $host"

    host_name="$(safe_name "$host")"
    host_dir="$OUT_ROOT/$host_name"
    mkdir -p "$host_dir"/{dns,discovery}

    {
        echo "Target: $host"
        echo "Started: $(date -Is)"
    } >"$host_dir/target.txt"

    echo "[*] DNS resolution"
    run_capture "$host_dir/dns/getent-hosts.txt" getent hosts "$host" || true
    run_capture "$host_dir/dns/getent-ahosts.txt" getent ahosts "$host" || true

    if have dig; then
        run_capture "$host_dir/dns/dig-short.txt" dig +short "$host" || true
        if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            run_capture "$host_dir/dns/reverse-dns.txt" dig -x "$host" +short || true
        fi
    fi

    echo "[*] Discovering open candidate Kafka ports: $PORTS"

    # First-pass port discovery only against the deliberately narrow list.
    nmap -Pn -sT -p "$PORTS" \
        --open \
        -oA "$host_dir/discovery/ports" \
        "$host" \
        >"$host_dir/discovery/console.txt" 2>&1 || true

    # Extract open TCP ports from normal Nmap output.
    mapfile -t OPEN_PORTS < <(
        awk '/^[0-9]+\/tcp[[:space:]]+open/ {
            split($1,a,"/");
            print a[1]
        }' "$host_dir/discovery/ports.nmap" 2>/dev/null | sort -n -u
    )

    if [[ "${#OPEN_PORTS[@]}" -eq 0 ]]; then
        echo "[!] No open ports found from candidate set ($PORTS)" | tee "$host_dir/discovery/no-open-kafka-ports.txt"
        add_note "$host" "No open TCP listener was identified on the configured Kafka candidate port(s): $PORTS. Treat as a coverage/connectivity note, not a vulnerability."
        {
            echo "Completed: $(date -Is)"
            echo "Open candidate ports: none"
        } >>"$host_dir/target.txt"
        continue
    fi

    printf '%s\n' "${OPEN_PORTS[@]}" >"$host_dir/discovery/open-ports.txt"
    echo "[+] Open candidate ports: ${OPEN_PORTS[*]}"

    for port in "${OPEN_PORTS[@]}"; do
        target="${host}:${port}"
        port_dir="$host_dir/port-$port"
        mkdir -p "$port_dir"/{tcp,nmap,tls,kcat}

        banner "$target"

        echo "[*] TCP connectivity"
        timeout "$TCP_TIMEOUT" nc -vz -w 5 "$host" "$port" \
            >"$port_dir/tcp/nc.txt" 2>&1
        nc_rc=$?
        printf '\n[exit-code] %s\n' "$nc_rc" >>"$port_dir/tcp/nc.txt"

        echo "[*] Nmap service/version detection"
        nmap -Pn -sT -sV --version-light -p "$port" \
            -oA "$port_dir/nmap/service" "$host" \
            >"$port_dir/nmap/console.txt" 2>&1 || true

        echo "[*] TLS handshake probe"
        tls_raw="$port_dir/tls/openssl-s_client.txt"
        timeout "$OPENSSL_TIMEOUT" openssl s_client \
            -connect "${host}:${port}" \
            -servername "$host" \
            -showcerts \
            </dev/null >"$tls_raw" 2>&1
        openssl_rc=$?
        printf '\n[exit-code] %s\n' "$openssl_rc" >>"$tls_raw"

        tls_detected=0
        if grep -Eq 'BEGIN CERTIFICATE|Protocol *:|Cipher is |Ciphersuite:' "$tls_raw"; then
            tls_detected=1
            echo "TLS detected" >"$port_dir/tls/status.txt"

            timeout "$OPENSSL_TIMEOUT" bash -c \
                "openssl s_client -connect '${host}:${port}' -servername '${host}' </dev/null 2>/dev/null \
                 | openssl x509 -noout -subject -issuer -serial -dates -ext subjectAltName" \
                >"$port_dir/tls/certificate-summary.txt" 2>&1 || true

            if [[ -f "$TESTSSL" ]]; then
                echo "[*] Running testssl.sh (LOG + JSON + CSV + HTML)"
                mkdir -p "$port_dir/tls/testssl"

                # -oA writes LOG, pretty JSON, CSV and HTML into the specified
                # directory. URI must remain the final argument to testssl.sh.
                MAX_OSSL_FAIL=6 \
                timeout "$TESTSSL_TIMEOUT" \
                bash "$TESTSSL" \
                    --socket-timeout 30 \
                    --openssl-timeout 30 \
                    --warnings batch \
                    -oA "$port_dir/tls/testssl" \
                    "${host}:${port}" \
                    >"$port_dir/tls/testssl-console.txt" 2>&1

                testssl_rc=$?
                printf '\n[exit-code] %s\n' "$testssl_rc" >>"$port_dir/tls/testssl-console.txt"
            else
                echo "[!] testssl.sh not found at: $TESTSSL" \
                    >"$port_dir/tls/testssl-not-run.txt"
            fi
        else
            echo "TLS not positively detected by openssl probe" >"$port_dir/tls/status.txt"
            echo "[*] TLS not positively detected; testssl.sh skipped"
            add_finding \
                "Transport Security" \
                "$target" \
                "Kafka listener did not present TLS during the initial handshake" \
                "If the listener accepts Kafka traffic without TLS, credentials and message contents may be exposed to interception or modification on the network path. Validate that this is genuinely a plaintext Kafka listener rather than a protocol-detection limitation." \
                "$port_dir/tls/openssl-s_client.txt"
        fi

        echo "[*] Kafka metadata request with kcat"

        if [[ "$tls_detected" -eq 1 ]]; then
            metadata_txt="$port_dir/kcat/metadata-ssl.txt"

            timeout "$KCAT_TIMEOUT" kcat \
                -b "$target" \
                -X security.protocol=SSL \
                -L \
                >"$metadata_txt" 2>&1
            kcat_rc=$?
            printf '\n[exit-code] %s\n' "$kcat_rc" >>"$metadata_txt"

            if kcat -h 2>&1 | grep -q -- '-J'; then
                timeout "$KCAT_TIMEOUT" kcat \
                    -b "$target" \
                    -X security.protocol=SSL \
                    -L -J \
                    >"$port_dir/kcat/metadata-ssl.json" \
                    2>"$port_dir/kcat/metadata-ssl-json.stderr"
                printf '\n[exit-code] %s\n' "$?" >>"$port_dir/kcat/metadata-ssl-json.stderr"
            fi
        else
            metadata_txt="$port_dir/kcat/metadata-plaintext.txt"

            timeout "$KCAT_TIMEOUT" kcat \
                -b "$target" \
                -L \
                >"$metadata_txt" 2>&1
            kcat_rc=$?
            printf '\n[exit-code] %s\n' "$kcat_rc" >>"$metadata_txt"

            if kcat -h 2>&1 | grep -q -- '-J'; then
                timeout "$KCAT_TIMEOUT" kcat \
                    -b "$target" \
                    -L -J \
                    >"$port_dir/kcat/metadata-plaintext.json" \
                    2>"$port_dir/kcat/metadata-plaintext-json.stderr"
                printf '\n[exit-code] %s\n' "$?" >>"$port_dir/kcat/metadata-plaintext-json.stderr"
            fi
        fi

        # A successful -L request was made without supplying any Kafka
        # credentials, SASL settings, client certificate or application token.
        if [[ "${kcat_rc:-1}" -eq 0 ]]; then
            add_finding \
                "Authentication / Information Exposure" \
                "$target" \
                "Kafka metadata was retrievable without supplied client credentials" \
                "An unauthenticated network client was able to obtain Kafka cluster metadata. Review whether anonymous metadata access is intended for this listener and whether broker/topic names reveal sensitive topology or application information." \
                "$metadata_txt"

            if grep -Eq '(^|[[:space:]])[0-9]+ brokers?:|[[:space:]]broker [0-9]+ at ' "$metadata_txt"; then
                add_note "$target" "Unauthenticated broker topology was returned by Kafka metadata."
            fi

            if grep -Eq '(^|[[:space:]])[0-9]+ topics?:|[[:space:]]topic "' "$metadata_txt"; then
                add_note "$target" "Unauthenticated topic metadata/names appear to have been returned. Review exposed names for sensitive application or environment information."
            fi

            if grep -Eq '(\.svc(\.|:)|\.cluster\.local|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)' "$metadata_txt"; then
                add_note "$target" "Kafka metadata appears to advertise internal/private addressing or cluster-local naming. This is context-dependent and is recorded as an observation rather than an automatic vulnerability."
            fi
        else
            if grep -Eqi 'SASL|authentication|SSL handshake|certificate|authorization' "$metadata_txt"; then
                add_note "$target" "Anonymous metadata retrieval was blocked or failed with an authentication/TLS/authorization-related response. Review the raw kcat evidence for the exact control encountered."
            else
                add_note "$target" "Kafka metadata retrieval did not succeed anonymously. Review the raw kcat error before drawing a security conclusion."
            fi
        fi

        {
            echo "Port: $port"
            echo "TCP nc exit code: $nc_rc"
            echo "TLS detected: $tls_detected"
            echo
        } >>"$host_dir/target.txt"
    done

    echo "Completed: $(date -Is)" >>"$host_dir/target.txt"
    echo "[+] Completed $host"
done

cat > "$OUT_ROOT/manual-review-checklist.md" <<'EOF'
# Kafka Manual Review Checklist

The automated script can only assess what is observable from the network without
credentials. Validate the following manually as evidence becomes available.

## Observable now
- Confirm the Kafka listener uses TLS where confidentiality/integrity are required.
- Review testssl.sh results for deprecated TLS protocols, weak ciphers, certificate
  expiry, hostname/SAN mismatch, trust-chain issues, and weak key/signature choices.
- Determine whether Kafka metadata is available without client authentication.
- Review whether anonymous metadata exposes broker names, private addressing,
  topic names, environment names, consumer/application naming, or other topology.
- Compare advertised broker listeners with the intended client/network boundary.

## Requires credentials or configuration access
- Confirm client authentication is required where intended (SASL and/or mTLS).
- Review enabled SASL mechanisms and avoid credential-bearing SASL/PLAIN over
  an unencrypted transport.
- Review ACLs for least privilege across Topic, Group, Cluster and transactional
  resources.
- Check for broad wildcard ACLs and excessive super-user assignments.
- Review any setting equivalent to allow.everyone.if.no.acl.found.
- Review whether auto topic creation is appropriate for the environment.
- Review listener separation for client, inter-broker and controller traffic.
- Review broker/client TLS trust stores, certificate lifecycle and secret storage.
- Review quotas / connection limits / request-size limits where availability abuse
  is in scope.
- Review topic replication, min.insync.replicas and unclean leader election against
  the application's integrity/availability requirements.
- Review retention and cleanup policies for sensitive message data.
- Review audit/operational logging and alerting for authentication failures,
  authorization failures, unusual producers/consumers and administrative changes.
- Review the Legacy Sink producer/consumer permissions against the exact intended
  topics and consumer groups.
- When approved test data is available, review downstream message validation and
  trust boundaries before any active malformed-message testing.
EOF

echo
echo "[+] Review complete"
echo "[+] Evidence saved under: $OUT_ROOT"
echo "[+] Candidate findings: $FINDINGS_MD"
echo "[+] Candidate findings CSV: $FINDINGS_CSV"
echo "[+] Review notes: $NOTES_MD"
echo "[+] Manual checklist: $OUT_ROOT/manual-review-checklist.md"
