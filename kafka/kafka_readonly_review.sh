#!/usr/bin/env bash

set -u
set -o pipefail

TESTSSL="${TESTSSL:-/home/kali/Desktop/testssl_2026-09-17/testssl.sh-3.3dev/testssl.sh}"
OUT_ROOT="${OUT_ROOT:-$PWD/kafka-review-$(date +%Y%m%d-%H%M%S)}"
PORTS="${PORTS:-9093}"

TCP_TIMEOUT="${TCP_TIMEOUT:-8}"
OPENSSL_TIMEOUT="${OPENSSL_TIMEOUT:-15}"
KCAT_TIMEOUT="${KCAT_TIMEOUT:-20}"
TESTSSL_TIMEOUT="${TESTSSL_TIMEOUT:-600}"

SASL_PROBE="${SASL_PROBE:-1}"
SASL_PROBE_USER="${SASL_PROBE_USER:-test_user}"
SASL_PROBE_PASS="${SASL_PROBE_PASS:-test_pwd}"

ALLOW_INSECURE_TLS_PROBE="${ALLOW_INSECURE_TLS_PROBE:-0}"

mkdir -p "$OUT_ROOT"

FINDINGS_MD="$OUT_ROOT/suggested-findings.md"
FINDINGS_CSV="$OUT_ROOT/suggested-findings.csv"
NOTES_MD="$OUT_ROOT/review-notes.md"
POSITIVE_MD="$OUT_ROOT/positive-controls.md"
SUMMARY_MD="$OUT_ROOT/security-summary.md"
FINDING_COUNT=0

cat > "$FINDINGS_MD" <<'EOF'

These are automatically generated **candidate findings** based on observed
network/TLS/Kafka behaviour. Every item requires analyst validation before being
included in a client report.

The script intentionally treats context-dependent issues such as private/self-
signed PKI, internal addressing, absent revocation URIs and post-quantum support
as observations unless stronger evidence establishes a practical weakness.

EOF

printf '"Category","Target","Suggested finding","Suggested severity","Rationale","Evidence"\n' > "$FINDINGS_CSV"

cat > "$NOTES_MD" <<'EOF'

Operational observations detected during the read-only review.

EOF

cat > "$POSITIVE_MD" <<'EOF'

Positive security controls observed during the read-only review.

EOF

usage() {
    cat <<'EOF'
Usage:
  kafka_readonly_review_v9.sh targets_fqdn.txt
  kafka_readonly_review_v9.sh targets_fqdn.txt targets_ip.txt

Environment:
  PORTS="9093"
  TESTSSL=/path/to/testssl.sh
  OUT_ROOT=/path/to/output
  TCP_TIMEOUT=8
  OPENSSL_TIMEOUT=15
  KCAT_TIMEOUT=20
  TESTSSL_TIMEOUT=600
  SASL_PROBE=1
  SASL_PROBE_USER=test_user
  SASL_PROBE_PASS=test_pwd
  ALLOW_INSECURE_TLS_PROBE=0

Input files contain one hostname or IPv4 address per line.
Blank lines and # comments are ignored.
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
    local severity="${6:-Review}"

    FINDING_COUNT=$((FINDING_COUNT + 1))

    {
        echo "## [$category] $title"
        echo
        echo "- **Target:** \`$target\`"
        echo "- **Suggested severity:** $severity"
        echo "- **Why it may matter:** $rationale"
        echo "- **Evidence:** \`$evidence\`"
        echo "- **Status:** Candidate finding — analyst validation required"
        echo
    } >> "$FINDINGS_MD"

    {
        csv_escape "$category"; printf ','
        csv_escape "$target"; printf ','
        csv_escape "$title"; printf ','
        csv_escape "$severity"; printf ','
        csv_escape "$rationale"; printf ','
        csv_escape "$evidence"; printf '\n'
    } >> "$FINDINGS_CSV"
}

add_note() {
    local target="$1"
    local note="$2"
    echo "- **$target:** $note" >> "$NOTES_MD"
}

add_positive() {
    local target="$1"
    local note="$2"
    echo "- **$target:** $note" >> "$POSITIVE_MD"
}

extract_kcat_result() {
    local infile="$1"
    local outfile="$2"
    local summary=""
    local exit_status=""

    exit_status="$(grep -Ea '^\[exit-code\]' "$infile" 2>/dev/null | tail -n 1 | sed -E 's/^\[exit-code\][[:space:]]*//')"

    if grep -Eqi 'Unsupported SASL mechanism' "$infile"; then
        summary="$(grep -Eai 'Unsupported SASL mechanism' "$infile" | tail -n 1)"
    elif grep -Eqi 'Authentication failed|Invalid username or password|SASL.*authentication.*failed' "$infile"; then
        summary="$(grep -Eai 'Authentication failed|Invalid username or password|SASL.*authentication.*failed' "$infile" | tail -n 1)"
    elif grep -Eqi 'certificate verify failed|certificate verification failed|SSL handshake failed' "$infile"; then
        summary="$(grep -Eai 'certificate verify failed|certificate verification failed|SSL handshake failed' "$infile" | tail -n 1)"
    elif grep -Eqi 'Failed to acquire metadata' "$infile"; then
        summary="$(grep -Eai 'Failed to acquire metadata' "$infile" | tail -n 1)"
    elif grep -Eqi 'Broker transport failure|Disconnected|disconnected|timed out|Timed out' "$infile"; then
        summary="$(grep -Eai 'Broker transport failure|Disconnected|disconnected|timed out|Timed out' "$infile" | tail -n 1)"
    elif metadata_success "$infile"; then
        summary="Kafka metadata returned successfully"
    else
        summary="$(grep -Eai '(^%[0-6]\|.*(ERROR|FAIL|AUTH)|(^|[[:space:]])ERROR[: ]|(^|[[:space:]])FAIL[: ]|Failed|failed)' "$infile" 2>/dev/null \
            | grep -Eavi '\|INIT\||initialized|builtin\.features' \
            | tail -n 1 || true)"
    fi

    if [[ -z "$summary" ]]; then
        summary="No concise result extracted; review full probe output"
    fi

    {
        echo "Summary: $summary"
        echo "Exit code: ${exit_status:-unknown}"
        echo
        echo "Relevant evidence:"
        grep -Eai 'Unsupported SASL mechanism|Authentication failed|Invalid username or password|SASL.*authentication.*failed|certificate verify failed|certificate verification failed|SSL handshake failed|Failed to acquire metadata|Broker transport failure|Disconnected|disconnected|timed out|Timed out|(^%[0-6]\|.*(ERROR|FAIL|AUTH))' "$infile" 2>/dev/null \
            | grep -Eavi '\|INIT\||initialized|builtin\.features' \
            | tail -n 25 || true
    } > "$outfile"
}

get_kcat_summary() {
    local summary_file="$1"
    sed -n 's/^Summary: //p' "$summary_file" | head -n 1
}

testssl_protocol_enabled() {
    local version_re="$1"
    local infile="$2"

    grep -Eai "$version_re" "$infile" 2>/dev/null         | grep -Eavi 'not offered|not supported|not available|disabled|(^|[[:space:]])no([[:space:]]|$)|false'         | grep -Eqi 'offered|supported|enabled|(^|[[:space:]])yes([[:space:]]|$)|true'
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

metadata_success() {
    local f="$1"
    grep -Eq '(^Metadata for all topics|[[:space:]]brokers?:|[[:space:]]broker [0-9]+ at |[[:space:]]topics?:)' "$f" 2>/dev/null
}

auth_failed_not_unsupported() {
    local f="$1"
    grep -Eqi 'Invalid username or password|Authentication failed|SASL.*authentication.*failed' "$f" 2>/dev/null && \
        ! grep -Eqi 'Unsupported SASL mechanism' "$f" 2>/dev/null
}

sasl_unsupported() {
    grep -Eqi 'Unsupported SASL mechanism' "$1" 2>/dev/null
}

extract_supported_mechs() {
    local dir="$1"
    grep -Ehi "broker's supported mechanisms:" "$dir"/*.txt 2>/dev/null \
      | sed -E "s/.*broker's supported mechanisms:[[:space:]]*//I" \
      | head -n 1
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage
    exit 1
fi

for f in "$@"; do
    [[ -r "$f" ]] || { echo "[!] Cannot read input file: $f" >&2; exit 1; }
done

missing=0
for cmd in getent nc nmap openssl kcat timeout awk sed grep sort date; do
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

        if [[ "$line" =~ ^[^:]+:[0-9]+$ ]]; then
            line="${line%:*}"
        fi

        TARGETS+=("$line")
    done < "$f"
done

mapfile -t TARGETS < <(printf '%s\n' "${TARGETS[@]}" | sort -u)

[[ "${#TARGETS[@]}" -gt 0 ]] || { echo "[!] No targets found." >&2; exit 1; }

{
    echo "Kafka read-only review"
    echo "Started: $(date -Is)"
    echo "Host: $(hostname)"
    echo "Input files: $*"
    echo "Candidate Kafka ports: $PORTS"
    echo "SASL probe enabled: $SASL_PROBE"
    echo "Insecure TLS diagnostic retry enabled: $ALLOW_INSECURE_TLS_PROBE"
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
} > "$OUT_ROOT/tool-versions.txt"

printf '%s\n' "${TARGETS[@]}" > "$OUT_ROOT/targets-normalised.txt"

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
    } > "$host_dir/target.txt"

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
    nmap -Pn -sT -p "$PORTS" --open \
        -oA "$host_dir/discovery/ports" "$host" \
        > "$host_dir/discovery/console.txt" 2>&1 || true

    mapfile -t OPEN_PORTS < <(
        awk '/^[0-9]+\/tcp[[:space:]]+open/ {
            split($1,a,"/");
            print a[1]
        }' "$host_dir/discovery/ports.nmap" 2>/dev/null | sort -n -u
    )

    if [[ "${#OPEN_PORTS[@]}" -eq 0 ]]; then
        echo "[!] No open candidate Kafka ports found" | tee "$host_dir/discovery/no-open-kafka-ports.txt"
        add_note "$host" "No open TCP listener was identified on the configured Kafka candidate port(s): $PORTS. This is a coverage/connectivity note, not a vulnerability."
        echo "Completed: $(date -Is)" >> "$host_dir/target.txt"
        continue
    fi

    printf '%s\n' "${OPEN_PORTS[@]}" > "$host_dir/discovery/open-ports.txt"

    for port in "${OPEN_PORTS[@]}"; do
        target="${host}:${port}"
        port_dir="$host_dir/port-$port"
        mkdir -p "$port_dir"/{tcp,nmap,tls,kcat/protocol-probes}

        banner "$target"

        echo "[*] TCP connectivity"
        timeout "$TCP_TIMEOUT" nc -vz -w 5 "$host" "$port" \
            > "$port_dir/tcp/nc.txt" 2>&1
        nc_rc=$?
        printf '\n[exit-code] %s\n' "$nc_rc" >> "$port_dir/tcp/nc.txt"

        echo "[*] Nmap service/version detection"
        nmap -Pn -sT -sV --version-light -p "$port" \
            -oA "$port_dir/nmap/service" "$host" \
            > "$port_dir/nmap/console.txt" 2>&1 || true

        echo "[*] TLS handshake probe"
        tls_raw="$port_dir/tls/openssl-s_client.txt"

        timeout "$OPENSSL_TIMEOUT" openssl s_client \
            -connect "${host}:${port}" \
            -servername "$host" \
            -showcerts </dev/null \
            > "$tls_raw" 2>&1
        openssl_rc=$?
        printf '\n[exit-code] %s\n' "$openssl_rc" >> "$tls_raw"

        tls_detected=0
        tls12_ok=0
        tls13_ok=0
        declare -a weak_tls_reasons=()
        declare -a weak_tls_sources=()

        if grep -Eq 'BEGIN CERTIFICATE|Protocol *:|Cipher is |Ciphersuite:' "$tls_raw"; then
            tls_detected=1
            echo "TLS detected" > "$port_dir/tls/status.txt"
            add_positive "$target" "TLS was detected on the Kafka listener."

            timeout "$OPENSSL_TIMEOUT" openssl s_client \
                -connect "${host}:${port}" -servername "$host" -tls1_3 \
                </dev/null > "$port_dir/tls/openssl-tls13.txt" 2>&1 || true

            timeout "$OPENSSL_TIMEOUT" openssl s_client \
                -connect "${host}:${port}" -servername "$host" -tls1_2 \
                </dev/null > "$port_dir/tls/openssl-tls12.txt" 2>&1 || true

            grep -Eq 'New, TLSv1\.3|Protocol *: TLSv1\.3|Protocol  *TLSv1\.3' "$port_dir/tls/openssl-tls13.txt" && tls13_ok=1
            [[ "$tls13_ok" -eq 1 ]] && add_positive "$target" "TLS 1.3 was successfully negotiated."
            grep -Eq 'New, TLSv1\.2|Protocol *: TLSv1\.2|Protocol  *TLSv1\.2' "$port_dir/tls/openssl-tls12.txt" && tls12_ok=1
            [[ "$tls12_ok" -eq 1 ]] && add_positive "$target" "TLS 1.2 was successfully negotiated."

            if [[ "$tls12_ok" -eq 1 && "$tls13_ok" -eq 0 ]]; then
                weak_tls_reasons+=("TLS 1.3 was not offered; TLS 1.2 was available")
                weak_tls_sources+=("$port_dir/tls/openssl-tls13.txt")
            fi

            timeout "$OPENSSL_TIMEOUT" bash -c \
                "openssl s_client -connect '${host}:${port}' -servername '${host}' </dev/null 2>/dev/null \
                 | openssl x509 -noout -subject -issuer -serial -dates -ext subjectAltName" \
                > "$port_dir/tls/certificate-summary.txt" 2>&1 || true

            if [[ -f "$TESTSSL" ]]; then
                echo "[*] Running testssl.sh"
                mkdir -p "$port_dir/tls/testssl"

                MAX_OSSL_FAIL=6 \
                timeout "$TESTSSL_TIMEOUT" \
                bash "$TESTSSL" \
                    --socket-timeout 30 \
                    --openssl-timeout 30 \
                    --warnings batch \
                    -oA "$port_dir/tls/testssl" \
                    "${host}:${port}" \
                    > "$port_dir/tls/testssl-console.txt" 2>&1
                testssl_rc=$?
                printf '\n[exit-code] %s\n' "$testssl_rc" >> "$port_dir/tls/testssl-console.txt"

                if grep -Eqi 'self[- ]signed' "$port_dir/tls/testssl-console.txt"; then
                    weak_tls_reasons+=("Self-signed/private certificate presented")
                    weak_tls_sources+=("$port_dir/tls/testssl-console.txt")
                fi

                if grep -Eqi 'neither CRL nor OCSP URI provided|CRL.*not provided|OCSP.*not provided' "$port_dir/tls/testssl-console.txt"; then
                    weak_tls_reasons+=("No CRL or OCSP URI was reported")
                    weak_tls_sources+=("$port_dir/tls/testssl-console.txt")
                fi

                if grep -Eqi 'KEM.*not offered|no KEM|post.?quantum.*not offered' "$port_dir/tls/testssl-console.txt"; then
                    weak_tls_reasons+=("No post-quantum/hybrid KEM was observed")
                    weak_tls_sources+=("$port_dir/tls/testssl-console.txt")
                fi

                if testssl_protocol_enabled 'TLS[[:space:]]*1\.0|TLSv1([^.]|$)' "$port_dir/tls/testssl-console.txt"; then
                    add_finding \
                        "TLS Hardening" "$target" \
                        "Deprecated TLS 1.0 appears to be supported" \
                        "TLS 1.0 is obsolete and should be disabled where application compatibility permits. Retain modern TLS versions and cipher suites." \
                        "$port_dir/tls/testssl-console.txt" \
                        "Medium"
                else
                    add_positive "$target" "TLS 1.0 was not reported as enabled by testssl.sh."
                fi

                if testssl_protocol_enabled 'TLS[[:space:]]*1\.1|TLSv1\.1' "$port_dir/tls/testssl-console.txt"; then
                    add_finding \
                        "TLS Hardening" "$target" \
                        "Deprecated TLS 1.1 appears to be supported" \
                        "TLS 1.1 is obsolete and should be disabled where application compatibility permits. Retain modern TLS versions and cipher suites." \
                        "$port_dir/tls/testssl-console.txt" \
                        "Medium"
                else
                    add_positive "$target" "TLS 1.1 was not reported as enabled by testssl.sh."
                fi

                if grep -Eqi 'certificate.*expired|expired.*certificate' "$port_dir/tls/testssl-console.txt"; then
                    add_finding \
                        "Certificate Management" "$target" \
                        "The Kafka TLS certificate appears to be expired" \
                        "Expired certificates undermine reliable server-authentication and commonly lead clients to disable certificate validation or experience service failures." \
                        "$port_dir/tls/testssl-console.txt" \
                        "Medium"
                fi

                if grep -Eqi 'hostname.*(mismatch|does not match)|certificate.*does not match.*(host|name)|SAN.*mismatch' "$port_dir/tls/testssl-console.txt"; then
                    add_finding \
                        "Certificate Management" "$target" \
                        "The Kafka TLS certificate may not match the tested hostname" \
                        "A hostname/SAN mismatch prevents clients from reliably authenticating the intended broker when normal certificate validation is enabled." \
                        "$port_dir/tls/testssl-console.txt" \
                        "Medium"
                fi
            else
                echo "[!] testssl.sh not found at: $TESTSSL" > "$port_dir/tls/testssl-not-run.txt"
            fi

            if [[ "${#weak_tls_reasons[@]}" -gt 0 ]]; then
                weak_tls_evidence="$port_dir/tls/weaker-tls-evidence.txt"
                {
                    echo "Low-risk TLS hardening observations for $target"
                    echo
                    for reason in "${weak_tls_reasons[@]}"; do
                        echo "- $reason"
                    done
                    echo
                    echo "Source evidence:"
                    for source in "${weak_tls_sources[@]}"; do
                        echo "- $source"
                    done
                } > "$weak_tls_evidence"

                weak_tls_summary="$(printf '%s; ' "${weak_tls_reasons[@]}")"
                weak_tls_summary="${weak_tls_summary%; }"

                add_finding \
                    "TLS Hardening" "$target" \
                    "Weaker TLS Configuration" \
                    "TLS is enabled and materially reduces network-level exposure; however, one or more lower-impact hardening observations were identified: ${weak_tls_summary}. Review these items in the context of the organisation's private-PKI model, client compatibility and cryptographic-agility requirements. Where practical, use a managed trust chain, defined revocation handling, TLS 1.3 and a forward plan for post-quantum/hybrid cryptography." \
                    "$weak_tls_evidence" \
                    "Informational / Very Low"
            fi
        else
            echo "TLS not positively detected by OpenSSL" > "$port_dir/tls/status.txt"
            add_note "$target" "TLS was not positively detected during the initial OpenSSL probe. Kafka protocol probes below are used to determine whether a plaintext Kafka listener is actually accessible."
        fi

        probe_dir="$port_dir/kcat/protocol-probes"
        protocol_csv="$port_dir/kcat/protocol-summary.csv"
        printf '"Protocol","Mechanism","Result","Evidence"\n' > "$protocol_csv"

        echo "[*] Kafka protocol probes starting for $target"
        echo "[*] Kafka protocol probe: PLAINTEXT"
        plaintext_file="$probe_dir/PLAINTEXT.txt"
        (
            echo "$ kcat -b $target -X security.protocol=PLAINTEXT -d security,broker,protocol -L"
            echo
            timeout "$KCAT_TIMEOUT" kcat \
                -b "$target" \
                -X security.protocol=PLAINTEXT \
                -d security,broker,protocol \
                -L
            plaintext_rc=$?
            printf '\n[exit-code] %s\n' "$plaintext_rc"
            exit "$plaintext_rc"
        ) > "$plaintext_file" 2>&1
        plaintext_rc=$?
        extract_kcat_result "$plaintext_file" "$probe_dir/PLAINTEXT-result-summary.txt"
        echo "[>] PLAINTEXT result: $(get_kcat_summary "$probe_dir/PLAINTEXT-result-summary.txt")"

        plaintext_success=0
        if [[ "$plaintext_rc" -eq 0 ]] && metadata_success "$plaintext_file"; then
            plaintext_success=1
            printf '"PLAINTEXT","","metadata returned","%s"\n' "$plaintext_file" >> "$protocol_csv"
            add_finding \
                "Transport Security / Authentication" "$target" \
                "Kafka metadata is accessible over an unauthenticated PLAINTEXT connection" \
                "The listener accepted an unencrypted, unauthenticated Kafka connection and returned cluster metadata. Kafka application data on such a listener would not receive TLS confidentiality or integrity protection." \
                "$plaintext_file" \
                "Medium"
        else
            printf '"PLAINTEXT","","not accepted / inconclusive","%s"\n' "$plaintext_file" >> "$protocol_csv"
            add_positive "$target" "Unauthenticated Kafka PLAINTEXT metadata retrieval was not successful on $port."
        fi

        echo "[*] Kafka protocol probe: SSL"
        ssl_file="$probe_dir/SSL.txt"
        (
            echo "$ kcat -b $target -X security.protocol=SSL -d security,broker,protocol -L"
            echo
            timeout "$KCAT_TIMEOUT" kcat \
                -b "$target" \
                -X security.protocol=SSL \
                -d security,broker,protocol \
                -L
            ssl_rc=$?
            printf '\n[exit-code] %s\n' "$ssl_rc"
            exit "$ssl_rc"
        ) > "$ssl_file" 2>&1
        ssl_rc=$?
        extract_kcat_result "$ssl_file" "$probe_dir/SSL-result-summary.txt"
        echo "[>] SSL result: $(get_kcat_summary "$probe_dir/SSL-result-summary.txt")"

        ssl_success=0
        ssl_diag_file=""
        if [[ "$ssl_rc" -eq 0 ]] && metadata_success "$ssl_file"; then
            ssl_success=1
            ssl_diag_file="$ssl_file"
        elif grep -Eqi 'certificate verify failed|certificate verification failed|SSL handshake failed' "$ssl_file" && \
             [[ "$ALLOW_INSECURE_TLS_PROBE" == "1" ]]; then
            ssl_diag_file="$probe_dir/SSL-insecure-diagnostic.txt"
            (
                echo "$ kcat -b $target -X security.protocol=SSL -X enable.ssl.certificate.verification=false -d security,broker,protocol -L"
                echo
                timeout "$KCAT_TIMEOUT" kcat \
                    -b "$target" \
                    -X security.protocol=SSL \
                    -X enable.ssl.certificate.verification=false \
                    -d security,broker,protocol \
                    -L
                ssl_diag_rc=$?
                printf '\n[exit-code] %s\n' "$ssl_diag_rc"
                exit "$ssl_diag_rc"
            ) > "$ssl_diag_file" 2>&1
            ssl_diag_rc=$?
            extract_kcat_result "$ssl_diag_file" "$probe_dir/SSL-insecure-diagnostic-result-summary.txt"
            echo "[>] SSL diagnostic retry (certificate verification disabled): $(get_kcat_summary "$probe_dir/SSL-insecure-diagnostic-result-summary.txt")"

            if [[ "$ssl_diag_rc" -eq 0 ]] && metadata_success "$ssl_diag_file"; then
                ssl_success=1
                add_note "$target" "SSL metadata succeeded only after certificate verification was disabled for diagnostic purposes. This does not establish that production clients disable certificate verification."
            fi
        fi

        if [[ "$ssl_success" -eq 1 ]]; then
            printf '"SSL","","metadata returned without Kafka credentials","%s"\n' "$ssl_diag_file" >> "$protocol_csv"
            add_finding \
                "Authentication / Information Exposure" "$target" \
                "Kafka metadata is retrievable over SSL without Kafka client authentication" \
                "An SSL-only Kafka client was able to retrieve cluster metadata without SASL credentials or a supplied client identity. Confirm whether anonymous metadata access is intended and assess whether exposed broker/topic information is sensitive." \
                "$ssl_diag_file" \
                "Informational / Low"

            if grep -Eq '(\.svc(\.|:)|\.cluster\.local|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)' "$ssl_diag_file"; then
                add_note "$target" "Anonymous SSL metadata appears to expose private/internal addressing or cluster-local naming."
            fi
        else
            printf '"SSL","","not accepted / authentication or TLS control encountered","%s"\n' "$ssl_file" >> "$protocol_csv"
            add_positive "$target" "SSL-only Kafka metadata retrieval without SASL credentials was not successful."
        fi

        plain_sasl_plaintext=0
        scram256_sasl_plaintext=0
        scram512_sasl_plaintext=0
        plain_sasl_ssl=0
        scram256_sasl_ssl=0
        scram512_sasl_ssl=0

        sasl_pt_dir="$probe_dir/SASL_PLAINTEXT"
        sasl_ssl_dir="$probe_dir/SASL_SSL"
        mkdir -p "$sasl_pt_dir" "$sasl_ssl_dir"

        if [[ "$SASL_PROBE" == "1" ]]; then
            echo "[*] Running SASL_PLAINTEXT and SASL_SSL mechanism probes"
            echo "SASL probes enabled" > "$probe_dir/SASL-probe-status.txt"

            for mech in PLAIN SCRAM-SHA-256 SCRAM-SHA-512; do
                f="$sasl_pt_dir/${mech}.txt"
                (
                    echo "$ kcat -b $target -X security.protocol=SASL_PLAINTEXT -X sasl.mechanism=$mech -X sasl.username=$SASL_PROBE_USER -X sasl.password=<dummy> -d security,broker,protocol -L"
                    echo
                    timeout "$KCAT_TIMEOUT" kcat \
                        -b "$target" \
                        -X security.protocol=SASL_PLAINTEXT \
                        -X "sasl.mechanism=$mech" \
                        -X "sasl.username=$SASL_PROBE_USER" \
                        -X "sasl.password=$SASL_PROBE_PASS" \
                        -d security,broker,protocol \
                        -L
                    rc=$?
                    printf '\n[exit-code] %s\n' "$rc"
                    exit "$rc"
                ) > "$f" 2>&1
                rc=$?
                extract_kcat_result "$f" "$sasl_pt_dir/${mech}-result-summary.txt"
                echo "[>] SASL_PLAINTEXT/$mech: $(get_kcat_summary "$sasl_pt_dir/${mech}-result-summary.txt")"

                if auth_failed_not_unsupported "$f"; then
                    printf '"SASL_PLAINTEXT","%s","mechanism accepted; dummy credentials rejected","%s"\n' "$mech" "$f" >> "$protocol_csv"
                    case "$mech" in
                        PLAIN) plain_sasl_plaintext=1 ;;
                        SCRAM-SHA-256) scram256_sasl_plaintext=1 ;;
                        SCRAM-SHA-512) scram512_sasl_plaintext=1 ;;
                    esac
                elif sasl_unsupported "$f"; then
                    printf '"SASL_PLAINTEXT","%s","unsupported mechanism","%s"\n' "$mech" "$f" >> "$protocol_csv"
                else
                    printf '"SASL_PLAINTEXT","%s","not accepted / inconclusive","%s"\n' "$mech" "$f" >> "$protocol_csv"
                fi

                f="$sasl_ssl_dir/${mech}.txt"
                declare -a ssl_args=()
                if [[ "$ALLOW_INSECURE_TLS_PROBE" == "1" ]]; then
                    ssl_args=(-X enable.ssl.certificate.verification=false)
                fi

                (
                    echo "$ kcat -b $target -X security.protocol=SASL_SSL -X sasl.mechanism=$mech -X sasl.username=$SASL_PROBE_USER -X sasl.password=<dummy> -d security,broker,protocol -L"
                    echo
                    timeout "$KCAT_TIMEOUT" kcat \
                        -b "$target" \
                        -X security.protocol=SASL_SSL \
                        -X "sasl.mechanism=$mech" \
                        -X "sasl.username=$SASL_PROBE_USER" \
                        -X "sasl.password=$SASL_PROBE_PASS" \
                        "${ssl_args[@]}" \
                        -d security,broker,protocol \
                        -L
                    rc=$?
                    printf '\n[exit-code] %s\n' "$rc"
                    exit "$rc"
                ) > "$f" 2>&1
                rc=$?
                extract_kcat_result "$f" "$sasl_ssl_dir/${mech}-result-summary.txt"
                echo "[>] SASL_SSL/$mech: $(get_kcat_summary "$sasl_ssl_dir/${mech}-result-summary.txt")"

                if auth_failed_not_unsupported "$f"; then
                    printf '"SASL_SSL","%s","mechanism accepted; dummy credentials rejected","%s"\n' "$mech" "$f" >> "$protocol_csv"
                    case "$mech" in
                        PLAIN) plain_sasl_ssl=1 ;;
                        SCRAM-SHA-256) scram256_sasl_ssl=1 ;;
                        SCRAM-SHA-512) scram512_sasl_ssl=1 ;;
                    esac
                elif sasl_unsupported "$f"; then
                    printf '"SASL_SSL","%s","unsupported mechanism","%s"\n' "$mech" "$f" >> "$protocol_csv"
                else
                    printf '"SASL_SSL","%s","not accepted / inconclusive","%s"\n' "$mech" "$f" >> "$protocol_csv"
                fi
            done

            if [[ "$plain_sasl_plaintext" -eq 0 && "$scram256_sasl_plaintext" -eq 0 && "$scram512_sasl_plaintext" -eq 0 ]]; then
                add_positive "$target" "No tested SASL mechanism progressed to credential validation over SASL_PLAINTEXT."
            fi

            if [[ "$plain_sasl_ssl" -eq 1 ]]; then
                add_positive "$target" "SASL_SSL authentication is enforced: the PLAIN mechanism was accepted but the dummy credentials were rejected."
            fi

            supported_mechs="$(extract_supported_mechs "$sasl_ssl_dir")"
            if [[ -z "$supported_mechs" ]]; then
                supported_mechs="$(extract_supported_mechs "$sasl_pt_dir")"
            fi
            if [[ -n "$supported_mechs" ]]; then
                add_note "$target" "Broker-advertised SASL mechanisms: $supported_mechs"
            fi

            if [[ "$plain_sasl_plaintext" -eq 1 ]]; then
                add_finding \
                    "Transport Security / Authentication" "$target" \
                    "SASL/PLAIN authentication is accepted without TLS protection" \
                    "The broker accepted the PLAIN SASL mechanism over SASL_PLAINTEXT and progressed to credential validation. PLAIN relies on the transport layer to protect credentials; exposing it without TLS can disclose usernames/passwords and Kafka message traffic to an attacker able to observe the network path." \
                    "$sasl_pt_dir/PLAIN.txt" \
                    "Medium / High"
            fi

            if [[ "$scram256_sasl_plaintext" -eq 1 || "$scram512_sasl_plaintext" -eq 1 ]]; then
                add_finding \
                    "Transport Security" "$target" \
                    "Kafka SASL authentication is accepted over an unencrypted transport" \
                    "SCRAM protects the password exchange better than SASL/PLAIN, but SASL_PLAINTEXT still leaves Kafka application traffic without TLS confidentiality and integrity. Prefer SASL_SSL for authenticated Kafka client traffic." \
                    "$sasl_pt_dir" \
                    "Medium"
            fi

            if [[ "$plain_sasl_ssl" -eq 1 && "$scram256_sasl_ssl" -eq 0 && "$scram512_sasl_ssl" -eq 0 ]]; then
                add_finding \
                    "Authentication Hardening" "$target" \
                    "SASL/PLAIN is enabled while Kafka SCRAM mechanisms are not offered" \
                    "SASL/PLAIN over TLS is a supported Kafka deployment and is not an authentication bypass. However, if password-based authentication is required, SCRAM provides stronger password authentication properties. Confirm whether PLAIN is required; if not, disable it and prefer the organisation's existing GSSAPI/Kerberos mechanism or consider SCRAM-SHA-512 where compatible. If PLAIN remains required, enforce SASL_SSL, certificate validation, strong unique credentials and secure secret storage." \
                    "$sasl_ssl_dir" \
                    "Informational / Low"
            fi

            if [[ "$ALLOW_INSECURE_TLS_PROBE" == "1" ]]; then
                add_note "$target" "SASL_SSL diagnostic probes disabled server-certificate verification because the tester did not have the listener trust anchor. This is a testing accommodation only and does not demonstrate production client behaviour."
            fi
        else
            echo "SASL probes disabled (SASL_PROBE=0)" > "$probe_dir/SASL-probe-status.txt"
            echo "SASL probes disabled" > "$sasl_pt_dir/NOT_RUN.txt"
            echo "SASL probes disabled" > "$sasl_ssl_dir/NOT_RUN.txt"
            add_note "$target" "SASL mechanism probes were not run (SASL_PROBE=0)."
        fi

        if [[ "$tls_detected" -eq 0 && "$plaintext_success" -eq 0 && \
              "$plain_sasl_plaintext" -eq 0 && "$scram256_sasl_plaintext" -eq 0 && \
              "$scram512_sasl_plaintext" -eq 0 ]]; then
            add_note "$target" "TLS was not positively identified, but plaintext Kafka probes also did not succeed. Treat transport classification as inconclusive rather than reporting lack of TLS."
        fi

        if [[ "$tls_detected" -eq 1 && "$plaintext_success" -eq 0 && \
              "$plain_sasl_plaintext" -eq 0 && "$scram256_sasl_plaintext" -eq 0 && \
              "$scram512_sasl_plaintext" -eq 0 ]]; then
            add_note "$target" "TLS was detected and the tested plaintext Kafka protocol variants were not accepted. This is a positive transport-control observation."
        fi

        {
            echo "Port: $port"
            echo "TCP nc exit code: $nc_rc"
            echo "TLS detected: $tls_detected"
            echo "TLS 1.2: $tls12_ok"
            echo "TLS 1.3: $tls13_ok"
            echo "PLAINTEXT metadata success: $plaintext_success"
            echo "SSL metadata success: $ssl_success"
            echo "SASL probe enabled: $SASL_PROBE"
            echo "SASL_PLAINTEXT PLAIN accepted: $plain_sasl_plaintext"
            echo "SASL_SSL PLAIN accepted: $plain_sasl_ssl"
            echo
        } >> "$host_dir/target.txt"
    done

    echo "Completed: $(date -Is)" >> "$host_dir/target.txt"
done

cat > "$OUT_ROOT/manual-review-checklist.md" <<'EOF'

The script can identify several network-visible controls and generate candidate
findings, but configuration/credential access is still required for a complete
Kafka security review.

- Kafka listener reachability and service fingerprinting.
- TLS presence, TLS 1.2/1.3, testssl.sh evidence and certificate observations.
- PLAINTEXT and SSL Kafka metadata behaviour.
- SASL_PLAINTEXT and SASL_SSL PLAIN/SCRAM mechanism behaviour (when enabled).
- Anonymous metadata/topology disclosure.
- Broker-advertised SASL mechanism information returned by the protocol.

- Confirm which authentication mechanism Legacy Sink actually uses.
- Validate production clients perform server-certificate verification.
- Review Kafka ACLs and least privilege for topics, groups, cluster and
  transactional resources.
- Identify wildcard ACLs, excessive super-users and any permissive defaults.
- Review allow.everyone.if.no.acl.found or equivalent authorizer behaviour.
- Review listener separation for client/inter-broker/controller traffic.
- Review secret storage and credential rotation.
- Review quotas, request/message-size limits and abuse controls.
- Review topic replication, min.insync.replicas and unclean leader election.
- Review retention/cleanup policies for sensitive message data.
- Review authentication/authorization/admin audit logging and alerting.
- Compare Legacy Sink/Broker producer and consumer rights with intended flows.
- Once explicitly approved, validate message schema/input handling and downstream
  trust boundaries using safe test data.
EOF

{
    echo
    echo "---"
    echo
    if [[ "$FINDING_COUNT" -eq 0 ]]; then
        echo "**Automated result:** No candidate findings were generated by the current checks."
    else
        echo "**Automated result:** $FINDING_COUNT candidate finding(s) generated. Review every item before reporting."
    fi
} >> "$FINDINGS_MD"

positive_count="$(grep -Ec '^- \*\*' "$POSITIVE_MD" 2>/dev/null || true)"
note_count="$(grep -Ec '^- \*\*' "$NOTES_MD" 2>/dev/null || true)"

{
    echo "# Kafka Security Review Summary"
    echo
    echo "## Security Positives"
    echo
    if [[ "${positive_count:-0}" -gt 0 ]]; then
        grep -E '^- \*\*' "$POSITIVE_MD" || true
    else
        echo "- No positive controls were automatically identified."
    fi
    echo
    echo "## Candidate Security Findings"
    echo
    if [[ "$FINDING_COUNT" -gt 0 ]]; then
        awk '
            /^## \[/ {
                title=$0
                sub(/^## /,"",title)
                severity=""
                target=""
            }
            /^- \*\*Target:\*\*/ {
                target=$0
                sub(/^- \*\*Target:\*\* /,"",target)
            }
            /^- \*\*Suggested severity:\*\*/ {
                severity=$0
                sub(/^- \*\*Suggested severity:\*\* /,"",severity)
                printf "- %s — %s — %s\n", title, severity, target
            }
        ' "$FINDINGS_MD"
    else
        echo "- No candidate findings were automatically identified."
    fi
    echo
    echo "## Contextual Observations"
    echo
    if [[ "${note_count:-0}" -gt 0 ]]; then
        grep -E '^- \*\*' "$NOTES_MD" || true
    else
        echo "- No additional contextual observations were recorded."
    fi
    echo
    echo "## Totals"
    echo
    echo "- Positive controls: ${positive_count:-0}"
    echo "- Candidate findings: $FINDING_COUNT"
    echo "- Contextual observations: ${note_count:-0}"
    echo
    echo "Automated classifications require analyst validation before reporting."
} > "$SUMMARY_MD"

echo
echo "============================================================"
echo "Kafka Security Review Summary"
echo "============================================================"
echo "[+] Positive controls:       ${positive_count:-0}"
echo "[-] Candidate findings:      $FINDING_COUNT"
echo "[i] Contextual observations: ${note_count:-0}"
echo
echo "[+] Positive security controls:"
if [[ "${positive_count:-0}" -gt 0 ]]; then
    grep -E '^- \*\*' "$POSITIVE_MD" | sed 's/^- /    + /' || true
else
    echo "    + None automatically identified"
fi
echo
echo "[-] Candidate security findings:"
if [[ "$FINDING_COUNT" -gt 0 ]]; then
    awk '
        /^## \[/ {
            title=$0
            sub(/^## /,"",title)
            severity=""
        }
        /^- \*\*Suggested severity:\*\*/ {
            severity=$0
            sub(/^- \*\*Suggested severity:\*\* /,"",severity)
            printf "    - %s — %s\n", title, severity
        }
    ' "$FINDINGS_MD"
else
    echo "    - None automatically identified"
fi
echo
echo "[i] Full contextual observations are stored in:"
echo "    $NOTES_MD"
echo
echo "[+] Review complete"
echo "[+] Evidence:                $OUT_ROOT"
echo "[+] Consolidated summary:    $SUMMARY_MD"
echo "[+] Candidate findings:      $FINDINGS_MD"
echo "[+] Candidate findings CSV:  $FINDINGS_CSV"
echo "[+] Positive controls:       $POSITIVE_MD"
echo "[+] Review notes:            $NOTES_MD"
echo "[+] Protocol summaries:      <target>/port-<port>/kcat/protocol-summary.csv"
