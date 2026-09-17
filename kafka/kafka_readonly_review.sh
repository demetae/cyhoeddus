#!/usr/bin/env bash

set -u
set -o pipefail

TESTSSL="${TESTSSL:-/home/kali/Desktop/testssl_2026-09-17/testssl.sh-3.3dev/testssl.sh}"
OUT_ROOT="${OUT_ROOT:-$PWD/kafka-review-$(date +%Y%m%d-%H%M%S)}"

# Intentionally narrow defaults.
PORTS="${PORTS:-9092,9093,9094}"

TCP_TIMEOUT="${TCP_TIMEOUT:-8}"
OPENSSL_TIMEOUT="${OPENSSL_TIMEOUT:-15}"
KCAT_TIMEOUT="${KCAT_TIMEOUT:-20}"
TESTSSL_TIMEOUT="${TESTSSL_TIMEOUT:-600}"

mkdir -p "$OUT_ROOT"

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
        fi

        echo "[*] Kafka metadata request with kcat"

        if [[ "$tls_detected" -eq 1 ]]; then
            timeout "$KCAT_TIMEOUT" kcat \
                -b "$target" \
                -X security.protocol=SSL \
                -L \
                >"$port_dir/kcat/metadata-ssl.txt" 2>&1
            printf '\n[exit-code] %s\n' "$?" >>"$port_dir/kcat/metadata-ssl.txt"

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
            timeout "$KCAT_TIMEOUT" kcat \
                -b "$target" \
                -L \
                >"$port_dir/kcat/metadata-plaintext.txt" 2>&1
            printf '\n[exit-code] %s\n' "$?" >>"$port_dir/kcat/metadata-plaintext.txt"

            if kcat -h 2>&1 | grep -q -- '-J'; then
                timeout "$KCAT_TIMEOUT" kcat \
                    -b "$target" \
                    -L -J \
                    >"$port_dir/kcat/metadata-plaintext.json" \
                    2>"$port_dir/kcat/metadata-plaintext-json.stderr"
                printf '\n[exit-code] %s\n' "$?" >>"$port_dir/kcat/metadata-plaintext-json.stderr"
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

echo
echo "[+] Review complete"
echo "[+] Evidence saved under: $OUT_ROOT"
