#!/usr/bin/env bash
set -Eeuo pipefail

LOG_FILE="${1:?usage: strategy-report.sh LOG_FILE ENGINE [RESULT_DIR]}"
ENGINE="${2:?usage: strategy-report.sh LOG_FILE ENGINE [RESULT_DIR]}"
RESULT_DIR="${3:-${LOG_FILE%.log}-results}"

[[ -f "${LOG_FILE}" ]] || { echo "Лог не найден: ${LOG_FILE}" >&2; exit 1; }
[[ "${ENGINE}" == "1" || "${ENGINE}" == "2" ]] || { echo "ENGINE должен быть 1 или 2" >&2; exit 1; }

mkdir -p "${RESULT_DIR}/domains" "${RESULT_DIR}/common"
: > "${RESULT_DIR}/index.tsv"

sanitize() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }
protocol_name() {
    case "$1" in
        curl_test_http) echo http ;;
        curl_test_https_tls12) echo tls12 ;;
        curl_test_https_tls13) echo tls13 ;;
        curl_test_http3) echo quic ;;
        *) echo unknown ;;
    esac
}
filter_for_protocol() {
    case "$1" in
        http) echo '--filter-tcp=80' ;;
        tls12|tls13) echo '--filter-tcp=443' ;;
        quic) echo '--filter-udp=443' ;;
    esac
}

in_summary=0
in_common=0
found=0
while IFS= read -r line; do
    line="${line%$'\r'}"
    if [[ "${line}" == "* SUMMARY" ]]; then in_summary=1; in_common=0; continue; fi
    if [[ "${line}" == "* COMMON" ]]; then in_common=1; continue; fi
    (( in_summary == 1 )) || continue
    [[ "${line}" == "Please note this SUMMARY"* ]] && break
    [[ -n "${line}" ]] || continue

    if (( in_common == 0 )) && [[ "${line}" =~ ^(curl_test_[^[:space:]]+)[[:space:]]+(ipv[46])[[:space:]]+([^[:space:]]+)[[:space:]]+:[[:space:]]+(nfqws2?|dvtws2?|winws2?)[[:space:]]+(.*)$ ]]; then
        test_name="${BASH_REMATCH[1]}"; ipver="${BASH_REMATCH[2]}"; domain_uri="${BASH_REMATCH[3]}"; strategy="${BASH_REMATCH[5]}"
        protocol="$(protocol_name "${test_name}")"
        domain="${domain_uri%%/*}"
        safe_domain="$(sanitize "${domain}")"
        target_dir="${RESULT_DIR}/domains/${safe_domain}"
        mkdir -p "${target_dir}"
        all_file="${target_dir}/${protocol}-${ipver}.all.conf"
        candidate_file="${target_dir}/${protocol}-${ipver}.candidate.conf"
        printf '%s\n' "${strategy}" >> "${all_file}"
        if [[ ! -f "${candidate_file}" ]]; then
            filter="$(filter_for_protocol "${protocol}")"
            {
                printf '# Generated from %s\n' "$(basename "${LOG_FILE}")"
                printf '# Domain: %s | protocol: %s | %s\n' "${domain}" "${protocol}" "${ipver}"
                printf '%s\n' "--new=${safe_domain}-${protocol}-${ipver}" "${filter}" "--hostlist-domains=${domain}"
                [[ "${ENGINE}" == "2" ]] && case "${protocol}" in
                    http) printf '%s\n' '--filter-l7=http' ;;
                    tls12|tls13) printf '%s\n' '--filter-l7=tls' ;;
                    quic) printf '%s\n' '--filter-l7=quic' ;;
                esac
                printf '%s\n' "${strategy}"
            } > "${candidate_file}"
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' "${domain}" "${protocol}" "${ipver}" "${candidate_file}" "${strategy}" >> "${RESULT_DIR}/index.tsv"
        ((found += 1))
    elif (( in_common == 1 )) && [[ "${line}" =~ ^(curl_test_[^[:space:]]+)[[:space:]]+(ipv[46])[[:space:]]+:[[:space:]]+(nfqws2?|dvtws2?|winws2?)[[:space:]]+(.*)$ ]]; then
        test_name="${BASH_REMATCH[1]}"; ipver="${BASH_REMATCH[2]}"; strategy="${BASH_REMATCH[4]}"
        protocol="$(protocol_name "${test_name}")"
        printf '%s\n' "${strategy}" >> "${RESULT_DIR}/common/${protocol}-${ipver}.all.conf"
    fi
done < "${LOG_FILE}"

find "${RESULT_DIR}" -type f -name '*.all.conf' -exec sort -u -o '{}' '{}' \;

# Build a ready-to-review candidate for strategies shared by all domains.
domains_csv="$(cut -f1 "${RESULT_DIR}/index.tsv" | LC_ALL=C sort -u | paste -sd, -)"
if [[ -n "${domains_csv}" ]]; then
    while IFS= read -r common_all; do
        base="$(basename "${common_all}" .all.conf)"
        protocol="${base%-ipv*}"
        ipver="ipv${base##*-ipv}"
        strategy="$(sed -n '1p' "${common_all}")"
        [[ -n "${strategy}" ]] || continue
        candidate_file="${RESULT_DIR}/common/${protocol}-${ipver}.candidate.conf"
        filter="$(filter_for_protocol "${protocol}")"
        {
            printf '# Shared candidate generated from %s\n' "$(basename "${LOG_FILE}")"
            printf '# Domains: %s | protocol: %s | %s\n' "${domains_csv}" "${protocol}" "${ipver}"
            printf '%s\n' "--new=common-${protocol}-${ipver}" "${filter}" "--hostlist-domains=${domains_csv}"
            [[ "${ENGINE}" == "2" ]] && case "${protocol}" in
                http) printf '%s\n' '--filter-l7=http' ;;
                tls12|tls13) printf '%s\n' '--filter-l7=tls' ;;
                quic) printf '%s\n' '--filter-l7=quic' ;;
            esac
            printf '%s\n' "${strategy}"
        } > "${candidate_file}"
    done < <(find "${RESULT_DIR}/common" -type f -name '*.all.conf' -print | LC_ALL=C sort)
fi

{
    echo "3B strategy test report"
    echo "source_log=${LOG_FILE}"
    echo "engine=nfqws${ENGINE}"
    echo "successful_domain_results=${found}"
    echo
    echo "domains/<domain>/*.candidate.conf  - first stable candidate, ready for review/copy"
    echo "domains/<domain>/*.all.conf        - every successful strategy for this domain/protocol"
    echo "common/*.candidate.conf            - first shared strategy wrapped for all tested domains"
    echo "common/*.all.conf                  - every strategy successful for all tested domains"
    echo "index.tsv                          - searchable index of all successes"
} > "${RESULT_DIR}/README.txt"

if (( found == 0 )); then
    echo "В SUMMARY нет успешных стратегий; структурированный отчёт пуст: ${RESULT_DIR}"
    exit 2
fi

echo "Структурированный отчёт: ${RESULT_DIR}"
echo "Успешных записей: ${found}"
find "${RESULT_DIR}/domains" -type f -name '*.candidate.conf' -print | LC_ALL=C sort
