#!/usr/bin/env bash
set -Eeuo pipefail

ENGINE="${1:?usage: live-strategy-capture.sh ENGINE RESULT_DIR [TOTAL] [STOP_AFTER_FOUND]}"
RESULT_DIR="${2:?usage: live-strategy-capture.sh ENGINE RESULT_DIR [TOTAL] [STOP_AFTER_FOUND]}"
TOTAL="${3:-0}"
STOP_AFTER_FOUND="${4:-0}"
mkdir -p "${RESULT_DIR}/domains" "${RESULT_DIR}/common"
touch "${RESULT_DIR}/index.live.tsv"

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

processed=0 found=0 started_at="$(date +%s)"
show_progress() {
    ((processed += 1))
    local width=30 filled=0 percent=0 elapsed now bar rest
    if (( TOTAL > 0 )); then
        percent=$((processed * 100 / TOTAL))
        (( percent > 100 )) && percent=100
        filled=$((percent * width / 100))
    fi
    printf -v bar '%*s' "${filled}" ''
    printf -v rest '%*s' "$((width - filled))" ''
    bar="${bar// /#}${rest// /-}"
    now="$(date +%s)"
    elapsed=$((now - started_at))
    if (( TOTAL > 0 )); then
        printf '\n>>> PROGRESS: [%s] %d/%d (%d%%) | найдено: %d | %02d:%02d\n\n' \
            "${bar}" "${processed}" "${TOTAL}" "${percent}" "${found}" "$((elapsed / 60))" "$((elapsed % 60))"
    else
        printf '\n>>> PROGRESS: обработано %d | найдено: %d | %02d:%02d\n\n' \
            "${processed}" "${found}" "$((elapsed / 60))" "$((elapsed % 60))"
    fi
}

current_test="" current_ipver="" current_domain="" current_strategy=""
while IFS= read -r line; do
    # Preserve the original tester output on screen.
    printf '%s\n' "${line}"
    clean="${line%$'\r'}"
    if [[ "${clean}" =~ ^-[[:space:]]+(curl_test_[^[:space:]]+)[[:space:]]+(ipv[46])[[:space:]]+([^[:space:]]+)[[:space:]]+:[[:space:]]+(nfqws2?|dvtws2?|winws2?)[[:space:]]+(.*)$ ]]; then
        current_test="${BASH_REMATCH[1]}"
        current_ipver="${BASH_REMATCH[2]}"
        current_domain="${BASH_REMATCH[3]}"
        current_strategy="${BASH_REMATCH[5]}"
        continue
    fi
    if [[ "${clean}" == UNAVAILABLE\ code=* ]] && [[ -n "${current_strategy}" ]]; then
        show_progress
        current_test="" current_ipver="" current_domain="" current_strategy=""
        continue
    fi
    [[ "${clean}" == *"!!!!! AVAILABLE !!!!!"* ]] || continue
    [[ -n "${current_test}" && -n "${current_domain}" && -n "${current_strategy}" ]] || continue

    protocol="$(protocol_name "${current_test}")"
    domain="${current_domain%%/*}"
    safe_domain="$(sanitize "${domain}")"
    target_dir="${RESULT_DIR}/domains/${safe_domain}"
    mkdir -p "${target_dir}"
    all_file="${target_dir}/${protocol}-${current_ipver}.all.conf"
    candidate_file="${target_dir}/${protocol}-${current_ipver}.candidate.conf"

    grep -Fxq -- "${current_strategy}" "${all_file}" 2>/dev/null || printf '%s\n' "${current_strategy}" >> "${all_file}"
    if [[ ! -f "${candidate_file}" ]]; then
        filter="$(filter_for_protocol "${protocol}")"
        {
            echo '# Captured live after all configured attempts succeeded'
            printf '# Domain: %s | protocol: %s | %s\n' "${domain}" "${protocol}" "${current_ipver}"
            printf '%s\n' "--new=${safe_domain}-${protocol}-${current_ipver}" "${filter}" "--hostlist-domains=${domain}"
            [[ "${ENGINE}" == "2" ]] && case "${protocol}" in
                http) echo '--filter-l7=http' ;;
                tls12|tls13) echo '--filter-l7=tls' ;;
                quic) echo '--filter-l7=quic' ;;
            esac
            printf '%s\n' "${current_strategy}"
        } > "${candidate_file}"
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "${domain}" "${protocol}" "${current_ipver}" "${candidate_file}" "${current_strategy}" >> "${RESULT_DIR}/index.live.tsv"
    printf '\n>>> FOUND: %s | %s | %s\n>>> SAVED: %s\n\n' "${domain}" "${protocol}" "${current_ipver}" "${candidate_file}"
    ((found += 1))
    show_progress
    current_test="" current_ipver="" current_domain="" current_strategy=""
    if (( STOP_AFTER_FOUND > 0 && found >= STOP_AFTER_FOUND )); then
        touch "${RESULT_DIR}/.stopped-after-found"
        printf '>>> AUTO-STOP: найдено %d/%d. Каждая находка прошла все настроенные повторы.\n' "${found}" "${STOP_AFTER_FOUND}"
        exit 0
    fi
done
