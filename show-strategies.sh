#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_ROOT="${SCRIPT_DIR}/logs/tests/results"
DOMAIN_FILTER="${1:-}"

[[ -d "${RESULTS_ROOT}" ]] || { echo "Отчётов пока нет. Запустите ./test-strategies.sh"; exit 1; }
latest="$(find "${RESULTS_ROOT}" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | head -n1 | cut -d' ' -f2-)"
[[ -n "${latest}" ]] || { echo "Отчётов пока нет."; exit 1; }

echo "Последний отчёт: ${latest}"
echo
found=0
while IFS= read -r candidate; do
    if [[ -n "${DOMAIN_FILTER}" && "${candidate}" != *"/domains/${DOMAIN_FILTER}/"* ]]; then continue; fi
    found=1
    echo "===== ${candidate#${latest}/domains/} ====="
    sed -n '1,200p' "${candidate}"
    echo
done < <(find "${latest}/domains" -type f -name '*.candidate.conf' -print | LC_ALL=C sort)

(( found == 1 )) || { echo "Кандидаты для '${DOMAIN_FILTER}' не найдены."; exit 1; }

if find "${latest}/common" -type f -name '*.all.conf' -print -quit | grep -q .; then
    echo "===== COMMON: подходит всем проверенным доменам ====="
    while IFS= read -r common; do
        echo "--- $(basename "${common}") ---"
        sed -n '1,200p' "${common}"
    done < <(find "${latest}/common" -type f -name '*.all.conf' -print | LC_ALL=C sort)
fi
