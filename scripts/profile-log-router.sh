#!/bin/bash

PID_FILE="$1"
DEBUG_LOG="$2"
PROFILE_MAP="$3"
PROFILE_LOG_DIR="$4"

echo "$$" > "${PID_FILE}"
trap 'rm -f "${PID_FILE}"' EXIT INT TERM

sanitize_name() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'
}

tail -n +1 -F "${DEBUG_LOG}" | while IFS= read -r line; do
    if [[ "${line}" =~ [Pp][Rr][Oo][Ff][Ii][Ll][Ee][[:space:]]+([0-9]+) ]]; then
        profile_number="${BASH_REMATCH[1]}"
        strategy_name=$(awk -F '\t' -v number="${profile_number}" '$1 == number { print $2; exit }' "${PROFILE_MAP}")
        strategy_name=$(sanitize_name "${strategy_name:-unknown}")
        printf '%s\n' "${line}" >> "${PROFILE_LOG_DIR}/profile-${profile_number}-${strategy_name}.log"
    fi
done
