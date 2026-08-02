#!/bin/bash

PID_FILE="$1"
LOG_DIR="$2"
MAX_BYTES="$3"

echo "$$" > "${PID_FILE}"
trap 'rm -f "${PID_FILE}"' EXIT INT TERM

while true; do
    total_size=0
    log_files=()
    while IFS= read -r -d '' log_file; do
        log_files+=("${log_file}")
        file_size=$(stat -c %s "${log_file}" 2>/dev/null || echo 0)
        total_size=$((total_size + file_size))
    done < <(find "${LOG_DIR}" -type f -name '*.log' -print0 2>/dev/null)

    if [ "${total_size}" -ge "${MAX_BYTES}" ]; then
        for log_file in "${log_files[@]}"; do
            truncate -s 0 "${log_file}"
        done
    fi
    sleep 5
done
