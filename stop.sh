#!/usr/bin/env bash
set -Eeuo pipefail

PID_FILE="/run/3b-nfqws.pid"
if sudo test -f "${PID_FILE}"; then
    pid="$(sudo cat "${PID_FILE}" 2>/dev/null || true)"
    [[ "${pid}" =~ ^[0-9]+$ ]] && sudo kill "${pid}" 2>/dev/null || true
    sudo rm -f "${PID_FILE}"
fi
for pair in "OUTPUT:THREEB_NFQWS_OUT" "INPUT:THREEB_NFQWS_IN" "OUTPUT:THREEB_NFQWS"; do
    builtin="${pair%%:*}"; chain="${pair#*:}"
    while sudo iptables -t mangle -C "${builtin}" -j "${chain}" 2>/dev/null; do sudo iptables -t mangle -D "${builtin}" -j "${chain}" || break; done
    sudo iptables -t mangle -F "${chain}" 2>/dev/null || true
    sudo iptables -t mangle -X "${chain}" 2>/dev/null || true
done
for helper in /run/3b-log-maintainer.pid /run/3b-log-router.pid; do
    if sudo test -f "${helper}"; then
        pid="$(sudo cat "${helper}" 2>/dev/null || true)"
        [[ "${pid}" =~ ^[0-9]+$ ]] && sudo kill "${pid}" 2>/dev/null || true
        sudo rm -f "${helper}"
    fi
done
echo "3B остановлен, управляемые правила удалены."
