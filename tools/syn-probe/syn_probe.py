#!/usr/bin/env python3
"""Client-side, time-limited SYN diagnostic. No host firewall mutations on import."""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid

import adaptive

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
STATE_DIR = Path('/run/3b-syn-probe')
STATE_FILE = STATE_DIR / 'state.json'
LOCK_FILE = STATE_DIR / 'lock'
REPORT_ROOT = ROOT / 'reports' / 'syn-probe'
BIN = ROOT / 'vendor/zapret2/nfq2/nfqws2'
LUA_LIB = ROOT / 'vendor/zapret2/lua/zapret-lib.lua'
LUA_ANTIDPI = ROOT / 'vendor/zapret2/lua/zapret-antidpi.lua'
VERSION_FILE = ROOT / 'vendor/zapret2/VERSION'
DEFAULTS = HERE / 'config.example.env'
KEYS = {'TARGET_IP', 'TARGET_PORT', 'NFQUEUE_NUM', 'TEST_DURATION_SECONDS',
        'TEST_ATTEMPTS', 'CONNECT_TIMEOUT_SECONDS', 'ENABLE_PACKET_CAPTURE',
        'ENABLE_SYNDATA', 'REPORT_FORMATS'} | set(adaptive.DEFAULTS)
MANDATORY = {'TARGET_IP', 'TARGET_PORT', 'NFQUEUE_NUM', 'TEST_DURATION_SECONDS',
             'TEST_ATTEMPTS', 'CONNECT_TIMEOUT_SECONDS', 'ENABLE_PACKET_CAPTURE',
             'ENABLE_SYNDATA', 'REPORT_FORMATS'}


class ProbeError(Exception):
    pass


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def run(args, *, check=True, timeout=10):
    try:
        return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, check=check, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        raise ProbeError(f"command failed: {args[0]}: {exc}") from exc


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp.' + uuid.uuid4().hex)
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')
    os.replace(tmp, path)


def read_json(path):
    return json.loads(Path(path).read_text())


def parse_env(path):
    values = {}
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            raise ProbeError(f'{path}:{number}: expected KEY=value')
        key, value = line.split('=', 1)
        if key not in KEYS or key in values:
            raise ProbeError(f'{path}:{number}: unknown or duplicate key {key}')
        values[key] = value.strip().strip('"').strip("'")
    if MANDATORY - values.keys():
        raise ProbeError('missing configuration: ' + ', '.join(sorted(MANDATORY - values.keys())))
    return validate(values)


def validate(values):
    cfg = dict(values)
    try:
        cfg = adaptive.validate(cfg)
        addr = ipaddress.ip_address(cfg['TARGET_IP'])
        if addr.version != 4 or not addr.is_global:
            raise ValueError('target must be a public IPv4 address')
        cfg['TARGET_IP'] = str(addr)
        for key, low, high in [('TARGET_PORT', 1, 65535), ('NFQUEUE_NUM', 1, 65535),
                               ('TEST_DURATION_SECONDS', 15, 3600), ('TEST_ATTEMPTS', 1, 100),
                               ('CONNECT_TIMEOUT_SECONDS', 1, 30)]:
            raw = cfg[key]
            if not re.fullmatch(r'[0-9]+', raw):
                raise ValueError(f'{key} must be an integer')
            cfg[key] = int(raw)
            if not low <= cfg[key] <= high:
                raise ValueError(f'{key} must be {low}..{high}')
        for key in ('ENABLE_PACKET_CAPTURE', 'ENABLE_SYNDATA'):
            if cfg[key].lower() not in ('true', 'false'):
                raise ValueError(f'{key} must be true or false')
            cfg[key] = cfg[key].lower() == 'true'
        formats = cfg['REPORT_FORMATS'].split(',')
        if not formats or any(x not in ('json', 'markdown') for x in formats) or len(formats) != len(set(formats)):
            raise ValueError('REPORT_FORMATS must be json,markdown or a subset')
        cfg['REPORT_FORMATS'] = formats
    except (KeyError, ValueError) as exc:
        raise ProbeError(f'invalid configuration: {exc}') from exc
    return cfg


def binary_check():
    if not BIN.is_file() or not os.access(BIN, os.X_OK):
        raise ProbeError(f'vendored nfqws2 missing or not executable: {BIN}')
    if not LUA_LIB.is_file() or not LUA_ANTIDPI.is_file():
        raise ProbeError('vendored Zapret2 Lua files are missing')
    manifest = VERSION_FILE.read_text()
    match = re.search(r'nfqws2 linux-x86_64 sha256: ([0-9a-f]{64})', manifest)
    if not match:
        raise ProbeError('nfqws2 SHA-256 missing from vendor VERSION')
    with BIN.open('rb') as handle:
        digest = hashlib.file_digest(handle, 'sha256').hexdigest()
    if digest != match.group(1):
        raise ProbeError('nfqws2 SHA-256 does not match vendor VERSION')
    version = run([str(BIN), '--version'], check=False).stdout.strip().splitlines()
    if not version or 'v1.0.4' not in version[0]:
        raise ProbeError('unexpected nfqws2 version; expected vendored v1.0.4')
    return version[0]


def nfq_args(cfg, *, dry=False):
    args = [str(BIN)]
    if dry:
        args += ['--dry-run', '--intercept=0']
    args += [f"--qnum={cfg['NFQUEUE_NUM']}", '--fwmark=0x20000000']
    if not dry:
        args += ['--uid=0:0', '--debug=1']
    args += [f'--lua-init=@{LUA_LIB}', f'--lua-init=@{LUA_ANTIDPI}',
             '--name=3b-syn-probe', f"--filter-tcp={cfg['TARGET_PORT']}",
             '--lua-desync=syndata']
    return args


def queue_conflict(queue, *, read_rules=True):
    proc = Path('/proc/net/netfilter/nfnetlink_queue')
    if proc.exists():
        for line in proc.read_text().splitlines():
            parts = line.split()
            if parts and parts[0] == str(queue):
                return f'NFQUEUE {queue} already has a listener'
    if read_rules:
        for cmd in (['iptables-save'], ['nft', '-a', 'list', 'ruleset']):
            if shutil.which(cmd[0]):
                result = run(cmd, check=False)
                if result.returncode:
                    raise ProbeError(f'cannot inspect {cmd[0]} rules for NFQUEUE conflicts')
                output = result.stdout
                if cmd[0] == 'iptables-save':
                    for match in re.finditer(r'--queue-(?:num|balance)\s+(\d+)(?::(\d+))?', output):
                        low, high = int(match.group(1)), int(match.group(2) or match.group(1))
                        if low <= queue <= high:
                            return f'NFQUEUE {queue} referenced by iptables'
                if cmd[0] == 'nft':
                    for match in re.finditer(r'\bqueue\s+num\s+(\d+)(?:-(\d+))?', output):
                        low, high = int(match.group(1)), int(match.group(2) or match.group(1))
                        if low <= queue <= high:
                            return f'NFQUEUE {queue} referenced by nftables'
    return None


def exact_rule(cfg, run_id):
    return ['-p', 'tcp', '-d', cfg['TARGET_IP'], '--dport', str(cfg['TARGET_PORT']),
            '--tcp-flags', 'SYN,ACK', 'SYN', '-m', 'mark', '!', '--mark',
            '0x20000000/0x20000000', '-m', 'comment',
            '--comment', f'3b-syn-probe-{run_id}', '-j', 'NFQUEUE',
            '--queue-num', str(cfg['NFQUEUE_NUM']), '--queue-bypass']


def ipt(action, rule, *, check=True):
    result = run(['iptables', '-w', '-t', 'mangle', action, 'OUTPUT', *rule], check=check)
    if not check and result.returncode not in (0, 1):
        raise ProbeError(f'iptables {action} failed with code {result.returncode}: {result.stdout[-500:]}')
    return result.returncode == 0


def rule_present(rule):
    return ipt('-C', rule, check=False)


def proc_starttime(pid):
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
        return raw.rsplit(')', 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def proc_state(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
    except (OSError, IndexError):
        return None


def stop_owned_process(pid, starttime):
    if not pid or not starttime or proc_starttime(pid) != starttime or proc_state(pid) in ('Z', 'X'):
        return True
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGTERM)
    for _ in range(20):
        if proc_starttime(pid) != starttime or proc_state(pid) in ('Z', 'X'):
            return True
        time.sleep(0.1)
    if proc_starttime(pid) == starttime:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
    return proc_starttime(pid) != starttime or proc_state(pid) in ('Z', 'X')


@contextlib.contextmanager
def locked():
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    with LOCK_FILE.open('a+') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def cleanup(run_id=None):
    """Remove only the exact rule and process recorded by this module."""
    with locked():
        if not STATE_FILE.exists():
            return {'rollback': 'not needed', 'rule_remaining': False}
        state = read_json(STATE_FILE)
        if run_id is not None and state['run_id'] != run_id:
            return {'rollback': 'superseded', 'rule_remaining': False}
        rule = state['rule']
        errors = []
        if rule_present(rule):
            try:
                ipt('-D', rule)
            except ProbeError as exc:
                errors.append(str(exc))
        remaining = rule_present(rule)
        for kind in ('capture', 'nfq'):
            try:
                if stop_owned_process(state.get(f'{kind}_pid'), state.get(f'{kind}_starttime')) is False:
                    errors.append(f'{kind} process survived termination')
            except OSError as exc:
                errors.append(f'{kind} process termination failed: {exc}')
        result = {'rollback': 'failed' if errors or remaining else 'complete',
                  'rule_remaining': remaining, 'errors': errors, 'at': utc_now()}
        report_dir = Path(state['report_dir'])
        write_json(report_dir / 'rollback.json', result)
        if not errors and not remaining:
            STATE_FILE.unlink(missing_ok=True)
            with contextlib.suppress(OSError):
                watchdog_ready_path(state['run_id']).unlink(missing_ok=True)
        return result


def watchdog_ready_path(run_id):
    return STATE_DIR / f'watchdog-{run_id}.ready.json'


def await_watchdog_ready(process, run_id, timeout=5):
    """Require an acknowledgement written by the watchdog after it read our state."""
    end = time.monotonic() + timeout
    path = watchdog_ready_path(run_id)
    while time.monotonic() < end:
        if process.poll() is not None:
            raise ProbeError('watchdog exited before readiness acknowledgement')
        try:
            ready = read_json(path)
        except (OSError, ValueError):
            ready = None
        starttime = proc_starttime(process.pid)
        if ready and starttime and ready.get('run_id') == run_id and ready.get('pid') == process.pid \
                and ready.get('starttime') == starttime:
            return
        time.sleep(0.05)
    raise ProbeError('watchdog did not acknowledge readiness before firewall installation')


def await_nfqws_queue_ready(process, queue, log_path, timeout=3):
    """A listener alone may belong to another process; require nfqws2's bind log too."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if process.poll() is not None:
            raise ProbeError('nfqws2 exited before queue setup; see nfqws-debug.log')
        try:
            output = log_path.read_text(errors='replace')
        except OSError:
            output = ''
        if f"binding this socket to queue '{queue}'" in output and 'setting copy_packet mode' in output \
                and queue_conflict(queue, read_rules=False):
            return
        if 'nfq_create_queue():' in output:
            raise ProbeError('nfqws2 could not create NFQUEUE; see nfqws-debug.log')
        time.sleep(0.05)
    raise ProbeError('nfqws2 queue binding was not confirmed before firewall installation')


def watchdog(run_id):
    if not run_id:
        raise ProbeError('watchdog run ID required')
    with locked():
        if not STATE_FILE.exists() or read_json(STATE_FILE).get('run_id') != run_id:
            return 0
        write_json(watchdog_ready_path(run_id),
                   {'run_id': run_id, 'pid': os.getpid(), 'starttime': proc_starttime(os.getpid()),
                    'at': utc_now()})
    while True:
        try:
            if not STATE_FILE.exists():
                return 0
            state = read_json(STATE_FILE)
            if state['run_id'] != run_id:
                return 0
            remaining = state['deadline_epoch'] - time.time()
            if 'deadline_monotonic' in state:
                remaining = min(remaining, state['deadline_monotonic'] - time.monotonic())
            if remaining > 0:
                time.sleep(min(remaining, 1))
                continue
            result = cleanup(run_id)
            if result['rollback'] in ('complete', 'not needed', 'superseded'):
                return 0
        except (ProbeError, OSError, BlockingIOError, ValueError, KeyError) as exc:
            with contextlib.suppress(OSError):
                with (STATE_DIR / f'watchdog-{run_id}.log').open('a') as log:
                    log.write(f'{utc_now()} rollback retry: {exc}\n')
        # A concurrent cleanup or temporary firewall error must not abandon rollback.
        time.sleep(1)


def readiness(cfg, *, require_root=False, check_nfqws=True):
    if sys.platform != 'linux':
        raise ProbeError('Linux required')
    if require_root and os.geteuid() != 0:
        raise ProbeError('root required; use sudo')
    if require_root:
        status = Path('/proc/self/status').read_text()
        match = re.search(r'^CapEff:\s*([0-9a-fA-F]+)', status, re.M)
        caps = int(match.group(1), 16) if match else 0
        if not caps & (1 << 12) or not caps & (1 << 13):
            raise ProbeError('CAP_NET_ADMIN and CAP_NET_RAW are required')
    for program in ('iptables', 'iptables-save', 'ip', 'ss'):
        if not shutil.which(program):
            raise ProbeError(f'missing dependency: {program}')
    backend = run(['iptables', '-V']).stdout
    if 'nf_tables' in backend and not shutil.which('nft'):
        raise ProbeError('iptables uses nf_tables; nft is required to inspect queue conflicts')
    if cfg['ENABLE_PACKET_CAPTURE'] and not shutil.which('tcpdump'):
        raise ProbeError('ENABLE_PACKET_CAPTURE=true requires tcpdump')
    if check_nfqws:
        version = binary_check()
        dry = run(nfq_args(cfg, dry=True), check=False)
        if dry.returncode:
            raise ProbeError(f'nfqws2 rejected syndata preflight: {dry.stdout[-1200:]}')
        return version
    return None


def route_info(ip):
    probe = run(['ip', '-4', 'route', 'get', ip], check=False)
    result = probe.stdout.strip()
    if probe.returncode or not result or 'unreachable' in result:
        raise ProbeError(f'no IPv4 route to {ip}: {result}')
    if result.startswith('local ') or re.search(r'\bdev\s+lo\b', result):
        raise ProbeError('target resolves to this machine; SYN Probe must run on the remote client')
    dev = re.search(r'\bdev\s+(\S+)', result)
    src = re.search(r'\bsrc\s+(\S+)', result)
    return {'route': result, 'interface': dev.group(1) if dev else None,
            'source_ip': src.group(1) if src else None}


def management_info(cfg):
    connection = os.environ.get('SSH_CONNECTION', '').split()
    peer = connection[0] if len(connection) == 4 else None
    local_port = connection[3] if len(connection) == 4 else None
    return {'ssh_session_detected': bool(peer), 'ssh_peer': peer,
            'ssh_local_port': local_port,
            'target_rule_matches_ssh': bool(peer == cfg['TARGET_IP'] and local_port == str(cfg['TARGET_PORT'])),
            'reserve_access_verified': False}


def ssh_target_conflict(cfg):
    """Refuse to experiment on an existing SSH connection to the same endpoint."""
    result = run(['ss', '-Htnp', 'state', 'established'], check=False).stdout
    target = f"{cfg['TARGET_IP']}:{cfg['TARGET_PORT']}"
    return any(target in line for line in result.splitlines() if re.search(r'\bssh\b|:22\b', line))


def new_report_dir():
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S')
    path = REPORT_ROOT / f'{stamp}-{uuid.uuid4().hex[:8]}'
    path.mkdir(parents=True, exist_ok=False)
    return path


def snapshot(path):
    path.write_text(run(['iptables-save']).stdout)
    if shutil.which('nft'):
        result = run(['nft', '-a', 'list', 'ruleset'], check=False)
        if result.returncode:
            raise ProbeError('cannot snapshot nftables ruleset')
        path.with_suffix('.nft.txt').write_text(result.stdout)


def firewall_integrity(directory, own_rule_remaining=False):
    """Separate our exact rule from unrelated structure and dynamic counters."""
    before, after = directory / 'firewall-before.txt', directory / 'firewall-after.txt'
    pairs = [(before, after),
             (directory / 'firewall-before.nft.txt', directory / 'firewall-after.nft.txt')]
    if not before.exists() or not after.exists() or any(a.exists() != b.exists() for a, b in pairs):
        return {'own_rule_remaining': own_rule_remaining, 'foreign_rules_changed': 'unknown',
                'dynamic_counter_changes': 'unknown', 'dynamic_or_raw_changes': 'unknown'}
    raw_changed = False
    structural_changed = False
    counter_changed = False
    for first, second in pairs:
        if not first.exists():
            continue
        try:
            left, right = first.read_text(), second.read_text()
        except OSError:
            return {'own_rule_remaining': own_rule_remaining, 'foreign_rules_changed': 'unknown',
                    'dynamic_counter_changes': 'unknown', 'dynamic_or_raw_changes': 'unknown'}
        raw_changed |= left != right
        counter_changed |= (re.findall(r'\bcounter packets \d+ bytes \d+', left)
                            != re.findall(r'\bcounter packets \d+ bytes \d+', right))
        def normalized(value):
            value = '\n'.join(line for line in value.splitlines()
                              if not line.startswith(('# Generated by iptables-save', '# Completed on')))
            value = re.sub(r'\bcounter packets \d+ bytes \d+', 'counter', value)
            value = re.sub(r'\s+# handle \d+', '', value)
            return value
        structural_changed |= normalized(left) != normalized(right)
    return {'own_rule_remaining': own_rule_remaining,
            'foreign_rules_changed': 'unknown' if own_rule_remaining else structural_changed,
            'dynamic_counter_changes': counter_changed,
            'dynamic_or_raw_changes': raw_changed and not structural_changed}


def start_capture(cfg, report_dir):
    if not cfg['ENABLE_PACKET_CAPTURE']:
        return None
    args = ['tcpdump', '-i', 'any', '-nn', '-U', '-w', str(report_dir / 'tcpdump-client.pcap'),
            'tcp', 'and', 'host', cfg['TARGET_IP'], 'and', 'port', str(cfg['TARGET_PORT'])]
    err = (report_dir / 'tcpdump.log').open('w')
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err, start_new_session=True)
    err.close()
    time.sleep(0.25)
    if proc.poll() is not None:
        raise ProbeError('tcpdump exited before capture; see tcpdump.log')
    return proc


def finish_capture(proc):
    if proc and proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


def connect_attempts(cfg, deadline=None, journal=None, monotonic_deadline=None):
    attempts = []
    def record(item):
        attempts.append(item)
        if journal is not None:
            with Path(journal).open('a') as handle:
                handle.write(json.dumps(item, ensure_ascii=False) + '\n')
                handle.flush()
    for n in range(cfg['TEST_ATTEMPTS']):
        if ((deadline is not None and time.time() + cfg['CONNECT_TIMEOUT_SECONDS'] >= deadline)
                or (monotonic_deadline is not None
                    and time.monotonic() + cfg['CONNECT_TIMEOUT_SECONDS'] >= monotonic_deadline)):
            record({'number': n + 1, 'status': 'skipped_deadline', 'latency_ms': None})
            continue
        start = time.monotonic()
        start_epoch = time.time()
        try:
            with socket.create_connection((cfg['TARGET_IP'], cfg['TARGET_PORT']),
                                          timeout=cfg['CONNECT_TIMEOUT_SECONDS']):
                pass
            status, error = 'connected', None
        except socket.timeout as exc:
            status, error = 'timeout', str(exc)
        except OSError as exc:
            status, error = 'error', f'{type(exc).__name__}: {exc}'
        end_epoch = time.time()
        if ((deadline is not None and end_epoch >= deadline)
                or (monotonic_deadline is not None and time.monotonic() >= monotonic_deadline)):
            status = 'overlapped_watchdog'
            error = 'attempt crossed the automatic rollback deadline; excluded from outcome'
        record({'number': n + 1, 'status': status, 'error': error,
                'start_epoch': start_epoch, 'end_epoch': end_epoch,
                'latency_ms': round((time.monotonic() - start) * 1000, 3)})
    return attempts


def packet_counts(report_dir, cfg):
    path = report_dir / 'tcpdump-client.pcap'
    try:
        available = path.is_file() and path.stat().st_size > 0
    except OSError:
        available = False
    if not available:
        return {'status': 'unavailable', 'source': 'no readable client pcap',
                'syn': None, 'syn_ack': None, 'rst': None,
                'outgoing_syn_payload': None, 'handshakes': 'unknown'}
    try:
        result = run(['tcpdump', '-nn', '-tt', '-r', str(path)], check=False, timeout=30)
    except ProbeError:
        return {'status': 'unavailable', 'source': 'tcpdump read timed out or failed',
                'syn': None, 'syn_ack': None, 'rst': None,
                'outgoing_syn_payload': None, 'handshakes': 'unknown'}
    if result.returncode:
        return {'status': 'unavailable', 'source': 'tcpdump could not read pcap',
                'syn': None, 'syn_ack': None, 'rst': None,
                'outgoing_syn_payload': None, 'handshakes': 'unknown'}
    counts = {'syn': 0, 'syn_ack': 0, 'rst': 0, 'outgoing_syn_payload': 0}
    target = re.escape(cfg['TARGET_IP']) + r'\.' + str(cfg['TARGET_PORT'])
    for line in result.stdout.splitlines():
        if not re.search(target, line):
            continue
        flags = re.search(r'Flags \[([^]]+)\]', line)
        if not flags:
            continue
        token = flags.group(1)
        if 'R' in token:
            counts['rst'] += 1
        elif 'S' in token and '.' in token:
            counts['syn_ack'] += 1
        elif 'S' in token:
            counts['syn'] += 1
            if re.search(r'>\s*' + target + r':', line):
                length = re.search(r'\blength (\d+)\s*$', line)
                if length and int(length.group(1)) > 0:
                    counts['outgoing_syn_payload'] += 1
    return {'status': 'observed', 'source': 'client tcpdump pcap; TCP flags, retransmissions included',
            **counts, 'handshakes': 'unknown'}


def interception_evidence(queue_packets, log_path, packets):
    try:
        lines = log_path.read_text(errors='replace').splitlines()
    except OSError:
        lines = []
    seen = sum(line.startswith('packet: id=') for line in lines)
    invoked = sum(bool(re.search(r'\bsyndata:\s', line)) for line in lines)
    payload = packets.get('outgoing_syn_payload')
    return {'nfqueue_rule_packets': queue_packets,
            'nfqueue_hit': None if queue_packets is None else queue_packets > 0,
            'nfqws_packets_logged': seen if lines else None,
            'syndata_invocations_logged': invoked if lines else None,
            'nfqws_action_observed': None if not lines else invoked > 0,
            'outgoing_syn_payload_packets': payload,
            'outgoing_syn_payload_observed': None if payload is None else payload > 0,
            'modified_packet_confirmed': False,
            'attribution_limit': 'client pcap can show outgoing SYN payload but cannot prove wire delivery or exclusive nfqws attribution'}


def latest_baseline(cfg):
    for path in sorted(REPORT_ROOT.glob('*/baseline.json'), reverse=True):
        try:
            data = read_json(path)
            if data.get('target_ip') == cfg['TARGET_IP'] and data.get('target_port') == cfg['TARGET_PORT']:
                return str(path)
        except (OSError, ValueError):
            pass
    return None


def do_baseline(cfg, *, steps=None):
    readiness(cfg, require_root=True, check_nfqws=False)
    if STATE_FILE.exists():
        raise ProbeError('SYN Probe experiment is active; baseline would be contaminated')
    directory = new_report_dir()
    snapshot(directory / 'firewall-before.txt')
    info = {'start': utc_now(), 'mode': 'baseline', 'target_ip': cfg['TARGET_IP'],
            'target_port': cfg['TARGET_PORT'], 'route': route_info(cfg['TARGET_IP']),
            'kernel': os.uname().release,
            'nfqws2_version': VERSION_FILE.read_text().splitlines()[0] if VERSION_FILE.exists() else 'unknown'}
    info['configuration'] = cfg
    write_json(directory / 'metadata.json', info)
    (directory / 'environment.txt').write_text(json.dumps(info, indent=2) + '\n')
    cap = None
    attempts = []
    errors = []
    old_handlers = {}
    def interrupted(signum, frame):
        raise ProbeError(f'interrupted by signal {signum}')
    for sig in (signal.SIGINT, signal.SIGTERM):
        old_handlers[sig] = signal.signal(sig, interrupted)
    try:
        cap = start_capture(cfg, directory)
        if steps is None:
            attempts = connect_attempts(cfg, journal=directory / 'attempts.live.jsonl')
        else:
            deadline = time.time() + cfg['ADAPTIVE_DURATION_SECONDS']
            monotonic_deadline = time.monotonic() + cfg['ADAPTIVE_DURATION_SECONDS']
            adaptive.execute(cfg, steps, 'baseline', directory, attempts, deadline,
                             monotonic_deadline=monotonic_deadline)
    except (ProbeError, OSError) as exc:
        errors.append(str(exc))
    except Exception as exc:
        errors.append(f'unexpected {type(exc).__name__}: {exc}')
    finally:
        try:
            finish_capture(cap)
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f'capture shutdown failed: {exc}')
        try:
            snapshot(directory / 'firewall-after.txt')
        except (ProbeError, OSError) as exc:
            errors.append(f'firewall after snapshot unavailable: {exc}')
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    integrity = firewall_integrity(directory)
    data = {'target_ip': cfg['TARGET_IP'], 'target_port': cfg['TARGET_PORT'],
            'start': info['start'], 'end': utc_now(), 'attempts': attempts,
            'packets': packet_counts(directory, cfg),
            'errors': errors,
            'firewall_changed': integrity['foreign_rules_changed'],
            'firewall_integrity': integrity}
    if steps is not None:
        data['adaptive_plan'] = steps
        data['adaptive_analysis'] = adaptive.analyze(attempts, cfg['TARGET_PORT'])
    write_json(directory / 'baseline.json', data)
    generate_report(directory, cfg)
    print(directory)
    if errors:
        raise ProbeError('baseline had errors; inspect report')
    return directory


def confirm_target(cfg, args):
    expected = f"{cfg['TARGET_IP']}:{cfg['TARGET_PORT']}"
    if args.confirm_target != expected:
        if not sys.stdin.isatty():
            raise ProbeError(f'noninteractive test requires --confirm-target {expected}')
        answer = input(f'Type {expected} to authorize this target: ').strip()
        if answer != expected:
            raise ProbeError('target not confirmed')
    if not args.ack_recovery:
        if not sys.stdin.isatty():
            raise ProbeError('noninteractive test requires --ack-recovery')
        answer = input('Confirm reserve console/SSH access is available (type YES): ').strip()
        if answer != 'YES':
            raise ProbeError('reserve access not confirmed')


def do_test(cfg, args, *, steps=None, baseline_file=None, confirmed=False):
    if not cfg['ENABLE_SYNDATA']:
        raise ProbeError('ENABLE_SYNDATA=false: test has no strategy; use baseline')
    if not confirmed:
        confirm_target(cfg, args)
    version = readiness(cfg, require_root=True)
    if management_info(cfg)['target_rule_matches_ssh']:
        raise ProbeError('target rule would match current SSH management connection')
    if ssh_target_conflict(cfg):
        raise ProbeError('target endpoint appears in an established SSH connection')
    if STATE_FILE.exists():
        raise ProbeError('another SYN Probe state exists; inspect status or stop first')
    conflict = queue_conflict(cfg['NFQUEUE_NUM'])
    if conflict:
        raise ProbeError(conflict)
    directory = new_report_dir()
    snapshot(directory / 'firewall-before.txt')
    env = {'kernel': os.uname().release, 'nfqws2_version': version, 'configuration': cfg,
           'route': route_info(cfg['TARGET_IP']), 'management': management_info(cfg),
           'queue_conflict': conflict, 'started': utc_now()}
    write_json(directory / 'metadata.json', env)
    (directory / 'environment.txt').write_text(json.dumps(env, indent=2) + '\n')
    run_id = uuid.uuid4().hex[:12]
    rule = exact_rule(cfg, run_id)
    deadline = time.time() + (cfg['ADAPTIVE_DURATION_SECONDS'] if steps is not None
                              else cfg['TEST_DURATION_SECONDS'])
    monotonic_deadline = time.monotonic() + (cfg['ADAPTIVE_DURATION_SECONDS'] if steps is not None
                                              else cfg['TEST_DURATION_SECONDS'])
    state = {'run_id': run_id, 'rule': rule, 'report_dir': str(directory),
             'deadline_epoch': deadline, 'deadline_monotonic': monotonic_deadline,
             'nfq_pid': None, 'nfq_starttime': None,
             'capture_pid': None, 'capture_starttime': None,
             'queue': cfg['NFQUEUE_NUM'], 'phase': 'armed'}
    old_handlers = {}
    def interrupted(signum, frame):
        raise ProbeError(f'interrupted by signal {signum}')
    for sig in (signal.SIGINT, signal.SIGTERM):
        old_handlers[sig] = signal.signal(sig, interrupted)
    # State and watchdog precede every firewall mutation.
    try:
        with locked():
            if STATE_FILE.exists():
                raise ProbeError('parallel experiment detected')
            write_json(STATE_FILE, state)
        with (directory / 'watchdog.log').open('a') as watchdog_log:
            watchdog_proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                              '_watchdog', '--run-id', run_id],
                                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                             stderr=watchdog_log, start_new_session=True, close_fds=True)
        await_watchdog_ready(watchdog_proc, run_id)
    except BaseException:
        try:
            cleanup(run_id)
        finally:
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
        raise
    process = None
    capture = None
    rule_was_installed = False
    outcome = {'start': utc_now(), 'target_ip': cfg['TARGET_IP'],
               'target_port': cfg['TARGET_PORT'], 'queue': cfg['NFQUEUE_NUM'],
               'strategy': '--lua-desync=syndata',
               'baseline_file': (baseline_file if steps is not None else latest_baseline(cfg)),
               'attempts': [], 'errors': []}
    if steps is not None:
        outcome['adaptive_plan'] = steps
    outcome['status'] = 'in_progress'
    try:
        write_json(directory / 'experiment.json', outcome)
        with locked():
            state = read_json(STATE_FILE)
            if state['run_id'] != run_id or time.time() >= deadline or time.monotonic() >= monotonic_deadline:
                raise ProbeError('experiment expired or state changed before nfqws2 start')
            with (directory / 'nfqws-debug.log').open('w') as log:
                process = subprocess.Popen(nfq_args(cfg), stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
            starttime = proc_starttime(process.pid)
            if not starttime:
                raise ProbeError('cannot identify nfqws2 process')
            state.update(nfq_pid=process.pid, nfq_starttime=starttime, phase='nfqws-running')
            write_json(STATE_FILE, state)
        await_nfqws_queue_ready(process, cfg['NFQUEUE_NUM'], directory / 'nfqws-debug.log')
        outcome['nfqueue_listener_observed'] = True
        with locked():
            state = read_json(STATE_FILE)
            if state['run_id'] != run_id or time.time() >= deadline or time.monotonic() >= monotonic_deadline:
                raise ProbeError('experiment expired before capture start')
            capture = start_capture(cfg, directory)
            if capture:
                state.update(capture_pid=capture.pid, capture_starttime=proc_starttime(capture.pid))
                write_json(STATE_FILE, state)
        with locked():
            state = read_json(STATE_FILE)
            if state['run_id'] != run_id or time.time() >= deadline or time.monotonic() >= monotonic_deadline:
                raise ProbeError('experiment expired before firewall installation')
            if watchdog_proc.poll() is not None or not watchdog_ready_path(run_id).exists():
                raise ProbeError('watchdog is unavailable before firewall installation')
            ipt('-I', rule)
            rule_was_installed = True
            if not rule_present(rule):
                raise ProbeError('experimental rule was not installed')
            state['phase'] = 'rule-installed'
            write_json(STATE_FILE, state)
        if steps is None:
            outcome['attempts'] = connect_attempts(
                cfg, deadline, journal=directory / 'attempts.live.jsonl',
                monotonic_deadline=monotonic_deadline)
        else:
            adaptive.execute(cfg, steps, 'syndata', directory, outcome['attempts'], deadline,
                             monotonic_deadline=monotonic_deadline)
    except (ProbeError, OSError) as exc:
        outcome['errors'].append(str(exc))
    except Exception as exc:
        outcome['errors'].append(f'unexpected {type(exc).__name__}: {exc}')
        raise
    finally:
        if rule_was_installed:
            try:
                counters_result = run(['iptables', '-t', 'mangle', '-nvxL', 'OUTPUT'], check=False)
                (directory / 'queue-counters.txt').write_text(counters_result.stdout)
                match = next((x for x in counters_result.stdout.splitlines()
                              if f'3b-syn-probe-{run_id}' in x), None)
                outcome['queue_rule_packets'] = (int(match.split()[0])
                                                 if counters_result.returncode == 0 and match
                                                 and match.split()[0].isdigit() else None)
            except (ProbeError, OSError) as exc:
                outcome['queue_rule_packets'] = None
                outcome['errors'].append(f'NFQUEUE counter read failed: {exc}')
            if outcome['queue_rule_packets'] is None:
                outcome['errors'].append('NFQUEUE rule packet counter unavailable; interception is unverified')
            elif outcome['queue_rule_packets'] == 0:
                outcome['errors'].append('No packets reached the experimental NFQUEUE rule')
        try:
            finish_capture(capture)
        except (OSError, subprocess.TimeoutExpired) as exc:
            outcome['errors'].append(f'capture shutdown failed: {exc}')
        try:
            outcome['rollback'] = cleanup(run_id)
            if outcome['rollback']['rollback'] == 'not needed' and (directory / 'rollback.json').exists():
                outcome['rollback'] = read_json(directory / 'rollback.json')
        except (ProbeError, OSError, BlockingIOError, ValueError, KeyError) as exc:
            outcome['rollback'] = {'rollback': 'failed', 'rule_remaining': 'unknown', 'errors': [str(exc)]}
        try:
            snapshot(directory / 'firewall-after.txt')
        except (ProbeError, OSError) as exc:
            outcome['errors'].append(f'firewall after snapshot unavailable: {exc}')
        outcome['end'] = utc_now()
        outcome['packets'] = packet_counts(directory, cfg)
        outcome['firewall_integrity'] = firewall_integrity(
            directory, own_rule_remaining=outcome['rollback'].get('rule_remaining', 'unknown'))
        outcome['interception_evidence'] = interception_evidence(
            outcome.get('queue_rule_packets'), directory / 'nfqws-debug.log', outcome['packets'])
        if steps is not None:
            outcome['adaptive_analysis'] = adaptive.analyze(outcome['attempts'], cfg['TARGET_PORT'])
        if (directory / 'nfqws-debug.log').exists():
            try:
                lines = (directory / 'nfqws-debug.log').read_text(errors='replace').splitlines()
                outcome['nfqws_errors'] = [x for x in lines if re.search(r'error|fail|not permitted', x, re.I)][-30:]
            except OSError as exc:
                outcome['errors'].append(f'nfqws2 log unavailable: {exc}')
        outcome['status'] = ('completed' if not outcome['errors']
                             and outcome['rollback'].get('rollback') == 'complete' else 'partial')
        try:
            write_json(directory / 'experiment.json', outcome)
            generate_report(directory, cfg)
        finally:
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
    print(directory)
    if outcome['errors'] or outcome['rollback'].get('rollback') != 'complete':
        raise ProbeError('experiment had errors; inspect report and rollback.json')
    return directory


def generate_report(directory, cfg):
    from report import render
    render(directory, cfg)


def do_doctor(cfg):
    version = readiness(cfg, require_root=True)
    route = route_info(cfg['TARGET_IP'])
    conflict = queue_conflict(cfg['NFQUEUE_NUM'])
    print(json.dumps({'nfqws2_version': version, 'kernel': os.uname().release,
                      'target': f"{cfg['TARGET_IP']}:{cfg['TARGET_PORT']}",
                      'route': route, 'iptables_backend': run(['iptables', '-V'], check=False).stdout.strip(),
                      'queue_conflict': conflict, 'management': management_info(cfg),
                      'root': os.geteuid() == 0,
                      'note': 'reserve management access cannot be verified automatically'}, indent=2))
    if conflict:
        raise ProbeError(conflict)


def do_adaptive(cfg, args):
    if set(cfg['REPORT_FORMATS']) != {'json', 'markdown'}:
        raise ProbeError('adaptive requires REPORT_FORMATS=json,markdown; CSV is always written')
    try:
        steps = adaptive.plan(cfg, args.scenario)
    except ValueError as exc:
        raise ProbeError(str(exc)) from exc
    if not steps:
        raise ProbeError('selected adaptive scenario has no configured measurements')
    extra_ports = [p for p in cfg['PORT_COMPARISON_PORTS'] if p != cfg['TARGET_PORT']]
    if any(step['scenario'] == 'ports' for step in steps) and extra_ports:
        expected = ','.join(str(p) for p in extra_ports)
        if args.confirm_ports != expected:
            if not sys.stdin.isatty():
                raise ProbeError(f'port comparison requires --confirm-ports {expected}')
            answer = input(f'Type confirmed listening VPS ports {expected}: ').strip()
            if answer != expected:
                raise ProbeError('comparison ports not confirmed')
        for port in extra_ports:
            if ssh_target_conflict(dict(cfg, TARGET_PORT=port)):
                raise ProbeError(f'port {port} appears in an established SSH connection')
    tls_ports = {step['port'] for step in steps if step['protocol'] == 'tls'}
    for port in tls_ports:
        if ssh_target_conflict(dict(cfg, TARGET_PORT=port)):
            raise ProbeError(f'TLS port {port} appears in an established SSH connection')
    confirm_target(cfg, args)
    if args.phase in ('syndata', 'compare'):
        if not cfg['ENABLE_SYNDATA']:
            raise ProbeError('ENABLE_SYNDATA=false: syndata phase unavailable')
        readiness(cfg, require_root=True)
        route_info(cfg['TARGET_IP'])
        conflict = queue_conflict(cfg['NFQUEUE_NUM'])
        if conflict:
            raise ProbeError(conflict)
        if STATE_FILE.exists():
            raise ProbeError('another SYN Probe experiment is active')
    print(f"Adaptive plan: {args.scenario}; phase={args.phase}; "
          f"{len(steps)} attempts per phase; maximum {cfg['ADAPTIVE_DURATION_SECONDS']} s per phase")
    baseline_dir = None
    if args.phase in ('baseline', 'compare'):
        baseline_dir = do_baseline(cfg, steps=steps)
    if args.phase in ('syndata', 'compare'):
        do_test(cfg, args, steps=steps,
                baseline_file=str(baseline_dir / 'baseline.json') if baseline_dir else None,
                confirmed=True)


def main():
    parser = argparse.ArgumentParser(description='3B client-side SYN Probe')
    parser.add_argument('command', choices=['doctor', 'baseline', 'test', 'adaptive',
                                            'status', 'stop', 'report', '_watchdog'])
    parser.add_argument('--config', default=str(HERE / 'config.env'))
    parser.add_argument('--confirm-target')
    parser.add_argument('--ack-recovery', action='store_true')
    parser.add_argument('--run-id', help=argparse.SUPPRESS)
    parser.add_argument('--report-dir', help='report directory for report command')
    parser.add_argument('--scenario', choices=adaptive.SCENARIOS, default='all',
                        help='adaptive scenario (default: all configured scenarios)')
    parser.add_argument('--phase', choices=('baseline', 'syndata', 'compare'), default='compare',
                        help='adaptive phase (default: baseline then syndata)')
    parser.add_argument('--confirm-ports', help='exact comma-separated list of confirmed comparison ports')
    args = parser.parse_args()
    if args.command == '_watchdog':
        return watchdog(args.run_id)
    if args.command == 'status':
        if not STATE_FILE.exists():
            print('No active SYN Probe experiment')
        else:
            state = read_json(STATE_FILE)
            print(json.dumps({**state, 'rule_present': rule_present(state['rule']),
                              'process_alive': proc_starttime(state.get('nfq_pid')) == state.get('nfq_starttime')
                              if state.get('nfq_pid') else False}, indent=2))
        return 0
    if args.command == 'stop':
        if os.geteuid() != 0:
            raise ProbeError('root required; use sudo')
        result = cleanup()
        print(json.dumps(result, indent=2))
        if result['rollback'] == 'failed':
            raise ProbeError('rollback failed; state retained for retry')
        return 0
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        raise ProbeError(f'configuration missing: {cfg_path}; copy config.example.env to config.env')
    cfg = parse_env(cfg_path)
    if args.command == 'doctor':
        do_doctor(cfg)
    elif args.command == 'baseline':
        do_baseline(cfg)
    elif args.command == 'test':
        do_test(cfg, args)
    elif args.command == 'adaptive':
        do_adaptive(cfg, args)
    elif args.command == 'report':
        directory = Path(args.report_dir) if args.report_dir else max((p for p in REPORT_ROOT.iterdir() if p.is_dir()), default=None) if REPORT_ROOT.is_dir() else None
        if directory is None or not directory.is_dir():
            raise ProbeError('no report directory found')
        cfg = (read_json(directory / 'metadata.json').get('configuration') or cfg)
        generate_report(directory, cfg)
        print(directory)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ProbeError, BlockingIOError, OSError) as exc:
        print(f'SYN Probe: {exc}', file=sys.stderr)
        sys.exit(1)
