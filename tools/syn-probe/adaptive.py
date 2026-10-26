"""Bounded, client-side observations of intermittent TCP availability."""
from __future__ import annotations

import csv
import datetime as dt
import re
import socket
import ssl
import time


DEFAULTS = {
    'ADAPTIVE_DURATION_SECONDS': '1200',
    'BURST_CONNECTIONS': '5',
    'BURST_RATE_PER_SECOND': '1',
    'RECOVERY_INTERVAL_SECONDS': '15',
    'RECOVERY_SAMPLES': '8',
    'TLS_TEST_PORT': '0',
    'TLS_SERVER_NAME': '',
    'PORT_COMPARISON_PORTS': '',
    'PORTS_VERIFIED_ON_VPS': 'false',
}
SCENARIOS = ('all', 'cooldown', 'burst', 'tls', 'ports', 'recovery')
COOLDOWNS = (30, 60, 120, 180)
CSV_FIELDS = ('started_utc', 'timestamp_utc', 'phase', 'scenario', 'stage', 'target_ip', 'port',
              'protocol', 'syndata_eligible', 'status', 'tcp_status', 'tls_status', 'latency_ms',
              'tls_latency_ms', 'error', 'elapsed_seconds', 'wait_before_seconds',
              'actual_wait_seconds', 'cumulative_planned_wait_seconds')


def validate(values):
    cfg = dict(DEFAULTS)
    cfg.update(values)
    for key, low, high in (('ADAPTIVE_DURATION_SECONDS', 600, 3600),
                           ('BURST_CONNECTIONS', 1, 10),
                           ('RECOVERY_INTERVAL_SECONDS', 10, 60),
                           ('RECOVERY_SAMPLES', 1, 12),
                           ('TLS_TEST_PORT', 0, 65535)):
        raw = str(cfg[key])
        if not re.fullmatch(r'[0-9]+', raw) or not low <= int(raw) <= high:
            raise ValueError(f'{key} must be an integer in {low}..{high}')
        cfg[key] = int(raw)
    raw_rate = str(cfg['BURST_RATE_PER_SECOND'])
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', raw_rate):
        raise ValueError('BURST_RATE_PER_SECOND must be 0.1..2')
    cfg['BURST_RATE_PER_SECOND'] = float(raw_rate)
    if not 0.1 <= cfg['BURST_RATE_PER_SECOND'] <= 2:
        raise ValueError('BURST_RATE_PER_SECOND must be 0.1..2')
    if str(cfg['PORTS_VERIFIED_ON_VPS']).lower() not in ('true', 'false'):
        raise ValueError('PORTS_VERIFIED_ON_VPS must be true or false')
    cfg['PORTS_VERIFIED_ON_VPS'] = str(cfg['PORTS_VERIFIED_ON_VPS']).lower() == 'true'
    name = str(cfg['TLS_SERVER_NAME']).strip()
    if name and (len(name) > 253 or not re.fullmatch(r'[A-Za-z0-9.-]+', name)
                 or name.startswith('.') or name.endswith('.')):
        raise ValueError('TLS_SERVER_NAME must be a DNS hostname')
    cfg['TLS_SERVER_NAME'] = name
    ports = str(cfg['PORT_COMPARISON_PORTS']).strip()
    if ports:
        raw_ports = ports.split(',')
        if len(raw_ports) > 4 or any(not re.fullmatch(r'[0-9]+', p) or not 1 <= int(p) <= 65535
                                    for p in raw_ports):
            raise ValueError('PORT_COMPARISON_PORTS accepts at most four TCP ports')
        parsed = [int(p) for p in raw_ports]
        if 22 in parsed:
            raise ValueError('PORT_COMPARISON_PORTS must not include SSH port 22')
        if len(parsed) != len(set(parsed)):
            raise ValueError('PORT_COMPARISON_PORTS contains duplicates')
        cfg['PORT_COMPARISON_PORTS'] = parsed
    else:
        cfg['PORT_COMPARISON_PORTS'] = []
    return cfg


def plan(cfg, scenario):
    if scenario not in SCENARIOS:
        raise ValueError(f'unknown scenario: {scenario}')
    selected = SCENARIOS[1:] if scenario == 'all' else (scenario,)
    steps = []

    def add(kind, stage, *, wait=0, port=None, protocol='tcp'):
        steps.append({'scenario': kind, 'stage': stage, 'wait_before_seconds': wait,
                      'port': port or cfg['TARGET_PORT'], 'protocol': protocol})

    if 'cooldown' in selected:
        add('cooldown', 'initial')
        for seconds in COOLDOWNS:
            add('cooldown', f'after_{seconds}s', wait=seconds)
    if 'burst' in selected:
        add('burst', 'before', wait=1 if steps else 0)
        for n in range(cfg['BURST_CONNECTIONS']):
            add('burst', f'burst_{n + 1}', wait=1 / cfg['BURST_RATE_PER_SECOND'])
        add('burst', 'after', wait=2)
    if 'recovery' in selected:
        add('recovery', 'initial', wait=1 if steps else 0)
        for n in range(cfg['RECOVERY_SAMPLES']):
            add('recovery', f'sample_{n + 1}', wait=cfg['RECOVERY_INTERVAL_SECONDS'])
    if 'tls' in selected:
        if cfg['TLS_TEST_PORT']:
            if cfg['TLS_TEST_PORT'] == 22:
                raise ValueError('TLS_TEST_PORT must not be SSH port 22')
            if not cfg['TLS_SERVER_NAME']:
                raise ValueError('TLS_SERVER_NAME is required for verified TLS handshake')
            add('tls', 'tcp_only', wait=1 if steps else 0, port=cfg['TLS_TEST_PORT'])
            add('tls', 'tls_handshake', wait=1, port=cfg['TLS_TEST_PORT'], protocol='tls')
        elif scenario == 'tls':
            raise ValueError('TLS_TEST_PORT must be set for the tls scenario')
    if 'ports' in selected:
        if cfg['PORT_COMPARISON_PORTS']:
            if not cfg['PORTS_VERIFIED_ON_VPS']:
                raise ValueError('confirm listening services on the VPS with PORTS_VERIFIED_ON_VPS=true')
            add('ports', 'primary', wait=1 if steps else 0, port=cfg['TARGET_PORT'])
            for port in cfg['PORT_COMPARISON_PORTS']:
                if port != cfg['TARGET_PORT']:
                    add('ports', f'port_{port}', wait=1, port=port)
        elif scenario == 'ports':
            raise ValueError('PORT_COMPARISON_PORTS must be set for the ports scenario')
    if len(steps) > 40:
        raise ValueError('adaptive plan exceeds 40 connection attempts')
    waits = sum(x['wait_before_seconds'] for x in steps)
    worst_case = (waits + len(steps) * cfg['CONNECT_TIMEOUT_SECONDS']
                  + sum(x['protocol'] == 'tls' for x in steps) * cfg['CONNECT_TIMEOUT_SECONDS'] + 10)
    if worst_case > cfg['ADAPTIVE_DURATION_SECONDS']:
        raise ValueError(f'ADAPTIVE_DURATION_SECONDS must be at least {worst_case:.0f} for this plan')
    return steps


def _once(cfg, step):
    started = time.monotonic()
    tcp_latency = None
    tls_latency = None
    tcp_status = 'unknown'
    tls_status = 'not_tested'
    error = ''
    try:
        with socket.create_connection((cfg['TARGET_IP'], step['port']),
                                      timeout=cfg['CONNECT_TIMEOUT_SECONDS']) as sock:
            tcp_status = 'connected'
            tcp_latency = round((time.monotonic() - started) * 1000, 3)
            if step['protocol'] == 'tls':
                sock.settimeout(cfg['CONNECT_TIMEOUT_SECONDS'])
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=cfg['TLS_SERVER_NAME'] or None):
                    tls_status = 'completed'
                tls_latency = round((time.monotonic() - started) * 1000 - tcp_latency, 3)
    except socket.timeout as exc:
        error = str(exc)
        if tcp_status == 'connected':
            tls_status = 'timeout'
        else:
            tcp_status = 'timeout'
    except (OSError, ssl.SSLError) as exc:
        error = f'{type(exc).__name__}: {exc}'
        if tcp_status == 'connected':
            tls_status = 'failed'
        else:
            tcp_status = 'error'
    status = ('connected' if step['protocol'] == 'tcp' and tcp_status == 'connected'
              else 'tls_completed' if tls_status == 'completed'
              else 'timeout' if tcp_status == 'timeout' or tls_status == 'timeout'
              else 'tls_failed' if tcp_status == 'connected' else 'error')
    if tcp_latency is None:
        tcp_latency = round((time.monotonic() - started) * 1000, 3)
    if step['protocol'] == 'tls' and tls_latency is None and tcp_status == 'connected':
        tls_latency = round((time.monotonic() - started) * 1000 - tcp_latency, 3)
    return status, tcp_status, tls_status, error, tcp_latency, tls_latency


def execute(cfg, steps, phase, directory, attempts, deadline=None, monotonic_deadline=None):
    """Append each measurement to CSV immediately so cancellation retains partial evidence."""
    def expires_within(seconds):
        return ((deadline is not None and time.time() + seconds >= deadline)
                or (monotonic_deadline is not None
                    and time.monotonic() + seconds >= monotonic_deadline))
    path = directory / 'timeline.csv'
    started = time.monotonic()
    with path.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        handle.flush()
        skip_rest = False
        cumulative_wait = 0
        for step in steps:
            wait = step['wait_before_seconds']
            cumulative_wait += wait
            before_wait = time.monotonic()
            needed = cfg['CONNECT_TIMEOUT_SECONDS'] * (2 if step['protocol'] == 'tls' else 1)
            if expires_within(wait + needed):
                skip_rest = True
            if wait and not skip_rest:
                # One bounded sleep per interval; no continuous polling.
                time.sleep(wait)
            actual_wait = round(time.monotonic() - before_wait, 3) if not skip_rest else 0
            if expires_within(needed):
                skip_rest = True
            if skip_rest:
                started_utc = dt.datetime.now(dt.timezone.utc).isoformat()
                status, tcp_status, tls_status, error, latency, tls_latency = (
                    'skipped_deadline', 'unknown', 'not_tested',
                    'automatic rollback deadline is near', None, None)
            else:
                started_utc = dt.datetime.now(dt.timezone.utc).isoformat()
                status, tcp_status, tls_status, error, latency, tls_latency = _once(cfg, step)
                if expires_within(0):
                    status = 'overlapped_watchdog'
                    error = 'measurement crossed the rollback deadline'
            row = {'started_utc': started_utc,
                   'timestamp_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                   'phase': phase, 'scenario': step['scenario'], 'stage': step['stage'],
                   'target_ip': cfg['TARGET_IP'], 'port': step['port'],
                   'protocol': step['protocol'],
                   'syndata_eligible': phase == 'syndata' and step['port'] == cfg['TARGET_PORT'],
                   'status': status,
                   'tcp_status': tcp_status, 'tls_status': tls_status,
                   'latency_ms': latency, 'tls_latency_ms': tls_latency, 'error': error,
                   'elapsed_seconds': round(time.monotonic() - started, 3),
                   'wait_before_seconds': wait, 'actual_wait_seconds': actual_wait,
                   'cumulative_planned_wait_seconds': cumulative_wait}
            attempts.append(row)
            writer.writerow(row)
            handle.flush()
    return attempts


def analyze(attempts, primary_port=None):
    """Recovery is interval-censored: last failed observation < recovery <= first success."""
    tcp = [a for a in attempts if a.get('protocol') == 'tcp'
           and a.get('status') not in ('skipped_deadline', 'overlapped_watchdog')]
    success = [a for a in tcp if a.get('tcp_status') == 'connected']
    failures = [a for a in tcp if a.get('tcp_status') != 'connected']
    periods = []
    for scenario in dict.fromkeys(a['scenario'] for a in tcp):
        observations = [a for a in tcp if a['scenario'] == scenario
                        and (primary_port is None or a['port'] == primary_port)]
        streak = []
        for item in observations:
            if item['tcp_status'] != 'connected':
                streak.append(item)
                continue
            if streak:
                low = streak[-1]['elapsed_seconds']
                high = item['elapsed_seconds']
                periods.append({'scenario': scenario, 'first_failure_utc': streak[0]['timestamp_utc'],
                                'last_failure_utc': streak[-1]['timestamp_utc'],
                                'first_success_utc': item['timestamp_utc'],
                                'recovery_after_last_failure_seconds': {'lower': 0, 'upper': round(high - low, 3)},
                                'observation_gap_seconds': round(high - low, 3),
                                'failure_observed_span_seconds': round(low - streak[0]['elapsed_seconds'], 3),
                                'status': 'interval_censored'})
                streak = []
        if streak:
            periods.append({'scenario': scenario, 'first_failure_utc': streak[0]['timestamp_utc'],
                            'last_failure_utc': streak[-1]['timestamp_utc'],
                            'first_success_utc': None, 'status': 'right_censored',
                            'failure_observed_span_seconds': round(streak[-1]['elapsed_seconds'] - streak[0]['elapsed_seconds'], 3)})
    by_port = {}
    for item in tcp:
        key = str(item['port'])
        value = by_port.setdefault(key, {'attempts': 0, 'connected': 0, 'failed': 0})
        value['attempts'] += 1
        value['connected' if item['tcp_status'] == 'connected' else 'failed'] += 1
    port_comparison = {}
    for item in tcp:
        if item['scenario'] != 'ports':
            continue
        key = str(item['port'])
        value = port_comparison.setdefault(key, {'attempts': 0, 'connected': 0, 'failed': 0})
        value['attempts'] += 1
        value['connected' if item['tcp_status'] == 'connected' else 'failed'] += 1
    cooldown = []
    points = {a['stage']: a for a in tcp if a['scenario'] == 'cooldown'}
    previous_stage = 'initial'
    for seconds in COOLDOWNS:
        before, after = points.get(previous_stage), points.get(f'after_{seconds}s')
        previous_stage = f'after_{seconds}s'
        if not before or not after:
            continue
        cooldown.append({'wait_seconds': seconds, 'before': before['tcp_status'],
                         'after': after['tcp_status'], 'before_utc': before['timestamp_utc'],
                         'after_utc': after['timestamp_utc'],
                         'cumulative_planned_wait_seconds': after.get('cumulative_planned_wait_seconds',
                                                                      sum(COOLDOWNS[:COOLDOWNS.index(seconds) + 1])),
                         'actual_wait_seconds': after.get('actual_wait_seconds')})
    burst = [a for a in tcp if a['scenario'] == 'burst']
    before = next((a for a in burst if a['stage'] == 'before'), None)
    after = next((a for a in burst if a['stage'] == 'after'), None)
    during = [a for a in burst if a['stage'].startswith('burst_')]
    return {'tcp_successes': len(success), 'tcp_failures': len(failures),
            'tls_successes': len([a for a in attempts if a.get('tls_status') == 'completed']),
            'tls_failures': len([a for a in attempts if a.get('protocol') == 'tls'
                                 and a.get('tls_status') not in ('completed', 'not_tested')]),
            'cooldown_before_after': cooldown,
            'cooldown_design': 'sequential pauses in one run; not four independent experiments',
            'burst_before_after': {'before': before['tcp_status'] if before else None,
                                   'after': after['tcp_status'] if after else None,
                                   'during_attempts': len(during),
                                   'during_successes': sum(a['tcp_status'] == 'connected' for a in during),
                                   'possible_temporal_association': bool(
                                       before and after and before['tcp_status'] == 'connected'
                                       and after['tcp_status'] != 'connected')},
            'by_port': by_port, 'port_comparison': port_comparison,
            'unavailable_periods': periods,
            'recovery_precision': 'bounded by gaps between observations; no continuous polling'}


def compare(baseline, syndata):
    if not baseline or not syndata:
        return {'status': 'unavailable', 'reason': 'both phases are required'}
    if baseline.get('adaptive_plan') != syndata.get('adaptive_plan'):
        return {'status': 'incomparable', 'reason': 'phase schedules differ'}
    left, right = baseline.get('attempts', []), syndata.get('attempts', [])
    pairs = []
    for before, after in zip(left, right):
        key = ('scenario', 'stage', 'port', 'protocol')
        if any(before.get(k) != after.get(k) for k in key):
            return {'status': 'incomparable', 'reason': 'measurement order differs'}
        pairs.append({'scenario': before['scenario'], 'stage': before['stage'],
                      'port': before['port'], 'protocol': before['protocol'],
                      'syndata_eligible': after.get('syndata_eligible'),
                      'baseline_tcp': before.get('tcp_status'),
                      'syndata_tcp': after.get('tcp_status'),
                      'baseline_tls': before.get('tls_status'),
                      'syndata_tls': after.get('tls_status')})
    interrupted = any(a.get('status') in ('skipped_deadline', 'overlapped_watchdog')
                      for a in left + right)
    return {'status': 'complete' if len(left) == len(right) and not interrupted else 'partial',
            'paired_measurements': pairs,
            'unpaired_baseline': max(0, len(left) - len(pairs)),
            'unpaired_syndata': max(0, len(right) - len(pairs)),
            'ordering': 'baseline first, syndata second; not a randomized A/B test; environmental drift remains possible'}
