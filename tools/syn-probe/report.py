#!/usr/bin/env python3
"""Render measured SYN Probe artifacts. Missing measurements remain unknown."""
from __future__ import annotations

import json
from pathlib import Path
import statistics

import adaptive


def load(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def metrics(data):
    if data is None:
        return None
    attempts = data.get('attempts', [])
    successful = [x['latency_ms'] for x in attempts if
                  (x.get('status') == 'connected' or
                   (x.get('tcp_status') == 'connected' and
                    x.get('status') != 'overlapped_watchdog'))
                  and x.get('latency_ms') is not None]
    packets = data.get('packets') or {}
    return {'tcp_attempts': len([x for x in attempts if x.get('status') != 'skipped_deadline']),
            'successful_connections': len(successful),
            'timeouts': len([x for x in attempts if x.get('status') == 'timeout']),
            'tcp_timeouts': len([x for x in attempts if
                                 x.get('tcp_status', x.get('status')) == 'timeout']),
            'tls_timeouts': len([x for x in attempts if x.get('tls_status') == 'timeout']),
            'other_errors': len([x for x in attempts if x.get('status') == 'error']),
            'skipped_deadline': len([x for x in attempts if x.get('status') == 'skipped_deadline']),
            'overlapped_watchdog': len([x for x in attempts if x.get('status') == 'overlapped_watchdog']),
            'tls_completed': len([x for x in attempts if x.get('tls_status') == 'completed']),
            'tls_failed': len([x for x in attempts if x.get('tls_status') in ('failed', 'timeout')]),
            'syn_observed_locally': packets.get('syn'),
            'syn_ack_received': packets.get('syn_ack'),
            'rst_observed': packets.get('rst'),
            'pcap_handshakes': packets.get('handshakes', 'unknown'),
            'packet_source': packets.get('source', 'unavailable'),
            'median_connect_ms': round(statistics.median(successful), 3) if successful else None,
            'average_connect_ms': round(statistics.mean(successful), 3) if successful else None,
            'min_connect_ms': min(successful) if successful else None,
            'max_connect_ms': max(successful) if successful else None}


def fmt(value):
    return 'N/A' if value is None else str(value)


def render(directory, cfg):
    directory = Path(directory)
    baseline = load(directory / 'baseline.json')
    experiment = load(directory / 'experiment.json')
    if experiment and not baseline and experiment.get('baseline_file'):
        baseline = load(experiment['baseline_file'])
    metadata = load(directory / 'metadata.json') or {}
    rollback = load(directory / 'rollback.json') or (experiment or {}).get('rollback')
    b, e = metrics(baseline), metrics(experiment)
    result = {'schema_version': 1, 'target': {'ip': cfg['TARGET_IP'], 'port': cfg['TARGET_PORT']},
              'environment': metadata, 'baseline': baseline, 'experiment': experiment,
              'metrics': {'baseline': b, 'syndata': e}, 'rollback': rollback,
              'limitations': ['Client-only capture cannot locate the drop hop.',
                              'PCAP flag counters include retransmissions and cannot prove a complete handshake.',
                              'A completed socket.connect is the source for successful handshake counts.',
                              'Server-side capture is required to distinguish forward from return-path loss.']}
    if (baseline or {}).get('adaptive_plan') or (experiment or {}).get('adaptive_plan'):
        result['adaptive_comparison'] = adaptive.compare(baseline, experiment)
        result['alternative_explanations'] = [
            'route or return route changed between phases',
            'client, VPS or provider firewall policy changed',
            'VPS listener state or connection limit changed',
            'other DPI bypass process affected baseline',
            'sequential phases do not establish a causal effect',
            'client-only packet capture cannot identify the drop location',
        ]
    if 'json' in cfg['REPORT_FORMATS']:
        (directory / 'report.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')

    rows = [('| TCP attempts | tcp_attempts |'), ('| Successful connections | successful_connections |'),
            ('| Timeouts | timeouts |'), ('| Other connect errors | other_errors |'),
            ('| TCP timeouts | tcp_timeouts |'), ('| TLS timeouts | tls_timeouts |'),
            ('| Attempts crossing rollback deadline | overlapped_watchdog |'),
            ('| SYN observed locally | syn_observed_locally |'),
            ('| SYN/ACK received | syn_ack_received |'), ('| TCP RST observed | rst_observed |'),
            ('| PCAP completed handshakes | pcap_handshakes |'),
            ('| Verified TLS handshakes | tls_completed |'),
            ('| Failed TLS handshakes | tls_failed |'),
            ('| Median connect latency, ms | median_connect_ms |'),
            ('| Average connect latency, ms | average_connect_ms |'),
            ('| Min connect latency, ms | min_connect_ms |'),
            ('| Max connect latency, ms | max_connect_ms |')]
    table = ['| Показатель | Baseline | Syndata |', '|---|---:|---:|']
    for raw in rows:
        label, key = [x.strip() for x in raw.strip('|').split('|')]
        table.append(f'| {label} | {fmt(b.get(key) if b else None)} | {fmt(e.get(key) if e else None)} |')

    baseline_ok = b is not None
    experiment_ok = e is not None
    if experiment_ok and baseline_ok:
        if e['successful_connections'] > b['successful_connections']:
            interpretation = 'В этом клиентском замере успешных connect с syndata больше, чем в baseline. Повторите проверку и сопоставьте с серверным захватом.'
        else:
            interpretation = 'В этом замере улучшение успешных connect не подтверждено.'
    else:
        interpretation = 'Для сравнения не хватает baseline или эксперимента.'
    errors = ((baseline or {}).get('errors', []) + (experiment or {}).get('errors', [])
              + (experiment or {}).get('nfqws_errors', []))
    rollback_text = rollback.get('rollback', 'unknown') if rollback else 'not applicable / unknown'
    rule_text = rollback.get('rule_remaining', 'unknown') if rollback else 'unknown'
    lines = ['# 3B SYN Probe report', '', '## Краткое резюме', '', interpretation, '',
             '## Окружение', '', f"- Kernel: {metadata.get('kernel', 'unknown')}",
             f"- nfqws2: {metadata.get('nfqws2_version', 'unknown')}",
             f"- Source interface/IP: {metadata.get('route', {}).get('interface', 'unknown')} / {metadata.get('route', {}).get('source_ip', 'unknown')}",
             '', '## Конфигурация', '', f"- Target: {cfg['TARGET_IP']}:{cfg['TARGET_PORT']}",
             f"- Queue: {cfg['NFQUEUE_NUM']}", f"- Strategy: {'syndata' if cfg['ENABLE_SYNDATA'] else 'disabled'}",
             f"- Attempts: {cfg['TEST_ATTEMPTS']}; timeout: {cfg['CONNECT_TIMEOUT_SECONDS']} s; duration: {cfg['TEST_DURATION_SECONDS']} s",
             '', '## Сравнение', '', *table, '', '## Анализ TCP-пакетов', '',
             f"- Baseline source: {b.get('packet_source') if b else 'unavailable'}",
             f"- Syndata source: {e.get('packet_source') if e else 'unavailable'}",
             '- Число SYN/SYN/ACK/RST получено из TCP-флагов клиентского pcap и включает повторы.',
             '- Завершённый handshake по pcap: unknown; успешный socket.connect учитывается отдельно.',
             f"- Пакетов, попавших в правило NFQUEUE: {(experiment or {}).get('queue_rule_packets', 'unknown')}",
             '', '## Ошибки и ограничения', '',
             *([f'- {item}' for item in errors] if errors else ['- Явных ошибок в сохранённых данных нет.']),
             '- Захват только на клиенте не устанавливает место потери пакетов.',
             '', '## Откат', '', f'- Rollback: {rollback_text}', f'- Экспериментальное правило осталось: {rule_text}',
             '', '## Предварительная интерпретация', '', interpretation,
             '', '## Что проверить дальше', '',
             '- Одновременно снять пакеты на клиенте и на VPS для этого IP и порта.',
             '- Проверить, пришёл ли SYN на VPS и вышел ли обратный SYN/ACK.',
             '- Повторить несколько серий в сопоставимых условиях; таймаут сам по себе не доказывает блокировку ТСПУ.', '']
    if (baseline or {}).get('adaptive_plan') or (experiment or {}).get('adaptive_plan'):
        lines += ['## Временная шкала', '',
                  '| UTC | Фаза | Сценарий | Этап | Порт | Протокол | TCP | TLS | Итог |',
                  '|---|---|---|---|---:|---|---|---|---|']
        for phase, data in (('baseline', baseline), ('syndata', experiment)):
            for item in (data or {}).get('attempts', []):
                lines.append(f"| {item.get('timestamp_utc', 'N/A')} | {phase} | "
                             f"{item.get('scenario', 'N/A')} | {item.get('stage', 'N/A')} | "
                             f"{item.get('port', 'N/A')} | {item.get('protocol', 'N/A')} | "
                             f"{item.get('tcp_status', 'unknown')} | "
                             f"{item.get('tls_status', 'not_tested')} | {item.get('status', 'N/A')} |")
        lines += ['', '## Паузы, серии и восстановление', '']
        for phase, data in (('baseline', baseline), ('syndata', experiment)):
            analysis = (data or {}).get('adaptive_analysis') or {}
            if not analysis:
                lines.append(f'- {phase}: измерения отсутствуют или не завершены.')
                continue
            lines.append(f"- {phase}: отдельных TCP-проверок успешно {analysis.get('tcp_successes', 0)}, "
                         f"неуспешных {analysis.get('tcp_failures', 0)}; TLS завершено "
                         f"{analysis.get('tls_successes', 0)}, TLS не завершено "
                         f"{analysis.get('tls_failures', 0)}.")
            for pause in analysis.get('cooldown_before_after', []):
                lines.append(f"- {phase}: пауза {pause['wait_seconds']} с: "
                             f"{pause['before']} → {pause['after']}.")
            burst = analysis.get('burst_before_after') or {}
            if burst.get('before') is not None:
                lines.append(f"- {phase}: серия соединений: до {burst['before']}, "
                             f"в серии успешно {burst.get('during_successes', 0)}/"
                             f"{burst.get('during_attempts', 0)}, после {burst.get('after', 'N/A')}. "
                             f"Временная связь с предыдущими подключениями: "
                             f"{burst.get('possible_temporal_association', False)}. Это временное совпадение, "
                             'причинная связь не установлена.')
            for port, values in analysis.get('port_comparison', {}).items():
                lines.append(f"- {phase}: порт {port}: {values['connected']}/{values['attempts']} "
                             'TCP connect успешны; различие портов само по себе не доказывает фильтрацию.')
            for period in analysis.get('unavailable_periods', []):
                if period['status'] == 'interval_censored':
                    lines.append(f"- {phase}: наблюдаемая недоступность с "
                                 f"{period['first_failure_utc']} до {period['last_failure_utc']}; "
                                 f"наблюдаемый минимум {period['failure_observed_span_seconds']} с; "
                                 f"доступность вернулась не позднее {period['first_success_utc']}. "
                                 f"Точность по времени: интервал {period['observation_gap_seconds']} с.")
                else:
                    lines.append(f"- {phase}: после {period['last_failure_utc']} "
                                 f"восстановление не наблюдалось (наблюдаемый минимум "
                                 f"{period['failure_observed_span_seconds']} с); "
                                 'срок восстановления неизвестен.')
        comparison = result['adaptive_comparison']
        lines += ['', '## Сопоставление одинаковых этапов', '',
                  f"Статус: {comparison['status']}. "
                  'Фазы идут последовательно, поэтому совпадение или разница не доказывает причину.', '']
        if comparison.get('paired_measurements'):
            lines += ['| Сценарий | Этап | Порт | Подпадает под правило | TCP baseline | TCP syndata | TLS baseline | TLS syndata |',
                      '|---|---|---:|---|---|---|---|---|']
            for pair in comparison['paired_measurements']:
                lines.append(f"| {pair['scenario']} | {pair['stage']} | {pair['port']} | "
                             f"{pair['syndata_eligible']} | "
                             f"{pair['baseline_tcp']} | {pair['syndata_tcp']} | "
                             f"{pair['baseline_tls']} | {pair['syndata_tls']} |")
        lines += ['', '## Альтернативные объяснения', '',
                  '- Маршрутизация и обратный маршрут могли измениться между фазами.',
                  '- Firewall клиента, VPS или провайдера может ограничивать соединения.',
                  '- Другие запущенные DPI-обходы на клиенте способны исказить baseline.',
                  '- Сервис на VPS мог менять состояние или достигнуть лимита соединений.',
                  '- Проверка порта допустима только при подтверждённом слушающем сервисе.',
                  '- Правило syndata действует только на основной TARGET_PORT; дополнительные порты служат контрольными измерениями.',
                  '- Baseline и syndata используют одинаковый план, но идут последовательно; '
                  'внешние сетевые условия могли измениться.',
                  '- Для локализации потерь нужен синхронный захват пакетов на клиенте и VPS.', '']
    if 'markdown' in cfg['REPORT_FORMATS']:
        (directory / 'summary.md').write_text('\n'.join(lines))
    return result
