import csv
import contextlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import adaptive
import syn_probe as probe
import report


class AdaptiveTests(unittest.TestCase):
    def setUp(self):
        self.cfg = probe.parse_env(probe.DEFAULTS)

    def test_bounded_cooldown_and_burst_plan(self):
        cooldown = adaptive.plan(self.cfg, 'cooldown')
        self.assertEqual([s['wait_before_seconds'] for s in cooldown], [0, 30, 60, 120, 180])
        burst = adaptive.plan(self.cfg, 'burst')
        self.assertEqual(len([s for s in burst if s['stage'].startswith('burst_')]), 5)
        self.assertTrue(all(s['wait_before_seconds'] >= 0.5 for s in burst
                            if s['stage'].startswith('burst_')))
        self.assertLessEqual(len(adaptive.plan(self.cfg, 'all')), 40)

    def test_rejects_stress_rates_and_too_short_watchdog(self):
        raw = dict((line.split('=', 1) for line in probe.DEFAULTS.read_text().splitlines()
                    if line and not line.startswith('#')))
        for key, value in [('BURST_CONNECTIONS', '11'), ('BURST_RATE_PER_SECOND', '3'),
                           ('RECOVERY_INTERVAL_SECONDS', '1')]:
            with self.subTest(key=key), self.assertRaises(probe.ProbeError):
                probe.validate(dict(raw, **{key: value}))
        cfg = dict(self.cfg, ADAPTIVE_DURATION_SECONDS=600, CONNECT_TIMEOUT_SECONDS=30)
        with self.assertRaisesRegex(ValueError, 'ADAPTIVE_DURATION_SECONDS'):
            adaptive.plan(cfg, 'all')

    def test_tls_requires_explicit_compatible_service(self):
        with self.assertRaisesRegex(ValueError, 'TLS_TEST_PORT'):
            adaptive.plan(self.cfg, 'tls')
        with self.assertRaisesRegex(ValueError, 'TLS_SERVER_NAME'):
            adaptive.plan(dict(self.cfg, TLS_TEST_PORT=443), 'tls')
        steps = adaptive.plan(dict(self.cfg, TLS_TEST_PORT=443,
                                   TLS_SERVER_NAME='vpn.example.test'), 'tls')
        self.assertEqual([s['protocol'] for s in steps], ['tcp', 'tls'])

    def test_port_comparison_requires_listener_attestation(self):
        cfg = dict(self.cfg, PORT_COMPARISON_PORTS=[443, 8443])
        with self.assertRaisesRegex(ValueError, 'PORTS_VERIFIED_ON_VPS'):
            adaptive.plan(cfg, 'ports')
        steps = adaptive.plan(dict(cfg, PORTS_VERIFIED_ON_VPS=True), 'ports')
        self.assertEqual([s['port'] for s in steps], [25531, 443, 8443])

    def test_csv_timeline_and_cooldown_waits_without_network(self):
        with tempfile.TemporaryDirectory() as temp:
            steps = adaptive.plan(self.cfg, 'cooldown')
            attempts = []
            with mock.patch.object(adaptive.time, 'sleep') as sleep, \
                 mock.patch.object(adaptive, '_once', return_value=('connected', 'connected',
                                                                      'not_tested', '', 1.0, None)):
                adaptive.execute(self.cfg, steps, 'baseline', Path(temp), attempts)
            self.assertEqual([c.args[0] for c in sleep.call_args_list], [30, 60, 120, 180])
            self.assertEqual(len(attempts), 5)
            self.assertEqual([a['cumulative_planned_wait_seconds'] for a in attempts],
                             [0, 30, 90, 210, 390])
            analysis = adaptive.analyze(attempts)
            self.assertEqual([x['cumulative_planned_wait_seconds']
                              for x in analysis['cooldown_before_after']], [30, 90, 210, 390])
            with (Path(temp) / 'timeline.csv').open() as handle:
                self.assertEqual(len(list(csv.DictReader(handle))), 5)

    def test_deadline_skips_long_wait_without_sleeping_or_connecting(self):
        with tempfile.TemporaryDirectory() as temp:
            steps = adaptive.plan(self.cfg, 'cooldown')
            attempts = []
            with mock.patch.object(adaptive.time, 'sleep') as sleep, \
                 mock.patch.object(adaptive, '_once', return_value=('connected', 'connected',
                                                                      'not_tested', '', 1.0, None)) as connect:
                adaptive.execute(self.cfg, steps, 'syndata', Path(temp), attempts,
                                 deadline=adaptive.time.time() + 20)
            self.assertEqual(connect.call_count, 1)
            sleep.assert_not_called()
            self.assertEqual([a['status'] for a in attempts[1:]], ['skipped_deadline'] * 4)

    def test_monotonic_deadline_skips_even_if_wall_clock_deadline_is_far_away(self):
        with tempfile.TemporaryDirectory() as temp:
            attempts = []
            with mock.patch.object(adaptive, '_once') as connect:
                adaptive.execute(self.cfg, adaptive.plan(self.cfg, 'burst'), 'syndata',
                                 Path(temp), attempts, deadline=adaptive.time.time() + 9999,
                                 monotonic_deadline=adaptive.time.monotonic() - 1)
            connect.assert_not_called()
            self.assertTrue(all(a['status'] == 'skipped_deadline' for a in attempts))

    def test_tls_failure_keeps_successful_tcp_distinct(self):
        cfg = dict(self.cfg, TLS_TEST_PORT=443, TLS_SERVER_NAME='vpn.example.test')
        step = adaptive.plan(cfg, 'tls')[1]
        with mock.patch.object(adaptive.socket, 'create_connection') as connector, \
             mock.patch.object(adaptive.ssl, 'create_default_context') as context:
            context.return_value.wrap_socket.side_effect = adaptive.ssl.SSLError('bad certificate')
            result = adaptive._once(cfg, step)
        self.assertEqual(result[:3], ('tls_failed', 'connected', 'failed'))

    def test_recovery_is_interval_censored_and_not_static_block(self):
        rows = [
            {'protocol': 'tcp', 'status': 'timeout', 'tcp_status': 'timeout',
             'port': 25531, 'scenario': 'recovery', 'stage': 'initial',
             'elapsed_seconds': 0, 'timestamp_utc': 't0'},
            {'protocol': 'tcp', 'status': 'timeout', 'tcp_status': 'timeout',
             'port': 25531, 'scenario': 'recovery', 'stage': 'sample_1',
             'elapsed_seconds': 15, 'timestamp_utc': 't1'},
            {'protocol': 'tcp', 'status': 'connected', 'tcp_status': 'connected',
             'port': 25531, 'scenario': 'recovery', 'stage': 'sample_2',
             'elapsed_seconds': 30, 'timestamp_utc': 't2'},
        ]
        analysis = adaptive.analyze(rows)
        self.assertEqual(analysis['unavailable_periods'][0]['status'], 'interval_censored')
        self.assertEqual(analysis['unavailable_periods'][0]['observation_gap_seconds'], 15)
        self.assertEqual(analysis['tcp_successes'], 1)

    def test_recovery_periods_do_not_cross_scenario_boundaries(self):
        rows = [
            {'protocol': 'tcp', 'status': 'timeout', 'tcp_status': 'timeout',
             'port': 25531, 'scenario': 'cooldown', 'stage': 'initial',
             'elapsed_seconds': 0, 'timestamp_utc': 't0'},
            {'protocol': 'tcp', 'status': 'connected', 'tcp_status': 'connected',
             'port': 25531, 'scenario': 'burst', 'stage': 'before',
             'elapsed_seconds': 30, 'timestamp_utc': 't1'},
        ]
        periods = adaptive.analyze(rows)['unavailable_periods']
        self.assertEqual(len(periods), 1)
        self.assertEqual(periods[0]['status'], 'right_censored')
        self.assertEqual(periods[0]['scenario'], 'cooldown')

    def test_comparison_refuses_different_schedules(self):
        self.assertEqual(adaptive.compare({'adaptive_plan': [1], 'attempts': []},
                                          {'adaptive_plan': [2], 'attempts': []})['status'],
                         'incomparable')
        before = {'adaptive_plan': [1], 'attempts': [{'scenario': 'burst', 'stage': 'before',
                   'port': 25531, 'protocol': 'tcp', 'tcp_status': 'timeout'}]}
        after = {'adaptive_plan': [1], 'attempts': [{'scenario': 'burst', 'stage': 'before',
                  'port': 25531, 'protocol': 'tcp', 'tcp_status': 'connected',
                  'syndata_eligible': True}]}
        comparison = adaptive.compare(before, after)
        self.assertEqual(comparison['status'], 'complete')
        self.assertTrue(comparison['paired_measurements'][0]['syndata_eligible'])
        after['attempts'][0]['status'] = 'skipped_deadline'
        self.assertEqual(adaptive.compare(before, after)['status'], 'partial')

    def test_same_plan_passed_to_baseline_and_syndata(self):
        args = mock.Mock(scenario='burst', phase='compare')
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(probe, 'confirm_target'), \
             mock.patch.object(probe, 'readiness'), \
             mock.patch.object(probe, 'route_info'), \
             mock.patch.object(probe, 'queue_conflict', return_value=None), \
             mock.patch.object(probe, 'STATE_FILE', Path(temp) / 'no-state'), \
             mock.patch.object(probe, 'do_baseline', return_value=Path(temp)) as baseline, \
             mock.patch.object(probe, 'do_test') as syndata:
            probe.do_adaptive(self.cfg, args)
        self.assertEqual(baseline.call_args.kwargs['steps'], syndata.call_args.kwargs['steps'])
        self.assertEqual(syndata.call_args.kwargs['baseline_file'], str(Path(temp) / 'baseline.json'))

    def test_interrupted_adaptive_syndata_removes_only_own_rule(self):
        steps = adaptive.plan(self.cfg, 'burst')
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            with contextlib.ExitStack() as stack:
                patches = [
                    mock.patch.object(probe, 'STATE_DIR', base / 'run'),
                    mock.patch.object(probe, 'STATE_FILE', base / 'run/state.json'),
                    mock.patch.object(probe, 'LOCK_FILE', base / 'run/lock'),
                    mock.patch.object(probe, 'new_report_dir', return_value=base / 'report'),
                    mock.patch.object(probe, 'readiness', return_value='v1.0.4'),
                    mock.patch.object(probe, 'management_info', return_value={'target_rule_matches_ssh': False}),
                    mock.patch.object(probe, 'ssh_target_conflict', return_value=False),
                    mock.patch.object(probe, 'queue_conflict',
                                      side_effect=lambda q, read_rules=True: None if read_rules else 'listener'),
                    mock.patch.object(probe, 'route_info', return_value={}),
                    mock.patch.object(probe, 'snapshot', side_effect=lambda path: path.write_text('rules')),
                    mock.patch.object(probe, 'start_capture', return_value=None),
                    mock.patch.object(probe, 'proc_starttime', return_value='123'),
                    mock.patch.object(probe, 'await_watchdog_ready'),
                    mock.patch.object(probe, 'await_nfqws_queue_ready'),
                    mock.patch.object(probe, 'watchdog_ready_path', return_value=base / 'ready'),
                    mock.patch.object(probe, 'prepare_lua_runtime', return_value=base / 'lua'),
                    mock.patch.object(probe, 'remove_lua_runtime'),
                    mock.patch.object(probe, 'stop_owned_process'),
                    mock.patch.object(probe, 'packet_counts', return_value={'handshakes': 'unknown'}),
                    mock.patch.object(probe, 'run', return_value=mock.Mock(returncode=0, stdout='')),
                    mock.patch.object(probe, 'generate_report'),
                ]
                for patch in patches:
                    stack.enter_context(patch)
                (base / 'report').mkdir()
                (base / 'ready').touch()
                rules = []
                def ipt(action, rule, check=True):
                    if action == '-I':
                        rules.append(rule)
                    elif action == '-D':
                        rules.remove(rule)
                    return True
                process = mock.Mock(pid=123, poll=mock.Mock(return_value=None))
                stack.enter_context(mock.patch.object(probe, 'ipt', side_effect=ipt))
                stack.enter_context(mock.patch.object(probe, 'rule_present',
                                                      side_effect=lambda rule: rule in rules))
                stack.enter_context(mock.patch.object(probe.subprocess, 'Popen', return_value=process))
                stack.enter_context(mock.patch.object(probe.time, 'sleep'))
                stack.enter_context(mock.patch.object(adaptive, 'execute',
                                                      side_effect=probe.ProbeError('interrupted')))
                with self.assertRaisesRegex(probe.ProbeError, 'inspect report'):
                    probe.do_test(self.cfg, mock.Mock(), steps=steps, confirmed=True)
                self.assertEqual(rules, [])
                self.assertFalse((base / 'run/state.json').exists())
                self.assertEqual(probe.read_json(base / 'report/rollback.json')['rollback'], 'complete')
                self.assertTrue((base / 'report/queue-counters.txt').exists())

    def test_adaptive_report_contains_timeline_and_alternatives(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            sample = {'timestamp_utc': '2026-08-10T00:00:00+00:00', 'scenario': 'cooldown',
                      'stage': 'initial', 'port': 25531, 'protocol': 'tcp',
                      'tcp_status': 'timeout', 'tls_status': 'not_tested',
                      'status': 'timeout', 'latency_ms': 5}
            probe.write_json(directory / 'metadata.json', {'configuration': self.cfg})
            probe.write_json(directory / 'baseline.json', {
                'attempts': [sample], 'adaptive_plan': [{'scenario': 'cooldown'}],
                'adaptive_analysis': adaptive.analyze([dict(sample, elapsed_seconds=0)])})
            successful = dict(sample, status='connected', tcp_status='connected',
                              syndata_eligible=True)
            probe.write_json(directory / 'experiment.json', {
                'attempts': [successful], 'adaptive_plan': [{'scenario': 'cooldown'}],
                'adaptive_analysis': adaptive.analyze([dict(successful, elapsed_seconds=0)])})
            result = report.render(directory, self.cfg)
            summary = (directory / 'summary.md').read_text()
            self.assertIn('Временная шкала', summary)
            self.assertIn('Сопоставление одинаковых этапов', summary)
            self.assertIn('Альтернативные объяснения', summary)
            self.assertIn('не строгий A/B-тест', summary)
            self.assertIn('REALITY', summary)
            self.assertEqual(result['metrics']['baseline']['tcp_attempts'], 1)
            self.assertEqual(result['adaptive_comparison']['status'], 'complete')


if __name__ == '__main__':
    unittest.main()
