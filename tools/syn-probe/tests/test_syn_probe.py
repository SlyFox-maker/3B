import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import syn_probe as probe
import report


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.values = dict(line.split('=', 1) for line in probe.DEFAULTS.read_text().splitlines()
                           if line and not line.startswith('#'))

    def test_example_is_valid(self):
        self.assertEqual(probe.validate(self.values)['TARGET_PORT'], 25531)

    def test_reject_bad_ip_port_and_ranges(self):
        for key, value in [('TARGET_IP', '10.0.0.0/8'), ('TARGET_IP', 'localhost'),
                           ('TARGET_PORT', '0'), ('TARGET_PORT', '65536'),
                           ('NFQUEUE_NUM', '-1'), ('TEST_DURATION_SECONDS', '1')]:
            with self.subTest(key=key, value=value):
                cfg = dict(self.values, **{key: value})
                with self.assertRaises(probe.ProbeError):
                    probe.validate(cfg)

    def test_env_never_executes_shell(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'config.env'
            file.write_text(probe.DEFAULTS.read_text() + '\nEXTRA=$(touch /tmp/should-not-run)\n')
            with self.assertRaises(probe.ProbeError):
                probe.parse_env(file)

    def test_missing_binary(self):
        with mock.patch.object(probe, 'BIN', Path('/nonexistent/nfqws2')):
            with self.assertRaisesRegex(probe.ProbeError, 'missing'):
                probe.binary_check()

    def test_root_and_capabilities_required(self):
        cfg = probe.validate(self.values)
        with mock.patch.object(probe.os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(probe.ProbeError, 'root required'):
                probe.readiness(cfg, require_root=True)

    def test_busy_queue(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'nfnetlink_queue'
            p.write_text('129 101 0 0 0 0 0 0 0\n')
            original = probe.Path
            with mock.patch.object(probe, 'Path', side_effect=lambda x: p if x == '/proc/net/netfilter/nfnetlink_queue' else original(x)):
                self.assertIn('listener', probe.queue_conflict(129, read_rules=False))

    def test_queue_ranges_are_conflicts(self):
        for command, output in [('iptables-save', '-j NFQUEUE --queue-balance 128:130'),
                                ('nft', 'queue num 128-130 bypass')]:
            with self.subTest(command=command), \
                 mock.patch.object(probe.shutil, 'which', side_effect=lambda x: x if x == command else None), \
                 mock.patch.object(probe, 'run', return_value=mock.Mock(returncode=0, stdout=output)):
                self.assertIn('referenced', probe.queue_conflict(129))


class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.old_state_dir = probe.STATE_DIR
        self.old_state_file = probe.STATE_FILE
        self.old_lock_file = probe.LOCK_FILE
        probe.STATE_DIR = self.base / 'run'
        probe.STATE_FILE = probe.STATE_DIR / 'state.json'
        probe.LOCK_FILE = probe.STATE_DIR / 'lock'
        self.addCleanup(self.restore)
        self.cfg = probe.parse_env(probe.DEFAULTS)

    def restore(self):
        probe.STATE_DIR = self.old_state_dir
        probe.STATE_FILE = self.old_state_file
        probe.LOCK_FILE = self.old_lock_file

    def state(self, run_id='a1'):
        directory = self.base / 'report'
        directory.mkdir(exist_ok=True)
        rule = probe.exact_rule(self.cfg, run_id)
        state = {'run_id': run_id, 'report_dir': str(directory), 'rule': rule,
                 'deadline_epoch': 0, 'nfq_pid': None, 'nfq_starttime': None,
                 'capture_pid': None, 'capture_starttime': None}
        probe.write_json(probe.STATE_FILE, state)
        return rule

    def test_exact_rule_is_only_target_syn_and_excludes_generated_mark(self):
        rule = probe.exact_rule(self.cfg, 'abc')
        text = ' '.join(rule)
        self.assertIn('-d 72.56.124.34', text)
        self.assertIn('--dport 25531', text)
        self.assertIn('--tcp-flags SYN,ACK SYN', text)
        self.assertIn('! --mark 0x20000000/0x20000000', text)
        self.assertIn('3b-syn-probe-abc', text)

    def test_cleanup_deletes_only_owned_rule_and_preserves_foreign(self):
        own = self.state()
        foreign = ['-p', 'tcp', '-d', '1.1.1.1', '-j', 'ACCEPT']
        rules = [foreign, own]
        def present(rule):
            return rule in rules
        def ipt(action, rule, check=True):
            if action == '-D':
                rules.remove(rule)
            return True
        with mock.patch.object(probe, 'rule_present', side_effect=present), \
             mock.patch.object(probe, 'ipt', side_effect=ipt), \
             mock.patch.object(probe, 'stop_owned_process'):
            outcome = probe.cleanup('a1')
        self.assertEqual(outcome['rollback'], 'complete')
        self.assertEqual(rules, [foreign])
        self.assertFalse(probe.STATE_FILE.exists())

    def test_failed_rule_removal_keeps_state_for_retry(self):
        self.state()
        with mock.patch.object(probe, 'rule_present', return_value=True), \
             mock.patch.object(probe, 'ipt', side_effect=probe.ProbeError('temporary firewall error')), \
             mock.patch.object(probe, 'stop_owned_process'):
            outcome = probe.cleanup('a1')
        self.assertEqual(outcome['rollback'], 'failed')
        self.assertTrue(probe.STATE_FILE.exists())

    def test_firewall_check_error_is_not_treated_as_absent_rule(self):
        self.state()
        with mock.patch.object(probe, 'run', return_value=mock.Mock(returncode=4, stdout='permission denied')):
            with self.assertRaisesRegex(probe.ProbeError, 'iptables -C failed'):
                probe.cleanup('a1')
        self.assertTrue(probe.STATE_FILE.exists())

    def test_watchdog_cleans_after_deadline_and_allows_new_run(self):
        own = self.state()
        rules = [own]
        with mock.patch.object(probe, 'rule_present', side_effect=lambda rule: rule in rules), \
             mock.patch.object(probe, 'ipt', side_effect=lambda action, rule, check=True: rules.remove(rule) or True), \
             mock.patch.object(probe, 'stop_owned_process'):
            self.assertEqual(probe.watchdog('a1'), 0)
        self.assertFalse(probe.STATE_FILE.exists())
        self.state('b2')
        self.assertEqual(probe.read_json(probe.STATE_FILE)['run_id'], 'b2')

    def test_parallel_lock_and_stale_watchdog(self):
        self.state('new')
        self.assertEqual(probe.watchdog('old'), 0)
        self.assertTrue(probe.STATE_FILE.exists())
        with probe.locked():
            with self.assertRaises(BlockingIOError):
                with probe.locked():
                    pass

    def test_incomplete_pcap_is_unknown(self):
        self.assertEqual(probe.packet_counts(self.base, self.cfg)['handshakes'], 'unknown')

    def test_baseline_does_not_run_nfqws(self):
        directory = self.base / 'baseline'
        directory.mkdir()
        def fake_snapshot(path):
            path.write_text('same rules\n')
        with mock.patch.object(probe, 'readiness', return_value=None) as ready, \
             mock.patch.object(probe, 'new_report_dir', return_value=directory), \
             mock.patch.object(probe, 'snapshot', side_effect=fake_snapshot), \
             mock.patch.object(probe, 'route_info', return_value={}), \
             mock.patch.object(probe, 'start_capture', return_value=None), \
             mock.patch.object(probe, 'connect_attempts', return_value=[]), \
             mock.patch.object(probe, 'generate_report'):
            probe.do_baseline(self.cfg)
        ready.assert_called_once_with(self.cfg, require_root=True, check_nfqws=False)
        self.assertFalse(probe.read_json(directory / 'baseline.json')['firewall_changed'])

    def test_deadline_overlap_is_not_success(self):
        with mock.patch.object(probe.socket, 'create_connection') as connector, \
             mock.patch.object(probe.time, 'time', side_effect=[1, 1, 11]):
            connector.return_value.__enter__.return_value = None
            cfg = dict(self.cfg, TEST_ATTEMPTS=1)
            attempts = probe.connect_attempts(cfg, deadline=10)
        self.assertEqual(attempts[0]['status'], 'overlapped_watchdog')


class ReportTests(unittest.TestCase):
    def test_missing_baseline_and_partial_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            cfg = probe.parse_env(probe.DEFAULTS)
            probe.write_json(directory / 'metadata.json', {'kernel': 'test', 'configuration': cfg})
            probe.write_json(directory / 'experiment.json', {
                'attempts': [{'number': 1, 'status': 'timeout', 'latency_ms': 5}],
                'packets': {'status': 'unavailable', 'source': 'no pcap', 'syn': None,
                            'syn_ack': None, 'rst': None, 'handshakes': 'unknown'},
                'errors': ['partial capture']})
            result = report.render(directory, cfg)
            self.assertIsNone(result['metrics']['baseline'])
            self.assertEqual(result['metrics']['syndata']['pcap_handshakes'], 'unknown')
            self.assertIn('partial capture', (directory / 'summary.md').read_text())
            self.assertTrue((directory / 'report.json').exists())


if __name__ == '__main__':
    unittest.main()
