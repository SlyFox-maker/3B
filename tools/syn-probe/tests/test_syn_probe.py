import json
import contextlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
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


class RuntimeLuaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        source = self.base / 'source'
        source.mkdir()
        (source / 'zapret-lib.lua').write_text('return true\n')
        (source / 'zapret-antidpi.lua').write_text('return true\n')
        self.patches = [mock.patch.object(probe, 'STATE_DIR', self.base / 'runroot/private'),
                        mock.patch.object(probe, 'STATE_FILE', self.base / 'runroot/private/state.json'),
                        mock.patch.object(probe, 'LOCK_FILE', self.base / 'runroot/private/lock'),
                        mock.patch.object(probe, 'LUA_LIB', source / 'zapret-lib.lua'),
                        mock.patch.object(probe, 'LUA_ANTIDPI', source / 'zapret-antidpi.lua')]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.cfg = probe.parse_env(probe.DEFAULTS)

    def test_runtime_lua_readable_while_state_and_watchdog_remain_private(self):
        source_modes = [stat.S_IMODE(path.stat().st_mode) for path in
                        (probe.LUA_LIB, probe.LUA_ANTIDPI)]
        directory = probe.prepare_lua_runtime()
        try:
            self.assertEqual(stat.S_IMODE(probe.STATE_DIR.parent.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(probe.STATE_DIR.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(probe.runtime_root().stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
            for name in ('zapret-lib.lua', 'zapret-antidpi.lua'):
                self.assertEqual(stat.S_IMODE((directory / name).stat().st_mode), 0o644)
            probe.write_json(probe.STATE_FILE, {'run_id': 'test'})
            probe.write_json(probe.watchdog_ready_path('test'), {'run_id': 'test'})
            self.assertEqual(stat.S_IMODE(probe.STATE_FILE.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(probe.watchdog_ready_path('test').stat().st_mode), 0o600)
            with probe.locked():
                self.assertEqual(stat.S_IMODE(probe.LOCK_FILE.stat().st_mode), 0o600)
        finally:
            probe.remove_lua_runtime(directory)
        self.assertFalse(directory.exists())
        self.assertTrue(probe.STATE_FILE.exists())
        self.assertEqual(source_modes, [stat.S_IMODE(path.stat().st_mode) for path in
                                        (probe.LUA_LIB, probe.LUA_ANTIDPI)])

    def test_real_launch_arguments_use_runtime_lua_only(self):
        directory = probe.prepare_lua_runtime()
        try:
            args = probe.nfq_args(self.cfg, lua_dir=directory)
            self.assertIn(f'--lua-init=@{directory / probe.LUA_LIB.name}', args)
            self.assertIn(f'--lua-init=@{directory / probe.LUA_ANTIDPI.name}', args)
            self.assertNotIn(f'--lua-init=@{probe.LUA_LIB}', args)
            with self.assertRaisesRegex(probe.ProbeError, 'prepared Lua runtime'):
                probe.nfq_args(self.cfg)
        finally:
            probe.remove_lua_runtime(directory)

    def test_doctor_dry_run_uses_runtime_copies_and_cleans_them(self):
        calls = []
        def fake_run(args, **kwargs):
            calls.append(args)
            if '--dry-run' in args:
                lua_paths = [Path(arg.split('@', 1)[1]) for arg in args if arg.startswith('--lua-init=@')]
                self.assertEqual(len(lua_paths), 2)
                self.assertTrue(all(path.exists() and path.parent.parent == probe.runtime_root()
                                    for path in lua_paths))
                self.assertIn('--intercept=0', args)
                return mock.Mock(returncode=0, stdout='command line parameters verified')
            return mock.Mock(returncode=0, stdout='iptables v1.8.9 (legacy)')
        with mock.patch.object(probe, 'binary_check', return_value='v1.0.4'), \
             mock.patch.object(probe.shutil, 'which', side_effect=lambda command: command), \
             mock.patch.object(probe, 'run', side_effect=fake_run):
            self.assertEqual(probe.readiness(self.cfg), 'v1.0.4')
        self.assertTrue(any('--dry-run' in args for args in calls))
        self.assertFalse(list(probe.runtime_root().glob('lua-*')))
        self.assertFalse(any('-I' in args or '-D' in args for args in calls))

    def test_doctor_command_does_not_call_firewall_mutation(self):
        with mock.patch.object(probe, 'readiness', return_value='v1.0.4'), \
             mock.patch.object(probe, 'route_info', return_value={}), \
             mock.patch.object(probe, 'queue_conflict', return_value=None), \
             mock.patch.object(probe, 'management_info', return_value={}), \
             mock.patch.object(probe, 'run', return_value=mock.Mock(stdout='iptables v1.8.9')), \
             mock.patch.object(probe, 'ipt') as ipt:
            probe.do_doctor(self.cfg)
        ipt.assert_not_called()

    def test_failed_lua_load_or_missing_source_cleans_runtime(self):
        with mock.patch.object(probe, 'binary_check', return_value='v1.0.4'), \
             mock.patch.object(probe.shutil, 'which', side_effect=lambda command: command), \
             mock.patch.object(probe, 'run', return_value=mock.Mock(
                 returncode=1, stdout='LUA file not accessible')):
            with self.assertRaisesRegex(probe.ProbeError, 'LUA file not accessible'):
                probe.readiness(self.cfg)
        self.assertFalse(list(probe.runtime_root().glob('lua-*')))
        with mock.patch.object(probe, 'binary_check', return_value='v1.0.4'), \
             mock.patch.object(probe.shutil, 'which', side_effect=lambda command: command), \
             mock.patch.object(probe, 'run', return_value=mock.Mock(
                 returncode=0, stdout='LUA file not accessible')):
            with self.assertRaisesRegex(probe.ProbeError, 'LUA file not accessible'):
                probe.readiness(self.cfg)
        self.assertFalse(list(probe.runtime_root().glob('lua-*')))
        with mock.patch.object(probe, 'LUA_ANTIDPI', self.base / 'missing.lua'):
            with self.assertRaisesRegex(probe.ProbeError, 'missing'):
                probe.prepare_lua_runtime()
        self.assertFalse(list(probe.runtime_root().glob('lua-*')))

    def test_refuses_exposed_private_state_directory(self):
        probe.STATE_DIR.mkdir(parents=True, mode=0o700)
        probe.STATE_DIR.chmod(0o755)
        with self.assertRaisesRegex(probe.ProbeError, 'unsafe private state directory'):
            probe.prepare_lua_runtime()

    def test_legacy_active_state_blocks_runtime_until_stopped(self):
        root = probe.STATE_DIR.parent
        root.mkdir(mode=0o700)
        (root / 'state.json').write_text('{}')
        with self.assertRaisesRegex(probe.ProbeError, 'legacy SYN Probe state'):
            probe.prepare_lua_runtime()
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)

    def test_stop_can_clean_legacy_exact_rule(self):
        root = probe.STATE_DIR.parent
        root.mkdir(mode=0o700)
        report_dir = self.base / 'legacy-report'
        report_dir.mkdir()
        rule = probe.exact_rule(self.cfg, 'legacy')
        probe.write_json(root / 'state.json', {'run_id': 'legacy', 'rule': rule,
                                              'report_dir': str(report_dir)})
        with mock.patch.object(probe, 'rule_present', side_effect=[True, False]), \
             mock.patch.object(probe, 'ipt', return_value=True) as ipt, \
             mock.patch.object(probe, 'stop_owned_process'):
            self.assertEqual(probe.cleanup()['rollback'], 'complete')
        ipt.assert_called_once_with('-D', rule)
        self.assertFalse((root / 'state.json').exists())


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

    def test_cleanup_removes_experiment_lua_runtime_after_owned_process(self):
        self.state()
        directory = probe.runtime_root() / 'lua-owned'
        directory.mkdir(parents=True)
        (directory / 'zapret-lib.lua').write_text('test')
        state = probe.read_json(probe.STATE_FILE)
        state['lua_runtime_dir'] = str(directory)
        probe.write_json(probe.STATE_FILE, state)
        with mock.patch.object(probe, 'rule_present', return_value=False), \
             mock.patch.object(probe, 'stop_owned_process', return_value=True):
            self.assertEqual(probe.cleanup('a1')['rollback'], 'complete')
        self.assertFalse(directory.exists())

    def test_failed_rule_removal_keeps_state_for_retry(self):
        self.state()
        with mock.patch.object(probe, 'rule_present', return_value=True), \
             mock.patch.object(probe, 'ipt', side_effect=probe.ProbeError('temporary firewall error')), \
             mock.patch.object(probe, 'stop_owned_process'):
            outcome = probe.cleanup('a1')
        self.assertEqual(outcome['rollback'], 'failed')
        self.assertTrue(probe.STATE_FILE.exists())

    def test_cleanup_is_idempotent_and_watchdog_retries_failed_deletion(self):
        self.assertEqual(probe.cleanup()['rollback'], 'not needed')
        self.state()
        calls = []
        def delete(action, rule, check=True):
            calls.append(action)
            if calls.count('-D') == 1:
                raise probe.ProbeError('transient deletion failure')
            return True
        present = iter([True, True, True, False])
        with mock.patch.object(probe, 'rule_present', side_effect=lambda rule: next(present)), \
             mock.patch.object(probe, 'ipt', side_effect=delete), \
             mock.patch.object(probe, 'stop_owned_process'), \
             mock.patch.object(probe.time, 'sleep'):
            self.assertEqual(probe.watchdog('a1'), 0)
        self.assertEqual(calls.count('-D'), 2)
        self.assertFalse(probe.STATE_FILE.exists())
        self.assertEqual(probe.cleanup()['rollback'], 'not needed')

    def test_watchdog_retries_if_nfqws_process_survives_first_cleanup(self):
        self.state()
        outcomes = iter([False, True])
        with mock.patch.object(probe, 'rule_present', return_value=False), \
             mock.patch.object(probe, 'stop_owned_process',
                               side_effect=lambda pid, start: next(outcomes) if pid == 123 else True), \
             mock.patch.object(probe.time, 'sleep'):
            # Only the nfqws process has an identity in this state.
            state = probe.read_json(probe.STATE_FILE)
            state['nfq_pid'], state['nfq_starttime'] = 123, '77'
            probe.write_json(probe.STATE_FILE, state)
            self.assertEqual(probe.watchdog('a1'), 0)
        self.assertFalse(probe.STATE_FILE.exists())

    def test_zombie_owned_process_does_not_keep_rollback_open(self):
        with mock.patch.object(probe, 'proc_starttime', return_value='77'), \
             mock.patch.object(probe, 'proc_state', return_value='Z'), \
             mock.patch.object(probe.os, 'kill') as kill:
            self.assertTrue(probe.stop_owned_process(123, '77'))
        kill.assert_not_called()

    def test_watchdog_readiness_requires_child_acknowledgement(self):
        process = mock.Mock(pid=101, poll=mock.Mock(return_value=None))
        with mock.patch.object(probe, 'proc_starttime', return_value='77'):
            with self.assertRaisesRegex(probe.ProbeError, 'acknowledge'):
                probe.await_watchdog_ready(process, 'a1', timeout=0.01)
            probe.write_json(probe.watchdog_ready_path('a1'),
                             {'run_id': 'a1', 'pid': 101, 'starttime': '77'})
            probe.await_watchdog_ready(process, 'a1', timeout=0.01)
        process.poll.return_value = 1
        with self.assertRaisesRegex(probe.ProbeError, 'exited'):
            probe.await_watchdog_ready(process, 'a1', timeout=0.01)

    def test_refuses_firewall_install_when_watchdog_not_ready(self):
        directory = self.base / 'report'
        directory.mkdir()
        process = mock.Mock(pid=101, poll=mock.Mock(return_value=None))
        with contextlib.ExitStack() as stack:
            for patch in [mock.patch.object(probe, 'readiness', return_value='v1.0.4'),
                          mock.patch.object(probe, 'management_info', return_value={'target_rule_matches_ssh': False}),
                          mock.patch.object(probe, 'ssh_target_conflict', return_value=False),
                          mock.patch.object(probe, 'queue_conflict', return_value=None),
                          mock.patch.object(probe, 'new_report_dir', return_value=directory),
                          mock.patch.object(probe, 'snapshot', side_effect=lambda path: path.write_text('rules')),
                          mock.patch.object(probe, 'route_info', return_value={}),
                          mock.patch.object(probe, 'proc_starttime', return_value='77'),
                          mock.patch.object(probe, 'rule_present', return_value=False),
                          mock.patch.object(probe, 'stop_owned_process'),
                          mock.patch.object(probe.subprocess, 'Popen', return_value=process),
                          mock.patch.object(probe, 'await_watchdog_ready',
                                            side_effect=probe.ProbeError('no acknowledgement'))]:
                stack.enter_context(patch)
            insert = stack.enter_context(mock.patch.object(probe, 'ipt'))
            with self.assertRaisesRegex(probe.ProbeError, 'no acknowledgement'):
                probe.do_test(self.cfg, mock.Mock(), confirmed=True)
            insert.assert_not_called()
        self.assertFalse(probe.STATE_FILE.exists())

    def test_nfqws_exit_prevents_firewall_install(self):
        process = mock.Mock(poll=mock.Mock(return_value=1))
        with self.assertRaisesRegex(probe.ProbeError, 'nfqws2 exited'):
            probe.await_nfqws_queue_ready(process, 129, self.base / 'missing', timeout=0.01)

    def test_do_test_nfqws_crash_keeps_rule_uninstalled_and_report(self):
        directory = self.base / 'report'
        directory.mkdir()
        ready = self.base / 'ready'
        ready.touch()
        watchdog = mock.Mock(pid=100, poll=mock.Mock(return_value=None))
        nfqws = mock.Mock(pid=101, poll=mock.Mock(return_value=1))
        with contextlib.ExitStack() as stack:
            for patch in [mock.patch.object(probe, 'readiness', return_value='v1.0.4'),
                          mock.patch.object(probe, 'management_info', return_value={'target_rule_matches_ssh': False}),
                          mock.patch.object(probe, 'ssh_target_conflict', return_value=False),
                          mock.patch.object(probe, 'queue_conflict', return_value=None),
                          mock.patch.object(probe, 'new_report_dir', return_value=directory),
                          mock.patch.object(probe, 'snapshot', side_effect=lambda path: path.write_text('rules')),
                          mock.patch.object(probe, 'route_info', return_value={}),
                          mock.patch.object(probe, 'proc_starttime', return_value='77'),
                          mock.patch.object(probe, 'rule_present', return_value=False),
                          mock.patch.object(probe, 'stop_owned_process'),
                          mock.patch.object(probe, 'packet_counts', return_value={'handshakes': 'unknown'}),
                          mock.patch.object(probe, 'generate_report'),
                          mock.patch.object(probe, 'await_watchdog_ready'),
                          mock.patch.object(probe, 'watchdog_ready_path', return_value=ready),
                          mock.patch.object(probe, 'prepare_lua_runtime', return_value=self.base / 'lua'),
                          mock.patch.object(probe, 'remove_lua_runtime'),
                          mock.patch.object(probe.subprocess, 'Popen', side_effect=[watchdog, nfqws])]:
                stack.enter_context(patch)
            insert = stack.enter_context(mock.patch.object(probe, 'ipt'))
            with self.assertRaisesRegex(probe.ProbeError, 'inspect report'):
                probe.do_test(self.cfg, mock.Mock(), confirmed=True)
            insert.assert_not_called()
        saved = probe.read_json(directory / 'experiment.json')
        self.assertEqual(saved['status'], 'partial')
        self.assertIn('nfqws2 exited', saved['errors'][0])
        self.assertFalse(probe.STATE_FILE.exists())

    def test_queue_listener_without_nfqws_bind_log_is_not_ready(self):
        log = self.base / 'nfqws.log'
        log.write_text('unrelated listener\n')
        process = mock.Mock(poll=mock.Mock(return_value=None))
        with mock.patch.object(probe, 'queue_conflict', return_value='listener'), \
             mock.patch.object(probe.time, 'sleep'):
            with self.assertRaisesRegex(probe.ProbeError, 'not confirmed'):
                probe.await_nfqws_queue_ready(process, 129, log, timeout=0.01)

    def test_firewall_integrity_separates_counters_and_foreign_rules(self):
        directory = self.base
        (directory / 'firewall-before.txt').write_text('# Generated by iptables-save on t1\nunchanged\n# Completed on t1\n')
        (directory / 'firewall-after.txt').write_text('# Generated by iptables-save on t2\nunchanged\n# Completed on t2\n')
        (directory / 'firewall-before.nft.txt').write_text('counter packets 1 bytes 40 # handle 5\n')
        (directory / 'firewall-after.nft.txt').write_text('counter packets 2 bytes 80 # handle 5\n')
        result = probe.firewall_integrity(directory)
        self.assertFalse(result['foreign_rules_changed'])
        self.assertTrue(result['dynamic_or_raw_changes'])
        (directory / 'firewall-after.txt').write_text('foreign rule added\n')
        changed = probe.firewall_integrity(directory)
        self.assertTrue(changed['foreign_rules_changed'])
        self.assertTrue(changed['dynamic_counter_changes'])

    def test_interception_evidence_levels_are_distinct(self):
        path = self.base / 'nfqws-debug.log'
        path.write_text('packet: id=1\nLUA: syndata: 00 00\n')
        evidence = probe.interception_evidence(2, path, {'outgoing_syn_payload': None})
        self.assertTrue(evidence['nfqueue_hit'])
        self.assertTrue(evidence['nfqws_action_observed'])
        self.assertIsNone(evidence['outgoing_syn_payload_observed'])
        self.assertFalse(evidence['modified_packet_confirmed'])

    def test_client_pcap_syn_payload_is_only_candidate_evidence(self):
        (self.base / 'tcpdump-client.pcap').write_bytes(b'pcap')
        output = ('1 IP 192.0.2.2.55555 > 72.56.124.34.25531: Flags [S], seq 1, length 16\n'
                  '2 IP 72.56.124.34.25531 > 192.0.2.2.55555: Flags [S.], seq 2, length 0\n')
        with mock.patch.object(probe, 'run', return_value=mock.Mock(returncode=0, stdout=output)):
            counts = probe.packet_counts(self.base, self.cfg)
        self.assertEqual(counts['outgoing_syn_payload'], 1)
        self.assertEqual(counts['syn_ack'], 1)

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

    def test_watchdog_uses_monotonic_deadline_when_wall_clock_moves_back(self):
        self.state()
        state = probe.read_json(probe.STATE_FILE)
        state['deadline_epoch'] = time.time() + 10000
        state['deadline_monotonic'] = time.monotonic() - 1
        probe.write_json(probe.STATE_FILE, state)
        with mock.patch.object(probe, 'rule_present', return_value=False), \
             mock.patch.object(probe, 'stop_owned_process'):
            self.assertEqual(probe.watchdog('a1'), 0)
        self.assertFalse(probe.STATE_FILE.exists())

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

    def test_connect_attempts_journal_survives_partial_run(self):
        path = self.base / 'attempts.live.jsonl'
        with mock.patch.object(probe.socket, 'create_connection') as connector:
            connector.return_value.__enter__.return_value = None
            rows = probe.connect_attempts(dict(self.cfg, TEST_ATTEMPTS=2), journal=path)
        saved = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(saved, rows)
        self.assertEqual(len(saved), 2)


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
