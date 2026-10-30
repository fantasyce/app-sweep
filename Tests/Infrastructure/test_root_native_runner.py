import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import importlib.util
spec = importlib.util.spec_from_file_location('root_native_runner', Path(__file__).with_name('root-native-runner.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerLifetimeTests(unittest.TestCase):
    def test_failed_privileged_test_stops_before_the_next_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requests = root / 'requests'; requests.mkdir()
            outputs = root / 'outputs'; outputs.mkdir()
            for name, operation in [('0001.json', 'root-foundation'), ('0002.json', 'root-service-deployment')]:
                request = requests / name
                request.write_text(json.dumps({'operation': operation})); request.chmod(0o600)
            with patch.object(runner.subprocess, 'run', return_value=type('Result', (), {'returncode': 1})()) as launch:
                running = runner.process_requests(requests, outputs, 10.0, set(), ['fixed-xctest'], {},
                                                  owner=request.stat().st_uid, clock=lambda: 0.0)
            self.assertFalse(running)
            self.assertEqual(launch.call_count, 1)
            self.assertFalse((outputs / '0002.log').exists())

    def test_timed_out_privileged_test_stops_before_the_next_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requests = root / 'requests'; requests.mkdir()
            outputs = root / 'outputs'; outputs.mkdir()
            for name in ['0001.json', '0002.json']:
                request = requests / name
                request.write_text('{"operation":"root-foundation"}'); request.chmod(0o600)
            with patch.object(runner.subprocess, 'run', side_effect=runner.subprocess.TimeoutExpired('fixed-xctest', 10)) as launch:
                running = runner.process_requests(requests, outputs, 10.0, set(), ['fixed-xctest'], {},
                                                  owner=request.stat().st_uid, clock=lambda: 0.0)
            self.assertFalse(running)
            self.assertEqual(launch.call_count, 1)
            self.assertFalse((outputs / '0002.log').exists())

    def test_service_installation_uses_only_the_fixed_native_test_selector(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requests = root / 'requests'; requests.mkdir()
            outputs = root / 'outputs'; outputs.mkdir()
            for name, operation in [('0001.json', 'root-foundation'), ('0002.json', 'root-service-deployment')]:
                request = requests / name
                request.write_text(json.dumps({'operation':operation})); request.chmod(0o600)
            with patch.object(runner.subprocess, 'run', return_value=type('Result', (), {'returncode': 0})()) as launch:
                runner.process_requests(requests, outputs, 10.0, set(), ['fixed-xctest'], {},
                                        owner=request.stat().st_uid, clock=lambda: 0.0)
            self.assertEqual(launch.call_count, 2)
            self.assertEqual(launch.call_args.args[0][1:3], ['-XCTest', 'AppSweepCoreTests.PrivilegedServiceDeploymentTests'])

    def test_service_installation_requires_successful_foundation_in_this_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requests = root / 'requests'; requests.mkdir()
            outputs = root / 'outputs'; outputs.mkdir()
            request = requests / '0001.json'
            request.write_text('{"operation":"root-service-deployment"}'); request.chmod(0o600)
            with patch.object(runner.subprocess, 'run') as launch:
                running = runner.process_requests(requests, outputs, 10.0, set(), ['fixed-xctest'], {},
                                                  owner=request.stat().st_uid, clock=lambda: 0.0)
            self.assertFalse(running)
            launch.assert_not_called()
            self.assertIn('foundation', (outputs / '0001.log').read_text())

    def test_service_installation_cannot_accept_a_package_path_from_the_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requests = root / 'requests'; requests.mkdir()
            outputs = root / 'outputs'; outputs.mkdir()
            request = requests / '0001.json'
            request.write_text('{"operation":"root-service-deployment","packageRoot":"/System"}'); request.chmod(0o600)
            with patch.object(runner.subprocess, 'run') as launch:
                runner.process_requests(requests, outputs, 10.0, set(), ['fixed-xctest'], {},
                                        owner=request.stat().st_uid, clock=lambda: 0.0)
            launch.assert_not_called()
            self.assertIn('ROOT_REQUEST_REJECTED', (outputs / '0001.log').read_text())

    def test_each_launch_obeys_remaining_lifetime_even_with_backlog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requests = root / 'requests'; requests.mkdir()
            outputs = root / 'outputs'; outputs.mkdir()
            for number in range(3):
                request = requests / ('%04d.json' % number)
                request.write_text(json.dumps({'operation': 'root-foundation'}))
                request.chmod(0o600)
            now = [0.0]
            launches = []
            def launch(*args, **kwargs):
                launches.append(kwargs['timeout'])
                now[0] = 11.0
                return type('Result', (), {'returncode': 0})()
            with patch.object(runner.subprocess, 'run', side_effect=launch):
                runner.process_requests(requests, outputs, 10.0, set(),
                                        ['fixed-xctest'], {}, owner=request.stat().st_uid,
                                        clock=lambda: now[0])
            self.assertEqual(launches, [10.0])
            self.assertEqual(len(list(outputs.glob('*.log'))), 1)

    def test_malformed_request_records_failure_and_next_request_still_runs(self):
        self.assert_malformed_then_valid('[')

    def test_deep_malformed_request_records_failure_and_next_request_still_runs(self):
        self.assert_malformed_then_valid('[' * 1024)

    def assert_malformed_then_valid(self, malformed):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requests = root / 'requests'; requests.mkdir()
            outputs = root / 'outputs'; outputs.mkdir()
            bad = requests / '0001.json'; bad.write_text(malformed); bad.chmod(0o600)
            good = requests / '0002.json'
            good.write_text('{"operation":"root-foundation"}'); good.chmod(0o600)
            with patch.object(runner.subprocess, 'run', return_value=type('Result', (), {'returncode': 0})()) as launch:
                runner.process_requests(requests, outputs, 10.0, set(), ['fixed-xctest'], {},
                                        owner=good.stat().st_uid, clock=lambda: 0.0)
            self.assertEqual(launch.call_count, 1)
            self.assertIn('ROOT_REQUEST_REJECTED', (outputs / '0001.log').read_text())
            self.assertIn('ROOT_TEST_EXIT=0', (outputs / '0002.log').read_text())


if __name__ == '__main__':
    unittest.main()
