"""Temporary privileged CI runner for this disposable VM; never shipped in App Sweep."""
import os, stat, json, time, subprocess
from pathlib import Path

TASK = Path('/Users/localtest/AppSweepAcceptanceGeneral-20261016')
SELECTORS = {'root-foundation': 'AppSweepCoreTests.PrivilegedNativeAcceptanceTests',
             'root-service-deployment': 'AppSweepCoreTests.PrivilegedServiceDeploymentTests', 'stop': None}


def process_requests(requests, outputs, deadline, seen, command, env, owner=501, clock=time.monotonic, completed=None):
    if completed is None:
        completed = set()
    for request in sorted(requests.glob('[0-9][0-9][0-9][0-9].json')):
        if clock() >= deadline:
            return False
        if request.name in seen:
            continue
        seen.add(request.name)
        target = outputs / (request.stem + '.log')
        try:
            logfd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        except OSError as error:
            print('CI output unavailable for ' + request.stem + ': ' + str(error), flush=True)
            continue
        with os.fdopen(logfd, 'w') as output:
            try:
                fd = os.open(request, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'r') as stream:
                    identity = os.fstat(stream.fileno())
                    if not stat.S_ISREG(identity.st_mode) or identity.st_uid != owner or identity.st_nlink != 1 or stat.S_IMODE(identity.st_mode) != 0o600 or identity.st_size > 1024:
                        raise ValueError('Invalid private CI request')
                    payload = json.loads(stream.read(1025))
                if not isinstance(payload, dict) or set(payload) != {'operation'} or not isinstance(payload['operation'], str) or payload['operation'] not in SELECTORS:
                    raise ValueError('Unknown fixed CI operation')
                if payload['operation'] == 'stop':
                    output.write('ROOT_RUNNER_STOPPED\n')
                    return False
                if payload['operation'] == 'root-service-deployment' and 'root-foundation' not in completed:
                    output.write('ROOT_REQUEST_REJECTED: root-foundation must succeed in this runner before service installation\n')
                    return False
                remaining = deadline - clock()
                if remaining <= 0:
                    output.write('ROOT_RUNNER_EXPIRED; no test launched\n')
                    return False
                result = subprocess.run(command + ['-XCTest', SELECTORS[payload['operation']], str(TASK / 'build/arm64-apple-macosx/debug/AppSweepPackageTests.xctest')],
                                        env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                        timeout=min(300, remaining))
                output.write('\nROOT_TEST_EXIT=' + str(result.returncode) + '\n')
                if result.returncode != 0:
                    return False
                completed.add(payload['operation'])
            except subprocess.TimeoutExpired:
                output.write('\nROOT_TEST_EXIT=124; timed out; preserve fixtures for inspection\n')
                return False
            except (OSError, ValueError, RecursionError) as error:
                output.write('ROOT_REQUEST_REJECTED: ' + str(error) + '\n')
        print('Completed fixed root CI request ' + request.stem, flush=True)
    return clock() < deadline


def main():
    if os.getuid() != 0 or os.geteuid() != 0 or subprocess.check_output(['/usr/sbin/sysctl', '-n', 'hw.model'], text=True).strip() != 'VirtualMac2,1':
        raise SystemExit('Requires root only inside the registered disposable VirtualMac2,1 VM')
    if TASK.is_symlink() or TASK.resolve() != TASK or TASK.stat().st_uid != 501:
        raise SystemExit('Task ownership mismatch')
    requests = TASK / 'root-service-requests.noindex'; outputs = TASK / 'root-service-outputs.noindex'
    for directory in [requests, outputs]:
        identity = directory.lstat()
        if not stat.S_ISDIR(identity.st_mode) or directory.is_symlink() or identity.st_uid != 501 or stat.S_IMODE(identity.st_mode) != 0o700:
            raise SystemExit('Invalid private CI mailbox')
    # Task-owned code has deliberate root CI authority only inside this VM.
    # No shell, executable path, command or test selector comes from a request.
    developer = TASK / 'developer/Xcode.app/Contents/Developer'
    env = os.environ.copy()
    env.update(DEVELOPER_DIR=str(developer), APP_SWEEP_PRIVILEGED_ACCEPTANCE='1',
               APP_SWEEP_SDK=str(developer / 'Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.2.sdk'),
               TMPDIR=str(TASK / 'tmp') + '/')
    pidfd = os.open(TASK / 'root-service-runner.pid', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(pidfd, 'w') as marker:
        marker.write(str(os.getpid()) + '\n')
    print('Temporary VM root CI runner active; fixed XCTest/task bundle only; expires in six hours.', flush=True)
    deadline = time.monotonic() + 21600
    seen = set(); completed = set()
    while process_requests(requests, outputs, deadline, seen, [str(developer / 'usr/bin/xctest')], env, completed=completed):
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(1, remaining))


if __name__ == '__main__':
    main()
