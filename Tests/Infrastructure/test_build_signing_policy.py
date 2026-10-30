"""Fail-fast packaging policy; explicit local macOS packaging gate, without building or installing."""
import os
import platform
from pathlib import Path
import subprocess
import unittest


@unittest.skipUnless(platform.system() == "Darwin" and platform.machine() == "arm64", "ARM macOS packaging gate")
class BuildSigningPolicyTests(unittest.TestCase):
    def check_failure(self, mode, identity, expected):
        env = dict(os.environ)
        env["APP_SWEEP_BUILD_HOST"] = "local"
        for key in ['APP_SWEEP_SIGNING_IDENTITY', 'APP_SWEEP_BUILD_MODE', 'APP_SWEEP_SDK']:
            env.pop(key, None)
        if mode is not None:
            env['APP_SWEEP_BUILD_MODE'] = mode
        if identity is not None:
            env['APP_SWEEP_SIGNING_IDENTITY'] = identity
        script = Path(__file__).resolve().parents[2] / 'script/build_guest.sh'
        result = subprocess.run(['/bin/bash', str(script)], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(expected, result.stdout)

    def test_default_delivery_requires_stable_identity(self):
        self.check_failure(None, None, '交付构建需要有效的稳定签名身份')

    def test_delivery_never_accepts_adhoc(self):
        self.check_failure('delivery', '-', '交付构建需要有效的稳定签名身份')

    def test_unknown_mode_does_not_fall_back(self):
        self.check_failure('typo', None, '构建模式无效')

    def test_explicit_development_passes_signing_gate(self):
        self.check_failure('development', None, 'Set the isolated macOS SDK path')

    def test_explicit_user_authorized_adhoc_delivery_is_available(self):
        self.check_failure('delivery-adhoc', None, 'Set the isolated macOS SDK path')


if __name__ == '__main__':
    unittest.main()
