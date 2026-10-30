#!/usr/bin/env python3
"""Read-only verification of a guest-built candidate, never an installer."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


def run(*args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if result.returncode:
        raise AssertionError(f"Verification command failed: {args[0]} ({result.returncode})")
    return result.stdout.decode() + result.stderr.decode()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


EXPECTED_ARCHES = sys.argv[2:] or ["arm64", "x86_64"]
assert EXPECTED_ARCHES in (["arm64"], ["arm64", "x86_64"])

def hashes(binary):
    require(set(run('/usr/bin/lipo', '-archs', str(binary)).split()) == set(EXPECTED_ARCHES), 'Candidate lacks a required architecture')
    run('/usr/bin/codesign', '--verify', '--strict', str(binary))
    result = []
    for arch in EXPECTED_ARCHES:
        description = run('/usr/bin/codesign', '-d', '--verbose=4', '--arch', arch, str(binary))
        flags = re.search(r'flags=0x([0-9a-fA-F]+)', description)
        digest = re.search(r'^CDHash=([0-9a-f]{40})$', description, re.MULTILINE)
        require(flags is not None and int(flags.group(1), 16) & 0x10000 != 0, 'Candidate lacks hardened runtime')
        require(digest is not None, 'Candidate code hash cannot be verified')
        result.append(digest.group(1))
    return result


def inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'Installer scripts may not contain symbolic links')
        mode = path.stat().st_mode & 0o7777
        if path.is_dir():
            result[str(path.relative_to(root))] = ('directory', mode)
        else:
            require(path.is_file() and path.stat().st_nlink == 1, 'Installer scripts contain a non-regular or linked file')
            result[str(path.relative_to(root))] = ('file', mode, hashlib.sha256(path.read_bytes()).hexdigest())
    return result


def verify_package(output, package, app, payload):
    staged = output / 'ServiceInstallerScripts'
    require(staged.is_dir() and not staged.is_symlink(), 'Installer script staging is missing')
    require(set(p.name for p in staged.iterdir()) == {'Payload', 'postinstall', 'AppSweepServiceInstaller'}, 'Unexpected installer entry points')
    require(inventory(staged / 'Payload') == inventory(payload), 'Installer staged payload differs from the reviewed service payload')
    require((staged / 'AppSweepServiceInstaller').read_bytes() == (app / 'Contents/Library/HelperTools/AppSweepServiceInstaller').read_bytes(), 'Installer executable differs from signed app copy')
    expected_script = Path(__file__).resolve().parents[2] / 'script/system-service/postinstall'
    require((staged / 'postinstall').read_bytes() == expected_script.read_bytes(), 'Installer entry script differs from reviewed source')
    require((staged / 'postinstall').stat().st_mode & 0o7777 == 0o755, 'Installer entry script is not executable with expected permissions')
    with tempfile.TemporaryDirectory(prefix='package-verification-', dir=output) as review:
        expanded = Path(review) / 'expanded'
        run('/usr/sbin/pkgutil', '--expand-full', str(package), str(expanded))
        require(set(p.name for p in expanded.iterdir()) == {'PackageInfo', 'Scripts'}, 'Installer may contain only scripts, with no automatic filesystem payload')
        info = ET.parse(expanded / 'PackageInfo').getroot()
        require(info.tag == 'pkg-info' and info.get('identifier') == 'org.appsweep.system-service.installer' and info.get('version') == '2.1.0', 'Installer identifier/version mismatch')
        require(info.get('auth') == 'root' and info.get('install-location') == '/' and info.get('relocatable') == 'false', 'Installer authentication or target mismatch')
        scripts = info.find('scripts')
        require(scripts is not None and len(scripts) == 1 and scripts[0].tag == 'postinstall' and scripts[0].get('file') == './postinstall', 'Installer has unexpected executable hooks')
        require(inventory(expanded / 'Scripts') == inventory(staged), 'Expanded installer scripts differ in bytes, types, permissions, or entries')


def main():
    require(sys.platform == 'darwin' and os.getuid() != 0, 'Only the disposable non-root macOS guest may verify this candidate')
    require(os.environ.get('APP_SWEEP_BUILD_HOST') == 'local' or run('/usr/sbin/sysctl', '-n', 'hw.model').startswith('VirtualMac'), 'Explicit local verification opt-in required')
    output = Path(sys.argv[1]).resolve(strict=True)
    require(str(output).startswith(str(Path(os.environ.get('APP_SWEEP_BUILD_ROOT', str(Path.home() / 'AppSweepAcceptance'))).resolve(strict=True)) + '/output/'), 'Candidate is outside the task build output')
    package = output / 'App-Sweep-System-Service-2.1.0.pkg'
    require(package.is_file() and not package.is_symlink(), 'Candidate is missing its authenticated system service package')
    require(0 < package.stat().st_size <= 64 * 1024 * 1024, 'Installer package exceeds its bounded capacity')
    app = output / 'App Sweep.app'
    helper = app / 'Contents/Library/HelperTools/AppSweepSystemService'
    require(helper.is_file() and not helper.is_symlink(), 'Candidate is missing its embedded system service')
    client_hashes = hashes(app / 'Contents/MacOS/AppSweepApp') + hashes(app / 'Contents/MacOS/app-sweep')
    service_hashes = hashes(helper)
    installer = app / 'Contents/Library/HelperTools/AppSweepServiceInstaller'
    require(installer.is_file() and not installer.is_symlink(), 'Candidate is missing its authenticated installer executable')
    hashes(installer)
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', str(app))
    payload = output / 'SystemServicePayload'
    support = payload / 'Library/Application Support/App Sweep'
    service = support / 'Service'
    pins_path = service / 'config.json'
    raw = pins_path.read_bytes()
    pins = json.loads(raw)
    require(set(pins) == {'schemaVersion', 'serviceBuild', 'clientCodeHashes', 'serviceCodeHashes'}, 'Unexpected configuration fields')
    require(raw == json.dumps(pins, sort_keys=True, separators=(',', ':')).encode(), 'Configuration is not canonical JSON')
    require(pins['schemaVersion'] == 1 and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', pins['serviceBuild']), 'Configuration version/build is invalid')
    require(pins['clientCodeHashes'] == sorted(set(client_hashes)), 'Configuration does not pin the final GUI and CLI for both architectures')
    require(pins['serviceCodeHashes'] == sorted(set(service_hashes)), 'Configuration does not pin the final helper for both architectures')
    installed_helper = service / 'AppSweepSystemService'
    require(hashlib.sha256(installed_helper.read_bytes()).digest() == hashlib.sha256(helper.read_bytes()).digest(), 'Payload service differs from the signed embedded service')
    for path, mode in [(support, 0o755), (service, 0o755), (pins_path, 0o644), (installed_helper, 0o755), (support / 'Recovery.noindex', 0o700)]:
        require(not path.is_symlink() and path.stat().st_mode & 0o7777 == mode, 'Payload permission/layout mismatch: ' + str(path.relative_to(payload)))
    require(not any((support / 'Recovery.noindex').iterdir()), 'New payload must not include recovery data')
    require(not (service / 'control.sock').exists(), 'Socket must be created by launchd, never copied from a build')
    declaration = payload / 'Library/LaunchDaemons/org.appsweep.system-service.plist'
    run('/usr/bin/plutil', '-lint', str(declaration))
    job = plistlib.loads(declaration.read_bytes())
    require(job['Label'] == 'org.appsweep.system-service' and job['UserName'] == 'root' and job['GroupName'] == 'wheel', 'Service label/user mismatch')
    require(job['ProgramArguments'] == ['/Library/Application Support/App Sweep/Service/AppSweepSystemService'], 'Service may not accept a caller path or extra arguments')
    socket = job['Sockets']['Control']
    require(socket['SockPathName'] == '/Library/Application Support/App Sweep/Service/control.sock' and socket['SockPathOwner'] == 0 and socket['SockPathGroup'] == 0 and socket['SockPathMode'] == 0o666 and socket['SockType'] == 'stream' and socket['SockPassive'] is True, 'Socket declaration does not match the native listener')
    verify_package(output, package, app, payload)
    print('Requested-architecture runtime signatures, final code pins, staged payload and script-only authenticated package contents verified; no installation or product launch performed.')


if __name__ == '__main__':
    main()
