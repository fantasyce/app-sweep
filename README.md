# App Sweep

`app-sweep` is a conservative macOS CLI for auditing and removing an app bundle plus high-confidence leftovers.

This package also includes `App Sweep.app`, a local SwiftUI front end that wraps the CLI. The app is unsigned for local use and does not request administrator privileges.

It is intentionally narrow:

- Default mode is read-only.
- Removal requires `--execute --trash-confirm`.
- Removal uses Finder Trash through `FileManager.trashItem`, not `rm -rf`.
- If the selected `.app` cannot be moved to Trash, its remaining leftovers are skipped to avoid a partial uninstall.
- System-level locations are reported by default; full-audit mode scans from root volumes read-only.
- Symlinks are never removed automatically.
- `com.apple.*` apps are refused.
- Backup reports can be restored for repeatable testing, and restore never overwrites an existing path.

## Requirements

- macOS 12 or newer
- Swift 6 toolchain

## Build

```sh
swift build -c release
```

The CLI binary will be at:

```text
.build/release/app-sweep
```

## App Bundle

```sh
./script/build_and_run.sh --verify
```

The built app is staged at:

```text
dist/App Sweep.app
```

The app bundle contains:

- `Contents/MacOS/AppSweep`: SwiftUI front end.
- `Contents/Resources/app-sweep-cli`: bundled CLI engine.
- `Contents/Resources/AppIcon.icns`: generated project app icon.

The app UI supports:

- browsing installed apps from `/Applications` and `~/Applications`;
- choosing an app bundle manually;
- read-only scan;
- read-only full audit across root-level scan surfaces;
- backup;
- uninstall with explicit confirmation and backup-first option;
- restore from a backup JSON report;
- logs and latest report path.

## Commands

```sh
app-sweep scan /Applications/Example.app --json ~/Desktop/example-scan-before.json
app-sweep audit-full /Applications/Example.app --json ~/Desktop/example-audit-full-before.json
app-sweep backup /Applications/Example.app --backup-root ~/Desktop/ExampleBackup --json ~/Desktop/example-backup.json
app-sweep uninstall /Applications/Example.app --execute --trash-confirm --backup-root ~/Desktop/ExampleBackup --json ~/Desktop/example-uninstall.json
app-sweep audit-full-known com.example.Example Example --json ~/Desktop/example-audit-full-after.json
app-sweep uninstall-known com.example.Example Example --execute --trash-confirm --backup-root ~/Desktop/ExampleBackup --json ~/Desktop/example-known-cleanup.json
app-sweep restore-report ~/Desktop/example-backup.json --execute --restore-confirm --json ~/Desktop/example-restore.json
```

## Confidence Levels

- `high`: exact bundle identifier match in user-level app state/cache paths.
- `medium`: exact app-name match in common user-level support/cache paths.
- `reportOnly`: system-level or privileged locations that should be reviewed manually.
- `blocked`: unsafe paths, symlinks, Apple-owned apps, or protected locations.

## Deep Audit Scope

`audit-full` and `audit-full-known` perform read-only path searches from `/` and `/System/Volumes/Data`, including `/System`, `/Library`, `/private`, and other root-level locations that the current user can enumerate. The command records permission-denied paths as unreadable errors instead of escalating privileges.

Full-audit output is evidence for review; it does not mean every matching path should be deleted. The uninstaller still only trashes high-confidence user-level candidates unless a path is explicitly selected with `trash-path`.

The scanner includes exact bundle-identifier caches in `/private/var/folders/*/*/{C,T}`. These are treated as high-confidence user cache leftovers, while broader system matches remain report-only or blocked.

This tool is built for auditability and recoverable testing, not maximum deletion.

## Development

```sh
./script/test_cli.sh
swift build -c release
```

The CLI safety test suite uses temporary app bundles and a temporary home directory. It should not touch real installed applications.

## License

MIT. See [LICENSE](LICENSE).
