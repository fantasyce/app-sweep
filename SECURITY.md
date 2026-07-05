# Security Policy

App Sweep is a local macOS uninstaller and audit tool. It is intentionally
conservative, but it still works with user files and app-related state. Review
scan output before running any command that moves files to Trash.

## Safety Boundaries

- App Sweep does not request administrator privileges.
- App Sweep does not use `sudo`.
- App Sweep moves eligible files to Finder Trash instead of deleting them with
  `rm -rf`.
- Apple and system apps with `com.apple.*` bundle identifiers are refused.
- Symlinks are never removed automatically.
- System-level and privileged paths are report-only unless the user explicitly
  chooses a path with `trash-path`.
- Restore never overwrites an existing original path.

## Reporting Issues

Please report safety bugs, unexpected deletion behavior, or incorrect cleanup
candidates through GitHub issues. Include the command used, the generated JSON
report when safe to share, and any relevant macOS version details.

Do not publish reports that contain private paths or app data you do not want
to disclose. Redact personal paths before posting publicly.
