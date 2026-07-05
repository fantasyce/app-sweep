# Contributing

App Sweep is safety-first software. Changes that expand deletion scope need
tests and clear user-facing documentation.

## Local Checks

```sh
./script/test_cli.sh
swift build -c release
./script/build_and_run.sh --verify
```

The GUI wrapper is unsigned and intended for local development builds.

## Safety Rules

- Prefer read-only reporting over automatic removal.
- Keep destructive operations behind explicit confirmation flags.
- Use Finder Trash for removal, not permanent deletion.
- Never add `sudo` or privileged-helper behavior without a separate design
  review and security discussion.
- Treat system, Apple-owned, and symlink paths as blocked or report-only.

## Pull Requests

Explain the safety impact of the change, list the validation commands you ran,
and include JSON report snippets only after redacting private local paths.
