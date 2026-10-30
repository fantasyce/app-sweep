# App Sweep

A native macOS app for reviewing caches, uninstalling applications and restoring removed items. Chinese interface with light and dark appearance.

## Install

Download the app ZIP and matching service installer from [Releases](https://github.com/fantasyce/app-sweep/releases). Move **App Sweep.app** to Applications. Follow the app's disk-access setup; the optional system service requires administrator authentication.

The current binary is for **Apple Silicon**, ad-hoc signed and not notarized. Privacy permissions may need renewal after replacement. Execution is limited to the platform/rule combinations in `NativeAcceptance.swift`; other combinations remain read-only.

## Use

Scan, review selected items, then move them into recovery. User data is retained by default. Running, shared, protected or unconfirmed items are kept. Moving items into recovery does **not** free disk space; permanent emptying requires separate confirmation.

## Build

Requires Swift 6: `swift build -c release`. Packaging: `script/build_guest.sh` (explicit SDK, output directory and signing mode required). Run destructive tests only with disposable fixtures.

[MIT license](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md)
