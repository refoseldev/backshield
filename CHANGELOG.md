# Changelog

## [1.1.0] - 2026-09-20

### Added
- Log rotation: `events.log` rotates to `events.log.1` once it exceeds `MaxLogBytes` (default 2 MB).
- In-game chat alerts for online admins on HIGH-severity events (`NotifyAdmins`, `NotifyThreshold`).
- CAMI integration: registers the `BackShield - View Reports` privilege (`AdminPrivilege`), used for console commands and alerts; falls back to `IsSuperAdmin()` when CAMI is absent.
- Windowed detection rules that match `RunString` within N characters after `http.Fetch`, `HTTP()` or `net.ReadString`, catching multi-line constructs.
- New rules: `sql.QueryTyped` concatenation, `string.format` in `sql.Query`, `_G["Run" .. "String"]`.
- Scan cache: unchanged files (by size) are skipped on rescans; `backshield_scan` forces a full rescan.

### Changed
- `net.Receive`, `RunString` and `CompileString` are patched only once, so re-including the file no longer loses the original functions.
- `backshield_scan` / `backshield_report` permission checks go through the CAMI-aware helper.
- README documents admin access and alerts.

## [1.0.0]

- Initial release: static Lua scanner, `BackShield.Receive` rate limiter, RunString/CompileString monitor.
