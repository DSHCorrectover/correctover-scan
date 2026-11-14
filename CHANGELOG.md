# Changelog

## v3.5.0 — Secret-detection rule expansion (verified against real-world leak vectors)

### Fixed
- **`sk_live_` / `sk_test_` keys were invisible to the scanner.** The Stripe-style pattern only matched `sk-` (hyphen). Underscore variants (`sk_live_…`, `sk_test_…`) — the exact format Stripe issues — never fired. New pattern: `sk_(live|test)_…`.
- **Database connection strings with embedded passwords were not detected at all.** `postgres://user:pass@host`, `mongodb://`, `mysql://`, `redis://`, `amqp(s)://`, `mssql://` credentials now fire a critical `cred-exposure` finding. The password segment tolerates literal `@` characters (greedy match to the last `@` before the host).

### Changed
- CLI banner version now tracks `package.json` (was hardcoded to an older value).

### Verification
- Live leak vector test: Stripe `sk_live_` key + PG connection string with `@`-containing password + MongoDB URI → all detected as critical `cred-exposure` findings (line-accurate).
- Regression suite: all tests passed (benign-context suppression, finding grounding, beautify/discovery unchanged).

### Known behavior (unchanged, by design)
- AWS doc-example keys (`AKIA…EXAMPLE`) are still suppressed as placeholder context — documented behavior, not a defect.
