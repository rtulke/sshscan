# CHANGELOG

All notable changes to SSH Algorithm Security Scanner are documented here.

---

## [3.1.0] — Current

### New Features

- **`--filter TOKENS`** — Filter live output by algorithm category and/or host result
  - Algorithm tokens: `supported`, `unsupported`, `flagged`, `weak`, `nsa`
  - Host tokens: `passed`, `failed`, `error`
  - Combinable, e.g. `--filter nsa,failed`
- **`--list-filter`** — Print all available filter tokens with descriptions
- **`--rate-limit N`** — Throttle scan submission to at most N new SSH connections per second; also configurable via `rate_limit` in `[scanner]`
- **`--timeout-banner SEC`** — Override the SSH banner grab timeout independently from `--timeout`; also configurable via `banner_timeout` in `[scanner]`
- **`--strict-host-key-checking MODE`** — Set SSH StrictHostKeyChecking (yes / no / accept-new); also configurable via `strict_host_key_checking` in `[scanner]`; default: `accept-new`
- **`SSHHostResult.from_dict()`** — Deserialize a `to_dict()` payload back into a full `SSHHostResult` including `SSHAlgorithmInfo` objects and parsed `datetime`
- **Stdin piping** — Hosts can be piped via stdin when no `--host`/`--file`/`--local` is given: `echo "host1,host2:2222" | ./sshscan.py`; any mix of commas, spaces, and newlines is accepted
- **Scan header** — One-line summary printed before each batch scan showing host count, threads, timeout, and active options
- **Exit codes** — Structured exit codes: `0` = clean, `1` = fatal/usage error, `2` = compliance failures, `3` = scan errors (connection/timeout)

### Bug Fixes

- **`sanitize_host_input()`** — Switched from character denylist to allowlist (`[a-zA-Z0-9.\-:\[\]_%]`); prevents bypass via uncommon characters
- **Inner parallelism** — `AlgorithmTester` max_workers changed from `min(10, max_workers // 2)` to `min(3, max_workers)`; eliminates potential 200+ concurrent SSH processes; threshold for using parallel algo scan lowered from `> 10` to `> 1`
- **`--port` not applied to `--file` mode** — `default_port` now passed through `load_hosts_from_file()` and `parse_host_string()`
- **ConfigValidator compliance default** — No longer silently defaults to `NIST` when no framework is configured; compliance check is skipped unless explicitly set
- **Compliance `required` check** — `bool(required & supported)` replaced with `required.issubset(supported)`; previously passing with only one matching required algorithm
- **`minimum_score` never enforced** — `security_score` now passed to `check_compliance()`; `score_meets_minimum` included in result
- **`show_nsa_warnings` / `--no-nsa-warnings`** — NSA analysis always runs; flag controls display only; NSA data still included in all exports
- **IPv6 banner scan** — `socket.create_connection()` replaces `socket.socket(AF_INET)` to correctly handle IPv6 hosts
- **Deduplication logging** — Added `_skipped` counter to all six dedup paths; log message now only fires when count > 0
- **`--list-frameworks`** — Fixed empty descriptions; now shows the framework's `name` field
- **`Set` missing from typing import** — Added `Set` to `from typing import ...`

### Configuration Format Change

Config files now use standard INI format (parsed by Python's built-in `configparser`) instead of TOML.
This removes the `toml` external dependency entirely — only `PyYAML` remains.

| Before | After |
|---|---|
| `config.toml` | `sshscan.conf` |
| `privacy_focus_config.toml` | `privacy_focus.conf` |
| `framework = "NIST"` | `framework = NIST` (no quotes) |

Auto-discovery order: `./sshscan.conf` (local) → `~/.conf/sshscan.conf` (user) → `/etc/sshscan/sshscan.conf` (system).

### Removed / Replaced

- **`SSHMultiplexer`** — Removed entirely; ControlMaster multiplexing caused false positives (multiplexed slaves ignore `-o Ciphers/MACs/Kex` flags) and had an unresolvable TOCTOU race condition in `establish_master()`
- **tqdm / `TQDM_AVAILABLE`** — Replaced with a lightweight built-in `Spinner` class (stderr, no external dependency, TTY-aware); eliminates `global TQDM_AVAILABLE` anti-pattern
- **Scan resume** — `ResumeManager`, `--resume`, `--list-scans` removed from scope; pickle-based state was an RCE risk

---

## [3.0.1]

### New Features

- **`setup_logging()`** — Structured logging with three levels: DEBUG (`--debug`), INFO/VERBOSE (`--verbose`), WARNING (default)
- **`--debug`** flag — Enables full function-level debug output including line numbers

---

## [3.0.0] — Major Rewrite

### New Features

- **`EnhancedDNSCache`** — Thread-safe TTL cache with IPv6 support, background cleanup thread, and hostname validation
- **`ConfigValidator`** — Validates all config values with explicit ranges before use; emits warnings for invalid values
- **`AlgorithmTester`** — Handles inner-host algorithm parallelism with configurable worker count
- **`KNOWN_ALGORITHMS`** — Authoritative hardcoded algorithm list covering all known SSH algorithms including those removed from modern OpenSSH; supplements `ssh -Q` output
- **`NSABackdoorDetector`** — Static analysis flagging NIST/NSA-linked algorithms (NIST P-curves, certain ECDH/ECDSA variants) with risk levels
- **`ComplianceFramework`** — Five built-in frameworks: `NIST`, `FIPS_140_2`, `BSI_TR_02102`, `ANSSI`, `PRIVACY_FOCUSED`
- **`--list-frameworks`** — List available compliance frameworks
- **`--compliance FRAMEWORK`** — Check hosts against a compliance framework
- **`--explicit ALGOS`** — Test a specific comma-separated list of algorithms instead of the full set
- **`--local`** — Scan the local SSH server (127.0.0.1)
- **`--summary` / `--summary-only`** — Print aggregated summary after scan; `--summary-only` suppresses live output (with spinner)
- **`--no-nsa-warnings`** — Suppress NSA risk annotations in live output
- **`--format` / `--output`** — Export results as JSON, CSV, or YAML
- **`SSHHostResult.to_dict()`** — Serialize result to plain dict; timestamp as ISO string
- **`SSHHostResult` fields** — Added `error_type`, `timestamp`, `retry_count`
- **`SSHAlgorithmInfo.__hash__()`** — Enables use in sets
- **`sanitize_host_input()`** — Strips shell metacharacters from host input
- **`validate_port()`** — Range-check 1–65535 with clear error
- **`retry_on_failure` decorator** — Exponential backoff with configurable attempts and exceptions
- **`mlkem768x25519-sha256`** — Added to `KNOWN_ALGORITHMS['kex']` (ML-KEM post-quantum KEX)
- **`hmac-sha1` variants** — Added to `WEAK_ALGORITHMS['mac']`

### Bug Fixes (from v2.0.0)

- **TOML config ignored** — `__init__` now reads from nested `config['scanner']` / `config['compliance']` sub-dicts
- **CLI args always overriding config** — All overridable args use `default=None`; only applied when explicitly provided
- **SSH port format** — All SSH commands now use `-p {port} {host}` instead of `{host}:{port}`
- **`str in bytes` TypeError** — Rejection patterns changed to `bytes` literals (`b'no matching cipher found'`)
- **Path traversal in control socket** — `get_control_path()` sanitizes hostname with `re.sub(r'[^\w.-]', '_', host)`
- **`retry_count` never incremented** — Dead code removed from retry decorator
- **`Dict[str, any]`** — Changed to `Dict[str, Any]` (capital `A`, from `typing`)
- **IPv6 host parsing** — `[::1]:22` bracket notation handled via regex before the generic `:` split
- **`ConnectionError` shadowing builtin** — Custom exception renamed to `SSHConnectionError`
- **`urlparse` unused import** — Removed
- **`import io` inside method** — Moved to top-level imports
- **`UserKnownHostsFile=/dev/null`** — Added to all SSH commands; `LogLevel=ERROR` replaces `LogLevel=quiet`
- **`get_local_ssh_algorithms()` called per host** — Now cached in `self._local_algorithms_cache` after first call

### Configuration

- TOML config auto-discovery: `--config FILE`, `~/.sshscan/config.toml`, `~/.sshscan.toml`, `/etc/sshscan/config.toml`, `/etc/sshscan.toml`
- `[scanner]` keys: `threads`, `timeout`, `retry_attempts`, `dns_cache_ttl`, `banner_timeout`, `rate_limit`, `strict_host_key_checking`
- `[compliance]` keys: `framework`

---

## [2.0.0] — Reference Baseline

Original version. 16 documented bugs across config parsing, port format, compliance logic, security, and type errors. See project history for details.
