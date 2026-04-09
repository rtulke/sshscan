# SSH Algorithm Security Scanner

A single-file Python tool for auditing SSH algorithm configuration across one or many hosts.
Wraps the system `ssh` binary to probe each algorithm individually — no paramiko, no authentication.

**Version:** 3.1.0 | **Author:** Robert Tulke

---

## What it can do

- Probe every cipher, MAC, key exchange, and host key algorithm a server supports
- Score each host 0–100 based on algorithm strength
- Detect weak and deprecated algorithms (3DES, arcfour, HMAC-MD5, DSA, ...)
- Flag algorithms with suspected NSA involvement (NIST P-curves and related)
- Check results against five compliance frameworks: NIST, FIPS 140-2, BSI TR-02102, ANSSI, PRIVACY_FOCUSED
- Scan a single host, a comma-separated list, a file (JSON/YAML/CSV/TXT), or stdin
- Filter live output by algorithm category or host result
- Rate-limit connections to protect fragile targets
- Export results as JSON, CSV, or YAML
- Run fully unattended with `--summary-only` (spinner on stderr, report at the end)

## What it cannot do

- **Not a port scanner** — assumes SSH is running on the given port; does not discover open ports
- **No authentication** — uses `PreferredAuthentications=none`; never logs in, never executes commands
- **No configuration push** — read-only analysis only
- **No CVE integration** — does not map findings to CVE IDs
- **No daemon / continuous monitoring** — single-run tool
- **Windows**: works fine under WSL (Windows Subsystem for Linux); native Windows requires the OpenSSH client (`winget install Microsoft.OpenSSH.Beta` or via Optional Features) — the tool should run but is untested, and `/etc/sshscan/` auto-discovery does not apply
- **No paramiko** — depends on the system SSH binary; behavior reflects the installed SSH client version
- **No scan resume** — interrupted scans cannot be continued

---

## Requirements

| Requirement | Minimum |
|---|---|
| Python | 3.8+ |
| OpenSSH client | `ssh` in PATH |
| PyYAML | for YAML host files and YAML export |

```bash
pip install -r requirements.txt
# or individually:
pip install pyyaml
```

---

## Installation

### Quick (system Python)

```bash
git clone https://github.com/rtulke/sshscan.git
cd sshscan
pip install pyyaml
chmod +x sshscan.py
./sshscan.py --version
```

### Windows (WSL or native OpenSSH)

**WSL** — open a WSL terminal and follow the Linux instructions above.

**Native Windows** — install the OpenSSH client first, then:
```powershell
winget install Microsoft.OpenSSH.Beta   # or via Settings > Optional Features
git clone https://github.com/rtulke/sshscan.git
cd sshscan
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
python sshscan.py --version
```
Note: `/etc/sshscan/` config auto-discovery does not apply on Windows; use `--config` or place `sshscan.conf` in the working directory.

### Virtual environment (recommended)

```bash
git clone https://github.com/rtulke/sshscan.git
cd sshscan
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 sshscan.py --version
```

### System-wide configuration

```bash
mkdir -p ~/.conf
cp sshscan.conf ~/.conf/sshscan.conf
# Edit to taste — loaded automatically without --config
```

---

## Configuration

### Config file auto-discovery (no --config needed)

The scanner checks these locations in order and loads the first file found:

| Priority | Path | Used when |
|---|---|---|
| 1 | `./sshscan.conf` | file exists in the current working directory |
| 2 | `~/.conf/sshscan.conf` | user-level config |
| 3 | `/etc/sshscan/sshscan.conf` | system-wide config |

`--config FILE` overrides auto-discovery entirely and always takes precedence.
CLI arguments always override config file values.

### `[scanner]` keys

| Key | Type | Range | Default | CLI equivalent |
|---|---|---|---|---|
| `threads` | int | 1–500 | 20 | `--threads` / `-T` |
| `timeout` | int (s) | 1–120 | 10 | `--timeout` / `-t` |
| `retry_attempts` | int | 1–10 | 3 | `--retry-attempts` |
| `dns_cache_ttl` | int (s) | 60–3600 | 300 | — |
| `banner_timeout` | int (s) | 1–30 | min(timeout, 5) | `--timeout-banner` |
| `rate_limit` | float | 0.1–1000 | unlimited | `--rate-limit` |
| `strict_host_key_checking` | string | yes / no / accept-new | accept-new | `--strict-host-key-checking` |

### `[compliance]` keys

| Key | Type | Default | CLI equivalent |
|---|---|---|---|
| `framework` | string | none | `--compliance` |

### Minimal config example

```ini
[scanner]
threads = 50
timeout = 10

[compliance]
framework = NIST
```

### Full config example

```ini
[scanner]
threads = 30
timeout = 15
retry_attempts = 3
dns_cache_ttl = 600
banner_timeout = 3
rate_limit = 10.0
strict_host_key_checking = accept-new

[compliance]
framework = BSI_TR_02102
```

### Privacy-focused preset

Use `privacy_focus.conf` (included) for a ready-made configuration that enforces
the `PRIVACY_FOCUSED` compliance framework:

```bash
python3 sshscan.py --config privacy_focus.conf --file hosts.txt
```

---

## Complete Parameter Reference

### General

| Parameter | Short | Description |
|---|---|---|
| `--version` | `-V` | Print version and author, then exit |
| `--config FILE` | `-c` | Load configuration from FILE (INI format) |
| `--help` | `-h` | Show help and exit |

### Host specification (mutually exclusive)

| Parameter | Short | Description |
|---|---|---|
| `--host HOSTS` | `-H` | Single host or comma-separated list, e.g. `host1,host2:2222` |
| `--file FILE` | `-f` | File containing hosts (.json, .yaml, .csv, .txt) |
| `--local` | `-l` | Scan local SSH server at 127.0.0.1 |
| *(stdin)* | | Pipe hosts when no other source is given |

### Scanning options

| Parameter | Short | Default | Description |
|---|---|---|---|
| `--port PORT` | `-p` | 22 | Default SSH port for hosts without explicit port |
| `--threads N` | `-T` | 20 | Concurrent scan threads |
| `--timeout SEC` | `-t` | 10 | SSH connection timeout in seconds |
| `--retry-attempts N` | | 3 | Retry attempts with exponential backoff |
| `--rate-limit N` | | unlimited | Max new SSH connections per second |
| `--timeout-banner SEC` | | min(timeout,5) | Timeout for initial SSH banner grab only |
| `--strict-host-key-checking MODE` | | accept-new | SSH StrictHostKeyChecking: yes / no / accept-new |

### Algorithm testing

| Parameter | Short | Description |
|---|---|---|
| `--explicit ALGOS` | `-e` | Test only the given comma-separated algorithms instead of the full set |

### Compliance

| Parameter | Description |
|---|---|
| `--compliance FRAMEWORK` | Check results against a framework (see table below) |
| `--list-frameworks` | List available compliance frameworks and exit |
| `--no-nsa-warnings` | Suppress NSA risk annotations in live output (analysis still runs; data included in exports) |

### Output

| Parameter | Short | Description |
|---|---|---|
| `--format FORMAT` | | Export format: `json`, `csv`, `yaml` |
| `--output FILE` | `-o` | Write exported results to FILE (default: stdout) |
| `--filter TOKENS` | | Filter live output (see Filter section) |
| `--list-filter` | | List all filter tokens and exit |
| `--summary` | | Print aggregated summary after scan |
| `--summary-only` | | Suppress live output; show only summary (with spinner) |
| `--verbose` | `-v` | Verbose logging (INFO level) |
| `--debug` | | Full debug logging with function names and line numbers |

---

## Usage Examples

### Single host

```bash
python3 sshscan.py --host example.com
python3 sshscan.py --host example.com:2222
python3 sshscan.py --host 192.168.1.1
```

### Multiple hosts

```bash
# Comma-separated inline
python3 sshscan.py --host "server1.com,server2.com:2222,192.168.1.100"

# From a text file
python3 sshscan.py --file hosts.txt

# From stdin (any mix of commas, spaces, newlines)
echo "server1.com server2.com:2222" | python3 sshscan.py
cat hosts.txt | python3 sshscan.py

# Multiple formats work
printf "server1.com\n192.168.1.1:2222\nserver3.com" | python3 sshscan.py
```

### Local SSH server

```bash
python3 sshscan.py --local
python3 sshscan.py --local --port 2222
```

### Compliance checking

```bash
# Check against NIST framework
python3 sshscan.py --host example.com --compliance NIST

# Strict BSI check across a server fleet
python3 sshscan.py --file servers.txt --compliance BSI_TR_02102

# Privacy-focused: exclude all NIST/NSA-suspected algorithms
python3 sshscan.py --file hosts.txt --compliance PRIVACY_FOCUSED

# List all available frameworks
python3 sshscan.py --list-frameworks
```

### Output filtering

```bash
# Show only NSA-flagged algorithms
python3 sshscan.py --host example.com --filter nsa

# Show only weak algorithms
python3 sshscan.py --file hosts.txt --filter weak

# Show all flagged algorithms (weak + NSA combined)
python3 sshscan.py --file hosts.txt --filter flagged

# Show only hosts that failed compliance
python3 sshscan.py --file hosts.txt --compliance NIST --filter failed

# Show only scan errors
python3 sshscan.py --file hosts.txt --filter error

# Combine: show NSA algorithms on failed hosts only
python3 sshscan.py --file hosts.txt --compliance NIST --filter nsa,failed

# List all filter tokens
python3 sshscan.py --list-filter
```

### Export results

```bash
# JSON export to stdout
python3 sshscan.py --file hosts.txt --format json

# JSON export to file
python3 sshscan.py --file hosts.txt --format json --output results.json

# CSV for spreadsheet import
python3 sshscan.py --file hosts.txt --compliance NIST --format csv --output audit.csv

# YAML
python3 sshscan.py --file hosts.txt --format yaml --output results.yaml
```

### Summary mode

```bash
# Suppress live output, show only report at the end
python3 sshscan.py --file hosts.txt --summary-only

# Live output + summary at the end
python3 sshscan.py --file hosts.txt --summary

# summary-only with compliance and JSON export
python3 sshscan.py --file hosts.txt --compliance NIST --summary-only --format json --output results.json
```

### Performance tuning

```bash
# Fast scan of a large network
python3 sshscan.py --file large_network.txt --threads 100 --timeout 5

# Gentle scan for rate-sensitive targets (5 connections/sec)
python3 sshscan.py --file hosts.txt --rate-limit 5.0

# Slow network: long timeout, short banner timeout
python3 sshscan.py --file hosts.txt --timeout 30 --timeout-banner 5

# Conservative: 10 threads, 3 retries, long timeout
python3 sshscan.py --file hosts.txt --threads 10 --timeout 30 --retry-attempts 5
```

### Specific algorithm testing

```bash
# Test only modern recommended algorithms
python3 sshscan.py --host example.com \
  --explicit "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,curve25519-sha256,ssh-ed25519"

# Check if legacy weak algorithms are still supported
python3 sshscan.py --file hosts.txt \
  --explicit "3des-cbc,arcfour,hmac-md5,ssh-dss"
```

### NSA analysis

```bash
# Show full NSA risk analysis per host (default)
python3 sshscan.py --host example.com

# Suppress NSA annotations in live output (data still in exports)
python3 sshscan.py --file hosts.txt --no-nsa-warnings --format json --output results.json
```

### Using a config file

```bash
# Explicit config
python3 sshscan.py --config sshscan.conf --file servers.txt

# Override config values on the CLI
python3 sshscan.py --config sshscan.conf --threads 50 --timeout 20

# Use privacy preset
python3 sshscan.py --config privacy_focus.conf --file hosts.txt

# Auto-loaded from ~/.conf/sshscan.conf (no --config needed)
python3 sshscan.py --file servers.txt
```

### Debug and logging

```bash
# Verbose INFO logging
python3 sshscan.py --host example.com --verbose

# Full debug output (function names, line numbers)
python3 sshscan.py --host example.com --debug
```

---

## Output Filtering

`--filter` accepts comma-separated tokens. Algorithm and host filters can be freely combined.

### Algorithm tokens (control which algorithm lines are shown)

| Token | Shows |
|---|---|
| `supported` | Algorithms the server supports, with no warning |
| `unsupported` | Algorithms the server does not support |
| `flagged` | All flagged algorithms (weak + NSA combined) |
| `weak` | Only weak/deprecated algorithms (subset of flagged) |
| `nsa` | Only NSA-suspected algorithms (subset of flagged) |

### Host tokens (show only hosts matching the condition)

| Token | Shows |
|---|---|
| `passed` | Hosts that passed the compliance check (requires `--compliance`) |
| `failed` | Hosts that failed the compliance check (requires `--compliance`) |
| `error` | Hosts where the scan failed (connection error, timeout, DNS failure) |

When host tokens are active, all output for a host is buffered until the scan completes,
then either flushed or discarded based on the filter result.

---

## Compliance Frameworks

| Framework | Description | Minimum Score |
|---|---|---|
| `NIST` | NIST Cybersecurity Framework — balanced baseline | 70 |
| `FIPS_140_2` | FIPS 140-2 Level 1 — requires NIST curves, forbids Curve25519 | 90 |
| `BSI_TR_02102` | German BSI TR-02102-4 — very strict, requires ETM MACs | 85 |
| `ANSSI` | French ANSSI guidelines — highest strictness | 90 |
| `PRIVACY_FOCUSED` | Anti-surveillance — forbids all NIST curves, requires Curve25519/Ed25519 | 95 |

Each framework defines required and forbidden algorithms per category (cipher, MAC, KEX, host key)
and a minimum security score. A host is compliant only when all required algorithms are present,
no forbidden algorithms are present, and the score meets the minimum.

---

## NSA Backdoor Detection

The scanner flags algorithms with suspected NSA design influence based on public research and
the Snowden disclosures.

### High-risk (NIST P-curves)

| Category | Algorithms |
|---|---|
| Key exchange | `ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521` |
| Host keys | `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521` |

### Recommended alternatives

| Purpose | Recommended |
|---|---|
| Key exchange | `curve25519-sha256`, `mlkem768x25519-sha256` (post-quantum) |
| Host keys | `ssh-ed25519` |
| Encryption | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com` |
| MAC | `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com` |

NSA analysis always runs. Use `--no-nsa-warnings` to suppress the annotations in live output;
the data is still included in all exports.

---

## Security Scoring

Each host is scored 0–100 based on the algorithms it supports.

| Score | Rating |
|---|---|
| 90–100 | Excellent — modern algorithms only |
| 70–89 | Good — mostly modern, few legacy |
| 50–69 | Fair — mixed |
| 30–49 | Poor — many weak algorithms |
| 0–29 | Critical — predominantly weak or NSA-flagged |

Weak algorithms reduce the score proportionally. NSA-flagged algorithms apply a 1.5× penalty.
The score must meet the framework's `minimum_score` threshold for compliance to pass.

### Weak algorithms detected

| Category | Algorithms |
|---|---|
| Cipher | DES, 3DES-CBC, Blowfish-CBC, CAST128-CBC, Arcfour, AES-CBC modes |
| MAC | HMAC-MD5, HMAC-SHA1, HMAC-SHA1-96, UMAC-64 (and ETM variants) |
| KEX | DH-Group1-SHA1, DH-Group14-SHA1, DH-GEX-SHA1 |
| Host keys | DSA, RSA |

---

## Input File Formats

### Text file (`.txt`)

```
server1.example.com
server2.example.com:2222
192.168.1.100
# Lines starting with # are ignored
[::1]:22
```

### JSON (`.json`)

```json
[
  "server1.example.com",
  "server2.example.com:2222",
  {"host": "server3.example.com", "port": 2222},
  "192.168.1.100"
]
```

### YAML (`.yaml` / `.yml`)

```yaml
- server1.example.com
- server2.example.com:2222
- host: server3.example.com
  port: 2222
```

### CSV (`.csv`)

```csv
server1.example.com,22
server2.example.com,2222
192.168.1.100,22
```

Duplicate hosts (same IP + port) are silently skipped regardless of file format.
IPv6 addresses use bracket notation: `[::1]:22` or `[2001:db8::1]:22`.

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | All hosts scanned successfully, no compliance failures |
| 1 | Fatal error or usage error (bad arguments, file not found, etc.) |
| 2 | One or more hosts failed compliance check |
| 3 | One or more hosts had scan errors (connection failure, timeout, DNS) |

Codes 2 and 3 can occur together; code 2 takes precedence.

---

## Troubleshooting

**All hosts time out**
Increase timeout or reduce threads: `--timeout 30 --threads 10`

**"No matching cipher found" for everything**
The local `ssh` binary may not support the algorithm. Check: `ssh -Q cipher`

**Scan is too slow**
Increase threads: `--threads 50`. Ensure DNS resolves quickly (or use IP addresses directly).

**Scan is hammering a target**
Use `--rate-limit 2.0` to cap at 2 new connections per second.

**IPv6 hosts not connecting**
Use bracket notation: `--host "[2001:db8::1]:22"` or put `[2001:db8::1]:22` in your host file.

**All algorithms show as not supported on a specific host**
The host may be blocking the connection entirely (firewall, wrong port).
Check the SSH banner: if it's empty, the host is not reachable on that port.
