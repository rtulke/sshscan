# SSH Algorithm Security Scanner

A single-file Python tool for auditing and compliant the SSH algorithm configuration of one host or an entire
network fleet. Identifies weak, deprecated, and NSA-linked algorithms; scores each host 0–100;
and checks results against industry compliance frameworks (NIST, FIPS 140-2, BSI TR-02102,
ANSSI, PRIVACY_FOCUSED) — making it suitable for periodic security reviews, pre/post-hardening
verification, and compliance evidence collection.

Wraps the system `ssh` binary to probe each algorithm individually — no paramiko, no
authentication, no credentials required. The tool never logs in and never executes commands;
it only observes what the server is willing to negotiate.

**Version:** 3.6.4 | **Author:** Robert Tulke

![Example](/demo/sshscan.png)


---

## Table of Contents

- [What it can do](#what-it-can-do)
- [What it cannot do](#what-it-cannot-do)
- [Requirements](#requirements)
- [Supported OS](#supported-os)
- [Installation](#installation)
  - [macOS (Homebrew)](#macos-homebrew)
  - [Quick (system Python)](#quick-system-python)
  - [Windows (WSL or native OpenSSH)](#windows-wsl-or-native-openssh)
  - [Virtual environment (recommended)](#virtual-environment-recommended)
  - [System-wide configuration](#system-wide-configuration)
  - [Tab Completion (Linux)](#tab-completion-linux)
- [Configuration](#configuration)
  - [Config file auto-discovery](#config-file-auto-discovery-no---config-needed)
  - [`[scanner]` keys](#scanner-keys)
  - [`[compliance]` keys](#compliance-keys)
  - [Minimal config example](#minimal-config-example)
  - [Full config example](#full-config-example)
  - [Privacy-focused preset](#privacy-focused-preset)
- [Complete Parameter Reference](#complete-parameter-reference)
  - [General](#general)
  - [Host specification](#host-specification-mutually-exclusive)
  - [Scanning options](#scanning-options)
  - [Algorithm testing](#algorithm-testing)
  - [Compliance](#compliance)
  - [Output](#output)
- [Usage Examples](#usage-examples)
  - [Single host](#single-host)
  - [Multiple hosts](#multiple-hosts)
  - [Local SSH server](#local-ssh-server)
  - [Compliance checking](#compliance-checking)
  - [Output filtering](#output-filtering)
  - [Jump host / proxy](#jump-host--proxy)
  - [Export results](#export-results)
  - [Summary mode](#summary-mode)
  - [Performance tuning](#performance-tuning)
  - [Specific algorithm testing](#specific-algorithm-testing)
  - [NSA analysis](#nsa-analysis)
  - [Using a config file](#using-a-config-file)
  - [Jump host / proxy](#jump-host--proxy)
  - [Debug and logging](#debug-and-logging)
- [Jump Hosts and Proxies](#jump-hosts-and-proxies)
  - [Global proxy (all hosts)](#global-proxy-all-hosts)
  - [Per-host proxy (mixed environments)](#per-host-proxy-mixed-environments)
  - [Priority order](#priority-order)
- [Output Filtering](#output-filtering-1)
  - [Category tokens](#category-tokens)
  - [Type tokens](#type-tokens)
  - [Output mode tokens](#output-mode-tokens)
  - [Host tokens](#host-tokens)
- [Compliance Frameworks](#compliance-frameworks)
- [NSA Backdoor Detection](#nsa-backdoor-detection)
  - [High-risk (NIST P-curves)](#high-risk-nist-p-curves)
  - [Recommended alternatives](#recommended-alternatives)
- [Security Scoring](#security-scoring)
  - [Weak algorithms detected](#weak-algorithms-detected)
- [Input File Formats](#input-file-formats)
  - [Text file (.txt)](#text-file-txt)
  - [JSON (.json)](#json-json)
  - [YAML (.yaml / .yml)](#yaml-yaml--yml)
  - [CSV (.csv)](#csv-csv)
- [Exit Codes](#exit-codes)
- [Troubleshooting](#troubleshooting)
- [Hardening Guide](#hardening-guide)
  - [Full SSH Hardening Guide](hardening-examples/ssh_hardening_guide.md)
  - [OpenSSH Server (sshd_config)](#openssh-server-etcsshsshd_config)
  - [OpenSSH Client (~/.ssh/config)](#openssh-client-sshconfig)
  - [Verify with sshscan](#verify-with-sshscan)

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

## Supported OS

### Scanner host (where you run sshscan.py)

| Platform | Status | Notes |
|---|---|---|
| Ubuntu 20.04 / 22.04 / 24.04 | Supported | Primary development platform |
| Debian 11 (Bullseye) / 12 (Bookworm) | Supported | |
| Debian-based distros | Supported | Linux Mint, Raspberry Pi OS, Pop!\_OS, Kali Linux, Parrot OS, MX Linux, Zorin OS and any other Debian/Ubuntu derivative — works as long as Python 3.8+ and `openssh-client` are installed |
| RHEL / Rocky Linux / AlmaLinux 8 | Supported | |
| RHEL / Rocky Linux / AlmaLinux 9 | Supported | |
| Fedora 38+ | Supported | |
| Arch Linux | Supported | |
| macOS 12 Monterey / 13 Ventura / 14 Sonoma / 15 Sequoia | Supported | Uses system OpenSSH; no extra dependencies |
| Windows — WSL (Ubuntu / Debian) | Supported | Run inside a WSL instance; full feature parity |
| Windows 10/11 — native OpenSSH | Untested | Requires OpenSSH client via `winget install Microsoft.OpenSSH.Beta` or Optional Features; `/etc/sshscan/` auto-discovery does not apply |
| FreeBSD / OpenBSD / NetBSD | Untested | Should work with Python 3.8+ and OpenSSH client; not regularly tested |
| Alpine Linux | Untested | Requires `openssh-client` package; the BusyBox `ssh` stub is not sufficient |

> **OpenSSH client version on the scanner host:**
> - Minimum: OpenSSH 7.x — covers all algorithms except the post-quantum KEX entries
> - Full feature support: OpenSSH 9.9+ — required to probe `mlkem768x25519-sha256` (ML-KEM)
> - OpenSSH 8.5–9.8 — can probe `sntrup761x25519-sha512@openssh.com` (NTRU Prime hybrid)
>
> The scanner detects which algorithms the local SSH client supports and skips those it cannot
> probe, so operation is graceful on older OpenSSH versions.

### Scan targets (what can be scanned)

Any SSH server is a valid target regardless of OS or hardware:

| Target type | Examples |
|---|---|
| Linux servers | Any distribution running OpenSSH or Dropbear |
| macOS | Built-in OpenSSH server |
| *BSD | OpenBSD, FreeBSD, NetBSD |
| Windows | Windows OpenSSH Server (`sshd` via Optional Features) |
| Network devices | Cisco IOS/IOS-XE/NX-OS, Juniper JunOS, Palo Alto PAN-OS, F5 BIG-IP |
| Embedded / IoT | Routers, NAS devices, industrial controllers with SSH |
| Cloud instances | AWS EC2, GCP Compute, Azure VM — any SSH-accessible endpoint |

---

## Installation

### macOS (Homebrew)

The recommended installation method on macOS. Homebrew manages Python, PyYAML,
and future upgrades automatically.

```bash
brew tap rtulke/sshscan
brew install sshscan
```

Verify:

```bash
sshscan --version
```

Upgrade when a new version is released:

```bash
brew update
brew upgrade sshscan
```

Uninstall:

```bash
brew uninstall sshscan
brew untap rtulke/sshscan
```

> The Homebrew tap is at [https://github.com/rtulke/homebrew-sshscan](https://github.com/rtulke/homebrew-sshscan).

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

### Tab Completion (Linux)

The completion script lives in `completion/sshscan.bash-completion` and works with
any distribution that has the `bash-completion` package installed.

**Install bash-completion if not already present**

```bash
# Debian / Ubuntu / Mint / Raspberry Pi OS
sudo apt install bash-completion

# RHEL / Rocky / AlmaLinux / Fedora
sudo dnf install bash-completion

# Arch Linux
sudo pacman -S bash-completion
```

**Install the sshscan completion — system-wide**

```bash
sudo cp completion/sshscan.bash-completion /etc/bash_completion.d/sshscan
```

**Install for your user only** (no sudo required)

```bash
mkdir -p ~/.local/share/bash-completion/completions
cp completion/sshscan.bash-completion ~/.local/share/bash-completion/completions/sshscan
```

Open a new shell and tab completion is active. To test immediately in the current
session without installing:

```bash
source completion/sshscan.bash-completion
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
| `jump_host` | string | `[user@]host[:port]` | — | `--jump-host` |
| `proxy_command` | string | ProxyCommand | — | `--proxy-command` |

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
| `--jump-host [USER@]HOST[:PORT]` | | — | Route all connections through an SSH jump / bastion host |
| `--proxy-command CMD` | | — | Route all connections via a ProxyCommand (SOCKS5/HTTP CONNECT) |
| `--prefer-ipv6` | | off | Prefer IPv6 (AAAA) when a host resolves to both A and AAAA records |
| `--ipv6-only` | | off | Scan only via IPv6; skip hosts that have no AAAA record (implies `--prefer-ipv6`) |

### Algorithm testing

| Parameter | Short | Description |
|---|---|---|
| `--explicit ALGOS` | `-e` | Test only the given comma-separated algorithms instead of the full set |

### Compliance

| Parameter | Description |
|---|---|
| `--compliance FRAMEWORK` | Check results against a framework (see table below) |
| `--list-frameworks` | List available compliance frameworks and exit |
| `--list-algorithms` | List all scannable algorithms grouped by type, with weak/NSA annotations, and exit |
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

# IPv6
python3 sshscan.py --host "[2001:db8::1]:22"
python3 sshscan.py --host "[::1]"
python3 sshscan.py --host 2001:db8::1
python3 sshscan.py --host "[2001:db8::1]:22" --prefer-ipv6
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

# IPv6 — mixed with IPv4 in a comma-separated list
python3 sshscan.py --host "192.168.1.1,[2001:db8::1]:22,[::1]"

# IPv6 — from a hosts file (bracket notation, one per line)
# hosts.txt:
#   [2001:db8::1]:22
#   [2001:db8::2]:2222
#   [::1]
python3 sshscan.py --file hosts.txt

# IPv6 — prefer AAAA when hostnames resolve to both A and AAAA
python3 sshscan.py --file hosts.txt --prefer-ipv6

# IPv6 — skip hosts that have no AAAA record
python3 sshscan.py --file hosts.txt --ipv6-only
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

# Type tokens: show only KEX algorithms
python3 sshscan.py --host example.com --filter kex

# Type + category: show only weak KEX algorithms
python3 sshscan.py --file hosts.txt --filter kex,weak

# Type + category: show weak ciphers and MACs
python3 sshscan.py --file hosts.txt --filter cipher,mac,weak

# Output mode: show only security score and compliance line per host (no algo lines)
python3 sshscan.py --file hosts.txt --compliance NIST --filter security

# Output mode: show only SSH banners per host
python3 sshscan.py --file hosts.txt --filter banner

# Output mode + category: banners + NSA algorithm lines
python3 sshscan.py --file hosts.txt --filter banner,nsa

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

### Jump host / proxy

```bash
# All hosts through a bastion (SSH jump host)
python3 sshscan.py --file internal-hosts.txt --jump-host admin@bastion.corp:22

# Multiple jump hops (comma-separated, OpenSSH syntax)
python3 sshscan.py --file hosts.txt --jump-host "hop1.corp,admin@hop2.corp:2222"

# All hosts through a SOCKS5 proxy (e.g. an SSH -D tunnel)
python3 sshscan.py --file hosts.txt --proxy-command "nc -X 5 -x 127.0.0.1:1080 %h %p"

# All hosts through an HTTP CONNECT proxy
python3 sshscan.py --file hosts.txt --proxy-command "nc -X connect -x proxy.corp:3128 %h %p"
```

Per-host proxy via YAML host file:

```yaml
# hosts.yaml
- host: internal1.corp
  via:
    type: jump
    host: bastion1.corp
    port: 22
    user: admin

- host: internal2.corp
  via:
    type: socks5
    host: 127.0.0.1
    port: 1080

- host: public.example.com   # no via — direct connection
```

Per-host proxy via CSV host file (columns: `host,port,via_type,via_host[,via_port[,via_user]]`):

```csv
internal1.corp,22,jump,bastion1.corp,22,admin
internal2.corp,22,socks5,127.0.0.1,1080
dmz-host.corp,2222,http,proxy.corp,3128
public.example.com,22
```

### Debug and logging

```bash
# Verbose INFO logging
python3 sshscan.py --host example.com --verbose

# Full debug output (function names, line numbers)
python3 sshscan.py --host example.com --debug
```

---

## Jump Hosts and Proxies

Route scan traffic through SSH jump hosts (bastions) or SOCKS5/HTTP CONNECT proxies.
Useful for scanning internal networks that are not directly reachable from the scanning machine.

### Global proxy (all hosts)

Apply the same proxy to every host in a scan run:

```bash
# SSH jump host
python3 sshscan.py --file internal.yaml --jump-host admin@bastion.corp

# SOCKS5 (e.g. an SSH -D dynamic tunnel)
python3 sshscan.py --file hosts.txt --proxy-command "nc -X 5 -x 127.0.0.1:1080 %h %p"

# HTTP CONNECT proxy
python3 sshscan.py --file hosts.txt --proxy-command "nc -X connect -x proxy.corp:3128 %h %p"
```

Or set a global configuration in `sshscan.conf`:

```ini
[scanner]
jump_host = admin@bastion.corp:22
# proxy_command = nc -X 5 -x socks5proxy.corp:1080 %h %p
```

### Per-host proxy (mixed environments)

Different hosts can have different proxies by adding a `via` field to JSON/YAML host files,
or extra columns to CSV files.

**YAML** — `via` dict with keys: `type` (`jump`/`socks5`/`http`), `host`, `port`, `user` (optional):

```yaml
- host: internal-db.corp
  via: {type: jump, host: bastion1.corp, port: 22, user: dbteam}

- host: dmz-web.corp
  via: {type: http, host: proxy.corp, port: 3128}

- host: external.example.com
  # no via — direct connection
```

**JSON** — same structure:

```json
[
  {"host": "internal-db.corp", "port": 22, "via": {"type": "jump", "host": "bastion1.corp", "user": "dbteam"}},
  {"host": "dmz-web.corp",     "port": 22, "via": {"type": "http",  "host": "proxy.corp", "port": 3128}},
  {"host": "external.example.com"}
]
```

**CSV** — extra columns after `host,port`: `via_type,via_host[,via_port[,via_user]]`:

```csv
internal-db.corp,22,jump,bastion1.corp,22,dbteam
dmz-web.corp,22,http,proxy.corp,3128
external.example.com,22
```

### Priority order

Per-host `via` → `--jump-host` (global) → `--proxy-command` (global) → direct connection.

### Notes

- Jump hosts require SSH key auth (no password prompt) — `BatchMode=yes` is always set
- When a proxy is active, the SSH banner is fetched via the SSH binary rather than a raw socket
- Use `--rate-limit` to avoid overwhelming the bastion with parallel connections

---

## Output Filtering

`--filter` accepts comma-separated tokens from any of the groups below.
All groups are composable. Type and category tokens combine with AND within their group.
Run `--list-filter` for a full reference with examples.

### Category tokens

Filter by security classification:

| Token | Shows | Marker |
|---|---|---|
| `supported` | Algorithms the server supports, no warning | `[x]` |
| `unsupported` | Algorithms the server does not support | `[-]` |
| `flagged` | All flagged algorithms (weak + NSA combined) | `[!]` |
| `weak` | Weak/deprecated algorithms only (subset of flagged) | `[!]` |
| `nsa` | NSA-suspected algorithms only (subset of flagged) | `[!]` |

### Type tokens

Filter by protocol layer. Composable with category tokens (`--filter kex,weak` = weak KEX only):

| Token | Shows |
|---|---|
| `cipher` | Cipher / encryption algorithm lines |
| `mac` | MAC algorithm lines |
| `kex` | Key exchange algorithm lines |
| `hostkey` | Host key algorithm lines |

### Output mode tokens

Suppress per-algorithm lines entirely; show only the specified host-level line.
Pairing with type or category tokens re-enables those matching algorithm lines.

| Token | Shows |
|---|---|
| `security` | Security score and compliance line per host |
| `banner` | SSH banner line per host |

### Host tokens

Show only hosts matching the condition. All output for a host is buffered until the scan
completes, then flushed or discarded based on the result.

| Token | Shows |
|---|---|
| `passed` | Hosts that passed the compliance check (requires `--compliance`) |
| `failed` | Hosts that failed the compliance check (requires `--compliance`) |
| `error` | Hosts where the scan failed (connection error, timeout, DNS failure) |

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
IPv6 addresses can be specified in three ways:
- Bracket notation with port: `[::1]:22`, `[2001:db8::1]:2222`
- Bracket notation without port (uses `--port` default): `[::1]`, `[2001:db8::1]`
- Bare address without port: `2001:db8::1`

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
Use bracket notation: `--host "[2001:db8::1]:22"` or a bare address `--host "2001:db8::1"` (uses default port).
If the host resolves to both A and AAAA records and IPv4 is being used, add `--prefer-ipv6` to force IPv6.
To skip all hosts that have no AAAA record, use `--ipv6-only`.

**All algorithms show as not supported on a specific host**
The host may be blocking the connection entirely (firewall, wrong port).
Check the SSH banner: if it's empty, the host is not reachable on that port.

---

## Hardening Guide

> For a comprehensive step-by-step guide covering firewall rules, 2FA, certificate
> authorities, jump hosts, cloud environments, and incident response, see the
> [SSH Hardening Guide](hardening-examples/ssh_hardening_guide.md).
> Ready-to-use config profiles are also available in
> [`hardening-examples/`](hardening-examples/).

Once sshscan reports weak or NSA-flagged algorithms, the next step is removing them from
the server configuration and optionally restricting what the SSH client will accept.
The configs below map directly to sshscan's compliance frameworks.

> **Before applying any server config:** ensure you have out-of-band console access
> (KVM, cloud console, serial port). A broken sshd config that prevents the daemon from
> starting will lock you out if SSH is your only access path. Always run `sudo sshd -t`
> before reloading.

---

### OpenSSH Server (`/etc/ssh/sshd_config`)

#### Balanced — no weak algorithms, NIST curves allowed

Removes all weak and deprecated algorithms. NIST P-curves (`ecdh-sha2-nistp*`,
`ecdsa-sha2-nistp*`) are kept for broader client compatibility.
Matches the **NIST**, **BSI\_TR\_02102**, and **ANSSI** compliance frameworks.

```ini
# /etc/ssh/sshd_config

# Modern AEAD ciphers only — no CBC, no arcfour, no 3DES
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# ETM MACs preferred; SHA-2 only — no MD5, no SHA-1, no 64-bit UMAC
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com

# Modern key exchange — DH group 14+ (SHA-2), Curve25519, NIST ECDH
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256

# Host key types to advertise — Ed25519 and RSA-SHA2; no DSA, no legacy RSA/SHA-1
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com
```

#### Strict — no NIST curves (anti-surveillance / PRIVACY\_FOCUSED)

Also removes NIST P-curves. Only Curve25519 and ChaCha20/AES-GCM remain.
Requires OpenSSH 7.x+ on the client side.
Matches the **PRIVACY\_FOCUSED** compliance framework.

```ini
# /etc/ssh/sshd_config

# ChaCha20 and AES-GCM only — no NIST-derived constructs
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com

# ETM MACs only
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# Curve25519 only — no NIST P-curves
# sntrup761x25519-sha512@openssh.com adds post-quantum protection (requires OpenSSH 8.5+)
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org

# Ed25519 only — no RSA, no ECDSA
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com
```

#### Apply and verify

```bash
# 1. Test the config — catches syntax errors and unsupported algorithm names
sudo sshd -t

# 2. Reload sshd without dropping existing sessions
sudo systemctl reload sshd
# or on older init systems:
sudo service ssh reload

# 3. Confirm the daemon is still running
sudo systemctl status sshd
```

#### Generate a missing Ed25519 host key

The strict config requires an Ed25519 host key. Generate one if it does not exist yet:

```bash
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
```

Then make sure `sshd_config` includes the key:

```ini
HostKey /etc/ssh/ssh_host_ed25519_key
```

---

### OpenSSH Client (`~/.ssh/config`)

Client restrictions apply to all outgoing connections from your machine.
Replace `Host *` with a specific hostname to restrict only one target.

#### Balanced — no weak algorithms, NIST curves allowed

```
# ~/.ssh/config

Host *
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
    KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
    HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com
```

#### Strict — no NIST curves

```
# ~/.ssh/config

Host *
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
    KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
    HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com
```

A strict client config will refuse to connect to servers that only offer NIST curves or
legacy host keys. Use a per-host override to allow exceptions:

```
# Allow legacy algorithms only for this specific host
Host legacy.example.com
    KexAlgorithms +ecdh-sha2-nistp256
    HostKeyAlgorithms +ecdsa-sha2-nistp256,rsa-sha2-256
```

---

### Verify with sshscan

After applying server changes, re-scan to confirm the result:

```bash
# Check the local server — should show no [!] lines
python3 sshscan.py --local --filter flagged

# Full compliance check against specific framework
python3 sshscan.py --local --compliance PRIVACY_FOCUSED --summary

# Remote host after hardening
python3 sshscan.py --host server.example.com --filter weak,nsa
python3 sshscan.py --host server.example.com --compliance BSI_TR_02102
```
