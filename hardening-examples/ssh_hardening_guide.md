# SSH Hardening Guide

A layered, defense-in-depth reference for securing SSH on Internet-facing Linux systems.
Covers cryptographic hardening, access control, brute-force mitigation, certificate-based
authentication, hardware security keys, monitoring, and verification.

---

## Table of Contents

- [Threat Landscape](#threat-landscape)
- [Detecting Brute-Force Attempts](#detecting-brute-force-attempts)
- [Layer 1: Key-Only Authentication](#layer-1-key-only-authentication)
  - [Generating an Ed25519 Key Pair](#generating-an-ed25519-key-pair)
  - [FIDO2 / Hardware Security Keys](#fido2--hardware-security-keys)
  - [Deploying the Public Key](#deploying-the-public-key)
  - [Disabling Password Authentication](#disabling-password-authentication)
  - [Key Security Practices](#key-security-practices)
- [Layer 2: sshd_config Hardening](#layer-2-sshd_config-hardening)
  - [Cryptographic Algorithm Hardening](#cryptographic-algorithm-hardening)
  - [DH Moduli Hardening](#dh-moduli-hardening)
  - [Host Key Management](#host-key-management)
  - [Access Control and Session Limits](#access-control-and-session-limits)
  - [Feature Restriction](#feature-restriction)
  - [sshd_config.d Drop-In Override Warning](#sshd_configd-drop-in-override-warning)
  - [Complete Hardened sshd_config Template](#complete-hardened-sshd_config-template)
  - [Changing the Default Port](#changing-the-default-port)
- [Layer 3: Two-Factor Authentication](#layer-3-two-factor-authentication)
  - [TOTP with PAM](#totp-with-pam)
  - [FIDO2 User Verification (PINs and Biometrics)](#fido2-user-verification-pins-and-biometrics)
- [Layer 4: SSH Certificate Authority](#layer-4-ssh-certificate-authority)
  - [User Certificates](#user-certificates)
  - [Host Certificates](#host-certificates)
  - [Certificate Revocation](#certificate-revocation)
  - [AuthorizedKeysCommand](#authorizedkeyscommand)
- [Layer 5: SSH Client Hardening](#layer-5-ssh-client-hardening)
  - [~/.ssh/config Hardening](#sshconfig-hardening)
  - [System-wide /etc/ssh/ssh_config](#system-wide-etcsshssh_config)
  - [known_hosts Management](#known_hosts-management)
  - [SSHFP DNS Records](#sshfp-dns-records)
- [Layer 6: Fail2ban](#layer-6-fail2ban)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Operation and Testing](#operation-and-testing)
- [Layer 7: Firewall Rate Limiting](#layer-7-firewall-rate-limiting)
  - [iptables: recent Module](#iptables-recent-module)
  - [ufw: limit Rule](#ufw-limit-rule)
  - [nftables](#nftables)
- [Layer 8: Port Knocking](#layer-8-port-knocking)
  - [How It Works](#how-it-works)
  - [Server Configuration](#server-configuration)
  - [Client Usage](#client-usage)
- [Monitoring and Alerting](#monitoring-and-alerting)
  - [Log Inspection](#log-inspection)
  - [Daily Reports: Logwatch](#daily-reports-logwatch)
  - [Real-Time Alerts: Logcheck and swatchdog](#real-time-alerts-logcheck-and-swatchdog)
  - [Live Traffic View: logtop](#live-traffic-view-logtop)
  - [Command-Level Auditing: auditd](#command-level-auditing-auditd)
- [Cloud Environments](#cloud-environments)
- [Incident Response](#incident-response)
- [Verification and Testing](#verification-and-testing)
- [Hardening Checklist](#hardening-checklist)
- [References](#references)

---

## Threat Landscape

Automated botnets continuously scan the entire IPv4 address space for port 22. Once a host is
identified, credential-stuffing and dictionary attacks begin within minutes of the system coming
online. Tools such as PumaBot — a Go-based botnet targeting Linux VMs, cloud instances, and
embedded devices — cycle through large pre-compiled credential lists at high speed.

Common default credentials targeted by automated scanners:

| Username | Password         |
|----------|------------------|
| `root`   | `toor`, `root`   |
| `admin`  | `admin123`       |
| `pi`     | `raspberry`      |
| `ubnt`   | `ubnt`           |
| `test`   | `123456`         |

Once compromised, a device is typically enlisted into the botnet, used to mine cryptocurrency,
exfiltrate data, or deliver additional payloads. The attack surface is present as long as
password-based authentication is reachable from the Internet.

---

## Detecting Brute-Force Attempts

SSH authentication events are logged to `/var/log/auth.log` (Debian/Ubuntu) or
`/var/log/secure` (RHEL/Fedora). Monitor in real time with:

```bash
sudo tail -f /var/log/auth.log
```

Indicators of brute-force activity:

```
Failed password for invalid user root from 203.0.113.55 port 51234 ssh2
Connection closed by authenticating user admin 198.51.100.27 port 60234 [preauth]
```

Look for:
- Repeated failures from the same IP within a short window
- `invalid user` — username does not exist on the system
- `[preauth]` — client disconnected before completing authentication
- High-frequency attempts from many distinct IPs (distributed / botnet attack)

Count unique source IPs with failed login attempts:

```bash
sudo grep "Failed password" /var/log/auth.log \
  | awk '{print $(NF-3)}' \
  | sort | uniq -c | sort -rn | head -20
```

Show failed login attempts from `lastb`:

```bash
lastb -n 50
```

---

## Layer 1: Key-Only Authentication

Eliminating password-based logins removes the attack surface for credential guessing entirely.
SSH public-key authentication uses asymmetric cryptography: the client proves possession of a
private key via a cryptographic challenge; no password is transmitted or guessable.

### Generating an Ed25519 Key Pair

Ed25519 is the recommended key type. It uses Curve25519 (a safe, non-NIST curve), produces
compact 256-bit keys, resists side-channel attacks, and is faster to verify than RSA-2048/4096.

On the **client machine**:

```bash
ssh-keygen -t ed25519 -C "user@hostname-$(date +%Y%m%d)"
```

Accept the default path (`~/.ssh/id_ed25519`) or provide a custom one. Always set a passphrase
to protect the private key at rest.

| File                    | Description                                        |
|-------------------------|----------------------------------------------------|
| `~/.ssh/id_ed25519`     | Private key — never share, never copy to servers   |
| `~/.ssh/id_ed25519.pub` | Public key — deployed to remote `authorized_keys`  |

> **SSH Agent:** To avoid re-entering the passphrase on every connection, load the key into the
> SSH agent for the session:
> ```bash
> eval "$(ssh-agent -s)"
> ssh-add ~/.ssh/id_ed25519
> ```
> GNOME and KDE include built-in agents that load keys at desktop login. The agent holds the
> decrypted key in memory only; it is never written to disk in decrypted form.

### FIDO2 / Hardware Security Keys

OpenSSH 8.2+ supports FIDO2/U2F hardware security keys (YubiKey, Nitrokey, SoloKey, etc.)
as key types `sk-ed25519` and `sk-ecdsa-sk`. Every authentication operation requires a
physical touch or PIN verification on the device.

**Generate a FIDO2-backed key:**

```bash
# Standard: credential stored on the host, physical touch required per auth
ssh-keygen -t ed25519-sk -C "yubikey-$(date +%Y%m%d)"

# Resident key: credential stored on the FIDO2 device itself (portable across machines)
ssh-keygen -t ed25519-sk -O resident -O verify-required -C "yubikey-resident"
```

| Option            | Effect                                                       |
|-------------------|--------------------------------------------------------------|
| `-t ed25519-sk`   | FIDO2-backed Ed25519 key (preferred over `ecdsa-sk`)         |
| `-O resident`     | Stores credential on the hardware key; importable with `ssh-keygen --import-resident-keys` |
| `-O verify-required` | Requires PIN or biometric before each use              |
| `-O no-touch-required` | Disables touch requirement (use only for automation)  |

Generated files follow the same deployment flow as standard keys. The private key file is a
handle referencing the credential on the hardware device — possession of both the file and the
hardware key is required to authenticate.

### Deploying the Public Key

The preferred method:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub username@server_ip
```

Manual deployment:

```bash
cat ~/.ssh/id_ed25519.pub \
  | ssh user@server_ip \
    "install -m 700 -d ~/.ssh && \
     cat >> ~/.ssh/authorized_keys && \
     chmod 600 ~/.ssh/authorized_keys"
```

Required permissions — sshd rejects keys if permissions are too open (`StrictModes yes`):

```
~/.ssh/                 → 700  (drwx------)
~/.ssh/authorized_keys  → 600  (-rw-------)
```

Restrict a key to specific source IPs or disable forwarding in `authorized_keys`:

```
from="192.168.1.0/24",no-agent-forwarding,no-port-forwarding ssh-ed25519 AAAA...
```

Verify key-based login works before disabling passwords:

```bash
ssh -o PreferredAuthentications=publickey user@server_ip
```

### Disabling Password Authentication

> **Before applying:** Open a second terminal and confirm key-based login works. Keep the
> first session open as a fallback until the change is verified.

Edit `/etc/ssh/sshd_config`:

```ini
PasswordAuthentication no
KbdInteractiveAuthentication no   # OpenSSH >= 7.5; replaces ChallengeResponseAuthentication
AuthenticationMethods publickey
PermitRootLogin no
UsePAM yes
```

> **`UsePAM yes` is correct here.** Setting `UsePAM no` disables the entire PAM stack,
> which breaks `pam_systemd` (cgroup session tracking), `pam_limits` (ulimits enforcement),
> `pam_env`, and MOTD. With `PasswordAuthentication no`, PAM's password modules are never
> invoked for SSH logins — there is no security benefit to disabling PAM.

> **Compatibility:** `ChallengeResponseAuthentication` was deprecated in OpenSSH 7.5 (2017)
> and removed in 8.7. Use `KbdInteractiveAuthentication` on all modern systems.

Validate configuration syntax before restarting:

```bash
sudo sshd -t
```

Apply:

```bash
sudo systemctl restart sshd
```

### Key Security Practices

- Always set a passphrase when generating private keys
- Never store private keys in email, cloud storage, chat, or version control
- Rotate keys periodically; revoke compromised keys immediately by removing the corresponding
  line from `~/.ssh/authorized_keys` on every authorized server
- For FIDO2 keys: if a hardware token is lost, remove its public key from all servers before
  the token can be used by someone else — FIDO2 keys have no passphrase protection at rest

---

## Layer 2: sshd_config Hardening

Beyond disabling passwords, sshd exposes a range of configuration options that control which
cryptographic algorithms are negotiated, which users may connect, and which features are
available post-authentication. These should be explicitly configured rather than left to
compiled defaults.

### Cryptographic Algorithm Hardening

Modern SSH sessions should use only authenticated encryption ciphers, ETM (encrypt-then-MAC)
MAC algorithms, and Diffie-Hellman using safe non-NIST curves. NIST P-curves have documented
NSA involvement in parameter selection.

Add to `/etc/ssh/sshd_config`:

```ini
# Ciphers: AEAD only (ChaCha20-Poly1305 preferred, AES-GCM acceptable)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com

# MACs: Encrypt-then-MAC only (ETM suffix); prevents CBC padding oracle attacks
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Key exchange: Curve25519 + post-quantum hybrid
# OpenSSH >= 9.9: mlkem768x25519-sha256 (IETF ML-KEM / FIPS 203)
# OpenSSH 8.5–9.8: sntrup761x25519-sha512@openssh.com (NTRU Prime hybrid)
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org

# Host key algorithms: Ed25519 only (includes FIDO2-backed sk variant)
HostKeyAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com
```

Verify what sshd will actually negotiate after restart:

```bash
sudo sshd -T | grep -E 'ciphers|macs|kexalgorithms|hostkeyalgorithms'
```

> **Why not AES-CBC or HMAC-SHA1?** CBC-mode ciphers are vulnerable to BEAST and Lucky13
> padding oracle attacks. Non-ETM MACs authenticate ciphertext after decryption, enabling
> timing attacks. Neither is acceptable on a hardened server.

### DH Moduli Hardening

OpenSSH uses `/etc/ssh/moduli` for Diffie-Hellman group exchange (`diffie-hellman-group-exchange-*`
algorithms). The default file ships with groups as small as 1023 bits. CIS Benchmark, BSI
TR-02102-4, and ANSSI recommend a minimum of 3072 bits.

> **Note:** If your `KexAlgorithms` contains only Curve25519 and ML-KEM entries (as in this
> guide's template), DH group exchange is not used and the moduli file is irrelevant. Filter it
> anyway as defense in depth, in case a future config change or client negotiation reintroduces
> a `diffie-hellman-group*` algorithm.

Remove all moduli shorter than 3072 bits:

```bash
# Check current minimum (first column is bit size)
awk '$5 >= 3071' /etc/ssh/moduli | head -3

# Filter in-place: keep only entries with bit count >= 3071
sudo awk '$5 >= 3071' /etc/ssh/moduli | sudo tee /etc/ssh/moduli.safe > /dev/null
sudo mv /etc/ssh/moduli.safe /etc/ssh/moduli

# Verify — all remaining groups should be >= 3072 bits
awk 'NF && !/^#/ {print $5}' /etc/ssh/moduli | sort -un
```

> The fifth column (`$5`) is the modulus bit size. The `3071` threshold is intentional:
> the field stores the highest bit index (0-indexed), so a 3072-bit group has `$5 = 3071`.

### Host Key Management

sshd ships with RSA, ECDSA (NIST P-256), and Ed25519 host keys by default. NIST P-curves
have suspected NSA-influenced parameters; RSA requires large key sizes for equivalent security.
Keep only the Ed25519 host key.

```bash
# Remove weak host keys
sudo rm -f /etc/ssh/ssh_host_rsa_key     /etc/ssh/ssh_host_rsa_key.pub
sudo rm -f /etc/ssh/ssh_host_dsa_key     /etc/ssh/ssh_host_dsa_key.pub
sudo rm -f /etc/ssh/ssh_host_ecdsa_key   /etc/ssh/ssh_host_ecdsa_key.pub

# If the Ed25519 host key doesn't exist or needs rotation:
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
sudo chmod 600 /etc/ssh/ssh_host_ed25519_key
sudo chmod 644 /etc/ssh/ssh_host_ed25519_key.pub
```

Explicitly declare the host key in `sshd_config`:

```ini
HostKey /etc/ssh/ssh_host_ed25519_key
```

Display the host key fingerprint for out-of-band verification:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Communicate this fingerprint to users via a trusted channel (server console, internal wiki)
so they can verify it on first connection instead of blindly accepting.

### Access Control and Session Limits

```ini
# Whitelist specific users or groups (comment out if managing via certificates)
AllowUsers alice bob deploy
# AllowGroups sshusers wheel

# Reduce the time window for completing authentication (default: 120s)
LoginGraceTime 30

# Limit failed authentication attempts per connection (default: 6)
MaxAuthTries 3

# Limit multiplexed sessions per connection (default: 10)
MaxSessions 3

# Throttle unauthenticated connections:
# format: start:rate:full  — start rejecting at 10, 30% chance, hard limit at 60
MaxStartups 10:30:60

# Terminate idle sessions after ClientAliveInterval * ClientAliveCountMax seconds (= 10 min)
ClientAliveInterval 300
ClientAliveCountMax 2

# Force periodic re-keying: after 1 GB of data transferred or 1 hour, whichever comes first.
# Limits the window of exposure for a compromised session key.
RekeyLimit 1G 1h

# Per-channel idle timeout (OpenSSH >= 9.2) — disconnect inactive session channels after 5 min.
# Format: channel-type:interval  — "session" covers interactive shells and exec requests.
ChannelTimeout session:300

# Drop the entire connection when no channels are open for N seconds (OpenSSH >= 9.2).
# Cleans up connections where the client has disconnected without proper teardown.
UnusedConnectionTimeout 300
```

`MaxStartups 10:30:60` means: once 10 unauthenticated connections are pending, each new
attempt has a 30% chance of being dropped; once 60 are pending, all new attempts are dropped.
This limits the effectiveness of parallel brute-force tooling against the handshake phase.

### Feature Restriction

Disable features that are not required. Each enabled feature increases attack surface.

```ini
# DisableForwarding yes disables all forwarding in a single directive (OpenSSH >= 7.8):
# X11, TCP, agent forwarding, and UNIX-domain socket forwarding.
# Use this instead of the four individual directives below when no forwarding is needed at all.
DisableForwarding yes

# TUN/TAP device tunneling — not covered by DisableForwarding
PermitTunnel no

# Prevent users from injecting environment variables via authorized_keys options
PermitUserEnvironment no

# sshd verifies file permissions on authorized_keys, known_hosts, etc.
StrictModes yes

# Disable GSSAPI / Kerberos authentication if not in use.
# On Debian/Ubuntu this is enabled by default and opens an unnecessary auth path.
GSSAPIAuthentication no

# Increase log verbosity — records key fingerprints and negotiated algorithms
LogLevel VERBOSE
SyslogFacility AUTH

# Display a legal warning banner before authentication
Banner /etc/issue.net
```

Create `/etc/issue.net` with a legal deterrent notice. Avoid revealing OS or version details:

```
Unauthorized access to this system is prohibited.
All activity is monitored and logged.
Disconnect immediately if you are not an authorized user.
```

> **Selective re-enabling:** Features can be re-enabled per user or per source IP using
> `Match` blocks:
> ```ini
> Match User tunneluser
>     DisableForwarding no
>     AllowTcpForwarding yes
>     X11Forwarding no
> ```

### sshd_config.d Drop-In Override Warning

On **Ubuntu 22.04+**, **Debian 12+**, and **RHEL/Rocky 9+**, the default `/etc/ssh/sshd_config`
contains:

```ini
Include /etc/ssh/sshd_config.d/*.conf
```

Cloud-init and provisioning tools often create files under this path that silently override
your hardening. The most common offender is **`50-cloud-init.conf`** with:

```ini
PasswordAuthentication yes
```

**Check for and remove overriding drop-ins before testing your config:**

```bash
# List all active drop-in files
ls -la /etc/ssh/sshd_config.d/

# Show effective value for PasswordAuthentication
sudo sshd -T | grep passwordauthentication

# Remove the cloud-init override (or set it to no)
sudo grep -r 'PasswordAuthentication' /etc/ssh/sshd_config.d/
```

If you find conflicting entries, either delete the drop-in file or correct the directive inside
it. Alternatively, place your hardened settings in a file with a higher sort order, e.g.
`/etc/ssh/sshd_config.d/99-hardening.conf` — files are processed in lexicographic order and
later entries override earlier ones for most directives.

> The `Include` line is processed **before** the rest of `sshd_config` on some distros
> and **after** on others. Verify with `sudo sshd -T` rather than reading files manually.

### Complete Hardened sshd_config Template

> **Ready-to-use profile files** are included in this repository for three common scenarios:
>
> | File | Use case |
> |---|---|
> | `sshd_config.strict` | No compromises — Curve25519/Ed25519/ML-KEM only, no NIST curves, no SFTP, aggressive limits |
> | `sshd_config.debian` | Debian/Ubuntu drop-in (`sshd_config.d/99-hardening.conf`), overrides cloud-init, correct paths |
> | `sshd_config.balanced` | Mixed environments — NIST fallback KEX for older clients, SFTP enabled, includes migration path |
>
> All three require `AllowUsers` to be set and `/etc/issue.net` to be created before use.

A production-ready starting point explaining each directive. Adjust `AllowUsers`, `Port`, and
`Match` blocks for your environment. Always run `sudo sshd -t` before restarting.

```ini
# /etc/ssh/sshd_config — Hardened configuration
# Run `sudo sshd -t` to validate syntax before restarting.

# ── Network ───────────────────────────────────────────────────────────────────
Port 22                     # see "Changing the Default Port" if you want non-22
AddressFamily any
ListenAddress 0.0.0.0       # restrict to a single interface if appropriate
ListenAddress ::

# ── Host key (Ed25519 only; remove RSA/DSA/ECDSA key files first) ─────────────
HostKey /etc/ssh/ssh_host_ed25519_key

# ── Cryptographic algorithms ──────────────────────────────────────────────────
Ciphers          chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs             hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms    mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
HostKeyAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com

# ── Authentication ─────────────────────────────────────────────────────────────
PermitRootLogin              no
AuthenticationMethods        publickey
PubkeyAuthentication         yes
PasswordAuthentication       no
KbdInteractiveAuthentication no
PermitEmptyPasswords         no
GSSAPIAuthentication         no   # disable unless Kerberos/GSSAPI is in use
IgnoreRhosts                 yes  # disable .rhosts and .shosts authentication
HostbasedAuthentication      no   # no host-based trust (rsh-style)
UsePAM                       yes  # required for pam_systemd, pam_limits, pam_env

# ── Access control ─────────────────────────────────────────────────────────────
AllowUsers alice bob deploy  # adjust; or use AllowGroups sshusers
LoginGraceTime  30
MaxAuthTries    3
MaxSessions     3
MaxStartups     10:30:60

# ── Session management ─────────────────────────────────────────────────────────
ClientAliveInterval      300   # send keepalive every 5 min
ClientAliveCountMax      2     # disconnect after 2 missed keepalives (= 10 min idle)
RekeyLimit               1G 1h # re-key after 1 GB or 1 hour
ChannelTimeout           session:300        # close idle session channels (OpenSSH >= 9.2)
UnusedConnectionTimeout  300               # drop idle connections with no channels (OpenSSH >= 9.2)

# ── Feature restriction ────────────────────────────────────────────────────────
DisableForwarding    yes  # disables X11, TCP, agent, UNIX-socket forwarding (OpenSSH >= 7.8)
PermitTunnel         no   # TUN/TAP tunneling (not covered by DisableForwarding)
PermitUserEnvironment no  # block env-var injection via authorized_keys options
StrictModes          yes  # verify file permissions on authorized_keys etc.

# ── Logging ────────────────────────────────────────────────────────────────────
LogLevel        VERBOSE
SyslogFacility  AUTH

# ── Misc ───────────────────────────────────────────────────────────────────────
Banner       /etc/issue.net  # legal warning banner; create /etc/issue.net with desired text
PrintMotd    no
PrintLastLog yes             # show last login time — helps users detect unauthorized access
TCPKeepAlive no              # TCP-level keepalives are spoofable; use ClientAliveInterval instead
Compression  no              # disable compression (mitigates CRIME-class attacks)

# Only pass locale variables from client — remove if not needed
AcceptEnv LANG LC_*

# SFTP subsystem — path varies by distro:
#   Debian/Ubuntu : /usr/lib/openssh/sftp-server
#   RHEL/Fedora   : /usr/libexec/openssh/sftp-server
#   macOS         : /usr/libexec/sftp-server
Subsystem sftp /usr/lib/openssh/sftp-server
```

> For SFTP-only users, restrict with a `Match` block:
> ```ini
> Match Group sftponly
>     ChrootDirectory /srv/sftp/%u
>     ForceCommand internal-sftp
>     AllowTcpForwarding no
>     X11Forwarding no
> ```

### Changing the Default Port

Running sshd on a port other than 22 eliminates automated botnet traffic that exclusively
probes port 22. It is a **noise-reduction** measure, not a security control: any targeted
attacker will port-scan and find the service. It does not replace key-only authentication
or other layers, but it can meaningfully reduce log volume.

**Pros:**
- Eliminates mass-scanning log noise immediately
- Prevents opportunistic bots that do not scan the full port range

**Cons:**
- Requires every client and CI/CD pipeline to specify the custom port
- Firewall rules, Fail2ban jails, and jump-host configs must all be updated
- Some networks block outbound non-standard ports
- Clouds with host-based firewalls need an additional inbound rule

**In `sshd_config`:**

```ini
Port 2222   # choose a high port (1024–65535); avoid well-known service ports
```

Validate and restart:

```bash
sudo sshd -t && sudo systemctl restart sshd
```

**SELinux (RHEL / Fedora / Rocky Linux):** SELinux enforces which ports sshd may bind.
Binding to an unlabelled port fails silently at restart. Update the policy before restarting:

```bash
sudo semanage port -a -t ssh_port_t -p tcp 2222
sudo semanage port -l | grep ssh   # verify
```

**AppArmor (Debian / Ubuntu with AppArmor):** The default OpenSSH AppArmor profile
typically does not restrict port binding, but check the profile if sshd fails to start:

```bash
sudo aa-status | grep sshd
sudo journalctl -u ssh | grep -i apparmor
```

**Fail2ban:** Update the jail port to match:

```ini
# /etc/fail2ban/jail.local
[sshd]
port = 2222
```

**Firewall:** Close port 22 and open the new port:

```bash
# iptables
sudo iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
sudo iptables -D INPUT -p tcp --dport 22 -j ACCEPT   # only after verifying new port works

# ufw
sudo ufw allow 2222/tcp
sudo ufw deny 22/tcp

# nftables: update the dport in your input chain ruleset
```

**Port knocking integration:** If using knockd, update `--dport` in the open/close commands
and keep port 22 blocked at the firewall:

```ini
command = /usr/sbin/iptables -A INPUT -s %IP% -p tcp --dport 2222 -j ACCEPT
```

> **Transition:** Keep port 22 open and test the new port thoroughly before closing 22.
> Update `~/.ssh/config` on all client machines to `Port 2222` for the relevant `Host` entries.

---

## Layer 3: Two-Factor Authentication

Two-factor authentication combines something you **have** (your SSH key) with something you
**know** or **possess** (a TOTP code or a hardware token touch/PIN). Even if a private key
is exfiltrated, the attacker cannot authenticate without the second factor.

### TOTP with PAM

Time-based One-Time Passwords (TOTP, RFC 6238) are generated by an authenticator app
(Google Authenticator, Authy, Aegis, etc.) and valid for 30 seconds.

**Install the PAM module:**

```bash
sudo apt install libpam-google-authenticator   # Debian/Ubuntu
sudo dnf install google-authenticator-libpam   # RHEL/Fedora
```

**Set up TOTP per user** (run as the target user, not root):

```bash
google-authenticator -t -d -f -r 3 -R 30 -W
```

| Flag | Meaning |
|------|---------|
| `-t` | Time-based tokens (TOTP) |
| `-d` | Disallow token reuse |
| `-f` | Write config without prompting |
| `-r 3 -R 30` | Max 3 logins per 30 seconds |
| `-W` | Window of 1 (strict; no clock skew tolerance) |

The command prints a QR code to scan with an authenticator app and generates scratch codes.
Save the scratch codes in a secure location — they are single-use emergency bypass codes.

**Configure PAM** — edit `/etc/pam.d/sshd`:

```
# Add AFTER the existing auth lines (or at the top for stricter enforcement)
auth required pam_google_authenticator.so
```

**Configure sshd** — edit `/etc/ssh/sshd_config`:

```ini
# Enable keyboard-interactive for the TOTP prompt
KbdInteractiveAuthentication yes
UsePAM yes

# Require both key AND TOTP
AuthenticationMethods publickey,keyboard-interactive
```

With this configuration, the authentication flow is:
1. Client authenticates with SSH public key
2. sshd prompts for a TOTP code via keyboard-interactive
3. PAM validates the code against the per-user `~/.google_authenticator` file

> **Single-factor fallback:** To allow users without TOTP configured to still log in with
> key-only, add `nullok` to the PAM line:
> `auth required pam_google_authenticator.so nullok`

### FIDO2 User Verification (PINs and Biometrics)

FIDO2 hardware keys support a `verify-required` option that mandates PIN or biometric
verification before each authentication. This is effectively 2FA within the key itself:
something you **have** (the hardware key) + something you **know** (PIN) or **are**
(fingerprint on supported keys).

Generate a key with mandatory verification:

```bash
ssh-keygen -t ed25519-sk -O verify-required -C "yubikey-pin-required"
```

Enforce verification server-side in `sshd_config` (OpenSSH 8.9+):

```ini
# Reject sk-* keys that were not generated with verify-required
PubkeyAuthOptions verify-required
```

This ensures that even if a hardware key is stolen without its PIN, it cannot authenticate.

---

## Layer 4: SSH Certificate Authority

Managing `authorized_keys` across many servers and users is error-prone:
N servers × M users = N×M deployment and revocation operations. SSH certificates solve this
by introducing a trusted Certificate Authority (CA): sign a user's key once, trusted by all
servers configured with `TrustedUserCAKeys`.

### User Certificates

**Generate the CA key** (keep this offline or in a hardware security module):

```bash
sudo ssh-keygen -t ed25519 -f /etc/ssh/ca_user_key -C "ssh-user-ca@example.com"
sudo chmod 600 /etc/ssh/ca_user_key
sudo chmod 644 /etc/ssh/ca_user_key.pub
```

**Sign a user's public key:**

```bash
ssh-keygen -s /etc/ssh/ca_user_key \
  -I "alice@workstation-$(date +%Y%m%d)" \   # certificate identity (logged on auth)
  -n alice,admin \                            # valid principals (must match Unix username)
  -V +30d \                                   # validity: 30 days from now
  -O no-agent-forwarding \                   # embedded option
  ~/.ssh/id_ed25519.pub
```

This creates `~/.ssh/id_ed25519-cert.pub`. The SSH client will automatically use it when
the private key is loaded.

**Configure sshd** on each server:

```ini
# Trust certificates signed by this CA
TrustedUserCAKeys /etc/ssh/ca_user_key.pub

# Optional: map certificate principals to system users
# File contains one principal per line; %u expands to the login username
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

Create `/etc/ssh/auth_principals/alice` containing the string `alice` (or `admin` for
shared accounts). Only certificates with a matching principal are accepted.

**Benefits over authorized_keys:**

| Property | authorized_keys | SSH Certificates |
|---|---|---|
| Deployment | Per-server, per-user | Sign once, trusted everywhere |
| Revocation | Remove from every server | Add to `RevokedKeys` file |
| Expiry | No built-in expiry | `--V` flag; short-lived certs possible |
| Audit | No identity on key | Certificate identity logged |
| Bastion-less | Need authorized_keys on all hosts | One CA public key on all hosts |

### Host Certificates

Host certificates eliminate the TOFU (Trust On First Use) problem in `known_hosts`. Instead
of manually verifying fingerprints, clients trust a CA that has signed server host keys.

**Generate the host CA:**

```bash
sudo ssh-keygen -t ed25519 -f /etc/ssh/ca_host_key -C "ssh-host-ca@example.com"
```

**Sign a server's host key:**

```bash
sudo ssh-keygen -s /etc/ssh/ca_host_key \
  -I "server1.example.com" \
  -h \                                         # host certificate flag
  -n "server1.example.com,192.168.1.100" \     # valid hostnames/IPs
  -V +365d \
  /etc/ssh/ssh_host_ed25519_key.pub
# Creates /etc/ssh/ssh_host_ed25519_key-cert.pub
```

Add to `sshd_config`:

```ini
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

**Client configuration** — add the host CA to `~/.ssh/known_hosts`:

```
@cert-authority *.example.com ssh-ed25519 AAAA[base64-of-ca_host_key.pub]
```

Clients will now accept any server presenting a certificate signed by the host CA without a
separate `known_hosts` entry.

### Certificate Revocation

**Revoke a compromised certificate or key:**

```bash
# Create or update the revocation list (KRL — Key Revocation List)
sudo ssh-keygen -kf /etc/ssh/revoked_keys -z 1 compromised_user_key.pub

# Add additional revoked keys to an existing KRL
sudo ssh-keygen -ukf /etc/ssh/revoked_keys -z 2 another_compromised_key.pub
```

Add to `sshd_config`:

```ini
RevokedKeys /etc/ssh/revoked_keys
```

sshd checks the KRL on every authentication attempt. Alternatively, issue short-lived
certificates (e.g. 8–24 hour validity) and let them expire naturally — no revocation
infrastructure needed.

### AuthorizedKeysCommand

`AuthorizedKeysCommand` lets sshd call an external program to look up a user's authorized
public keys at authentication time instead of — or in addition to — reading a static
`authorized_keys` file. This enables centralized key management for fleets: keys are stored
in LDAP, a REST API, or a secrets manager, and servers always see the current authoritative set.

**How it works:**

1. sshd calls the configured command, passing at minimum `%u` (the login username) as an argument
2. The command writes one or more public keys (in `authorized_keys` format) to stdout
3. sshd authenticates the connecting key against that output
4. If the command returns no keys and no static `authorized_keys` exists, authentication fails

**Configuration:**

```ini
# The program called with the username as argument
# Must be owned by root, not world-writable, and in a safe path
AuthorizedKeysCommand     /usr/local/bin/fetch-ssh-keys %u
AuthorizedKeysCommandUser nobody   # run the command as this unprivileged user
```

> `AuthorizedKeysCommandUser` must be an existing system account. Using `nobody` prevents the
> command from accessing user files or sensitive system resources.

**Example: LDAP via `ldapsearch`** — a minimal wrapper script at `/usr/local/bin/fetch-ssh-keys`:

```bash
#!/bin/bash
set -euo pipefail
USERNAME="${1:?username required}"

# Validate input — only allow safe characters
[[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || exit 1

ldapsearch -x -H ldap://ldap.example.com \
  -b "ou=people,dc=example,dc=com" \
  "(uid=${USERNAME})" \
  sshPublicKey 2>/dev/null \
  | awk '/^sshPublicKey:/ {print substr($0, index($0,$2))}'
```

Set required permissions:

```bash
sudo chown root:root /usr/local/bin/fetch-ssh-keys
sudo chmod 755 /usr/local/bin/fetch-ssh-keys
```

**Example: REST API / vault lookup** — replace the ldapsearch call with a curl request to
an internal API or a HashiCorp Vault lookup. The script must write valid public key lines
to stdout and return exit code 0 on success.

**Combining with static `authorized_keys`:** By default, sshd checks `AuthorizedKeysCommand`
**and** `authorized_keys`. Either source can provide the key. To rely exclusively on the
command (enforcing central control), set:

```ini
AuthorizedKeysFile none
```

**Key management workflow with `AuthorizedKeysCommand`:**

| Operation | How |
|---|---|
| Add a user's key | Add the key to LDAP/API for that user |
| Remove a user's key | Remove from LDAP/API; effective immediately on next login |
| Rotate a key | Replace in LDAP/API; no per-server action needed |
| Decommission a user | Disable/delete in LDAP/API; revoke on all servers instantly |

> **Security note:** The command's output is trusted as-is. If the backend is compromised,
> an attacker can inject arbitrary public keys. Protect the key store at least as carefully
> as you would `authorized_keys` files.

---

## Layer 5: SSH Client Hardening

Client-side hardening prevents the client from offering weak algorithms, protects against
host key spoofing, and limits what the remote server can do with the connection.

### ~/.ssh/config Hardening

`~/.ssh/config` applies defaults to all connections. Settings can be overridden per host.

```
# Global defaults applied to all connections
Host *
  # Only offer explicitly configured keys; don't probe the agent for others
  IdentitiesOnly yes
  IdentityFile ~/.ssh/id_ed25519

  # Modern algorithms only — mirror the server-side restrictions
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
  KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org

  # Host key verification
  StrictHostKeyChecking accept-new  # accept on first connect, reject changed keys
  VerifyHostKeyDNS yes              # verify against SSHFP DNS records when available
  HashKnownHosts yes                # store hashed hostnames in known_hosts

  # Connection keepalive (client-initiated, complements server ClientAliveInterval)
  ServerAliveInterval 60
  ServerAliveCountMax 3

  # Disable forwarding by default; re-enable per trusted host below
  ForwardAgent no
  ForwardX11 no
  ForwardX11Trusted no

  # Don't pass locale and other environment variables unless explicitly needed
  SendEnv LANG LC_*

# Example: internal jump host — agent forwarding allowed, specific key
Host bastion.example.com
  User           admin
  IdentityFile   ~/.ssh/id_ed25519_bastion
  ForwardAgent   yes

# Example: target host reached via bastion
Host *.internal.example.com
  ProxyJump      bastion.example.com
  IdentityFile   ~/.ssh/id_ed25519
```

Set correct permissions on `~/.ssh/config`:

```bash
chmod 600 ~/.ssh/config
```

### System-wide /etc/ssh/ssh_config

`/etc/ssh/ssh_config` is the **system-wide** SSH client configuration. It applies to every
user on the machine — including `root`, service accounts, Ansible, and CI/CD pipelines — for
any outbound SSH connection. On a server that makes outbound connections (deployments, backups,
monitoring agents), this is the equivalent of `~/.ssh/config` for the system itself.

Its settings are weaker in priority than `~/.ssh/config` and per-invocation flags, but any
server that uses the default `/etc/ssh/ssh_config` (which typically has `GSSAPIAuthentication yes`
and no algorithm restrictions) is making those weak defaults available to every system-level
SSH call.

Harden `/etc/ssh/ssh_config` to match the per-user config:

```ini
# /etc/ssh/ssh_config — system-wide SSH client hardening

Host *
    # Algorithm restrictions (same as ~/.ssh/config)
    Ciphers          chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
    MACs             hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
    KexAlgorithms    mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
    HostKeyAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com

    # Host key verification
    StrictHostKeyChecking accept-new
    HashKnownHosts        yes

    # Disable forwarding at the system level; enable per trusted host if needed
    ForwardAgent    no
    ForwardX11      no

    # Disable GSSAPI — not needed unless Kerberos is in use
    GSSAPIAuthentication no

    # Keepalive (application-level)
    ServerAliveInterval 60
    ServerAliveCountMax 3

    # Suppress sending locale variables unless explicitly required
    SendEnv LANG LC_*
```

> **Drop-in files:** On modern systems, `/etc/ssh/ssh_config` may also `Include`
> `/etc/ssh/ssh_config.d/*.conf`. Check for and clean up any conflicting entries there,
> just as with `sshd_config.d/`.

### known_hosts Management

`known_hosts` stores server public key fingerprints and protects against MITM attacks.

Verify the host fingerprint out-of-band before the first connection:

```bash
# On the server (get fingerprint via console/trusted channel)
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub

# On the client (scan and display fingerprint before connecting)
ssh-keyscan -t ed25519 server_ip | ssh-keygen -lf -
```

Compare the two outputs. They should be identical.

Remove a stale or changed entry:

```bash
ssh-keygen -R hostname_or_ip
```

Audit `known_hosts` for unhashed entries (should be empty with `HashKnownHosts yes`):

```bash
awk '!/^\|/' ~/.ssh/known_hosts
```

### SSHFP DNS Records

SSHFP (SSH Fingerprint) records publish host key fingerprints in DNS. When `VerifyHostKeyDNS yes`
is set and DNSSEC is active, the SSH client automatically verifies host keys against DNS without
manual fingerprint exchange.

Generate SSHFP records for your server:

```bash
ssh-keygen -r server.example.com -f /etc/ssh/ssh_host_ed25519_key.pub
```

Example output to add to your DNS zone:

```
server.example.com IN SSHFP 4 1 [SHA-1 fingerprint]
server.example.com IN SSHFP 4 2 [SHA-256 fingerprint]
```

> SSHFP type 4 = Ed25519. Algorithm 2 (SHA-256) is preferred over algorithm 1 (SHA-1).
> DNSSEC must be enabled on the zone for SSHFP to be trusted by the client.

---

## Layer 6: Fail2ban

Fail2ban is a Python daemon that parses log files using regular expressions, detects abuse
patterns such as repeated authentication failures, and issues temporary bans via the host
firewall. It operates reactively and is a useful second layer when password authentication
cannot be fully disabled, or as defense-in-depth alongside key-only auth.

### Installation

**Debian/Ubuntu:**

```bash
sudo apt install fail2ban
sudo systemctl enable --now fail2ban
```

**RHEL/Fedora/Rocky Linux:**

```bash
sudo dnf install fail2ban
sudo systemctl enable --now fail2ban
```

### Configuration

Never edit `jail.conf` directly — it is overwritten on package upgrades. Use a local override:

```bash
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

Configure the `[sshd]` jail in `jail.local`:

```ini
[DEFAULT]
# Never ban management networks or monitoring systems
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24

# Escalating bans for repeat offenders
bantime.increment  = true
bantime.multiplier = 2
bantime.maxtime    = 86400   # cap at 24 hours

[sshd]
enabled  = true
port     = ssh               # update if SSH is on a non-standard port
filter   = sshd
logpath  = /var/log/auth.log  # Debian/Ubuntu; use /var/log/secure on RHEL
maxretry = 5                  # failures before ban
findtime = 600                # observation window in seconds (10 min)
bantime  = 3600               # initial ban duration in seconds (1 hour)
```

| Directive         | Description                                              |
|-------------------|----------------------------------------------------------|
| `enabled`         | Activates this jail                                      |
| `port`            | SSH port to monitor                                      |
| `logpath`         | Log file to parse                                        |
| `maxretry`        | Failure count within `findtime` that triggers a ban      |
| `findtime`        | Sliding observation window in seconds                    |
| `bantime`         | Ban duration in seconds; `-1` = permanent ban            |
| `bantime.increment` | Doubles ban duration for each repeat offense           |

Apply changes:

```bash
sudo systemctl restart fail2ban
```

### Operation and Testing

```bash
# List all active jails
sudo fail2ban-client status

# Inspect the SSH jail (banned IPs, failure counts)
sudo fail2ban-client status sshd

# Unban a specific IP
sudo fail2ban-client set sshd unbanip 203.0.113.55

# Follow activity in real time
sudo tail -f /var/log/fail2ban.log
```

To test: intentionally trigger `maxretry` failures from a test IP, verify the ban appears,
then unban:

```bash
sudo fail2ban-client set sshd unbanip <test-ip>
```

---

## Layer 7: Firewall Rate Limiting

Rate limiting at the firewall layer throttles connection attempts before they reach sshd,
reducing log noise and limiting the speed of brute-force tooling independently of log-based
detection.

### iptables: recent Module

The following rules allow up to 3 new SSH connections per 60-second window per source IP
and drop the 4th and subsequent attempts:

```bash
# Track every new SSH connection attempt per source IP
sudo iptables -A INPUT -p tcp --dport 22 \
  -m conntrack --ctstate NEW \
  -m recent --set --name SSH_RATELIMIT

# Drop if >=4 new connections within 60 seconds from same IP
sudo iptables -A INPUT -p tcp --dport 22 \
  -m conntrack --ctstate NEW \
  -m recent --update --seconds 60 --hitcount 4 --name SSH_RATELIMIT \
  -j DROP
```

> `--ctstate` (conntrack module) is the modern replacement for the deprecated `--state` module.
> Both work for `NEW` state matching but `conntrack` is actively maintained on kernels ≥ 3.7.

Persist rules across reboots:

```bash
sudo iptables-save | sudo tee /etc/iptables/rules.v4
# Or use the persistence package:
sudo apt install iptables-persistent
```

### ufw: limit Rule

```bash
sudo ufw limit ssh/tcp
```

Applies an equivalent rate limit (≤6 connections per 30 seconds per IP). Verify:

```bash
sudo ufw status numbered
```

### nftables

On systems using nftables natively (Debian 11+, RHEL 9+), the equivalent ruleset:

```
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        ct state established,related accept
        ct state invalid drop

        tcp dport 22 ct state new \
            limit rate over 3/minute burst 5 packets \
            drop

        tcp dport 22 ct state new accept
    }
}
```

Load with `sudo nft -f /etc/nftables.conf`.

---

## Layer 8: Port Knocking

Port knocking keeps port 22 closed in the firewall at all times. It opens temporarily only
when the connecting host sends a specific sequence of TCP SYN packets to a series of closed
ports. This hides SSH entirely from passive scanners and eliminates the attack surface for
bots that do not know the knock sequence.

### How It Works

The `knockd` daemon listens for connection attempts on ports that host no services. When the
correct sequence arrives from a source IP within the configured timeout, `knockd` executes a
firewall rule that opens SSH for that IP only. A reverse sequence closes it again.

Port knocking is a security-through-obscurity mechanism and does not replace strong
authentication. It is most effective as an additional layer on top of key-only auth.

### Server Configuration

```bash
sudo apt install knockd      # Debian/Ubuntu
sudo dnf install knock       # RHEL/Fedora
```

Edit `/etc/knockd.conf`:

```ini
[options]
  UseSyslog
  Interface = eth0    # replace with your actual interface

[openSSH]
  sequence    = 7000,8000,9000
  seq_timeout = 15            # seconds to complete the sequence
  tcpflags    = syn
  command     = /usr/sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT

[closeSSH]
  sequence    = 9000,8000,7000
  seq_timeout = 15
  tcpflags    = syn
  command     = /usr/sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
```

Enable knockd startup. Edit `/etc/default/knockd`:

```ini
START_KNOCKD=1
```

Enable and start:

```bash
sudo systemctl enable --now knockd
```

> **Sequence selection:** Use ports above 1024. Avoid sequential or predictable numbers.
> Never assign knock ports to actual services. Consider mixing TCP and UDP for additional
> stealth. Change the sequence periodically.

### Client Usage

```bash
# knock client is included in the knockd package
knock server_ip 7000 8000 9000
ssh user@server_ip
knock server_ip 9000 8000 7000   # close the port when done
```

Automate open-connect-close in `~/.ssh/config`:

```
Host myserver
  HostName      server_ip
  User          myuser
  IdentityFile  ~/.ssh/id_ed25519
  ProxyCommand  bash -c 'knock %h 7000 8000 9000; sleep 1; exec nc %h %p'
```

---

## Monitoring and Alerting

Hardening reduces attack surface; monitoring detects what still reaches the system and
provides forensic data when incidents occur.

### Log Inspection

| Distribution    | SSH log path           |
|-----------------|------------------------|
| Debian / Ubuntu | `/var/log/auth.log`    |
| RHEL / Fedora   | `/var/log/secure`      |
| systemd (any)   | `journalctl -u sshd -f` |

```bash
# Filter all sshd events
sudo grep "sshd" /var/log/auth.log

# Count failed attempts by source IP
sudo grep "Failed password" /var/log/auth.log \
  | awk '{print $(NF-3)}' \
  | sort | uniq -c | sort -rn | head -20

# Successful logins
last -n 50

# Failed login attempts (requires utmp/wtmp write permissions for sshd)
lastb -n 50
```

### Daily Reports: Logwatch

Logwatch aggregates log data and delivers structured daily summaries.

```bash
sudo apt install logwatch
```

On-demand SSH report:

```bash
sudo logwatch \
  --detail High \
  --service sshd \
  --range today \
  --mailto admin@example.com \
  --format html
```

Schedule via cron (`/etc/cron.d/logwatch-ssh`):

```cron
0 6 * * *  root  logwatch --detail High --service sshd --range yesterday \
                           --mailto admin@example.com --format html
```

### Real-Time Alerts: Logcheck and swatchdog

**Logcheck** emails anomalies as they appear:

```bash
sudo apt install logcheck
```

Configure ignore patterns in `/etc/logcheck/ignore.d.server/` and alert triggers in
`/etc/logcheck/violations.d/`.

**swatchdog** tails log files and triggers actions on regex matches:

```bash
sudo apt install swatchdog
```

Example config (`~/.swatchrc`):

```
watchfor /Failed password/
  mail     addresses=admin@example.com,subject=SSH brute-force alert
  throttle 5:00,key=$0
```

Run as a daemon:

```bash
swatchdog --config-file ~/.swatchrc --tail-file /var/log/auth.log &
```

### Live Traffic View: logtop

`logtop` renders a live sorted count of log lines, useful for identifying top attack sources:

```bash
sudo apt install logtop
sudo tail -F /var/log/auth.log | logtop
```

### Command-Level Auditing: auditd

The Linux Audit Daemon records kernel-level events: system calls, file access, and privilege
changes. It provides post-authentication forensic visibility.

**Installation:**

```bash
sudo apt install auditd audispd-plugins
sudo systemctl enable --now auditd
```

**Persistent rules** — create `/etc/audit/rules.d/ssh-hardening.rules`:

```
# Log all command executions (both 32-bit and 64-bit)
-a always,exit -F arch=b64 -S execve -k exec_commands
-a always,exit -F arch=b32 -S execve -k exec_commands

# Alert on sshd_config modifications
-w /etc/ssh/sshd_config -p wa -k sshd_config_change

# Alert on authorized_keys modifications (add entries for all users)
-w /root/.ssh/authorized_keys -p wa -k authorized_keys_change
-w /home/alice/.ssh/authorized_keys -p wa -k authorized_keys_change

# Alert on SSH host key modifications
-w /etc/ssh/ -p wa -k ssh_host_keys
```

Load without rebooting:

```bash
sudo augenrules --load
sudo auditctl -l   # verify rules are loaded
```

Query audit logs:

```bash
# Command execution history
sudo ausearch -k exec_commands | aureport -f

# sshd_config change events
sudo ausearch -k sshd_config_change

# Summary report of all audit events
sudo aureport --summary
```

---

## Cloud Environments

Cloud providers offer managed alternatives to open-port SSH that should be evaluated before
deploying a publicly accessible port 22 on cloud VMs.

### AWS: Systems Manager Session Manager

AWS SSM Session Manager provides browser-based and CLI shell access to EC2 instances without
opening any inbound port, using outbound HTTPS (443) from the instance to AWS endpoints.

**Prerequisites:**
- `AmazonSSMManagedInstanceCore` IAM policy attached to the instance role
- SSM Agent running on the instance (pre-installed on Amazon Linux 2/2023, Ubuntu 20.04+)

```bash
# Start a session from any machine with AWS credentials configured
aws ssm start-session --target i-0123456789abcdef0

# Tunnel SSH through SSM (allows scp, sftp, and local SSH tooling)
aws ssm start-session \
  --target i-0123456789abcdef0 \
  --document-name AWS-StartSSHSession \
  --parameters portNumber=22
# Then in ~/.ssh/config:
# Host i-*
#   ProxyCommand sh -c "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p"
```

**Security profile:** No inbound firewall rules needed; access controlled entirely by IAM
policies. All session activity is optionally logged to CloudWatch or S3.

If SSM is used as the primary access method, close inbound port 22 in the Security Group
and restrict SSH to `127.0.0.1` or an internal management CIDR.

### GCP: OS Login and IAP Tunneling

**OS Login** (recommended for GCP) ties SSH access to Google identities and IAM roles,
replacing project-level SSH keys in metadata.

```bash
# Enable OS Login on an instance
gcloud compute instances add-metadata INSTANCE \
  --metadata enable-oslogin=TRUE

# Push your SSH key via OS Login
gcloud compute os-login ssh-keys add --key-file ~/.ssh/id_ed25519.pub
```

**Identity-Aware Proxy (IAP) TCP tunneling** — like SSM, allows SSH without a public IP or
open firewall rule:

```bash
gcloud compute ssh INSTANCE \
  --tunnel-through-iap \
  --project PROJECT_ID \
  --zone ZONE
```

Access is governed by IAM `roles/iap.tunnelResourceAccessor`. No inbound firewall rule for
port 22 is needed; the instance can be fully internal.

### Azure: Just-In-Time VM Access and Bastion

**Azure Bastion** is a managed jump host service that provides browser-based SSH/RDP without
exposing a public IP or open port on the VM:

```bash
# SSH via Azure CLI through Bastion
az network bastion ssh \
  --name MyBastionHost \
  --resource-group MyRG \
  --target-resource-id /subscriptions/.../virtualMachines/MyVM \
  --auth-type ssh-key \
  --username azureuser \
  --ssh-key ~/.ssh/id_ed25519
```

**Just-In-Time (JIT) VM access** — Microsoft Defender for Cloud can lock down the SSH port in
the NSG and open it on-demand for a specified IP and time window:

```bash
az security jit-policy initiate \
  --resource-group MyRG \
  --vm-id /subscriptions/.../virtualMachines/MyVM \
  --ports "[{\"number\":22,\"duration\":\"PT3H\",\"allowedSourceAddressPrefix\":\"YOUR_IP\"}]"
```

### General Cloud Hardening Notes

| Concern | Recommendation |
|---|---|
| Instance metadata service (IMDS) | Enforce IMDSv2 on AWS; disable legacy metadata on GCP/Azure if not needed |
| SSH key injection via metadata | Use OS Login (GCP) or avoid instance metadata SSH keys (AWS SSM replaces them) |
| Cloud-init authorized_keys | Remove cloud-init SSH key management after provisioning if using CA or LDAP |
| Security groups / NSGs | Restrict port 22 to known management CIDRs or close it entirely when using SSM/IAP/Bastion |

---

## Incident Response

When a breach or unauthorized access is suspected, time-ordered actions to contain and
investigate.

### Immediate Containment

**Terminate active sessions without disconnecting legitimate users:**

```bash
# List all active SSH sessions and their PIDs
who -u
# Or: ps aux | grep sshd | grep -v grep

# Find sessions from suspicious IPs
ss -tn state established '( dport = :22 or sport = :22 )' | grep -v 127.0.0.1
netstat -tnp 2>/dev/null | grep :22

# Terminate a specific session by PID (sends HUP to the sshd child process)
sudo kill -HUP <pid>

# Force-disconnect all sessions for a specific user
sudo pkill -u suspicioususer -KILL
```

**Block the attacker's IP immediately:**

```bash
# iptables — drop all traffic from attacker IP
sudo iptables -I INPUT -s <attacker-ip> -j DROP

# Fail2ban — permanent ban
sudo fail2ban-client set sshd banip <attacker-ip>

# ufw
sudo ufw deny from <attacker-ip>
```

### Revoke Compromised Keys and Certificates

```bash
# Remove a specific key from authorized_keys on this host
sudo sed -i '/COMPROMISED_KEY_COMMENT_OR_FRAGMENT/d' /root/.ssh/authorized_keys
sudo sed -i '/COMPROMISED_KEY_COMMENT_OR_FRAGMENT/d' /home/alice/.ssh/authorized_keys

# If using SSH Certificate Authority: add the cert or key to the KRL
sudo ssh-keygen -ukf /etc/ssh/revoked_keys -z $(date +%s) compromised_user_key.pub
# sshd picks up the updated KRL automatically (no restart needed)

# Verify the KRL is active
sudo sshd -T | grep revokedkeys
```

### Forensic Log Commands

```bash
# Timeline of successful and failed logins (most recent first)
last -Fwa | head -50
lastb -Fwa | head -50

# All sshd events from the current boot
sudo journalctl -u sshd --since today --no-pager

# Commands executed by a specific user (requires auditd exec_commands rule)
sudo ausearch -k exec_commands --start today | aureport -i -f | grep alice

# Files accessed or modified by a user session
sudo ausearch -ua alice --start today | grep -E 'open|write|rename|unlink'

# All logins and commands in one timeline
sudo aureport --login --summary
sudo aureport --file --summary

# Network connections made during the incident window
sudo ausearch --start 2026-04-09 06:00:00 --end 2026-04-09 08:00:00 \
  -sc connect | ausearch -i
```

### Post-Incident Hardening Steps

1. **Rotate host keys** — if the attacker had access to `/etc/ssh/`:
   ```bash
   sudo rm /etc/ssh/ssh_host_*
   sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
   sudo systemctl restart sshd
   # Notify users to re-verify the new host key fingerprint
   ```

2. **Rotate user keys** — generate fresh keys for all accounts that accessed the system;
   remove all old `authorized_keys` entries.

3. **Re-issue CA certificates** — if the CA private key may have been exposed, generate a
   new CA and re-sign all user and host certificates; update `TrustedUserCAKeys` on all servers.

4. **Audit `authorized_keys` across the fleet:**
   ```bash
   for user in $(cut -d: -f1 /etc/passwd); do
     keyfile="/home/${user}/.ssh/authorized_keys"
     [ -f "$keyfile" ] && echo "=== $user ===" && cat "$keyfile"
   done
   ```

5. **Preserve evidence** — copy `/var/log/auth.log`, audit logs, and shell history before
   they rotate; hash the copies (`sha256sum`) for chain-of-custody.

---

## Verification and Testing

After applying hardening measures, verify that the configuration has taken effect and that
no regressions were introduced.

### Verify sshd Configuration

```bash
# Syntax check — always run before restarting sshd
sudo sshd -t

# Show the full effective configuration (all directives, including defaults)
sudo sshd -T

# Check the negotiated algorithms specifically
sudo sshd -T | grep -E 'ciphers|macs|kexalgorithms|hostkeyalgorithms|pubkeyacceptedalgorithms'

# Show effective configuration for a specific user (OpenSSH >= 6.7)
# Resolves Match blocks — what a real login for "alice" would actually see
sudo sshd -G -u alice
# Or for a connection from a specific address:
sudo sshd -G -u alice -a 203.0.113.55
```

> `-G` is essential when using `Match` blocks: `-T` does not evaluate `Match` conditions,
> so the per-user or per-IP effective values may differ from the global output.
> Use `-G` to verify that SFTP chroots, `ForceCommand` overrides, and forwarding restrictions
> are applied as intended for actual users.

### Scan Your Own Server

Use `sshscan` (this project) to audit algorithm configuration and compliance:

```bash
# Scan local server against NIST framework
python3 sshscan.py --local --compliance NIST

# Scan with full output and NSA detection
python3 sshscan.py --host 127.0.0.1 --filter weak,nsa

# Export results for documentation
python3 sshscan.py --local --compliance NIST --format json --output hardening-audit.json
```

Use `ssh-audit` for an independent second opinion:

```bash
sudo apt install ssh-audit   # or: pip3 install ssh-audit
ssh-audit localhost
ssh-audit -p 22 your.server.ip
```

`ssh-audit` reports algorithm grades (good/warn/fail), banner information, and policy
compliance.

### Nmap Algorithm Enumeration

```bash
nmap --script ssh2-enum-algos -p 22 localhost
```

### Test That Disabled Authentication Methods Are Rejected

```bash
# Verify password auth is rejected
ssh -o PasswordAuthentication=yes \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    user@server_ip
# Expected: Permission denied (publickey).

# Verify root login is rejected
ssh -o PreferredAuthentications=publickey root@server_ip
# Expected: Permission denied.

# Verify weak cipher is rejected (if server is hardened)
ssh -o Ciphers=aes128-cbc user@server_ip
# Expected: no matching cipher found / connection closed.
```

### Verify Negotiated Algorithms on Connect

```bash
# Show the algorithms negotiated during connection establishment
ssh -v user@server_ip 2>&1 | grep -E 'kex|cipher|mac|host key'
```

---

## Hardening Checklist

| # | Action | Layer / Tool |
|---|--------|--------------|
| 1 | Generate Ed25519 key pair; deploy to server | `ssh-keygen`, `ssh-copy-id` |
| 2 | Disable `PasswordAuthentication`, `KbdInteractiveAuthentication`; set `AuthenticationMethods publickey` | `sshd_config` |
| 3 | Disable direct root login (`PermitRootLogin no`) | `sshd_config` |
| 4 | Restrict algorithms: `Ciphers`, `MACs`, `KexAlgorithms`, `HostKeyAlgorithms` | `sshd_config` |
| 5 | Filter `/etc/ssh/moduli` to DH groups ≥ 3072 bits (`awk '$5 >= 3071'`) | `/etc/ssh/moduli` |
| 6 | Remove weak host keys (RSA, DSA, ECDSA); keep only Ed25519 | `ssh_host_*_key` files |
| 7 | Set session limits: `LoginGraceTime`, `MaxAuthTries`, `MaxStartups`, `ClientAliveInterval` | `sshd_config` |
| 8 | Disable unused features: `DisableForwarding yes`, `PermitTunnel no`, `GSSAPIAuthentication no`, `IgnoreRhosts yes`, `HostbasedAuthentication no`, `Compression no` | `sshd_config` |
| 9 | Set re-keying and idle timeouts: `RekeyLimit 1G 1h`, `ChannelTimeout session:300`, `UnusedConnectionTimeout 300` (OpenSSH ≥ 9.2) | `sshd_config` |
| 10 | Restrict login to explicit users or groups (`AllowUsers` / `AllowGroups`) | `sshd_config` |
| 11 | Check `/etc/ssh/sshd_config.d/` for drop-in files that override hardening (especially cloud-init's `50-cloud-init.conf` re-enabling `PasswordAuthentication yes`) | `sshd_config.d/` |
| 12 | Validate config syntax before every restart (`sshd -t`); verify effective per-user config with `sshd -G -u <user>` for `Match` blocks | `sshd` |
| 13 | Harden SSH client: `~/.ssh/config` with `IdentitiesOnly`, modern algorithms, `HashKnownHosts` | `~/.ssh/config` |
| 14 | Harden system-wide client: `/etc/ssh/ssh_config` with algorithm restrictions and `GSSAPIAuthentication no` — applies to all users and automation | `/etc/ssh/ssh_config` |
| 15 | Consider 2FA: TOTP with PAM or FIDO2 hardware key with `verify-required` | `libpam-google-authenticator`, `sk-ed25519` |
| 16 | For fleets: deploy SSH Certificate Authority; issue short-lived user certificates; consider `AuthorizedKeysCommand` for LDAP/API key lookup | `ssh-keygen -s`, `TrustedUserCAKeys`, `AuthorizedKeysCommand` |
| 17 | Deploy Fail2ban with tuned `maxretry`, `findtime`, `bantime`; whitelist trusted IPs; update `port` if not using 22 | `jail.local` |
| 18 | Rate-limit new SSH connections at the firewall layer | `iptables` / `ufw limit` / `nftables` |
| 19 | Optionally reduce noise: change default port and/or add port knocking | `sshd_config`, `knockd` |
| 20 | On cloud VMs: evaluate SSM Session Manager (AWS), IAP tunneling (GCP), or Azure Bastion before opening port 22 to the Internet | cloud provider |
| 21 | Enable `LogLevel VERBOSE` in sshd; review `auth.log` / `journalctl -u sshd` regularly | `sshd_config`, `grep`, `lastb` |
| 22 | Schedule daily log summaries | `logwatch` |
| 23 | Enable real-time alerting | `logcheck` / `swatchdog` |
| 24 | Enable kernel-level auditing for commands, config changes, and key modifications | `auditd` |
| 25 | Scan the server after hardening to verify algorithm configuration | `sshscan`, `ssh-audit`, `nmap` |
| 26 | Prepare incident response runbook: document key revocation steps, forensic log commands, and post-incident host key rotation | `ssh-keygen -ukf`, `ausearch`, `last` |

---

## References

| # | Resource |
|---|----------|
| 1 | OpenSSH project — [https://www.openssh.com/](https://www.openssh.com/) |
| 2 | OpenSSH `sshd_config` manual — [https://linux.die.net/man/5/sshd_config](https://linux.die.net/man/5/sshd_config) |
| 3 | ssh-audit (algorithm scanner) — [https://github.com/jtesta/ssh-audit](https://github.com/jtesta/ssh-audit) |
| 4 | Fail2ban — [https://github.com/fail2ban/fail2ban](https://github.com/fail2ban/fail2ban) |
| 5 | iptables manual — [https://linux.die.net/man/8/iptables](https://linux.die.net/man/8/iptables) |
| 6 | nftables (Arch Wiki) — [https://wiki.archlinux.org/title/Nftables](https://wiki.archlinux.org/title/Nftables) |
| 7 | ufw (Arch Wiki) — [https://wiki.archlinux.org/title/Uncomplicated_Firewall](https://wiki.archlinux.org/title/Uncomplicated_Firewall) |
| 8 | knockd manual — [https://linux.die.net/man/1/knockd](https://linux.die.net/man/1/knockd) |
| 9 | libpam-google-authenticator — [https://github.com/google/google-authenticator-libpam](https://github.com/google/google-authenticator-libpam) |
| 10 | FIDO Alliance CTAP2 specification — [https://fidoalliance.org/specs/fido-v2.0-ps-20190130/](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/) |
| 11 | ML-KEM (FIPS 203) — [https://csrc.nist.gov/pubs/fips/203/final](https://csrc.nist.gov/pubs/fips/203/final) |
| 12 | SafeCurves (Curve25519 rationale) — [https://safecurves.cr.yp.to/](https://safecurves.cr.yp.to/) |
| 13 | Logwatch — [https://sourceforge.net/projects/logwatch](https://sourceforge.net/projects/logwatch) |
| 14 | Logcheck — [https://logcheck.org/](https://logcheck.org/) |
| 15 | swatchdog — [https://github.com/ToddAtkins/swatchdog](https://github.com/ToddAtkins/swatchdog) |
| 16 | logtop — [https://manpages.ubuntu.com/manpages/plucky/man1/logtop.1.html](https://manpages.ubuntu.com/manpages/plucky/man1/logtop.1.html) |
| 17 | auditd manual — [https://linux.die.net/man/8/auditd](https://linux.die.net/man/8/auditd) |
| 18 | SSHFP DNS records (RFC 4255) — [https://datatracker.ietf.org/doc/html/rfc4255](https://datatracker.ietf.org/doc/html/rfc4255) |
| 19 | CIS OpenSSH Benchmark — [https://www.cisecurity.org/benchmark/openssh](https://www.cisecurity.org/benchmark/openssh) |
| 20 | NIST SP 800-53 Rev. 5 — Access Control and System & Communications Protection — [https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) |
| 21 | AWS SSM Session Manager — [https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html) |
| 22 | GCP Identity-Aware Proxy TCP tunneling — [https://cloud.google.com/iap/docs/using-tcp-forwarding](https://cloud.google.com/iap/docs/using-tcp-forwarding) |
| 23 | Azure Bastion — [https://learn.microsoft.com/en-us/azure/bastion/bastion-overview](https://learn.microsoft.com/en-us/azure/bastion/bastion-overview) |
