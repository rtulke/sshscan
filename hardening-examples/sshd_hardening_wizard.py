#!/usr/bin/env python3
"""
SSH Hardening Config Wizard — single-file, no dependencies.

Generates a version-accurate, hardened OpenSSH configuration for a chosen
distribution/release (or a directly given / auto-detected OpenSSH version).

Design principle: the OpenSSH *version* is what actually decides which
algorithms are valid — the distro/release is only a convenience lookup that
pre-fills a default version. Every algorithm choice is gated on the resolved
version (e.g. ML-KEM only on >= 9.9, sntrup only on >= 8.5), so the output
always passes `sshd -t` on the target.

All prompts and notes go to STDERR; only the generated config goes to STDOUT,
so you can pipe it straight into a file:

    python3 sshd_hardening_wizard.py > /etc/ssh/sshd_config.d/99-hardening.conf
    python3 sshd_hardening_wizard.py --format crypto >> /etc/ssh/sshd_config

Non-interactive (scriptable) example:

    python3 sshd_hardening_wizard.py \
        --distro ubuntu --release 24.04 --profile strict --format dropin \
        --allow-users "alice bob" --non-interactive > 99-hardening.conf

Author: generated for the sshscan project.
"""

import argparse
import re
import shutil
import subprocess
import sys
from datetime import datetime

__version__ = "1.0.0"


# ---------------------------------------------------------------------------
# Distribution metadata
#
# Each release maps to the OpenSSH version it ships. These are best-effort
# defaults — the auto-detected or manually entered version always wins. Entries
# marked "(verify)" are the ones I am least certain about; confirm with
# `ssh -V` on the target if in doubt.
# ---------------------------------------------------------------------------

# family -> distro-specific paths / service names / crypto-policy behaviour
FAMILIES = {
    "debian": {
        "sftp": "/usr/lib/openssh/sftp-server",
        "service": "ssh",            # Debian/Ubuntu call the unit ssh.service
        "crypto_policies": False,
    },
    "rhel": {
        "sftp": "/usr/libexec/openssh/sftp-server",
        "service": "sshd",
        "crypto_policies": True,     # RHEL/Fedora use update-crypto-policies
    },
    "suse": {
        "sftp": "/usr/lib/ssh/sftp-server",
        "service": "sshd",
        "crypto_policies": False,
    },
    "generic": {
        "sftp": "/usr/lib/openssh/sftp-server",
        "service": "sshd",
        "crypto_policies": False,
    },
}

# distro -> (display name, family, [(release label, (openssh_major, openssh_minor)), ...])
# Newest first; "current + last 3" per the project's request.
DISTROS = {
    "ubuntu": ("Ubuntu", "debian", [
        ("26.04 LTS (projected)", (10, 0)),
        ("24.04 LTS (Noble)",     (9, 6)),
        ("22.04 LTS (Jammy)",     (8, 9)),
        ("20.04 LTS (Focal)",     (8, 2)),
    ]),
    "debian": ("Debian", "debian", [
        ("13 (Trixie)",    (10, 0)),
        ("12 (Bookworm)",  (9, 2)),
        ("11 (Bullseye)",  (8, 4)),
        ("10 (Buster)",    (7, 9)),
    ]),
    "rhel": ("RHEL / Rocky / AlmaLinux", "rhel", [
        ("10",        (9, 9)),
        ("9",         (8, 7)),
        ("8",         (8, 0)),
        ("7 (EOL)",   (7, 4)),
    ]),
    "fedora": ("Fedora", "rhel", [
        ("42", (10, 0)),
        ("41", (9, 9)),
        ("40", (9, 6)),
        ("39", (9, 3)),
    ]),
    "sles": ("SUSE Linux Enterprise", "suse", [
        ("16 (verify)",       (9, 8)),
        ("15 SP6 (verify)",   (9, 6)),
        ("15 SP5",            (8, 4)),
        ("15 SP4",            (8, 4)),
    ]),
    "opensuse": ("openSUSE", "suse", [
        ("Tumbleweed (rolling)", (10, 0)),
        ("Leap 15.6 (verify)",   (9, 6)),
        ("Leap 15.5",            (8, 4)),
        ("Leap 15.4",            (8, 4)),
    ]),
    "generic": ("Generic / other", "generic", []),
}


# ---------------------------------------------------------------------------
# I/O helpers — prompts to stderr, config to stdout
# ---------------------------------------------------------------------------

def err(*a, **k):
    k.setdefault("file", sys.stderr)
    print(*a, **k)


def out(*a, **k):
    print(*a, **k)


def fmt_ver(v):
    return f"{v[0]}.{v[1]}"


def parse_ver(s):
    """Parse '9.6', '9.6p1', 'OpenSSH_9.6p1 ...' -> (9, 6). Return None on failure."""
    m = re.search(r"(\d+)\.(\d+)", s)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)))


def detect_local_openssh():
    """Return (major, minor) from `ssh -V`, or None if unavailable."""
    if not shutil.which("ssh"):
        return None
    try:
        # ssh -V prints to stderr, e.g. "OpenSSH_9.6p1 Ubuntu-3ubuntu13.16, OpenSSL ..."
        proc = subprocess.run(["ssh", "-V"], capture_output=True, text=True, timeout=5)
        text = (proc.stderr or "") + (proc.stdout or "")
    except Exception:
        return None
    m = re.search(r"OpenSSH_(\d+)\.(\d+)", text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)))


def detect_local_distro():
    """Best-effort read of /etc/os-release -> a DISTROS key, or None."""
    try:
        data = {}
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, _, val = line.strip().partition("=")
                    data[k] = val.strip().strip('"')
    except OSError:
        return None
    ident = " ".join([data.get("ID", ""), data.get("ID_LIKE", ""), data.get("NAME", "")]).lower()
    for key in ("ubuntu", "debian", "fedora", "opensuse", "sles"):
        if key in ident:
            return key
    if any(x in ident for x in ("rhel", "red hat", "rocky", "alma", "centos")):
        return "rhel"
    if "suse" in ident:
        return "sles"
    return None


# ---------------------------------------------------------------------------
# Interactive prompt helpers (stderr)
# ---------------------------------------------------------------------------

def choose(title, labels, default_idx=0):
    """Show a numbered menu on stderr, return the chosen 0-based index."""
    err("")
    err(title)
    for i, label in enumerate(labels):
        marker = " (default)" if i == default_idx else ""
        err(f"  {i + 1}) {label}{marker}")
    while True:
        err(f"Select [1-{len(labels)}] (Enter = {default_idx + 1}): ")
        try:
            raw = input().strip()
        except EOFError:
            return default_idx
        if raw == "":
            return default_idx
        if raw.isdigit() and 1 <= int(raw) <= len(labels):
            return int(raw) - 1
        err("  ! invalid choice")


def ask_text(prompt, default=""):
    err("")
    err(prompt + (f" [{default}]" if default else "") + ": ")
    try:
        raw = input().strip()
    except EOFError:
        return default
    return raw or default


def ask_yes_no(prompt, default=True):
    d = "Y/n" if default else "y/N"
    err("")
    err(f"{prompt} [{d}]: ")
    try:
        raw = input().strip().lower()
    except EOFError:
        return default
    if raw == "":
        return default
    return raw in ("y", "yes")


# ---------------------------------------------------------------------------
# Version-gated algorithm builders
# ---------------------------------------------------------------------------

def build_ciphers(profile):
    if profile == "strict":
        return ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"]
    return ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]


def build_macs(profile):
    # With AEAD ciphers the MAC list is unused; kept as defense in depth.
    macs = ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"]
    if profile == "balanced":
        macs.append("umac-128-etm@openssh.com")
    return macs


def build_kex(v, profile):
    kex = []
    if v >= (9, 9):
        kex.append("mlkem768x25519-sha256")          # ML-KEM / FIPS 203
    if v >= (8, 5):
        kex.append("sntrup761x25519-sha512@openssh.com")  # NTRU Prime hybrid
    if v >= (6, 5):
        kex += ["curve25519-sha256", "curve25519-sha256@libssh.org"]
    if profile == "balanced":
        if v >= (7, 3):
            kex += ["diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512"]
        # NIST P-curve ECDH only as a last-resort fallback for pre-Curve25519 clients
        if v >= (5, 7):
            kex += ["ecdh-sha2-nistp521", "ecdh-sha2-nistp384", "ecdh-sha2-nistp256"]
    return kex


def build_hostkeyalgs(v, profile):
    algs = ["ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com"]
    if profile == "balanced" and v >= (7, 2):
        # RSA-SHA2 is the best compatibility fallback (broader than ECDSA, and no
        # NIST curve). ssh-rsa (SHA-1) is intentionally NOT included.
        algs += [
            "rsa-sha2-512", "rsa-sha2-256",
            "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
        ]
    return algs


def build_hostkeys(profile):
    keys = ["/etc/ssh/ssh_host_ed25519_key"]
    if profile == "balanced":
        keys.append("/etc/ssh/ssh_host_rsa_key")
    return keys


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def kbd_interactive_directive(v):
    # KbdInteractiveAuthentication replaced ChallengeResponseAuthentication in 7.5.
    if v >= (7, 5):
        return "KbdInteractiveAuthentication no"
    return "ChallengeResponseAuthentication no"


def header_comment(v, profile, distro_key, release_label, detected):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    src = "auto-detected" if detected else "selected"
    dname = DISTROS.get(distro_key, ("Generic", "generic", []))[0]
    lines = [
        "# Generated by sshd_hardening_wizard.py "
        f"v{__version__} on {now}",
        f"# Target: {dname}" + (f" {release_label}" if release_label else "")
        + f"  |  OpenSSH {fmt_ver(v)} ({src})  |  profile: {profile}",
        "# Validate before use:  sudo sshd -t -f <this-file>",
    ]
    return lines


def crypto_block(v, profile):
    lines = []
    if v >= (9, 9):
        pq = "ML-KEM (FIPS 203) + NTRU-Prime hybrid, Curve25519"
    elif v >= (8, 5):
        pq = "NTRU-Prime hybrid + Curve25519 (ML-KEM needs OpenSSH >= 9.9)"
    elif v >= (6, 5):
        pq = "Curve25519 (no post-quantum KEX before OpenSSH 8.5)"
    else:
        pq = "WARNING: OpenSSH < 6.5 lacks Curve25519/Ed25519 — output is best-effort"
    lines.append(f"# Key exchange: {pq}")
    lines.append(f"Ciphers {','.join(build_ciphers(profile))}")
    lines.append(f"MACs {','.join(build_macs(profile))}")
    lines.append(f"KexAlgorithms {','.join(build_kex(v, profile))}")
    lines.append(f"HostKeyAlgorithms {','.join(build_hostkeyalgs(v, profile))}")
    return lines


def crypto_policies_note(family):
    if not FAMILIES[family]["crypto_policies"]:
        return []
    return [
        "",
        "# NOTE (RHEL/Fedora): system-wide crypto-policies may override these lines via",
        "#   /etc/crypto-policies/back-ends/opensshserver.config (included by sshd_config).",
        "# Either raise the policy:      sudo update-crypto-policies --set FUTURE",
        "# or keep a custom subpolicy, and confirm the effective result with:",
        "#   sudo sshd -T | grep -E 'ciphers|macs|kexalgorithms|hostkeyalgorithms'",
    ]


def render_crypto(v, profile, family, distro_key, release_label, detected):
    lines = header_comment(v, profile, distro_key, release_label, detected)
    lines.append("")
    lines += crypto_block(v, profile)
    lines += crypto_policies_note(family)
    return "\n".join(lines) + "\n"


def render_config(v, profile, family, distro_key, release_label, detected,
                  allow_users, port, with_sftp, dropin):
    fam = FAMILIES[family]
    L = header_comment(v, profile, distro_key, release_label, detected)
    if dropin:
        L += [
            "# Drop-in for /etc/ssh/sshd_config.d/99-hardening.conf",
            "# (its lexicographic order lets it override earlier drop-ins such as",
            "#  cloud-init's 50-cloud-init.conf that may re-enable password auth).",
        ]
    else:
        L += ["# Complete /etc/ssh/sshd_config"]
    L += [""]

    L += ["# -- Network --------------------------------------------------------------"]
    L += [f"Port {port}"]
    if not dropin:
        L += ["AddressFamily any", "ListenAddress 0.0.0.0", "ListenAddress ::"]
    L += [""]

    L += ["# -- Host keys ------------------------------------------------------------"]
    for hk in build_hostkeys(profile):
        L += [f"HostKey {hk}"]
    L += [""]

    L += ["# -- Cryptographic algorithms --------------------------------------------"]
    L += crypto_block(v, profile)
    L += crypto_policies_note(family)
    L += [""]

    L += ["# -- Authentication -------------------------------------------------------"]
    L += [
        "PermitRootLogin no",
        "AuthenticationMethods publickey",
        "PubkeyAuthentication yes",
        "PasswordAuthentication no",
        kbd_interactive_directive(v),
        "PermitEmptyPasswords no",
        "GSSAPIAuthentication no",
        "IgnoreRhosts yes",
        "HostbasedAuthentication no",
        "UsePAM yes",
    ]
    L += [""]

    L += ["# -- Access control -------------------------------------------------------"]
    au = allow_users.strip() if allow_users else "REPLACE_ME"
    if au == "REPLACE_ME":
        L += ["# IMPORTANT: replace REPLACE_ME with real account name(s) before applying"]
    L += [f"AllowUsers {au}"]
    grace, tries, sess, startups = (
        (20, 2, 2, "5:50:10") if profile == "strict" else (30, 3, 5, "10:30:60")
    )
    L += [
        f"LoginGraceTime {grace}",
        f"MaxAuthTries {tries}",
        f"MaxSessions {sess}",
        f"MaxStartups {startups}",
    ]
    L += [""]

    L += ["# -- Session management ---------------------------------------------------"]
    alive, rekey = ((120, "512M 30m") if profile == "strict" else (300, "1G 1h"))
    L += [f"ClientAliveInterval {alive}", "ClientAliveCountMax 2", f"RekeyLimit {rekey}"]
    if v >= (9, 2):
        idle = 180 if profile == "strict" else 300
        L += [f"ChannelTimeout session:{idle}", f"UnusedConnectionTimeout {idle}"]
    else:
        L += ["# ChannelTimeout / UnusedConnectionTimeout require OpenSSH >= 9.2 (omitted)"]
    L += [""]

    L += ["# -- Feature restriction --------------------------------------------------"]
    if v >= (7, 8):
        L += ["DisableForwarding yes"]
    else:
        L += ["AllowTcpForwarding no", "AllowAgentForwarding no", "X11Forwarding no"]
    L += ["PermitTunnel no", "PermitUserEnvironment no", "StrictModes yes",
          "Compression no", "TCPKeepAlive no"]
    L += [""]

    L += ["# -- Logging --------------------------------------------------------------"]
    L += ["LogLevel VERBOSE", "SyslogFacility AUTH"]
    L += [""]

    L += ["# -- Misc -----------------------------------------------------------------"]
    L += ["Banner /etc/issue.net", "PrintMotd no", "PrintLastLog yes"]
    if with_sftp:
        L += [f"Subsystem sftp {fam['sftp']}"]
    else:
        L += ["# SFTP subsystem disabled (strict). To enable, add:",
              f"# Subsystem sftp {fam['sftp']}"]
    return "\n".join(L) + "\n"


def apply_hints(family, dropin, v):
    fam = FAMILIES[family]
    err("")
    err("# ---------------------------------------------------------------------------")
    err("# Next steps (this section is on stderr and NOT part of the generated config):")
    if dropin:
        err(f"#   sudo cp <output> /etc/ssh/sshd_config.d/99-hardening.conf")
        err(f"#   sudo chmod 600 /etc/ssh/sshd_config.d/99-hardening.conf")
    err("#   sudo sshd -t                      # validate syntax + algorithm names")
    err("#   sudo sshd -T | grep -E 'kexalgorithms|ciphers|macs|hostkeyalgorithms'")
    err(f"#   sudo systemctl restart {fam['service']}")
    err("#")
    err("#   Ensure the Ed25519 host key exists before restart:")
    err("#     sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''")
    err("#   Create /etc/issue.net (login banner) and set AllowUsers to real accounts.")
    if v < (6, 5):
        err("#")
        err("#   WARNING: OpenSSH < 6.5 predates Curve25519/Ed25519 — review the output.")
    err("# ---------------------------------------------------------------------------")


# ---------------------------------------------------------------------------
# Resolution of version / distro from args or interactively
# ---------------------------------------------------------------------------

def list_distros():
    err("Supported distributions and their default OpenSSH versions:")
    for key, (name, family, releases) in DISTROS.items():
        if not releases:
            err(f"\n  {key:10} {name}")
            continue
        err(f"\n  {key:10} {name}  (family: {family})")
        for label, ver in releases:
            err(f"      {label:26} OpenSSH {fmt_ver(ver)}")
    err("\nThe detected/entered OpenSSH version always overrides these defaults.")


def resolve(args):
    """Return (version, profile, family, distro_key, release_label, detected, extras)."""
    detected = False
    distro_key = args.distro
    release_label = ""
    version = None

    # 1) Explicit --openssh wins outright.
    if args.openssh:
        version = parse_ver(args.openssh)
        if not version:
            err(f"error: could not parse --openssh {args.openssh!r} (expected e.g. 9.6)")
            sys.exit(2)

    # 2) --detect (or interactive detect) reads ssh -V.
    if version is None and args.detect:
        version = detect_local_openssh()
        if version is None:
            err("error: --detect failed (no ssh binary or unparsable `ssh -V`)")
            sys.exit(2)
        detected = True
        if distro_key is None:
            distro_key = detect_local_distro()

    interactive = not args.non_interactive and sys.stdin.isatty()

    # 3) Interactive path fills in whatever is still missing.
    if distro_key is None and version is None and interactive:
        det_v = detect_local_openssh()
        det_d = detect_local_distro()
        opts = ["Auto-detect from this machine (`ssh -V`)",
                "Pick a distribution + release",
                "Enter an OpenSSH version manually"]
        default = 0 if det_v else 1
        pick = choose("How should the target OpenSSH version be determined?", opts, default)
        if pick == 0:
            version = det_v or detect_local_openssh()
            if version is None:
                err("  ! detection failed; falling back to manual entry")
            else:
                detected = True
                distro_key = det_d
        if pick == 1 or version is None:
            keys = list(DISTROS.keys())
            names = [DISTROS[k][0] for k in keys]
            di = choose("Distribution:", names, keys.index(det_d) if det_d in keys else 0)
            distro_key = keys[di]
            releases = DISTROS[distro_key][2]
            if releases:
                labels = [f"{lbl}  (OpenSSH {fmt_ver(vv)})" for lbl, vv in releases]
                ri = choose(f"{DISTROS[distro_key][0]} release:", labels, 0)
                release_label, version = releases[ri]
            else:
                version = None
        if version is None:
            raw = ask_text("OpenSSH version on the target (e.g. 9.6)",
                           fmt_ver(det_v) if det_v else "")
            version = parse_ver(raw)
            if version is None:
                err("error: no valid OpenSSH version given")
                sys.exit(2)

    # 4) Non-interactive: derive version from distro/release lookup if needed.
    if version is None and distro_key:
        releases = DISTROS.get(distro_key, (None, None, []))[2]
        if args.release:
            for lbl, vv in releases:
                if args.release.lower() in lbl.lower():
                    release_label, version = lbl, vv
                    break
        if version is None and releases:
            release_label, version = releases[0]  # newest

    if version is None:
        err("error: could not determine an OpenSSH version. Use --openssh X.Y, "
            "--detect, or --distro/--release. See --list-distros.")
        sys.exit(2)

    if distro_key is None:
        distro_key = "generic"
    family = DISTROS.get(distro_key, ("", "generic", []))[1]

    # Profile / format / extras
    profile = args.profile
    if profile is None:
        if interactive:
            pi = choose("Hardening profile:",
                        ["strict   — Ed25519 only, no NIST curves, no forwarding, no SFTP",
                         "balanced — RSA/NIST fallback for older clients, SFTP enabled"], 0)
            profile = "strict" if pi == 0 else "balanced"
        else:
            profile = "strict"

    fmt = args.format
    if fmt is None:
        if interactive:
            fi = choose("Output format:",
                        ["crypto — just the 4 algorithm lines (append with >>)",
                         "dropin — full drop-in for sshd_config.d/99-hardening.conf",
                         "full   — complete sshd_config"], 1)
            fmt = ["crypto", "dropin", "full"][fi]
        else:
            fmt = "dropin"

    allow_users = args.allow_users
    port = args.port
    with_sftp = args.with_sftp
    if fmt in ("dropin", "full") and interactive:
        if allow_users is None:
            allow_users = ask_text("AllowUsers (space-separated accounts; blank = REPLACE_ME)", "")
        if port == 22:
            raw = ask_text("SSH port", "22")
            port = int(raw) if raw.isdigit() else 22
        if with_sftp is None:
            with_sftp = ask_yes_no("Enable the SFTP subsystem?", default=(profile == "balanced"))
    if with_sftp is None:
        with_sftp = (profile == "balanced")

    return (version, profile, family, distro_key, release_label, detected,
            {"allow_users": allow_users, "port": port, "with_sftp": with_sftp, "format": fmt})


def main():
    p = argparse.ArgumentParser(
        description="Generate a version-accurate, hardened OpenSSH configuration.",
        epilog="Prompts go to stderr; the config goes to stdout (safe to redirect with > or >>).",
    )
    p.add_argument("--distro", choices=list(DISTROS.keys()),
                   help="target distribution (default: ask / auto-detect)")
    p.add_argument("--release", metavar="TEXT",
                   help="release label substring, e.g. 24.04 or bookworm")
    p.add_argument("--openssh", metavar="X.Y",
                   help="target OpenSSH version, overrides distro lookup (e.g. 9.6)")
    p.add_argument("--detect", action="store_true",
                   help="auto-detect the OpenSSH version from local `ssh -V`")
    p.add_argument("--profile", choices=["strict", "balanced"],
                   help="hardening profile (default: strict / ask)")
    p.add_argument("--format", choices=["crypto", "dropin", "full"],
                   help="output format (default: dropin / ask)")
    p.add_argument("--allow-users", metavar="LIST",
                   help='AllowUsers value, e.g. "alice bob"')
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    sftp = p.add_mutually_exclusive_group()
    sftp.add_argument("--with-sftp", dest="with_sftp", action="store_true", default=None,
                      help="include the SFTP subsystem")
    sftp.add_argument("--no-sftp", dest="with_sftp", action="store_false",
                      help="omit the SFTP subsystem")
    p.add_argument("--non-interactive", action="store_true",
                   help="never prompt; fail if inputs are missing")
    p.add_argument("--list-distros", action="store_true",
                   help="list supported distributions and their OpenSSH versions, then exit")
    p.add_argument("--version", "-V", action="version",
                   version=f"sshd_hardening_wizard {__version__}")
    args = p.parse_args()

    if args.list_distros:
        list_distros()
        return 0

    version, profile, family, distro_key, release_label, detected, extras = resolve(args)

    if extras["format"] == "crypto":
        out(render_crypto(version, profile, family, distro_key, release_label, detected), end="")
    else:
        out(render_config(version, profile, family, distro_key, release_label, detected,
                          extras["allow_users"], extras["port"], extras["with_sftp"],
                          dropin=(extras["format"] == "dropin")), end="")

    if sys.stderr.isatty() or not sys.stdout.isatty():
        apply_hints(family, extras["format"] in ("dropin", "full"), version)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        err("\naborted")
        sys.exit(130)
