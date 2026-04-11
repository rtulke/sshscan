#!/usr/bin/env python3
"""
SSH Algorithm Security Scanner
Features: Compliance Frameworks, NSA Backdoor Detection, TOML Config,
         Retry Logic, DNS Caching, Enhanced Debug Mode, JumpHost/Bastion Function
"""

__version__ = '3.6.2'
__author__  = 'Robert Tulke, rt@debian.sh'

import subprocess
import socket
import json
import sys
import csv
import yaml
import configparser
import threading
import time
import functools
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict, field
from pathlib import Path
import argparse
import shutil
import io
import logging
from datetime import datetime

# ---------------------------------------------------------------------------
# ANSI color helpers (no external dependency; auto-disabled when not a TTY)
# ---------------------------------------------------------------------------
_C_RESET  = '\033[0m'
_C_BOLD   = '\033[1m'
_C_DIM    = '\033[2m'
_C_RED    = '\033[31m'
_C_GREEN  = '\033[32m'
_C_YELLOW = '\033[33m'
_C_CYAN   = '\033[36m'

def _colorize(text: str, code: str, enabled: bool) -> str:
    """Wrap text in ANSI escape code; no-op when enabled is False."""
    return f"{code}{text}{_C_RESET}" if enabled else text


def setup_logging(debug_enabled=False, verbose_enabled=False):
    """Setup logging with proper debug support"""
    if debug_enabled:
        level = logging.DEBUG
        format_str = '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    elif verbose_enabled:
        level = logging.INFO
        format_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    else:
        level = logging.WARNING
        format_str = '%(levelname)s - %(message)s'
    
    logging.basicConfig(
        level=level,
        format=format_str,
        datefmt='%Y-%m-%d %H:%M:%S',
        force=True  # Override existing configuration
    )
    
    # Set specific logger levels for different components
    if debug_enabled:
        logging.getLogger('SSHEnhancedScanner').setLevel(logging.DEBUG)
        logging.getLogger('EnhancedDNSCache').setLevel(logging.DEBUG)
        logging.getLogger('AlgorithmTester').setLevel(logging.DEBUG)
    
    return logging.getLogger(__name__)


# Initialize logger (will be reconfigured in main())
logger = logging.getLogger(__name__)


# Custom Exceptions for better error handling
class SSHScannerError(Exception):
    """Base exception for SSH Scanner"""
    pass

class ConfigurationError(SSHScannerError):
    """Configuration related errors"""
    pass

class SSHConnectionError(SSHScannerError):
    """Connection related errors"""
    pass

class ValidationError(SSHScannerError):
    """Input validation errors"""
    pass


@dataclass
class SSHAlgorithmInfo:
    """Data class for SSH algorithm information"""
    name: str
    type: str  # 'encryption', 'mac', 'kex', 'hostkey'
    supported: bool = True
    
    def __hash__(self):
        return hash((self.name, self.type))


@dataclass
class SSHHostResult:
    """Data class for SSH host scan results"""
    host: str
    port: int
    hostname: str = ""  # original DNS name if resolved; empty when host was already an IP
    status: str = "unknown"  # success, failed, timeout, error
    security_score: int = 0
    compliance_status: Dict[str, bool] = field(default_factory=dict)
    nsa_backdoor_analysis: Dict[str, Any] = field(default_factory=dict)
    algorithms: Dict[str, List[SSHAlgorithmInfo]] = field(default_factory=dict)
    scan_time: float = 0.0
    ssh_banner: str = ""
    error_message: str = ""
    error_type: str = ""  # connection, timeout, dns, validation
    retry_count: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result

    @classmethod
    def from_dict(cls, data: dict) -> 'SSHHostResult':
        """Reconstruct an SSHHostResult from a to_dict() payload."""
        d = data.copy()
        # Rebuild SSHAlgorithmInfo objects from plain dicts
        raw_algos = d.pop('algorithms', {})
        algorithms: Dict[str, List[SSHAlgorithmInfo]] = {
            algo_type: [SSHAlgorithmInfo(**a) for a in algo_list]
            for algo_type, algo_list in raw_algos.items()
        }
        # Parse ISO timestamp string back to datetime
        ts = d.pop('timestamp', None)
        timestamp = datetime.fromisoformat(ts) if isinstance(ts, str) else (ts or datetime.now())
        return cls(algorithms=algorithms, timestamp=timestamp, **d)



@dataclass
class ProxyConfig:
    """Per-host or global proxy / jump-host configuration."""
    type: str          # 'jump' | 'socks5' | 'http'
    host: str          # proxy or bastion hostname / IP
    port: int = 22     # proxy port (22 for jump, 1080 for socks5, 3128 for http)
    user: str = ''     # SSH username for jump hosts; unused for SOCKS5/HTTP

    def to_ssh_args(self) -> List[str]:
        """Return SSH command-line arguments that route through this proxy."""
        host = sanitize_host_input(self.host)
        port = validate_port(self.port)
        if self.type == 'jump':
            user_at = f"{self.user}@" if self.user else ""
            return ['-J', f"{user_at}{host}:{port}"]
        elif self.type == 'socks5':
            return ['-o', f'ProxyCommand=nc -X 5 -x {host}:{port} %h %p']
        elif self.type == 'http':
            return ['-o', f'ProxyCommand=nc -X connect -x {host}:{port} %h %p']
        return []

    @classmethod
    def from_dict(cls, d: dict) -> Optional['ProxyConfig']:
        """Parse a ``via`` dict from a host file entry.  Returns None on error."""
        if not isinstance(d, dict):
            return None
        proxy_type = str(d.get('type', '')).lower()
        if proxy_type not in ('jump', 'socks5', 'http'):
            logger.warning(f"ProxyConfig: unknown type {proxy_type!r}, must be jump/socks5/http")
            return None
        host = d.get('host', '')
        if not host:
            logger.warning("ProxyConfig: missing 'host'")
            return None
        default_port = 22 if proxy_type == 'jump' else (1080 if proxy_type == 'socks5' else 3128)
        try:
            port = validate_port(d.get('port', default_port))
        except ValidationError:
            port = default_port
        user_raw = str(d.get('user', ''))
        user = re.sub(r'[^a-zA-Z0-9._@-]', '', user_raw)[:64]
        return cls(type=proxy_type, host=host, port=port, user=user)


class EnhancedDNSCache:
    """Thread-safe DNS resolution cache with TTL, IPv6 support and background cleanup"""
    
    def __init__(self, ttl: int = 300, max_size: int = 1000, cleanup_interval: int = 60):
        self.cache = {}
        self.ttl = ttl
        self.max_size = max_size
        self.cleanup_interval = cleanup_interval
        self.lock = threading.Lock()
        self.stats = {'hits': 0, 'misses': 0, 'errors': 0, 'cleanups': 0}
        self._stop_cleanup = threading.Event()
        self._cleanup_thread = None
        self._start_cleanup_thread()
        logger.debug(f"DNS cache initialized with TTL={ttl}s, max_size={max_size}")
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        logger.debug("DNS cache cleanup thread started")
    
    def _cleanup_loop(self):
        """Background thread to clean expired entries"""
        while not self._stop_cleanup.is_set():
            try:
                self._cleanup_expired()
                self._stop_cleanup.wait(self.cleanup_interval)
            except Exception as e:
                logger.error(f"DNS cache cleanup error: {e}")
    
    def _cleanup_expired(self):
        """Remove expired entries from cache"""
        now = time.time()
        with self.lock:
            expired_keys = [
                hostname for hostname, (_, timestamp) in self.cache.items()
                if now - timestamp >= self.ttl
            ]
            for hostname in expired_keys:
                del self.cache[hostname]
            
            if expired_keys:
                self.stats['cleanups'] += len(expired_keys)
                logger.debug(f"Cleaned {len(expired_keys)} expired DNS entries")
    
    def resolve(self, hostname: str, prefer_ipv4: bool = True) -> Optional[str]:
        """Resolve hostname with caching and IPv6 support"""
        # Validate hostname first
        if not self._is_valid_hostname(hostname):
            logger.error(f"Invalid hostname: {hostname}")
            return None
        
        # Check if already an IP address
        try:
            ipaddress.ip_address(hostname)
            logger.debug(f"Hostname {hostname} is already an IP address")
            return hostname
        except ValueError:
            pass
        
        now = time.time()
        
        with self.lock:
            # Check cache first
            if hostname in self.cache:
                ip, timestamp = self.cache[hostname]
                if now - timestamp < self.ttl:
                    self.stats['hits'] += 1
                    logger.debug(f"DNS cache hit for {hostname} -> {ip}")
                    return ip
        
        # Cache miss - resolve
        try:
            logger.debug(f"Resolving {hostname} (cache miss)")
            # Try both IPv4 and IPv6
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            
            # Filter and sort addresses
            ipv4_addrs = []
            ipv6_addrs = []
            
            for family, _, _, _, sockaddr in addr_info:
                ip = sockaddr[0]
                if family == socket.AF_INET:
                    ipv4_addrs.append(ip)
                elif family == socket.AF_INET6:
                    ipv6_addrs.append(ip)
            
            # Choose based on preference
            if prefer_ipv4 and ipv4_addrs:
                resolved_ip = ipv4_addrs[0]
            elif ipv6_addrs:
                resolved_ip = ipv6_addrs[0]
            elif ipv4_addrs:
                resolved_ip = ipv4_addrs[0]
            else:
                raise socket.gaierror("No addresses found")
            
            with self.lock:
                # Manage cache size
                if len(self.cache) >= self.max_size:
                    # Remove oldest entry
                    oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k][1])
                    del self.cache[oldest_key]
                
                self.cache[hostname] = (resolved_ip, now)
                self.stats['misses'] += 1
            
            logger.debug(f"Resolved {hostname} to {resolved_ip}")
            return resolved_ip
            
        except (socket.gaierror, socket.error) as e:
            with self.lock:
                self.stats['errors'] += 1
            logger.warning(f"DNS resolution failed for {hostname}: {e}")
            return None
    
    def _is_valid_hostname(self, hostname: str) -> bool:
        """Validate hostname to prevent injection attacks"""
        # Basic validation - alphanumeric, dots, hyphens
        if not hostname or len(hostname) > 253:
            return False
        
        # Check for valid characters
        allowed = re.match(r'^[a-zA-Z0-9.-]+$', hostname)
        if not allowed:
            return False
        
        # Check each label
        labels = hostname.split('.')
        for label in labels:
            if not label or len(label) > 63:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
        
        return True
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        with self.lock:
            total = self.stats['hits'] + self.stats['misses']
            hit_rate = (self.stats['hits'] / total * 100) if total > 0 else 0
            return {
                'hit_rate': f"{hit_rate:.1f}%",
                'total_lookups': total,
                'cache_size': len(self.cache),
                'expired_cleaned': self.stats['cleanups'],
                **self.stats
            }
    
    def stop(self):
        """Stop cleanup thread"""
        self._stop_cleanup.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=1)


def validate_port(port: Any) -> int:
    """Validate and convert port number"""
    try:
        port_int = int(port)
        if not 1 <= port_int <= 65535:
            raise ValidationError(f"Port {port} out of valid range (1-65535)")
        return port_int
    except (ValueError, TypeError):
        raise ValidationError(f"Invalid port: {port}")


def validate_ip_address(ip: str) -> bool:
    """Validate IP address (v4 or v6)"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def sanitize_host_input(host: str) -> str:
    """Sanitize host input — allowlist of valid hostname/IP/bracket characters."""
    host = host.strip()
    # Allow: letters, digits, dot, hyphen, colon (port sep / IPv6), brackets (IPv6), underscore, percent (scope)
    host = re.sub(r'[^a-zA-Z0-9.\-:\[\]_%]', '', host)
    if len(host) > 253:  # Max DNS name length
        raise ValidationError(f"Hostname too long: {host}")
    return host


class ConfigValidator:
    """Validate and sanitize configuration options"""
    
    VALID_FRAMEWORKS = ['NIST', 'FIPS_140_2', 'BSI_TR_02102', 'ANSSI', 'PRIVACY_FOCUSED']
    
    @staticmethod
    def validate_config(config: Dict) -> Dict:
        """Validate configuration dictionary"""
        validated = {}
        
        # Scanner configuration
        scanner_config = config.get('scanner', {})
        validated['scanner'] = {}
        
        # Validate threads
        threads = scanner_config.get('threads', 20)
        try:
            threads = int(threads)
            if not 1 <= threads <= 500:
                raise ValueError
            validated['scanner']['threads'] = threads
        except (ValueError, TypeError):
            logger.warning(f"Invalid threads value: {threads}, using default 20")
            validated['scanner']['threads'] = 20
        
        # Validate timeout
        timeout = scanner_config.get('timeout', 10)
        try:
            timeout = int(timeout)
            if not 1 <= timeout <= 120:
                raise ValueError
            validated['scanner']['timeout'] = timeout
        except (ValueError, TypeError):
            logger.warning(f"Invalid timeout value: {timeout}, using default 10")
            validated['scanner']['timeout'] = 10
        
        # Validate retry_attempts
        retry = scanner_config.get('retry_attempts', 3)
        try:
            retry = int(retry)
            if not 1 <= retry <= 10:
                raise ValueError
            validated['scanner']['retry_attempts'] = retry
        except (ValueError, TypeError):
            logger.warning(f"Invalid retry_attempts value: {retry}, using default 3")
            validated['scanner']['retry_attempts'] = 3
        
        # Validate dns_cache_ttl
        dns_ttl = scanner_config.get('dns_cache_ttl', 300)
        try:
            dns_ttl = int(dns_ttl)
            if not 60 <= dns_ttl <= 3600:
                raise ValueError
            validated['scanner']['dns_cache_ttl'] = dns_ttl
        except (ValueError, TypeError):
            logger.warning(f"Invalid dns_cache_ttl value: {dns_ttl}, using default 300")
            validated['scanner']['dns_cache_ttl'] = 300

        # Validate banner_timeout (optional — None = min(timeout, 5))
        banner_timeout = scanner_config.get('banner_timeout', None)
        if banner_timeout is not None:
            try:
                banner_timeout = int(banner_timeout)
                if not 1 <= banner_timeout <= 30:
                    raise ValueError
                validated['scanner']['banner_timeout'] = banner_timeout
            except (ValueError, TypeError):
                logger.warning(f"Invalid banner_timeout value: {banner_timeout}, ignoring (valid range: 1-30)")

        # Validate rate_limit (optional — None = unlimited)
        rate_limit = scanner_config.get('rate_limit', None)
        if rate_limit is not None:
            try:
                rate_limit = float(rate_limit)
                if not 0.1 <= rate_limit <= 1000:
                    raise ValueError
                validated['scanner']['rate_limit'] = rate_limit
            except (ValueError, TypeError):
                logger.warning(f"Invalid rate_limit value: {rate_limit}, ignoring (valid range: 0.1-1000)")

        # Validate strict_host_key_checking (optional — default: accept-new)
        _SSHKC_VALUES = ('yes', 'no', 'accept-new')
        sshkc = scanner_config.get('strict_host_key_checking', 'accept-new')
        if sshkc in _SSHKC_VALUES:
            validated['scanner']['strict_host_key_checking'] = sshkc
        else:
            logger.warning(f"Invalid strict_host_key_checking value: {sshkc!r}, "
                           f"using 'accept-new' (valid: {', '.join(_SSHKC_VALUES)})")
            validated['scanner']['strict_host_key_checking'] = 'accept-new'

        # jump_host (optional — None = no jump host)
        jump_host = scanner_config.get('jump_host', None)
        if jump_host:
            validated['scanner']['jump_host'] = str(jump_host).strip()

        # proxy_command (optional — raw ProxyCommand string, passed through as-is)
        proxy_command = scanner_config.get('proxy_command', None)
        if proxy_command:
            validated['scanner']['proxy_command'] = str(proxy_command).strip()

        # Compliance configuration (optional — no framework = no compliance check)
        compliance_config = config.get('compliance', {})
        validated['compliance'] = {}

        framework = compliance_config.get('framework', None)
        if framework is not None:
            if framework in ConfigValidator.VALID_FRAMEWORKS:
                validated['compliance']['framework'] = framework
            else:
                logger.warning(f"Invalid compliance framework: {framework}, ignoring")

        return validated


def retry_on_failure(max_attempts: int = 3, backoff_factor: float = 2.0, exceptions: Tuple = None):
    """Decorator for retry logic with exponential backoff"""
    if exceptions is None:
        exceptions = (subprocess.TimeoutExpired, subprocess.CalledProcessError, SSHConnectionError)
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            retry_count = 0
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    retry_count += 1
                    
                    if attempt < max_attempts - 1:
                        sleep_time = backoff_factor ** attempt
                        logger.debug(f"Attempt {attempt + 1} failed: {e}. Retrying in {sleep_time:.1f}s...")
                        time.sleep(sleep_time)
                    else:
                        logger.warning(f"All {max_attempts} attempts failed for {func.__name__}")
            
            raise last_exception
        return wrapper
    return decorator


class NSABackdoorDetector:
    """Detection of algorithms with suspected NSA backdoors"""
    
    # Algorithms with suspected NSA involvement/backdoors
    SUSPECTED_NSA_ALGORITHMS = {
        'kex': {
            'ecdh-sha2-nistp256': {
                'risk': 'HIGH',
                'reason': 'NIST P-256 curve - NSA involvement in curve selection',
                'alternative': 'curve25519-sha256',
                'reference': 'Snowden revelations, SafeCurves project'
            },
            'ecdh-sha2-nistp384': {
                'risk': 'HIGH', 
                'reason': 'NIST P-384 curve - NSA involvement in curve selection',
                'alternative': 'curve25519-sha256',
                'reference': 'Snowden revelations, SafeCurves project'
            },
            'ecdh-sha2-nistp521': {
                'risk': 'HIGH',
                'reason': 'NIST P-521 curve - NSA involvement in curve selection', 
                'alternative': 'curve25519-sha256',
                'reference': 'Snowden revelations, SafeCurves project'
            }
        },
        'key': {
            'ecdsa-sha2-nistp256': {
                'risk': 'HIGH',
                'reason': 'ECDSA with NIST P-256 - potential NSA backdoor in curve',
                'alternative': 'ssh-ed25519',
                'reference': 'NSA Suite B cryptography concerns'
            },
            'ecdsa-sha2-nistp384': {
                'risk': 'HIGH',
                'reason': 'ECDSA with NIST P-384 - potential NSA backdoor in curve',
                'alternative': 'ssh-ed25519',
                'reference': 'NSA Suite B cryptography concerns'
            },
            'ecdsa-sha2-nistp521': {
                'risk': 'HIGH',
                'reason': 'ECDSA with NIST P-521 - potential NSA backdoor in curve',
                'alternative': 'ssh-ed25519',
                'reference': 'NSA Suite B cryptography concerns'
            },
            'ecdsa-sha2-nistp256-cert-v01@openssh.com': {
                'risk': 'HIGH',
                'reason': 'ECDSA certificate with NIST P-256 - same curve concerns',
                'alternative': 'ssh-ed25519-cert-v01@openssh.com',
                'reference': 'NSA Suite B cryptography concerns'
            },
            'ecdsa-sha2-nistp384-cert-v01@openssh.com': {
                'risk': 'HIGH',
                'reason': 'ECDSA certificate with NIST P-384 - same curve concerns',
                'alternative': 'ssh-ed25519-cert-v01@openssh.com',
                'reference': 'NSA Suite B cryptography concerns'
            },
            'ecdsa-sha2-nistp521-cert-v01@openssh.com': {
                'risk': 'HIGH',
                'reason': 'ECDSA certificate with NIST P-521 - same curve concerns',
                'alternative': 'ssh-ed25519-cert-v01@openssh.com',
                'reference': 'NSA Suite B cryptography concerns'
            },
            'sk-ecdsa-sha2-nistp256@openssh.com': {
                'risk': 'HIGH',
                'reason': 'FIDO/SK ECDSA with NIST P-256 - same curve concerns',
                'alternative': 'sk-ssh-ed25519@openssh.com',
                'reference': 'NSA Suite B cryptography concerns'
            },
            'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com': {
                'risk': 'HIGH',
                'reason': 'FIDO/SK ECDSA certificate with NIST P-256 - same curve concerns',
                'alternative': 'sk-ssh-ed25519-cert-v01@openssh.com',
                'reference': 'NSA Suite B cryptography concerns'
            },
        },
        'cipher': {
            # Historical NSA involvement
            'des': {
                'risk': 'CRITICAL',
                'reason': 'NSA involvement in S-box design, weak key size',
                'alternative': 'aes256-gcm@openssh.com',
                'reference': 'Historical NSA involvement in DES design'
            }
        },
        'mac': {
            'hmac-sha1': {
                'risk': 'MEDIUM',
                'reason': 'SHA-1 developed with NSA involvement, collision attacks',
                'alternative': 'hmac-sha2-256-etm@openssh.com',
                'reference': 'SHA-1 cryptanalysis and NSA design'
            },
            'hmac-sha1-etm@openssh.com': {
                'risk': 'MEDIUM',
                'reason': 'SHA-1 with NSA involvement (ETM variant)',
                'alternative': 'hmac-sha2-256-etm@openssh.com',
                'reference': 'SHA-1 cryptanalysis and NSA design'
            },
        }
    }
    
    @classmethod
    def check_nsa_backdoor_risk(cls, algorithms: Dict[str, List[SSHAlgorithmInfo]], check_enabled: bool = True) -> Dict:
        """Check for algorithms with suspected NSA backdoors"""
        backdoor_analysis = {
            'enabled': check_enabled,
            'high_risk_algorithms': [],
            'medium_risk_algorithms': [],
            'confirmed_backdoors': [],
            'recommendations': [],
            'overall_risk_score': 0,
            'trusted_alternatives': []
        }
        
        if not check_enabled:
            backdoor_analysis['status'] = 'disabled'
            return backdoor_analysis
        
        total_algorithms = 0
        risky_algorithms = 0
        
        for algo_type, algo_list in algorithms.items():
            for algo in algo_list:
                if algo.supported:
                    total_algorithms += 1
                    
                    # Check for suspected backdoors
                    if algo_type in cls.SUSPECTED_NSA_ALGORITHMS:
                        if algo.name in cls.SUSPECTED_NSA_ALGORITHMS[algo_type]:
                            risky_algorithms += 1
                            risk_info = cls.SUSPECTED_NSA_ALGORITHMS[algo_type][algo.name]
                            
                            risk_entry = {
                                'algorithm': algo.name,
                                'type': algo_type,
                                'risk_level': risk_info['risk'],
                                'reason': risk_info['reason'],
                                'recommended_alternative': risk_info['alternative'],
                                'reference': risk_info['reference']
                            }
                            
                            if risk_info['risk'] == 'HIGH' or risk_info['risk'] == 'CRITICAL':
                                backdoor_analysis['high_risk_algorithms'].append(risk_entry)
                            else:
                                backdoor_analysis['medium_risk_algorithms'].append(risk_entry)
        
        # Calculate overall risk score
        if total_algorithms > 0:
            risk_percentage = (risky_algorithms / total_algorithms) * 100
            backdoor_analysis['overall_risk_score'] = min(100, risk_percentage * 2)  # Amplify risk
        
        # Generate recommendations
        if backdoor_analysis['high_risk_algorithms']:
            backdoor_analysis['recommendations'].extend([
                'CRITICAL: Replace NIST P-curve algorithms with Curve25519/Ed25519',
                'Avoid ECDH/ECDSA with NIST curves (P-256, P-384, P-521)',
                'Use independently developed cryptographic primitives',
                'Consider SafeCurves.cr.yp.to recommendations'
            ])
        
        # Trusted alternatives
        backdoor_analysis['trusted_alternatives'] = [
            'curve25519-sha256 (Key Exchange)',
            'ssh-ed25519 (Host Keys)', 
            'aes256-gcm@openssh.com (Encryption)',
            'chacha20-poly1305@openssh.com (Encryption)',
            'hmac-sha2-256-etm@openssh.com (MAC)'
        ]
        
        return backdoor_analysis


class ComplianceFramework:
    """SSH compliance framework definitions with NSA backdoor awareness"""
    
    FRAMEWORKS = {
        'PRIVACY_FOCUSED': {
            'name': 'Privacy-Focused Anti-Surveillance Framework',
            'required_ciphers': [
                'chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com'
            ],
            'forbidden_ciphers': [
                'des', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'arcfour', 'arcfour128', 'arcfour256',
                'aes128-cbc', 'aes192-cbc', 'aes256-cbc'
            ],
            'required_mac': [
                'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com'
            ],
            'forbidden_mac': [
                # Non-ETM (MAC-then-Encrypt, vulnerable to padding oracle attacks)
                'hmac-sha2-256', 'hmac-sha2-512', 'umac-128@openssh.com',
                # SHA-1 based (NSA involvement, collision attacks known)
                'hmac-sha1', 'hmac-sha1-96', 'hmac-sha1-etm@openssh.com', 'hmac-sha1-96-etm@openssh.com',
                # MD5 based (broken)
                'hmac-md5', 'hmac-md5-96', 'hmac-md5-etm@openssh.com', 'hmac-md5-96-etm@openssh.com',
                # 64-bit UMAC (tag too short)
                'umac-64', 'umac-64@openssh.com', 'umac-64-etm@openssh.com',
            ],
            'required_kex': [
                'curve25519-sha256', 'curve25519-sha256@libssh.org'
            ],
            'forbidden_kex': [
                'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1',
                # NSA-suspicious NIST curves
                'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521'
            ],
            'required_hostkey': [
                'ssh-ed25519'
            ],
            'forbidden_hostkey': [
                # DSA (broken)
                'ssh-dss', 'ssh-dss-cert-v01@openssh.com',
                # RSA (weak if < 2048 bit; cert chains not auditable)
                'ssh-rsa', 'ssh-rsa-cert-v01@openssh.com',
                # NSA NIST ECDSA — plain, cert, and FIDO/SK variants
                'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
                'ecdsa-sha2-nistp256-cert-v01@openssh.com',
                'ecdsa-sha2-nistp384-cert-v01@openssh.com',
                'ecdsa-sha2-nistp521-cert-v01@openssh.com',
                'sk-ecdsa-sha2-nistp256@openssh.com',
                'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com',
            ],
            'minimum_score': 95
        },
        
        'NIST': {
            'name': 'NIST SP 800-53 / IR 7966',
            'required_ciphers': [
                'aes256-ctr', 'aes128-ctr'
            ],
            'forbidden_ciphers': [
                'des', '3des-cbc', 'blowfish-cbc', 'cast128-cbc',
                'arcfour', 'arcfour128', 'arcfour256', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc'
            ],
            'required_mac': [
                'hmac-sha2-256', 'hmac-sha2-512'
            ],
            'forbidden_mac': [
                'hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96', 'umac-64'
            ],
            'required_kex': [
                'ecdh-sha2-nistp256'
            ],
            'forbidden_kex': [
                'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1'
            ],
            'required_hostkey': [
                'ecdsa-sha2-nistp256'
            ],
            'forbidden_hostkey': [
                'ssh-dss', 'ssh-rsa'
            ],
            'minimum_score': 80
        },
        
        'FIPS_140_2': {
            'name': 'FIPS 140-2 Level 1',
            'required_ciphers': [
                'aes256-ctr', 'aes192-ctr', 'aes128-ctr'
            ],
            'forbidden_ciphers': [
                'des', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'arcfour', 'arcfour128', 'arcfour256',
                # Not FIPS 140-2 approved
                'chacha20-poly1305@openssh.com',
            ],
            'required_mac': [
                'hmac-sha2-256', 'hmac-sha2-512'
            ],
            'forbidden_mac': [
                'hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96'
            ],
            'required_kex': [
                'ecdh-sha2-nistp256'
            ],
            'forbidden_kex': [
                'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                # Not FIPS 140-2 approved (Curve25519 / non-NIST curves)
                'curve25519-sha256', 'curve25519-sha256@libssh.org',
                'sntrup761x25519-sha512@openssh.com', 'sntrup761x25519-sha512',
                'mlkem768x25519-sha256',
            ],
            'required_hostkey': [
                'ecdsa-sha2-nistp256'
            ],
            'forbidden_hostkey': [
                'ssh-dss',
                'ssh-rsa',  # SHA-1 based signature
                # Not FIPS 140-2 approved (Ed25519 = Curve25519-based)
                'ssh-ed25519', 'ssh-ed25519-cert-v01@openssh.com',
                'sk-ssh-ed25519@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com',
            ],
            'minimum_score': 90
        },
        
        'BSI_TR_02102': {
            'name': 'BSI TR-02102-4 (German Federal Office)',
            'required_ciphers': [
                'aes256-gcm@openssh.com', 'aes256-ctr', 'chacha20-poly1305@openssh.com'
            ],
            'forbidden_ciphers': [
                'des', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'arcfour', 'arcfour128', 'arcfour256',
                'aes128-cbc', 'aes192-cbc', 'aes256-cbc'
            ],
            'required_mac': [
                'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com'
            ],
            'forbidden_mac': [
                'hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96', 'umac-64'
            ],
            'required_kex': [
                'curve25519-sha256', 'curve25519-sha256@libssh.org'
            ],
            'forbidden_kex': [
                'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1',
            ],
            'required_hostkey': [
                'ssh-ed25519'
            ],
            'forbidden_hostkey': [
                'ssh-dss', 'ssh-rsa', 'ecdsa-sha2-nistp256'
            ],
            'minimum_score': 85
        },
        
        'ANSSI': {
            'name': 'ANSSI (French National Cybersecurity Agency)',
            'required_ciphers': [
                'aes256-gcm@openssh.com', 'chacha20-poly1305@openssh.com'
            ],
            'forbidden_ciphers': [
                'des', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'arcfour', 'arcfour128', 'arcfour256',
                'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'aes128-ctr'
            ],
            'required_mac': [
                'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com'
            ],
            'forbidden_mac': [
                'hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96', 'umac-64', 'umac-128@openssh.com'
            ],
            'required_kex': [
                'curve25519-sha256', 'curve25519-sha256@libssh.org'
            ],
            'forbidden_kex': [
                'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1', 'ecdh-sha2-nistp256'
            ],
            'required_hostkey': [
                'ssh-ed25519'
            ],
            'forbidden_hostkey': [
                'ssh-dss', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'
            ],
            'minimum_score': 95
        }
    }
    
    @classmethod
    def check_compliance(cls, algorithms: Dict[str, List[SSHAlgorithmInfo]], framework: str,
                         security_score: int = None) -> Dict[str, bool]:
        """Check compliance against specified framework"""
        if framework not in cls.FRAMEWORKS:
            raise ValueError(f"Unknown framework: {framework}")
        
        fw = cls.FRAMEWORKS[framework]
        compliance_result = {}
        
        # Get supported algorithms by type
        supported_by_type = {}
        for algo_type, algo_list in algorithms.items():
            supported_by_type[algo_type] = [algo.name for algo in algo_list if algo.supported]
        
        # Map internal types to framework types
        type_mapping = {
            'cipher': 'ciphers',
            'mac': 'mac', 
            'kex': 'kex',
            'key': 'hostkey'
        }
        
        for internal_type, fw_type in type_mapping.items():
            if internal_type in supported_by_type:
                supported = set(supported_by_type[internal_type])
                
                # Check required algorithms
                required_key = f'required_{fw_type}'
                if required_key in fw:
                    required = set(fw[required_key])
                    has_required = required.issubset(supported)
                    compliance_result[f'{fw_type}_has_required'] = has_required
                
                # Check forbidden algorithms
                forbidden_key = f'forbidden_{fw_type}'
                if forbidden_key in fw:
                    forbidden = set(fw[forbidden_key])
                    has_forbidden = bool(forbidden & supported)
                    compliance_result[f'{fw_type}_has_forbidden'] = has_forbidden
        
        # Overall compliance (algorithm checks)
        algo_compliant = (
            all(v for k, v in compliance_result.items() if 'has_required' in k) and
            not any(v for k, v in compliance_result.items() if 'has_forbidden' in k)
        )

        # Minimum score check
        min_score = fw.get('minimum_score')
        if min_score is not None and security_score is not None:
            compliance_result['minimum_score_required'] = min_score
            score_ok = security_score >= min_score
            compliance_result['score_meets_minimum'] = score_ok
            compliance_result['overall_compliant'] = algo_compliant and score_ok
        else:
            compliance_result['overall_compliant'] = algo_compliant

        return compliance_result
    
    @classmethod
    def get_framework_list(cls) -> List[str]:
        """Get list of available frameworks"""
        return list(cls.FRAMEWORKS.keys())
    
    @classmethod
    def get_framework_info(cls, framework: str) -> Dict:
        """Get framework information"""
        return cls.FRAMEWORKS.get(framework, {})



class AlgorithmTester:
    """Handles algorithm testing with parallelization"""
    
    def __init__(self, test_function, max_workers: int = 5):
        self.test_function = test_function
        self.max_workers = max_workers
        logger.debug(f"Algorithm tester initialized with {max_workers} workers")
    
    def test_algorithms_parallel(self, host: str, port: int, algorithms: Dict[str, List[str]],
                                  line_callback=None) -> Dict[str, List[SSHAlgorithmInfo]]:
        """Test algorithms in parallel for a single host"""
        results = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_algo = {}

            for algo_type, algo_list in algorithms.items():
                results[algo_type] = []
                for algorithm in algo_list:
                    future = executor.submit(self.test_function, host, algorithm, algo_type, port)
                    future_to_algo[future] = (algo_type, algorithm)

            logger.debug(f"Submitted {len(future_to_algo)} algorithm tests for {host}:{port}")

            for future in as_completed(future_to_algo):
                algo_type, algorithm = future_to_algo[future]
                try:
                    is_supported = future.result()
                    results[algo_type].append(SSHAlgorithmInfo(
                        name=algorithm, type=algo_type, supported=is_supported
                    ))
                    if line_callback:
                        line_callback(algo_type, algorithm, is_supported)
                    logger.debug(f"Algorithm test completed: {algorithm} ({'supported' if is_supported else 'not supported'})")
                except Exception as e:
                    logger.error(f"Error testing {algorithm}: {e}")
                    results[algo_type].append(SSHAlgorithmInfo(
                        name=algorithm, type=algo_type, supported=False
                    ))

        return results


class SSHEnhancedScanner:
    """Enhanced SSH scanner with all advanced features"""

    WEAK_ALGORITHMS: Dict[str, List[str]] = {
        'cipher': [
            'des', '3des-cbc', 'blowfish-cbc', 'cast128-cbc',
            'arcfour', 'arcfour128', 'arcfour256',
            'aes128-cbc', 'aes192-cbc', 'aes256-cbc',
        ],
        'mac': [
            'hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96', 'umac-64',
            'hmac-md5-etm@openssh.com', 'hmac-md5-96-etm@openssh.com',
            'hmac-sha1-etm@openssh.com', 'hmac-sha1-96-etm@openssh.com',
            'umac-64@openssh.com', 'umac-64-etm@openssh.com',
        ],
        'kex': [
            'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
            'diffie-hellman-group-exchange-sha1',
        ],
        'key': [
            'ssh-dss', 'ssh-rsa',
            'ssh-dss-cert-v01@openssh.com', 'ssh-rsa-cert-v01@openssh.com',
        ],
    }

    # Comprehensive list of all known SSH algorithms (including those removed from
    # modern OpenSSH). This is the authoritative test set — not limited to what the
    # local ssh client reports via `ssh -Q`.
    KNOWN_ALGORITHMS: Dict[str, List[str]] = {
        'cipher': [
            # Modern / recommended
            'chacha20-poly1305@openssh.com',
            'aes256-gcm@openssh.com',
            'aes128-gcm@openssh.com',
            'aes256-ctr',
            'aes192-ctr',
            'aes128-ctr',
            # Weak CBC (still seen on legacy servers)
            'aes256-cbc',
            'aes192-cbc',
            'aes128-cbc',
            '3des-cbc',
            'blowfish-cbc',
            'cast128-cbc',
            # Broken legacy (removed from OpenSSH 8.5+)
            'arcfour256',
            'arcfour128',
            'arcfour',
            'des',
        ],
        'mac': [
            # Modern ETM (encrypt-then-MAC)
            'hmac-sha2-512-etm@openssh.com',
            'hmac-sha2-256-etm@openssh.com',
            'umac-128-etm@openssh.com',
            # Modern non-ETM
            'hmac-sha2-512',
            'hmac-sha2-256',
            'umac-128@openssh.com',
            # Weak
            'hmac-sha1',
            'hmac-sha1-etm@openssh.com',
            'umac-64-etm@openssh.com',
            'umac-64@openssh.com',
            'hmac-sha1-96',
            'hmac-md5',
            'hmac-md5-etm@openssh.com',
            'hmac-md5-96',
            'hmac-md5-96-etm@openssh.com',
        ],
        'kex': [
            # Modern / recommended (including post-quantum)
            'mlkem768x25519-sha256',
            'sntrup761x25519-sha512@openssh.com',
            'curve25519-sha256',
            'curve25519-sha256@libssh.org',
            'diffie-hellman-group18-sha512',
            'diffie-hellman-group16-sha512',
            'diffie-hellman-group14-sha256',
            'diffie-hellman-group-exchange-sha256',
            # NSA / NIST curves
            'ecdh-sha2-nistp521',
            'ecdh-sha2-nistp384',
            'ecdh-sha2-nistp256',
            # Weak / deprecated
            'diffie-hellman-group-exchange-sha1',
            'diffie-hellman-group14-sha1',
            'diffie-hellman-group1-sha1',
        ],
        'key': [
            # Modern / recommended
            'ssh-ed25519',
            'ssh-ed25519-cert-v01@openssh.com',
            'sk-ssh-ed25519@openssh.com',
            'sk-ssh-ed25519-cert-v01@openssh.com',
            'rsa-sha2-512',
            'rsa-sha2-256',
            'rsa-sha2-512-cert-v01@openssh.com',
            'rsa-sha2-256-cert-v01@openssh.com',
            # NSA / NIST curves
            'ecdsa-sha2-nistp256',
            'ecdsa-sha2-nistp384',
            'ecdsa-sha2-nistp521',
            'ecdsa-sha2-nistp256-cert-v01@openssh.com',
            'ecdsa-sha2-nistp384-cert-v01@openssh.com',
            'ecdsa-sha2-nistp521-cert-v01@openssh.com',
            'sk-ecdsa-sha2-nistp256@openssh.com',
            'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com',
            # Weak / deprecated
            'ssh-rsa',
            'ssh-rsa-cert-v01@openssh.com',
            'ssh-dss',
            'ssh-dss-cert-v01@openssh.com',
        ],
    }

    def __init__(self, config: Dict = None):
        """Initialize scanner with configuration"""
        logger.debug("Initializing SSH Enhanced Scanner")
        
        # Load and validate configuration
        if config is None:
            config = self._load_default_config()
        
        self.config = ConfigValidator.validate_config(config)
        
        # Extract validated settings
        scanner_config = self.config.get('scanner', {})
        self.timeout = scanner_config.get('timeout', 10)
        self.max_workers = scanner_config.get('threads', 20)
        self.retry_attempts = scanner_config.get('retry_attempts', 3)
        self.dns_cache_ttl = scanner_config.get('dns_cache_ttl', 300)

        # Initialize components
        self.dns_cache = EnhancedDNSCache(ttl=self.dns_cache_ttl)
        self.lock = threading.Lock()
        self.show_nsa_warnings: bool = True  # controls display only; analysis always runs

        # Compliance framework
        compliance_config = self.config.get('compliance', {})
        self.compliance_framework = compliance_config.get('framework', None)

        self._local_algorithms_cache: Optional[Dict[str, List[str]]] = None
        self.summary_only: bool = False
        self.spinner: Optional['Spinner'] = None
        self.filter_algo: Set[str] = set()   # e.g. {'supported', 'nsa'}
        self.filter_hosts: Set[str] = set()  # e.g. {'failed', 'error'}
        self._output_buffer: Dict[str, List[str]] = {}
        self.rate_limit: Optional[float] = scanner_config.get('rate_limit', None)
        self.banner_timeout: Optional[int] = scanner_config.get('banner_timeout', None)
        self.strict_host_key_checking: str = scanner_config.get('strict_host_key_checking', 'accept-new')
        self.use_color: bool = sys.stdout.isatty()  # auto-disabled when piped; override via --no-color
        self.show_hostnames: bool = False
        self._hostname_map: Dict[str, str] = {}   # resolved_ip → original_hostname
        self.jump_host: Optional[str] = scanner_config.get('jump_host', None)
        self.proxy_command: Optional[str] = scanner_config.get('proxy_command', None)
        self._proxy_map: Dict[str, ProxyConfig] = {}  # "host:port" → ProxyConfig

        logger.info(f"Initialized scanner with {self.max_workers} threads, "
                   f"DNS cache TTL={self.dns_cache_ttl}s")
    
    def _load_default_config(self) -> Dict:
        """Load configuration from default locations"""
        config_locations = [
            Path('sshscan.conf'),                            # local directory
            Path.home() / '.conf' / 'sshscan.conf',         # user config
            Path('/etc/sshscan/sshscan.conf'),               # system-wide
        ]

        for config_path in config_locations:
            if config_path.exists():
                try:
                    return load_config_file(str(config_path))
                except Exception as e:
                    logger.warning(f"Failed to load config from {config_path}: {e}")

        logger.info("No configuration file found, using defaults")
        return {}
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.dns_cache:
            self.dns_cache.stop()
    
    def parse_host_string(self, host_string: str, default_port: int = 22) -> Tuple[str, int]:
        """Parse host:port string with DNS caching and validation"""
        # Basic validation
        host_string = host_string.strip()
        if not host_string:
            raise ValidationError("Empty host string")
        
        logger.debug(f"Parsing host string: {host_string}")
        
        # Check for IPv6 format [::1]:22
        ipv6_match = re.match(r'^\[([^\]]+)\]:(\d+)$', host_string)
        if ipv6_match:
            host = ipv6_match.group(1)
            port = int(ipv6_match.group(2))
        else:
            # Standard host:port format
            if ':' in host_string and not validate_ip_address(host_string):
                host, port_str = host_string.rsplit(':', 1)
                try:
                    port = validate_port(port_str)
                except ValidationError:
                    # Not a valid port, treat whole string as hostname
                    host = host_string
                    port = default_port
            else:
                host = host_string
                port = default_port
        
        # Sanitize and validate host
        host = sanitize_host_input(host)
        port = validate_port(port)
        
        # Resolve hostname using DNS cache
        resolved_ip = self.dns_cache.resolve(host.strip())
        if resolved_ip:
            original = host.strip()
            if original != resolved_ip:
                self._hostname_map[resolved_ip] = original
            logger.debug(f"Parsed and resolved {host_string} -> {resolved_ip}:{port}")
            return resolved_ip, port
        else:
            logger.warning(f"DNS resolution failed for {host}, using hostname directly")
            return host.strip(), port
    
    def load_hosts_from_file(self, file_path: str, default_port: int = 22) -> List[Tuple[str, int]]:
        """Load hosts from various file formats with error handling and deduplication"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        logger.debug(f"Loading hosts from file: {file_path}")
        hosts = []
        seen_hosts = set()
        _skipped = 0
        
        try:
            if file_path.suffix.lower() == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                host_tuple = self.parse_host_string(item, default_port)
                                if host_tuple not in seen_hosts:
                                    hosts.append(host_tuple)
                                    seen_hosts.add(host_tuple)
                                else:
                                    _skipped += 1
                            elif isinstance(item, dict) and 'host' in item:
                                host = sanitize_host_input(item['host'])
                                port = validate_port(item.get('port', default_port))
                                resolved_ip = self.dns_cache.resolve(host)
                                if resolved_ip and resolved_ip != host:
                                    self._hostname_map[resolved_ip] = host
                                effective_host = resolved_ip or host
                                host_tuple = (effective_host, port)
                                if host_tuple not in seen_hosts:
                                    hosts.append(host_tuple)
                                    seen_hosts.add(host_tuple)
                                    via = item.get('via')
                                    if via:
                                        proxy = ProxyConfig.from_dict(via)
                                        if proxy:
                                            self._proxy_map[f"{effective_host}:{port}"] = proxy
                                else:
                                    _skipped += 1

            elif file_path.suffix.lower() in ['.yml', '.yaml']:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                host_tuple = self.parse_host_string(item, default_port)
                                if host_tuple not in seen_hosts:
                                    hosts.append(host_tuple)
                                    seen_hosts.add(host_tuple)
                                else:
                                    _skipped += 1
                            elif isinstance(item, dict) and 'host' in item:
                                host = sanitize_host_input(item['host'])
                                port = validate_port(item.get('port', default_port))
                                resolved_ip = self.dns_cache.resolve(host)
                                if resolved_ip and resolved_ip != host:
                                    self._hostname_map[resolved_ip] = host
                                effective_host = resolved_ip or host
                                host_tuple = (effective_host, port)
                                if host_tuple not in seen_hosts:
                                    hosts.append(host_tuple)
                                    seen_hosts.add(host_tuple)
                                    via = item.get('via')
                                    if via:
                                        proxy = ProxyConfig.from_dict(via)
                                        if proxy:
                                            self._proxy_map[f"{effective_host}:{port}"] = proxy
                                else:
                                    _skipped += 1

            elif file_path.suffix.lower() == '.csv':
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if row and not row[0].startswith('#'):
                            if len(row) >= 2:
                                try:
                                    host = sanitize_host_input(row[0].strip())
                                    port = validate_port(row[1].strip())
                                    resolved_ip = self.dns_cache.resolve(host)
                                    if resolved_ip and resolved_ip != host:
                                        self._hostname_map[resolved_ip] = host
                                    effective_host = resolved_ip or host
                                    host_tuple = (effective_host, port)
                                    if host_tuple not in seen_hosts:
                                        hosts.append(host_tuple)
                                        seen_hosts.add(host_tuple)
                                        # Optional per-host proxy columns:
                                        # col2=via_type, col3=via_host, col4=via_port, col5=via_user
                                        if len(row) >= 4 and row[2].strip() and row[3].strip():
                                            via_dict = {
                                                'type': row[2].strip(),
                                                'host': row[3].strip(),
                                            }
                                            if len(row) >= 5 and row[4].strip():
                                                via_dict['port'] = row[4].strip()
                                            if len(row) >= 6 and row[5].strip():
                                                via_dict['user'] = row[5].strip()
                                            proxy = ProxyConfig.from_dict(via_dict)
                                            if proxy:
                                                self._proxy_map[f"{effective_host}:{port}"] = proxy
                                except (ValueError, ValidationError) as e:
                                    logger.warning(f"Invalid entry in CSV: {row} - {e}")
                            else:
                                host_tuple = self.parse_host_string(row[0], default_port)
                                if host_tuple not in seen_hosts:
                                    hosts.append(host_tuple)
                                    seen_hosts.add(host_tuple)
                                else:
                                    _skipped += 1
            
            else:  # .txt or other text files
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                host_tuple = self.parse_host_string(line, default_port)
                                if host_tuple not in seen_hosts:
                                    hosts.append(host_tuple)
                                    seen_hosts.add(host_tuple)
                                else:
                                    _skipped += 1
                            except ValidationError as e:
                                logger.warning(f"Line {line_num}: Invalid host entry '{line}' - {e}")
        
        except Exception as e:
            raise ValueError(f"Error parsing file {file_path}: {e}")
        
        logger.info(f"Loaded {len(hosts)} unique hosts from {file_path}")
        if _skipped > 0:
            logger.info(f"Skipped {_skipped} duplicate entries")
        
        return hosts
    
    @retry_on_failure(max_attempts=3, backoff_factor=1.5)
    def get_local_ssh_algorithms(self) -> Dict[str, List[str]]:
        """Return the full set of algorithms to test.

        Uses KNOWN_ALGORITHMS as the authoritative base (covers legacy algorithms
        removed from modern OpenSSH). Any additional algorithms reported by the
        local client via `ssh -Q` that are not already in the list are appended.
        """
        if self._local_algorithms_cache is not None:
            return self._local_algorithms_cache

        if not shutil.which('ssh'):
            raise SSHScannerError("SSH client not found. Please install OpenSSH.")

        logger.debug("Building algorithm test list from KNOWN_ALGORITHMS + ssh -Q")

        results: Dict[str, List[str]] = {}
        for algo_type, known_list in self.KNOWN_ALGORITHMS.items():
            # Start with the comprehensive hardcoded list
            combined: List[str] = list(known_list)
            known_set: set = set(known_list)

            # Supplement with anything the local client knows that we don't
            try:
                proc = subprocess.run(
                    ['ssh', '-Q', algo_type],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=True,
                )
                for line in proc.stdout.split('\n'):
                    algo = line.strip()
                    if algo and algo not in known_set:
                        combined.append(algo)
                        known_set.add(algo)
                        logger.debug(f"ssh -Q added unknown {algo_type}: {algo}")
            except subprocess.CalledProcessError as e:
                logger.warning(f"ssh -Q {algo_type} failed: {e}")
            except subprocess.TimeoutExpired:
                logger.warning(f"ssh -Q {algo_type} timed out")
            except FileNotFoundError:
                raise SSHScannerError("SSH client not found")

            results[algo_type] = combined
            logger.debug(f"{algo_type}: {len(combined)} algorithms to test")

        self._local_algorithms_cache = results
        return results
    
    def _proxy_args_for(self, host: str, port: int) -> List[str]:
        """Return SSH args that route through the proxy for this host.

        Priority: per-host entry in _proxy_map → global jump_host → global proxy_command → no proxy.
        """
        proxy = self._proxy_map.get(f"{host}:{port}")
        if proxy:
            return proxy.to_ssh_args()
        if self.jump_host:
            return ['-J', self.jump_host]
        if self.proxy_command:
            return ['-o', f'ProxyCommand={self.proxy_command}']
        return []

    def _scan_banner_via_ssh(self, host: str, port: int, proxy_args: List[str],
                             timeout: int) -> Optional[str]:
        """Grab the SSH banner through a proxy/jump-host via the SSH binary.

        Uses LogLevel=VERBOSE and parses the 'Remote protocol version' debug line.
        Falls back to None if the line is not found.
        """
        cmd = [
            'ssh',
            '-o', 'BatchMode=yes',
            '-o', f'ConnectTimeout={timeout}',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=VERBOSE',
            '-o', 'PreferredAuthentications=none',
            '-p', str(port),
        ] + proxy_args + [host, 'exit']
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout + 2, check=False,
            )
            for line in result.stderr.split('\n'):
                m = re.search(r'remote software version (.+)', line, re.IGNORECASE)
                if m:
                    version = m.group(1).strip()
                    return f"SSH-2.0-{version}"
        except Exception as e:
            logger.debug(f"Banner via SSH failed for {host}:{port}: {e}")
        return None

    @retry_on_failure(max_attempts=2, backoff_factor=1.0)
    def test_algorithm_connection(self, host: str, algorithm: str, algo_type: str, port: int = 22) -> bool:
        """Test whether a remote SSH server supports a specific algorithm.

        Always uses a fresh SSH connection — never a multiplexed one.
        Multiplexed slaves reuse the master's already-negotiated session and
        completely ignore Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms options,
        which would cause false positives for every algorithm the local client
        supports regardless of what the server actually accepts.
        """
        logger.debug(f"Testing {algorithm} ({algo_type}) on {host}:{port}")
        ssh_options = {
            'cipher': f'Ciphers={algorithm}',
            'mac': f'MACs={algorithm}',
            'kex': f'KexAlgorithms={algorithm}',
            'key': f'HostKeyAlgorithms={algorithm}'
        }
        
        if algo_type not in ssh_options:
            return False
        
        # Validate inputs
        host = sanitize_host_input(host)
        port = validate_port(port)
        
        cmd = [
            'ssh',
            '-o', 'BatchMode=yes',
            '-o', f'ConnectTimeout={self.timeout}',
            '-o', f'StrictHostKeyChecking={self.strict_host_key_checking}',
            '-o', ssh_options[algo_type],
            '-o', 'PreferredAuthentications=none',
            '-o', 'LogLevel=ERROR',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-p', str(port),
        ] + self._proxy_args_for(host, port) + [
            host,
            'exit'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
                check=False
            )
            
            stderr_lower = result.stderr.lower()
            rejection_patterns = [
                # Server-side negotiation failures
                b'no matching cipher found',
                b'no matching mac found',
                b'no matching key exchange method found',
                b'no matching host key type found',
                b'no mutual signature algorithm',
                # Client-side: local ssh doesn't support this algorithm
                # (e.g. arcfour removed in OpenSSH 8.5+, blowfish in 7.6+)
                b'bad ssh2 cipher spec',
                b'bad ssh2 mac spec',
                b'bad ssh2 kex spec',
                b'unknown cipher type',
                b'unknown mac type',
                b'unknown key type',
                b'unsupported cipher',
            ]
            
            supported = not any(pattern in stderr_lower for pattern in rejection_patterns)
            logger.debug(f"Algorithm {algorithm} test result: {'supported' if supported else 'not supported'}")
            return supported
            
        except subprocess.TimeoutExpired:
            logger.debug(f"Timeout testing {algorithm} on {host}:{port}")
            return False
        except Exception as e:
            logger.error(f"Error testing {algorithm} on {host}:{port}: {e}")
            return False
    
    @retry_on_failure(max_attempts=2, backoff_factor=1.0)
    def scan_ssh_banner(self, host: str, port: int = 22, timeout: int = None) -> Optional[str]:
        """Get SSH banner with retry logic and configurable timeout.

        When a proxy or jump-host is configured for this host the banner is fetched
        via the SSH binary (LogLevel=VERBOSE) instead of a raw socket, because raw
        sockets cannot traverse jump-hosts or SOCKS/HTTP proxies without additional
        libraries.
        """
        if timeout is None:
            timeout = self.banner_timeout if self.banner_timeout is not None else min(self.timeout, 5)

        proxy_args = self._proxy_args_for(host, port)
        if proxy_args:
            logger.debug(f"Scanning SSH banner for {host}:{port} via proxy")
            return self._scan_banner_via_ssh(host, port, proxy_args, timeout)

        logger.debug(f"Scanning SSH banner for {host}:{port}")

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                banner_raw = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                # Sanitize: strip control/non-printable chars, truncate
                banner = ''.join(c for c in banner_raw if c.isprintable() or c == ' ')[:256]
                logger.debug(f"Banner received from {host}:{port}: {banner[:50]}...")
                return banner
        except (socket.error, socket.timeout) as e:
            logger.debug(f"Failed to get banner from {host}:{port}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting banner from {host}:{port}: {e}")
            return None
    
    def _host_passes_filter(self, result: SSHHostResult) -> bool:
        """Return True if this host result matches the active host filter tokens."""
        if not self.filter_hosts:
            return True
        for token in self.filter_hosts:
            if token == 'error' and result.status != 'success':
                return True
            if token == 'passed' and result.status == 'success':
                if not self.compliance_framework or result.compliance_status.get('overall_compliant', True):
                    return True
            if token == 'failed' and result.status == 'success':
                if self.compliance_framework and not result.compliance_status.get('overall_compliant', True):
                    return True
        return False

    def scan_single_host(self, host: str, port: int, explicit_algorithms: List[str] = None) -> SSHHostResult:
        """Scan single host with live per-algorithm output"""
        start_time = time.time()
        original_name = self._hostname_map.get(host, '')
        result = SSHHostResult(host=host, port=port, hostname=original_name)
        if self.show_hostnames and original_name:
            host_label = f"{original_name}:{port}"
        else:
            host_label = f"{host}:{port}"

        _algo_labels = {
            'cipher': 'Cipher',
            'mac': 'MAC',
            'kex': 'KEX',
            'key': 'HostKey',
            'explicit': 'Algorithm',
        }

        use_buffer = bool(self.filter_hosts) and not self.summary_only

        # Pre-compute filter components once so on_algorithm doesn't recompute per call
        _F_TYPE_MAP = {'cipher': 'cipher', 'mac': 'mac', 'kex': 'kex', 'hostkey': 'key'}
        _f_types = {_F_TYPE_MAP[t] for t in self.filter_algo if t in _F_TYPE_MAP}
        _f_cats  = self.filter_algo & {'supported', 'unsupported', 'flagged', 'weak', 'nsa'}
        # 'banner' or 'security' with no type/category tokens → suppress all algo detail lines
        _suppress_algos = bool(self.filter_algo) and not _f_types and not _f_cats

        def _emit(line: str) -> None:
            """Print line directly or buffer it when host-level filtering is active."""
            with self.lock:
                if use_buffer:
                    self._output_buffer.setdefault(host_label, []).append(line)
                else:
                    print(line)

        def on_algorithm(algo_type: str, algo_name: str, is_supported: bool) -> None:
            if self.summary_only:
                return
            label = _algo_labels.get(algo_type, algo_type.capitalize())
            nsa_info = (NSABackdoorDetector.SUSPECTED_NSA_ALGORITHMS.get(algo_type, {}).get(algo_name)
                        if self.show_nsa_warnings else None)
            is_weak = algo_name in SSHEnhancedScanner.WEAK_ALGORITHMS.get(algo_type, [])

            # Classify for filtering
            if not is_supported:
                category = 'unsupported'
            elif nsa_info:
                category = 'nsa'
            elif is_weak:
                category = 'weak'
            else:
                category = 'supported'

            # Apply algo filter (empty = show all)
            if self.filter_algo:
                # 'banner' / 'security' without any type or category token → suppress all algo lines
                if _suppress_algos:
                    return
                # Type filter: cipher / mac / kex / hostkey
                if _f_types and algo_type not in _f_types:
                    return
                # Category filter: supported / unsupported / flagged / weak / nsa
                if _f_cats:
                    show = (
                        ('supported' in _f_cats and category == 'supported') or
                        ('unsupported' in _f_cats and category == 'unsupported') or
                        ('flagged' in _f_cats and category in ('nsa', 'weak')) or
                        ('weak' in _f_cats and category == 'weak') or
                        ('nsa' in _f_cats and category == 'nsa')
                    )
                    if not show:
                        return

            # Build line
            if not is_supported:
                line = f"[-] Host: {host_label}  {label}: {algo_name}"
            elif nsa_info:
                risk = nsa_info.get('risk', '').upper()
                if risk in ('HIGH', 'CRITICAL'):
                    line = f"[!] Host: {host_label}  {label}: {algo_name}  (NSA high risk)"
                elif risk == 'MEDIUM':
                    line = f"[!] Host: {host_label}  {label}: {algo_name}  (NSA medium risk)"
                else:
                    line = f"[x] Host: {host_label}  {label}: {algo_name}"
            elif is_weak:
                line = f"[!] Host: {host_label}  {label}: {algo_name}  (weak)"
            else:
                line = f"[x] Host: {host_label}  {label}: {algo_name}"

            # Apply color based on category
            if self.use_color:
                if category == 'unsupported':
                    line = _colorize(line, _C_DIM, True)
                elif category == 'nsa':
                    nsa_color = _C_RED if nsa_info.get('risk', '').upper() in ('HIGH', 'CRITICAL') else _C_YELLOW
                    line = _colorize(line, nsa_color, True)
                elif category == 'weak':
                    line = _colorize(line, _C_YELLOW, True)
                else:  # supported
                    line = _colorize(line, _C_GREEN, True)

            _emit(line)

        logger.debug(f"Starting scan of {host}:{port}")

        try:
            result.ssh_banner = self.scan_ssh_banner(host, port) or ""

            if not result.ssh_banner:
                result.status = "failed"
                result.error_type = "connection"
                result.error_message = "Unable to connect to SSH service"
                logger.debug(f"No SSH banner received from {host}:{port}")
            else:
                if not self.summary_only:
                    _emit(_colorize(f"[x] Host: {host_label}  Banner: {result.ssh_banner}", _C_CYAN, self.use_color))

                if explicit_algorithms:
                    explicit_results = self.test_explicit_algorithms(host, port, explicit_algorithms)
                    for algo, (algo_type, supported) in explicit_results.items():
                        if algo_type not in result.algorithms:
                            result.algorithms[algo_type] = []
                        result.algorithms[algo_type].append(
                            SSHAlgorithmInfo(name=algo, type=algo_type, supported=supported)
                        )
                        on_algorithm(algo_type, algo, supported)
                    total_tested = len(explicit_results)
                    supported_count = sum(1 for _, s in explicit_results.values() if s)
                    result.security_score = (supported_count * 100 // total_tested) if total_tested > 0 else 0
                else:
                    if self.max_workers > 1:
                        result.algorithms = self.scan_all_algorithms_parallel(host, port, line_callback=on_algorithm)
                    else:
                        result.algorithms = self.scan_all_algorithms(host, port, line_callback=on_algorithm)

                    result.security_score = self.calculate_security_score(result.algorithms)

                    result.nsa_backdoor_analysis = NSABackdoorDetector.check_nsa_backdoor_risk(
                        result.algorithms, check_enabled=True
                    )

                    if self.compliance_framework:
                        result.compliance_status = ComplianceFramework.check_compliance(
                            result.algorithms, self.compliance_framework,
                            security_score=result.security_score
                        )

                result.status = "success"
                logger.debug(f"Successfully scanned {host}:{port} - Score: {result.security_score}")

        except ValidationError as e:
            result.status = "failed"
            result.error_type = "validation"
            result.error_message = str(e)
            logger.error(f"Validation error for {host}:{port}: {e}")
        except SSHConnectionError as e:
            result.status = "failed"
            result.error_type = "connection"
            result.error_message = str(e)
            logger.error(f"Connection error for {host}:{port}: {e}")
        except Exception as e:
            result.status = "failed"
            result.error_type = "unknown"
            result.error_message = str(e)
            logger.error(f"Unexpected error scanning {host}:{port}: {e}", exc_info=True)

        result.scan_time = time.time() - start_time

        if not self.summary_only:
            if result.status == 'success':
                _emit(_colorize(f"[x] Host: {host_label}  Security Score: {result.security_score}/100", _C_GREEN, self.use_color))
                if result.compliance_status and 'overall_compliant' in result.compliance_status:
                    fw = self.compliance_framework or 'N/A'
                    compliant = result.compliance_status['overall_compliant']
                    status_str = "PASS" if compliant else "FAIL"
                    cpl_color = _C_GREEN if compliant else _C_RED
                    _emit(_colorize(f"[x] Host: {host_label}  Compliance {fw}: {status_str}", cpl_color, self.use_color))
            else:
                err = f" ({result.error_type})" if result.error_type else ""
                _emit(_colorize(f"[x] Host: {host_label}  Status: failed{err}", _C_RED, self.use_color))
                if result.error_message:
                    _emit(_colorize(f"[x] Host: {host_label}  Error: {result.error_message}", _C_RED, self.use_color))
            _emit(_colorize(f"[x] Host: {host_label}  Scanned in: {result.scan_time:.1f}s", _C_DIM, self.use_color))

            # If host-level filtering is active: flush buffer for matching hosts, discard the rest
            if use_buffer:
                lines = self._output_buffer.pop(host_label, [])
                if self._host_passes_filter(result):
                    with self.lock:
                        for line in lines:
                            print(line)

        logger.debug(f"Scan of {host}:{port} completed in {result.scan_time:.2f}s")
        return result
    
    def test_explicit_algorithms(self, host: str, port: int, algorithms: List[str]) -> Dict[str, Tuple[str, bool]]:
        """Test explicit algorithms. Returns {algo_name: (algo_type, supported)}."""
        results = {}
        local_algorithms = self.get_local_ssh_algorithms()

        logger.debug(f"Testing {len(algorithms)} explicit algorithms on {host}:{port}")

        algo_type_map = {}
        for algo_type, algo_list in local_algorithms.items():
            for algo in algo_list:
                algo_type_map[algo] = algo_type

        for algorithm in algorithms:
            algorithm = algorithm.strip()
            if algorithm in algo_type_map:
                algo_type = algo_type_map[algorithm]
                supported = self.test_algorithm_connection(host, algorithm, algo_type, port)
                results[algorithm] = (algo_type, supported)
            else:
                # Unknown algorithm — try all types
                found_type = None
                for algo_type in ['cipher', 'mac', 'kex', 'key']:
                    if self.test_algorithm_connection(host, algorithm, algo_type, port):
                        found_type = algo_type
                        break
                results[algorithm] = (found_type or 'unknown', found_type is not None)

        return results
    
    def scan_all_algorithms(self, host: str, port: int, line_callback=None) -> Dict[str, List[SSHAlgorithmInfo]]:
        """Scan all algorithms sequentially, calling line_callback immediately for each supported one"""
        local_algorithms = self.get_local_ssh_algorithms()
        results = {}

        logger.debug(f"Scanning all algorithms for {host}:{port}")

        algo_type_map = {
            'cipher': 'encryption',
            'mac': 'mac',
            'kex': 'key_exchange',
            'key': 'host_key'
        }

        for algo_type, algo_list in local_algorithms.items():
            if not algo_list:
                continue
            supported_algorithms = []
            for algorithm in algo_list:
                is_supported = self.test_algorithm_connection(host, algorithm, algo_type, port)
                supported_algorithms.append(SSHAlgorithmInfo(
                    name=algorithm,
                    type=algo_type_map.get(algo_type, algo_type),
                    supported=is_supported
                ))
                if line_callback:
                    line_callback(algo_type, algorithm, is_supported)
            results[algo_type] = supported_algorithms

        return results

    def scan_all_algorithms_parallel(self, host: str, port: int, line_callback=None) -> Dict[str, List[SSHAlgorithmInfo]]:
        """Scan all algorithms in parallel, calling line_callback as each supported one is confirmed"""
        local_algorithms = self.get_local_ssh_algorithms()

        logger.debug(f"Scanning all algorithms for {host}:{port} in parallel")

        tester = AlgorithmTester(
            test_function=self.test_algorithm_connection,
            max_workers=min(3, self.max_workers)
        )

        return tester.test_algorithms_parallel(host, port, local_algorithms, line_callback=line_callback)
    
    def calculate_security_score(self, algorithms: Dict[str, List[SSHAlgorithmInfo]]) -> int:
        """Calculate security score based on supported algorithms including NSA backdoor risks"""
        total_supported = 0
        weak_count = 0
        nsa_risk_count = 0

        for algo_type, algo_list in algorithms.items():
            for algo in algo_list:
                if algo.supported:
                    total_supported += 1

                    # Check for traditional weak algorithms
                    if algo.name in self.WEAK_ALGORITHMS.get(algo_type, []):
                        weak_count += 1

                    # Check for NSA-suspicious algorithms (double penalty)
                    if algo.name in NSABackdoorDetector.SUSPECTED_NSA_ALGORITHMS.get(algo_type, {}):
                        nsa_risk_count += 1
        
        if total_supported == 0:
            return 0
        
        # Calculate score with NSA risk penalty
        weak_penalty = (weak_count * 100 // total_supported)
        nsa_penalty = (nsa_risk_count * 150 // total_supported)  # 1.5x penalty for NSA risk
        
        final_score = max(0, 100 - weak_penalty - nsa_penalty)
        logger.debug(f"Security score calculated: {final_score} (weak_penalty={weak_penalty}, nsa_penalty={nsa_penalty})")
        return final_score
    
    def batch_scan(self, hosts: List[Tuple[str, int]], explicit_algorithms: List[str] = None, 
                   resume_state: Tuple[List, List] = None) -> List[SSHHostResult]:
        """Enhanced batch scanning with improved error handling and debugging"""
        logger.debug(f"Starting batch_scan with {len(hosts) if hosts else 0} hosts")
        
        if resume_state:
            pending_hosts, completed_results = resume_state
            logger.info(f"Resuming scan with {len(pending_hosts)} pending hosts and {len(completed_results)} completed")
        else:
            pending_hosts = hosts.copy()
            completed_results = []
        
        # Track completion for resume functionality
        completed_hosts = {(r.host, r.port) for r in completed_results}
        pending_list = [h for h in pending_hosts if h not in completed_hosts]
        
        logger.debug(f"Total hosts to process: {len(pending_list)}")
        logger.debug(f"Max workers: {self.max_workers}")
        
        if not pending_list:
            logger.warning("No pending hosts to scan")
            return completed_results
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks at once
            future_to_host = {}
            
            _submit_interval = (1.0 / self.rate_limit) if self.rate_limit else 0.0
            for i, (host, port) in enumerate(pending_list):
                if _submit_interval and i > 0:
                    time.sleep(_submit_interval)
                logger.debug(f"Submitting scan task {i+1}/{len(pending_list)}: {host}:{port}")
                future = executor.submit(self.scan_single_host, host, port, explicit_algorithms)
                future_to_host[future] = (host, port)
            
            logger.debug(f"Submitted {len(future_to_host)} scan tasks")
            
            # Process completed futures
            try:
                for future in as_completed(future_to_host):
                    host, port = future_to_host[future]
                    logger.debug(f"Processing completed future for {host}:{port}")
                    
                    try:
                        result = future.result()
                        completed_results.append(result)
                        completed_hosts.add((host, port))
                        if self.spinner:
                            self.spinner.update(len(completed_results))
                        logger.debug(f"Processed {host}:{port} - Status: {result.status}, Score: {result.security_score}")

                    except Exception as e:
                        logger.error(f"Error processing result for {host}:{port}: {e}", exc_info=True)
                        error_result = SSHHostResult(
                            host=host, port=port, status="error",
                            error_message=str(e), error_type="processing"
                        )
                        completed_results.append(error_result)
                        show = (not self.summary_only and
                                (not self.filter_hosts or 'error' in self.filter_hosts))
                        if show:
                            with self.lock:
                                print(_colorize(f"[x] Host: {host}:{port}  Status: error (processing)", _C_RED, self.use_color))
                                print(_colorize(f"[x] Host: {host}:{port}  Error: {e}", _C_RED, self.use_color))
            
            except Exception as e:
                logger.error(f"Error in batch scan executor loop: {e}", exc_info=True)
                # Ensure we don't lose progress
                for future, (host, port) in future_to_host.items():
                    if not future.done():
                        logger.warning(f"Cancelling incomplete future for {host}:{port}")
                        future.cancel()
        
        logger.info(f"Batch scan completed: {len(completed_results)} total results")
        return sorted(completed_results, key=lambda x: (x.host, x.port))
    
    def export_results(self, results: List[SSHHostResult], format_type: str = 'json') -> str:
        """Enhanced export with compliance data and proper formatting"""
        if format_type.lower() == 'json':
            json_data = []
            for result in results:
                # Convert to dict and ensure proper serialization
                result_dict = result.to_dict()
                json_data.append(result_dict)
            return json.dumps(json_data, indent=2, default=str)
        
        elif format_type.lower() == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write headers
            headers = ['Host', 'Port', 'Status', 'Security_Score', 'Compliance_Status']
            
            if self.show_nsa_warnings:
                headers.extend(['NSA_Risk_Level', 'NSA_High_Risk_Count'])
            
            headers.extend(['SSH_Banner', 'Scan_Time', 'Error_Type', 'Error_Message', 'Supported_Algorithms'])
            writer.writerow(headers)
            
            for result in results:
                supported_algos = []
                if result.algorithms:
                    for algo_type, algo_list in result.algorithms.items():
                        for algo in algo_list:
                            if algo.supported:
                                supported_algos.append(f"{algo.name}({algo.type})")
                
                compliance_status = "N/A"
                if result.compliance_status and 'overall_compliant' in result.compliance_status:
                    compliance_status = "PASS" if result.compliance_status['overall_compliant'] else "FAIL"
                
                row = [
                    result.host,
                    result.port,
                    result.status,
                    result.security_score,
                    compliance_status
                ]
                
                # NSA risk information
                if self.show_nsa_warnings:
                    nsa_risk_level = "UNKNOWN"
                    nsa_high_risk_count = 0
                    if result.nsa_backdoor_analysis and 'enabled' in result.nsa_backdoor_analysis:
                        if result.nsa_backdoor_analysis['enabled']:
                            high_risk_algorithms = result.nsa_backdoor_analysis.get('high_risk_algorithms', [])
                            nsa_high_risk_count = len(high_risk_algorithms)
                            
                            if nsa_high_risk_count > 0:
                                nsa_risk_level = "HIGH"
                            elif len(result.nsa_backdoor_analysis.get('medium_risk_algorithms', [])) > 0:
                                nsa_risk_level = "MEDIUM"
                            else:
                                nsa_risk_level = "LOW"
                    row.extend([nsa_risk_level, nsa_high_risk_count])
                
                row.extend([
                    result.ssh_banner,
                    f"{result.scan_time:.2f}",
                    result.error_type or "",
                    result.error_message or "",
                    "; ".join(supported_algos)
                ])
                
                writer.writerow(row)
            
            return output.getvalue()
        
        elif format_type.lower() == 'yaml':
            yaml_data = []
            for result in results:
                result_dict = result.to_dict()
                yaml_data.append(result_dict)
            return yaml.dump(yaml_data, default_flow_style=False, sort_keys=False)

        return ""
    


def load_config_file(config_path: str) -> Dict:
    """Load configuration from INI/conf file with validation"""
    config_file = Path(config_path)
    if not config_file.exists():
        logger.warning(f"Config file not found: {config_path}")
        return {}
    try:
        logger.info(f"Loading configuration from {config_path}")
        parser = configparser.ConfigParser(inline_comment_prefixes=('#',))
        parser.read(config_file, encoding='utf-8')
        config = {section: dict(parser.items(section)) for section in parser.sections()}
        return ConfigValidator.validate_config(config)
    except configparser.Error as e:
        logger.error(f"Invalid config syntax in {config_path}: {e}")
        raise ConfigurationError(f"Failed to parse configuration: {e}")
    except Exception as e:
        logger.error(f"Error loading config file {config_path}: {e}")
        raise ConfigurationError(f"Failed to load configuration: {e}")


def print_summary_report(results: List[SSHHostResult], scanner: SSHEnhancedScanner, total_time: float):
    """Print comprehensive summary report"""
    c = scanner.use_color
    sep = "=" * 80

    def _label(r: SSHHostResult) -> str:
        """Return display label: hostname:port when show_hostnames is on and name is known."""
        if scanner.show_hostnames and r.hostname:
            return f"{r.hostname}:{r.port}"
        return f"{r.host}:{r.port}"

    def _section(title: str, title_code: str = _C_BOLD) -> None:
        print(f"\n{_colorize(sep, _C_BOLD, c)}")
        print(_colorize(title, title_code, c))
        print(_colorize(sep, _C_BOLD, c))

    successful_scans = sum(1 for r in results if r.status == "success")
    failed_scans = len(results) - successful_scans
    avg_score = sum(r.security_score for r in results if r.status == "success") / max(successful_scans, 1)

    _section("SUMMARY")
    print(f"Total hosts scanned: {_colorize(str(len(results)), _C_BOLD, c)}")
    print(f"Successful scans:    {_colorize(str(successful_scans), _C_GREEN if successful_scans else _C_DIM, c)}")
    print(f"Failed scans:        {_colorize(str(failed_scans), _C_RED if failed_scans else _C_DIM, c)}")

    if failed_scans > 0:
        # Break down failures by type
        error_types = {}
        for r in results:
            if r.status != "success" and r.error_type:
                error_types[r.error_type] = error_types.get(r.error_type, 0) + 1

        print(_colorize("\nFailure breakdown:", _C_RED, c))
        for error_type, count in sorted(error_types.items()):
            print(_colorize(f"  {error_type}: {count}", _C_RED, c))

        print(_colorize("\nFailed hosts:", _C_RED, c))
        for r in results:
            if r.status != 'success':
                err = f"  ({r.error_type})" if r.error_type else ""
                print(_colorize(f"  {_label(r)}{err}", _C_RED, c))

    # Score: green ≥80, yellow ≥50, red <50
    score_color = _C_GREEN if avg_score >= 80 else (_C_YELLOW if avg_score >= 50 else _C_RED)
    print(f"\nAverage security score: {_colorize(f'{avg_score:.1f}/100', score_color, c)}")
    print(f"Total scan time:        {total_time:.1f}s")
    print(f"Average time per host:  {total_time / len(results):.1f}s")

    # Compliance summary
    if scanner.compliance_framework and successful_scans > 0:
        compliant_hosts = sum(1 for r in results
                              if r.compliance_status and r.compliance_status.get('overall_compliant', False))
        compliance_rate = (compliant_hosts / successful_scans) * 100
        cpl_color = _C_GREEN if compliance_rate == 100 else (_C_YELLOW if compliance_rate > 0 else _C_RED)
        print(f"\nCompliance ({scanner.compliance_framework}):")
        print(f"  Compliant hosts: {_colorize(f'{compliant_hosts}/{successful_scans} ({compliance_rate:.1f}%)', cpl_color, c)}")

        failed_compliance = [r for r in results
                             if r.status == 'success' and r.compliance_status
                             and not r.compliance_status.get('overall_compliant', True)]
        if failed_compliance:
            print(_colorize("  Non-compliant hosts:", _C_RED, c))
            for r in failed_compliance:
                print(_colorize(f"    {_label(r)}", _C_RED, c))

    # NSA backdoor analysis summary
    if scanner.show_nsa_warnings and any(r.nsa_backdoor_analysis for r in results):
        _section("NSA BACKDOOR RISK ANALYSIS", '\033[1;31m')  # bold red

        total_high_risk = 0
        total_medium_risk = 0
        affected_hosts = 0

        for result in results:
            if result.nsa_backdoor_analysis and 'enabled' in result.nsa_backdoor_analysis:
                if result.nsa_backdoor_analysis['enabled']:
                    high_risk_count = len(result.nsa_backdoor_analysis.get('high_risk_algorithms', []))
                    medium_risk_count = len(result.nsa_backdoor_analysis.get('medium_risk_algorithms', []))

                    if high_risk_count > 0 or medium_risk_count > 0:
                        affected_hosts += 1
                        total_high_risk += high_risk_count
                        total_medium_risk += medium_risk_count

        aff_color = _C_RED if affected_hosts > 0 else _C_GREEN
        print(f"Hosts with NSA backdoor risks: {_colorize(f'{affected_hosts}/{successful_scans}', aff_color, c)}")
        print(f"Total high-risk algorithms:    {_colorize(str(total_high_risk), _C_RED if total_high_risk else _C_DIM, c)}")
        print(f"Total medium-risk algorithms:  {_colorize(str(total_medium_risk), _C_YELLOW if total_medium_risk else _C_DIM, c)}")

        if affected_hosts > 0:
            print(_colorize("\nAffected hosts:", '\033[1;31m', c))
            for r in results:
                if not (r.nsa_backdoor_analysis and r.nsa_backdoor_analysis.get('enabled')):
                    continue
                h = len(r.nsa_backdoor_analysis.get('high_risk_algorithms', []))
                m = len(r.nsa_backdoor_analysis.get('medium_risk_algorithms', []))
                if h == 0 and m == 0:
                    continue
                parts = []
                if h:
                    parts.append(_colorize(f"{h} high", _C_RED, c))
                if m:
                    parts.append(_colorize(f"{m} medium", _C_YELLOW, c))
                print(f"  {_colorize(_label(r), _C_BOLD, c)}  {', '.join(parts)}")

        # Show top risky algorithms
        if total_high_risk > 0:
            print(_colorize(f"\nMost common HIGH RISK algorithms:", '\033[1;31m', c))
            risk_counter = {}
            for result in results:
                if result.nsa_backdoor_analysis and 'high_risk_algorithms' in result.nsa_backdoor_analysis:
                    for risk_algo in result.nsa_backdoor_analysis['high_risk_algorithms']:
                        algo_name = risk_algo['algorithm']
                        risk_counter[algo_name] = risk_counter.get(algo_name, 0) + 1

            for algo, count in sorted(risk_counter.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(_colorize(f"  - {algo}: found on {count} hosts", _C_RED, c))

    # Scanner configuration & DNS cache stats
    _section("SCANNER STATISTICS")
    print(f"Threads:          {_colorize(str(scanner.max_workers), _C_CYAN, c)}")
    print(f"Timeout:          {_colorize(f'{scanner.timeout}s', _C_CYAN, c)}")
    print(f"Retry attempts:   {_colorize(str(scanner.retry_attempts), _C_CYAN, c)}")
    print(f"NSA warnings:     {_colorize('enabled' if scanner.show_nsa_warnings else 'disabled', _C_GREEN if scanner.show_nsa_warnings else _C_DIM, c)}")

    dns = scanner.dns_cache.get_stats()
    print(f"\nDNS Cache:")
    print(f"  Hit rate:       {_colorize(dns['hit_rate'], _C_CYAN, c)}")
    print(f"  Lookups:        {_colorize(str(dns['total_lookups']), _C_CYAN, c)}  (hits: {dns['hits']}, misses: {dns['misses']})")


class Spinner:
    """Thread-based spinner for --summary-only mode. Writes to stderr."""

    CHARS = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

    def __init__(self, message: str = 'Scanning'):
        self.message = message
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._done = 0
        self._total = 0
        self._lock = threading.Lock()

    def start(self, total: int = 0):
        self._total = total
        self._done = 0
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def update(self, done: int):
        with self._lock:
            self._done = done

    def _spin(self):
        i = 0
        t0 = time.time()
        tty = sys.stderr.isatty()
        while not self._stop.is_set():
            elapsed = time.time() - t0
            char = self.CHARS[i % len(self.CHARS)]
            with self._lock:
                done, total = self._done, self._total
            parts = [char, self.message]
            if total:
                parts.append(f'{done}/{total} hosts')
            parts.append(f'{elapsed:.0f}s')
            line = '\r' + '  '.join(parts) + '  '
            if tty:
                sys.stderr.write(line)
                sys.stderr.flush()
            time.sleep(0.1)
            i += 1

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.5)
        if sys.stderr.isatty():
            sys.stderr.write('\r' + ' ' * 60 + '\r')
            sys.stderr.flush()


def print_algorithm_list():
    """Print all scannable algorithms grouped by type with weak/NSA annotations."""
    weak  = SSHEnhancedScanner.WEAK_ALGORITHMS
    nsa   = NSABackdoorDetector.SUSPECTED_NSA_ALGORITHMS
    known = SSHEnhancedScanner.KNOWN_ALGORITHMS

    labels = {
        'cipher': 'Ciphers',
        'mac':    'MACs',
        'kex':    'Key Exchange',
        'key':    'Host Keys',
    }

    print("Scannable algorithms:\n")
    for algo_type, display in labels.items():
        print(f"  {display} ({algo_type}):")
        for name in known.get(algo_type, []):
            flags = []
            if name in weak.get(algo_type, []):
                flags.append('[!] weak')
            nsa_entry = nsa.get(algo_type, {}).get(name)
            if nsa_entry:
                flags.append(f'[!] nsa ({nsa_entry["risk"].lower()})')
            flag_str = ('  ' + '  '.join(flags)) if flags else ''
            print(f"    {name:<52}{flag_str}")
        print()


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description=f'SSH Algorithm Security Scanner v{__version__}',
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=36, width=120),
        epilog="""
Examples:
  %(prog)s --host example.com
  %(prog)s --host "server1.com:22,server2.com:2222,192.168.1.100"
  %(prog)s --file hosts.txt --threads 50 --compliance NIST
  %(prog)s --file hosts.txt --format json --output results.json
  %(prog)s --host example.com --explicit "aes256-gcm@openssh.com,ssh-ed25519"
"""
    )

    # Version
    parser.add_argument('--version', '-V', action='version',
                        version=f'%(prog)s {__version__}  by {__author__}')

    # Configuration
    parser.add_argument('--config', '-c', metavar='FILE',
                        help='TOML configuration file path')

    # Host specification (mutually exclusive)
    host_group = parser.add_mutually_exclusive_group()
    host_group.add_argument('--host', '-H', metavar='HOSTS',
                            help='Single host or comma-separated list')
    host_group.add_argument('--file', '-f', metavar='FILE',
                            help='File containing hosts (.json, .yaml, .csv, .txt)')
    host_group.add_argument('--local', '-l', action='store_true',
                            help='Scan local SSH server (127.0.0.1)')

    # Scanning options
    parser.add_argument('--port', '-p', type=int, default=22,
                        help='Default SSH port (default: 22)')
    parser.add_argument('--threads', '-T', type=int, default=None,
                        help='Number of concurrent threads (default: 20)')
    parser.add_argument('--timeout', '-t', type=int, default=None,
                        help='Connection timeout in seconds (default: 10)')
    parser.add_argument('--retry-attempts', type=int, default=None,
                        help='Retry attempts for failed connections (default: 3)')
    parser.add_argument('--rate-limit', type=float, default=None, metavar='N',
                        help='Max new SSH connections per second, e.g. 5.0 (default: unlimited)')
    parser.add_argument('--timeout-banner', type=int, default=None, metavar='SEC',
                        help='Timeout for SSH banner grab in seconds (default: min(timeout, 5))')
    parser.add_argument('--strict-host-key-checking', default=None,
                        choices=['yes', 'no', 'accept-new'],
                        metavar='MODE',
                        help='SSH StrictHostKeyChecking: yes, no, accept-new (default: accept-new)')
    parser.add_argument('--jump-host', default=None, metavar='[USER@]HOST[:PORT]',
                        help='Route all connections through an SSH jump/bastion host, e.g. admin@bastion.corp:22')
    parser.add_argument('--proxy-command', default=None, metavar='CMD',
                        help='Route all connections via a ProxyCommand, e.g. "nc -X 5 -x socks5host:1080 %%h %%p"')

    # Algorithm testing
    parser.add_argument('--explicit', '-e', metavar='ALGOS',
                        help='Comma-separated list of specific algorithms to test')

    # Compliance
    parser.add_argument('--compliance', metavar='FRAMEWORK',
                        choices=ComplianceFramework.get_framework_list(),
                        help='Compliance framework: NIST, FIPS_140_2, BSI_TR_02102, ANSSI, PRIVACY_FOCUSED')
    parser.add_argument('--list-frameworks', action='store_true',
                        help='List available compliance frameworks')
    parser.add_argument('--list-filter', action='store_true',
                        help='List available --filter tokens')
    parser.add_argument('--list-algorithms', action='store_true',
                        help='List all scannable algorithms grouped by type, with weak/NSA annotations')
    parser.add_argument('--no-nsa-warnings', action='store_true',
                        help='Suppress NSA risk annotations in live output and summary (analysis still runs; NSA data included in exports)')

    # Output options
    parser.add_argument('--format', choices=['json', 'csv', 'yaml'],
                        default=None, help='Export format (json, csv, yaml); use with --output or alone')
    parser.add_argument('--output', '-o', metavar='FILE',
                        help='Write exported results to FILE')
    parser.add_argument('--filter', metavar='TOKENS',
                        help='Filter output. Category: supported, unsupported, flagged, weak, nsa. '
                             'Type: cipher, mac, kex, hostkey. '
                             'Output mode: banner, security. '
                             'Host: passed, failed, error. '
                             'Combinable, e.g.: --filter kex,weak  --filter banner,security')
    parser.add_argument('--summary', action='store_true',
                        help='Print summary report after scan')
    parser.add_argument('--summary-only', action='store_true',
                        help='Suppress live output, print only the summary report')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable ANSI color output')
    parser.add_argument('--show-hostnames', '-n', action='store_true',
                        help='Show original DNS names in output instead of resolved IPs')

    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(args.debug, args.verbose)

    # --list-frameworks: no scanner needed
    if args.list_frameworks:
        print("Available compliance frameworks:")
        for fw_name in ComplianceFramework.get_framework_list():
            fw_info = ComplianceFramework.get_framework_info(fw_name)
            name = fw_info.get('name', fw_name)
            print(f"  {fw_name:<20} {name}")
        return 0

    # --list-filter: no scanner needed
    if args.list_filter:
        print("Available --filter tokens:\n")
        print("  Category filters (filter by security classification):")
        print(f"  {'supported':<16} Supported algorithms with no warning  [x]")
        print(f"  {'unsupported':<16} Algorithms the server does not support  [-]")
        print(f"  {'flagged':<16} All flagged algorithms (weak + NSA combined)  [!]")
        print(f"  {'weak':<16} Weak/deprecated algorithms only  [!]")
        print(f"  {'nsa':<16} NSA-suspicious algorithms only  [!]")
        print()
        print("  Type filters (filter by protocol layer):")
        print(f"  {'cipher':<16} Cipher / encryption algorithms only")
        print(f"  {'mac':<16} MAC algorithms only")
        print(f"  {'kex':<16} Key exchange algorithms only")
        print(f"  {'hostkey':<16} Host key algorithms only")
        print()
        print("  Output mode (suppress algorithm detail lines):")
        print(f"  {'security':<16} Show only security score and compliance per host")
        print(f"  {'banner':<16} Show only the SSH banner per host")
        print()
        print("  Host filters (show only hosts matching the condition):")
        print(f"  {'passed':<16} Hosts that passed the compliance check (requires --compliance)")
        print(f"  {'failed':<16} Hosts that failed the compliance check (requires --compliance)")
        print(f"  {'error':<16} Hosts where the scan failed (connection error, timeout, etc.)")
        print()
        print("  All token groups are composable. Type and category tokens combine with AND.")
        print("  'banner'/'security' alone suppress algo lines; pairing with type/category re-enables them.")
        print()
        print("  Examples:")
        print("    --filter weak                     weak algorithms of any type")
        print("    --filter kex                      all KEX algorithms")
        print("    --filter kex,weak                 weak KEX algorithms only")
        print("    --filter cipher,nsa               NSA-flagged cipher algorithms")
        print("    --filter security                 score + compliance per host, no algo detail")
        print("    --filter banner                   SSH banner per host, no algo detail")
        print("    --filter banner,security          banner + score, no algo detail")
        print("    --filter security,nsa             score + NSA algo lines")
        print("    --filter nsa,failed               NSA lines, compliance-failed hosts only")
        return 0

    # --list-algorithms: no scanner needed
    if args.list_algorithms:
        print_algorithm_list()
        return 0

    # Load config file if specified
    config = {}
    if args.config:
        config = load_config_file(args.config)
        if not config:
            print(f"Warning: Could not load config from {args.config}", file=sys.stderr)

    # Apply CLI overrides (only when explicitly provided)
    if 'scanner' not in config:
        config['scanner'] = {}
    if args.threads is not None:
        config['scanner']['threads'] = args.threads
    if args.timeout is not None:
        config['scanner']['timeout'] = args.timeout
    if args.retry_attempts is not None:
        config['scanner']['retry_attempts'] = args.retry_attempts
    if args.rate_limit is not None:
        if args.rate_limit <= 0:
            print("Error: --rate-limit must be a positive number", file=sys.stderr)
            return 1
        config['scanner']['rate_limit'] = args.rate_limit
    if args.timeout_banner is not None:
        if args.timeout_banner <= 0:
            print("Error: --timeout-banner must be a positive number", file=sys.stderr)
            return 1
        config['scanner']['banner_timeout'] = args.timeout_banner
    if args.strict_host_key_checking is not None:
        config['scanner']['strict_host_key_checking'] = args.strict_host_key_checking
    if args.jump_host is not None:
        config['scanner']['jump_host'] = args.jump_host
    if args.proxy_command is not None:
        config['scanner']['proxy_command'] = args.proxy_command

    if args.compliance:
        if 'compliance' not in config:
            config['compliance'] = {}
        config['compliance']['framework'] = args.compliance

    # Explicit algorithms list
    explicit_algorithms = None
    if args.explicit:
        explicit_algorithms = [a.strip() for a in args.explicit.split(',') if a.strip()]

    # Accept hosts from stdin when piped (no --host/--file/--local given)
    if not args.host and not args.file and not args.local:
        if not sys.stdin.isatty():
            stdin_data = sys.stdin.read().strip()
            if stdin_data:
                # Normalize any mix of commas, spaces, newlines into a comma-separated string
                args.host = re.sub(r'[\s,]+', ',', stdin_data).strip(',')
            else:
                parser.print_help()
                return 1
        else:
            parser.print_help()
            return 1

    scan_start = time.time()
    results = []

    try:
        with SSHEnhancedScanner(config) as scanner:
            scanner.show_nsa_warnings = not args.no_nsa_warnings
            scanner.summary_only = args.summary_only
            scanner.show_hostnames = args.show_hostnames
            # Disable color if explicitly requested, or when piping format output to stdout
            if args.no_color or (args.format and not args.output):
                scanner.use_color = False

            if args.summary_only:
                scanner.spinner = Spinner('Scanning')

            # Parse --filter tokens
            _ALGO_TOKENS = {
                'supported', 'unsupported', 'flagged', 'weak', 'nsa',  # category
                'cipher', 'mac', 'kex', 'hostkey',                      # type
                'banner', 'security',                                    # output mode
            }
            _HOST_TOKENS = {'passed', 'failed', 'error'}
            if args.filter:
                tokens = {t.strip().lower() for t in args.filter.split(',') if t.strip()}
                unknown = tokens - _ALGO_TOKENS - _HOST_TOKENS
                if unknown:
                    print(f"Warning: unknown filter tokens: {', '.join(sorted(unknown))}", file=sys.stderr)
                scanner.filter_algo = tokens & _ALGO_TOKENS
                scanner.filter_hosts = tokens & _HOST_TOKENS

            def _scan_header(host_count: int) -> None:
                """Print a one-line scan summary before scanning starts."""
                if scanner.summary_only:
                    return
                parts = [f"{scanner.max_workers} threads", f"{scanner.timeout}s timeout"]
                if scanner.banner_timeout is not None:
                    parts.append(f"banner-timeout {scanner.banner_timeout}s")
                if scanner.rate_limit:
                    parts.append(f"rate-limit {scanner.rate_limit}/s")
                if scanner.compliance_framework:
                    parts.append(f"{scanner.compliance_framework} compliance")
                if explicit_algorithms:
                    alg_str = ', '.join(explicit_algorithms[:3])
                    if len(explicit_algorithms) > 3:
                        alg_str += f' +{len(explicit_algorithms) - 3} more'
                    parts.append(f"explicit: {alg_str}")
                noun = 'host' if host_count == 1 else 'hosts'
                header = f"Scanning {host_count} {noun}  {'  '.join(parts)}"
                print(_colorize(header, _C_BOLD, scanner.use_color) + "\n")

            # --local: scan the local SSH server (127.0.0.1)
            if args.local:
                if not args.summary_only:
                    print(f"Scanning local SSH server (127.0.0.1:{args.port}) ...\n")
                if scanner.spinner:
                    scanner.spinner.start(total=1)
                result = scanner.scan_single_host('127.0.0.1', args.port)
                if scanner.spinner:
                    scanner.spinner.update(1)
                results = [result]

            if args.host:
                hosts = []
                for host_str in args.host.split(','):
                    host_str = host_str.strip()
                    if not host_str:
                        continue
                    try:
                        host, port = scanner.parse_host_string(host_str)
                        if ':' not in host_str and '[' not in host_str:
                            port = args.port
                        hosts.append((host, port))
                    except ValidationError as e:
                        print(f"Warning: Skipping invalid host '{host_str}': {e}", file=sys.stderr)

                if not hosts:
                    print("No valid hosts to scan.", file=sys.stderr)
                    return 1

                _scan_header(len(hosts))
                if scanner.spinner:
                    scanner.spinner.start(total=len(hosts))
                results = scanner.batch_scan(hosts, explicit_algorithms=explicit_algorithms)

            elif args.file:
                hosts = scanner.load_hosts_from_file(args.file, default_port=args.port)

                if not hosts:
                    print("No hosts found in file.", file=sys.stderr)
                    return 1

                _scan_header(len(hosts))
                if scanner.spinner:
                    scanner.spinner.start(total=len(hosts))
                results = scanner.batch_scan(hosts, explicit_algorithms=explicit_algorithms)

            if scanner.spinner:
                scanner.spinner.stop()

            # Export results if --format or --output requested
            if results and (args.format or args.output):
                fmt = args.format or 'json'
                output_content = scanner.export_results(results, fmt)
                if args.output:
                    with open(args.output, 'w') as out_f:
                        out_f.write(output_content)
                    print(f"Results written to {args.output}")
                else:
                    print(output_content)

            if args.summary or args.summary_only:
                print_summary_report(results, scanner, time.time() - scan_start)

    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        return 130
    except (ConfigurationError, ValidationError) as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        logger.error(f"Configuration error: {e}", exc_info=True)
        return 1
    except SSHScannerError as e:
        print(f"Scanner error: {e}", file=sys.stderr)
        logger.error(f"Scanner error: {e}", exc_info=True)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return 1

    if results:
        has_compliance_failures = (
            scanner.compliance_framework and
            any(r.compliance_status and not r.compliance_status.get('overall_compliant', True)
                for r in results if r.status == 'success')
        )
        has_scan_errors = any(r.status != 'success' for r in results)
        if has_compliance_failures:
            return 2
        if has_scan_errors:
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
