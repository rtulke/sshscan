"""Network-independent unit tests for sshscan.py.

Run from the repo root with either:
    python3 -m unittest discover -s tests
    python3 -m pytest tests/

All tests avoid real DNS/SSH: host parsing uses IP literals (which short-circuit
before resolution) and the one DNS-cache test mocks socket.getaddrinfo.
"""

import os
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sshscan
from sshscan import (
    ComplianceFramework,
    ConfigValidator,
    EnhancedDNSCache,
    ProxyConfig,
    SSHAlgorithmInfo,
    SSHEnhancedScanner,
    SSHHostResult,
    ValidationError,
    find_default_config,
    sanitize_host_input,
    validate_port,
)


def algos(cipher=(), mac=(), kex=(), key=()):
    """Build the algorithms dict check_compliance expects (all marked supported)."""
    def infos(names, algo_type):
        return [SSHAlgorithmInfo(name=n, type=algo_type, supported=True) for n in names]
    return {
        'cipher': infos(cipher, 'cipher'),
        'mac': infos(mac, 'mac'),
        'kex': infos(kex, 'kex'),
        'key': infos(key, 'key'),
    }


# A fully NIST-compliant algorithm set (all required present, none forbidden).
NIST_COMPLIANT = dict(
    cipher=('aes256-ctr', 'aes128-ctr'),
    mac=('hmac-sha2-256', 'hmac-sha2-512'),
    kex=('ecdh-sha2-nistp256',),
    key=('ecdsa-sha2-nistp256',),
)


class ValidatePortTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_port(22), 22)
        self.assertEqual(validate_port('2222'), 2222)
        self.assertEqual(validate_port(1), 1)
        self.assertEqual(validate_port(65535), 65535)

    def test_invalid(self):
        for bad in (0, -1, 65536, 'abc', None, ''):
            with self.assertRaises(ValidationError):
                validate_port(bad)


class SanitizeHostInputTest(unittest.TestCase):
    def test_strips_whitespace_and_illegal_chars(self):
        self.assertEqual(sanitize_host_input('  example.com '), 'example.com')
        self.assertEqual(sanitize_host_input('ex$am|ple.com'), 'example.com')

    def test_keeps_ipv6_brackets_and_colons(self):
        self.assertEqual(sanitize_host_input('[2001:db8::1]'), '[2001:db8::1]')

    def test_too_long_raises(self):
        with self.assertRaises(ValidationError):
            sanitize_host_input('a' * 254)


class ProxyConfigTest(unittest.TestCase):
    def test_jump_defaults_and_args(self):
        p = ProxyConfig.from_dict({'type': 'jump', 'host': 'bastion.corp', 'user': 'admin'})
        self.assertIsNotNone(p)
        self.assertEqual(p.type, 'jump')
        self.assertEqual(p.port, 22)
        self.assertEqual(p.to_ssh_args(), ['-J', 'admin@bastion.corp:22'])

    def test_socks5_default_port(self):
        p = ProxyConfig.from_dict({'type': 'socks5', 'host': '127.0.0.1'})
        self.assertEqual(p.port, 1080)
        self.assertEqual(p.to_ssh_args(),
                         ['-o', 'ProxyCommand=nc -X 5 -x 127.0.0.1:1080 %h %p'])

    def test_http_default_port(self):
        p = ProxyConfig.from_dict({'type': 'http', 'host': 'proxy.corp'})
        self.assertEqual(p.port, 3128)
        self.assertEqual(p.to_ssh_args(),
                         ['-o', 'ProxyCommand=nc -X connect -x proxy.corp:3128 %h %p'])

    def test_user_is_sanitized(self):
        p = ProxyConfig.from_dict({'type': 'jump', 'host': 'b', 'user': 'ad;min rm'})
        self.assertEqual(p.user, 'adminrm')

    def test_invalid_inputs_return_none(self):
        self.assertIsNone(ProxyConfig.from_dict({'type': 'bogus', 'host': 'b'}))
        self.assertIsNone(ProxyConfig.from_dict({'type': 'jump'}))  # missing host
        self.assertIsNone(ProxyConfig.from_dict('not-a-dict'))


class ComplianceTest(unittest.TestCase):
    def test_compliant_set_passes(self):
        result = ComplianceFramework.check_compliance(
            algos(**NIST_COMPLIANT), 'NIST', security_score=80)
        self.assertTrue(result['overall_compliant'])

    def test_forbidden_algorithm_fails(self):
        spec = dict(NIST_COMPLIANT)
        spec['cipher'] = spec['cipher'] + ('3des-cbc',)
        result = ComplianceFramework.check_compliance(
            algos(**spec), 'NIST', security_score=80)
        self.assertTrue(result['ciphers_has_forbidden'])
        self.assertFalse(result['overall_compliant'])

    def test_missing_required_fails(self):
        spec = dict(NIST_COMPLIANT)
        spec['cipher'] = ('aes256-ctr',)  # drop the required aes128-ctr
        result = ComplianceFramework.check_compliance(
            algos(**spec), 'NIST', security_score=80)
        self.assertFalse(result['ciphers_has_required'])
        self.assertFalse(result['overall_compliant'])

    def test_score_below_minimum_fails(self):
        result = ComplianceFramework.check_compliance(
            algos(**NIST_COMPLIANT), 'NIST', security_score=50)
        self.assertFalse(result['score_meets_minimum'])
        self.assertFalse(result['overall_compliant'])

    def test_unknown_framework_raises(self):
        with self.assertRaises(ValueError):
            ComplianceFramework.check_compliance(algos(), 'NOPE')


class ConfigValidatorTest(unittest.TestCase):
    def test_empty_config_uses_defaults(self):
        v = ConfigValidator.validate_config({})['scanner']
        self.assertEqual(v['threads'], 20)
        self.assertEqual(v['timeout'], 10)
        self.assertEqual(v['retry_attempts'], 3)

    def test_out_of_range_falls_back_to_default(self):
        v = ConfigValidator.validate_config({'scanner': {'threads': '600'}})['scanner']
        self.assertEqual(v['threads'], 20)

    def test_valid_override(self):
        v = ConfigValidator.validate_config({'scanner': {'threads': '50'}})['scanner']
        self.assertEqual(v['threads'], 50)

    def test_rate_limit_parsed(self):
        v = ConfigValidator.validate_config({'scanner': {'rate_limit': '5.0'}})['scanner']
        self.assertEqual(v['rate_limit'], 5.0)

    def test_invalid_strict_host_key_checking(self):
        v = ConfigValidator.validate_config(
            {'scanner': {'strict_host_key_checking': 'bogus'}})['scanner']
        self.assertEqual(v['strict_host_key_checking'], 'accept-new')

    def test_invalid_framework_dropped(self):
        v = ConfigValidator.validate_config({'compliance': {'framework': 'NOPE'}})
        self.assertNotIn('framework', v['compliance'])


class ScannerHostParsingTest(unittest.TestCase):
    def setUp(self):
        # Pass an explicit (empty) config so no on-disk sshscan.conf is picked up.
        self.scanner = SSHEnhancedScanner(config={})

    def tearDown(self):
        self.scanner.dns_cache.stop()

    def test_ipv4_default_port(self):
        self.assertEqual(self.scanner.parse_host_string('192.168.1.1'), ('192.168.1.1', 22))

    def test_ipv4_default_port_override(self):
        self.assertEqual(self.scanner.parse_host_string('192.168.1.1', 2222),
                         ('192.168.1.1', 2222))

    def test_ipv4_explicit_port(self):
        self.assertEqual(self.scanner.parse_host_string('192.168.1.1:2200'),
                         ('192.168.1.1', 2200))

    def test_ipv6_bracketed_with_port(self):
        self.assertEqual(self.scanner.parse_host_string('[2001:db8::1]:22'),
                         ('2001:db8::1', 22))

    def test_ipv6_bracketed_without_port_honors_default(self):
        # Regression: bracketed IPv6 without a port must use the given default.
        self.assertEqual(self.scanner.parse_host_string('[2001:db8::1]', 2222),
                         ('2001:db8::1', 2222))

    def test_bare_ipv6_honors_default_port(self):
        # Regression: bare IPv6 literals must not silently fall back to port 22.
        self.assertEqual(self.scanner.parse_host_string('2001:db8::1', 2222),
                         ('2001:db8::1', 2222))


class HostFilterTest(unittest.TestCase):
    def setUp(self):
        self.scanner = SSHEnhancedScanner(config={})

    def tearDown(self):
        self.scanner.dns_cache.stop()

    def _result(self, status='success', compliant=True):
        return SSHHostResult(host='h', port=22, status=status,
                             compliance_status={'overall_compliant': compliant})

    def test_no_filter_passes_everything(self):
        self.scanner.filter_hosts = set()
        self.assertTrue(self.scanner._host_passes_filter(self._result()))

    def test_error_token_matches_failed_host(self):
        self.scanner.filter_hosts = {'error'}
        self.assertTrue(self.scanner._host_passes_filter(self._result(status='failed')))
        self.assertFalse(self.scanner._host_passes_filter(self._result(status='success')))

    def test_passed_and_failed_with_compliance(self):
        self.scanner.compliance_framework = 'NIST'
        self.scanner.filter_hosts = {'passed'}
        self.assertTrue(self.scanner._host_passes_filter(self._result(compliant=True)))
        self.assertFalse(self.scanner._host_passes_filter(self._result(compliant=False)))

        self.scanner.filter_hosts = {'failed'}
        self.assertTrue(self.scanner._host_passes_filter(self._result(compliant=False)))
        self.assertFalse(self.scanner._host_passes_filter(self._result(compliant=True)))


class DNSCachePreferenceTest(unittest.TestCase):
    """Regression for the cache key ignoring the IPv6 preference."""

    DUAL_STACK = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('192.0.2.1', 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 0, '', ('2001:db8::1', 0, 0, 0)),
    ]

    def setUp(self):
        self.cache = EnhancedDNSCache(ttl=300)

    def tearDown(self):
        self.cache.stop()

    def test_preference_is_part_of_cache_key(self):
        with mock.patch('socket.getaddrinfo', return_value=self.DUAL_STACK):
            # Populate the cache with the IPv4 answer first ...
            self.assertEqual(self.cache.resolve('dual.test', prefer_ipv4=True), '192.0.2.1')
            # ... a later IPv6-preferring lookup must NOT get the cached IPv4.
            self.assertEqual(self.cache.resolve('dual.test', prefer_ipv4=False), '2001:db8::1')

    def test_ipv6_only_without_aaaa_returns_none(self):
        ipv4_only = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('192.0.2.1', 0))]
        with mock.patch('socket.getaddrinfo', return_value=ipv4_only):
            self.assertIsNone(self.cache.resolve('v4.test', ipv6_only=True))


class FindDefaultConfigTest(unittest.TestCase):
    def test_local_config_is_found(self):
        import tempfile
        prev = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                with open('sshscan.conf', 'w') as f:
                    f.write('[scanner]\nthreads = 5\n')
                found = find_default_config()
                self.assertIsNotNone(found)
                self.assertEqual(os.path.basename(str(found)), 'sshscan.conf')
            finally:
                os.chdir(prev)


class KexinitParserTest(unittest.TestCase):
    @staticmethod
    def _name_list(names):
        s = ','.join(names).encode('ascii')
        return len(s).to_bytes(4, 'big') + s

    def _payload(self, kex, hostkey, enc_c2s, enc_s2c, mac_c2s, mac_s2c):
        nl = self._name_list
        comp = nl(['none'])
        empty = nl([])
        return (bytes([20]) + b'\x00' * 16
                + nl(kex) + nl(hostkey)
                + nl(enc_c2s) + nl(enc_s2c)
                + nl(mac_c2s) + nl(mac_s2c)
                + comp + comp + empty + empty
                + b'\x00' + (0).to_bytes(4, 'big'))

    def test_extracts_server_to_client_lists(self):
        payload = self._payload(
            kex=['curve25519-sha256', 'ecdh-sha2-nistp256'],
            hostkey=['ssh-ed25519'],
            enc_c2s=['aes128-ctr'],
            enc_s2c=['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com'],
            mac_c2s=['hmac-sha1'],
            mac_s2c=['hmac-sha2-256-etm@openssh.com'],
        )
        result = SSHEnhancedScanner._parse_kexinit_payload(payload)
        self.assertEqual(result['kex'], {'curve25519-sha256', 'ecdh-sha2-nistp256'})
        self.assertEqual(result['key'], {'ssh-ed25519'})
        # cipher/mac are taken from the server-to-client name-lists
        self.assertEqual(result['cipher'],
                         {'chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com'})
        self.assertEqual(result['mac'], {'hmac-sha2-256-etm@openssh.com'})

    def test_truncated_payload_returns_none(self):
        self.assertIsNone(SSHEnhancedScanner._parse_kexinit_payload(b'\x14' + b'\x00' * 10))


class FastModeShapingTest(unittest.TestCase):
    def setUp(self):
        self.scanner = SSHEnhancedScanner(config={})

    def tearDown(self):
        self.scanner.dns_cache.stop()

    def test_marks_advertised_supported_and_rest_unsupported(self):
        advertised = {
            'cipher': {'aes256-gcm@openssh.com'},
            'mac': {'hmac-sha2-256-etm@openssh.com'},
            'kex': {'curve25519-sha256'},
            'key': {'ssh-ed25519'},
        }
        local = {
            'cipher': ['aes256-gcm@openssh.com', '3des-cbc'],
            'mac': ['hmac-sha2-256-etm@openssh.com', 'hmac-md5'],
            'kex': ['curve25519-sha256'],
            'key': ['ssh-ed25519'],
        }
        with mock.patch.object(self.scanner, '_read_server_kexinit', return_value=advertised), \
             mock.patch.object(self.scanner, '_proxy_args_for', return_value=[]), \
             mock.patch.object(self.scanner, 'get_local_ssh_algorithms', return_value=local):
            result = self.scanner.scan_all_algorithms_fast('192.0.2.1', 22)

        by_name = {a.name: a.supported for lst in result.values() for a in lst}
        self.assertTrue(by_name['aes256-gcm@openssh.com'])
        self.assertTrue(by_name['curve25519-sha256'])
        self.assertFalse(by_name['3des-cbc'])
        self.assertFalse(by_name['hmac-md5'])

    def test_falls_back_when_kexinit_fails(self):
        sentinel = {'cipher': [], 'mac': [], 'kex': [], 'key': []}
        with mock.patch.object(self.scanner, '_read_server_kexinit', return_value=None), \
             mock.patch.object(self.scanner, '_proxy_args_for', return_value=[]), \
             mock.patch.object(self.scanner, '_scan_all_algorithms_dispatch',
                               return_value=sentinel) as dispatch:
            out = self.scanner.scan_all_algorithms_fast('192.0.2.1', 22)
        dispatch.assert_called_once()
        self.assertIs(out, sentinel)

    def test_falls_back_behind_proxy(self):
        sentinel = {'cipher': [], 'mac': [], 'kex': [], 'key': []}
        with mock.patch.object(self.scanner, '_proxy_args_for', return_value=['-J', 'bastion']), \
             mock.patch.object(self.scanner, '_read_server_kexinit') as read_kex, \
             mock.patch.object(self.scanner, '_scan_all_algorithms_dispatch',
                               return_value=sentinel) as dispatch:
            out = self.scanner.scan_all_algorithms_fast('192.0.2.1', 22)
        read_kex.assert_not_called()
        dispatch.assert_called_once()
        self.assertIs(out, sentinel)


if __name__ == '__main__':
    unittest.main()
