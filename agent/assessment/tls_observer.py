"""One real hostname-verified TLS handshake; no HTTP, secrets or packet capture.

Public ssl.MemoryBIO drives the TLS implementation. Only public ServerHello
fields are parsed; observations are emitted after certificate and Finished
verification succeeds. A hybrid exchange is distinct from PQ authentication.
"""
import ipaddress
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path


GROUPS = {23: 'secp256r1', 24: 'secp384r1', 25: 'secp521r1', 29: 'x25519',
          30: 'x448', 4587: 'SecP256r1MLKEM768', 4588: 'X25519MLKEM768',
          4589: 'SecP384r1MLKEM1024'}
HYBRID = {4587, 4588, 4589}
RETRY_RANDOM = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')


class HybridPolicyRejected(ValueError):
    """The authenticated connection did not satisfy the selected hybrid gate."""


def enforce_hybrid(version, group):
    if version != 'TLSv1.3' or type(group) is not int or group not in HYBRID:
        raise HybridPolicyRejected('Hybrid-only gate rejected an older, classical or unobserved exchange; no fallback.')


class PublicHello:
    def __init__(self):
        self.records = bytearray()
        self.handshake = bytearray()
        self.group = None
        self.total = 0
        self.cipher_started = False

    def feed(self, data):
        self.total += len(data)
        if self.total > 262144:
            raise ValueError('Handshake observation exceeds bounded input')
        self.records.extend(data)
        while len(self.records) >= 5:
            length = int.from_bytes(self.records[3:5], 'big')
            if length > 18432:
                raise ValueError('Oversized TLS record')
            if len(self.records) < 5 + length:
                break
            kind = self.records[0]
            payload = bytes(self.records[5:5 + length])
            del self.records[:5 + length]
            if kind == 20:
                # TLS 1.2 Finished still uses record type 22 after keys start.
                # It is ciphertext, not a plaintext handshake length/header.
                self.cipher_started = True
                self.handshake.clear()
                continue
            if kind != 22 or self.cipher_started:
                continue
            self.handshake.extend(payload)
            while len(self.handshake) >= 4:
                size = int.from_bytes(self.handshake[1:4], 'big')
                if size > 131072:
                    raise ValueError('Oversized handshake message')
                if len(self.handshake) < size + 4:
                    break
                message = bytes(self.handshake[4:4 + size])
                message_type = self.handshake[0]
                del self.handshake[:4 + size]
                if message_type == 2:
                    self.server_hello(message)

    def server_hello(self, message):
        if len(message) < 38:
            raise ValueError('Truncated ServerHello')
        retry = message[2:34] == RETRY_RANDOM
        cursor = 35 + message[34] + 3
        if cursor == len(message):  # TLS 1.2 can omit extensions.
            return
        if cursor + 2 > len(message):
            raise ValueError('Truncated ServerHello extension length')
        length = int.from_bytes(message[cursor:cursor + 2], 'big')
        cursor += 2
        if cursor + length != len(message):
            raise ValueError('ServerHello extension length mismatch')
        seen = set()
        while cursor < len(message):
            if cursor + 4 > len(message):
                raise ValueError('Truncated ServerHello extension')
            kind = int.from_bytes(message[cursor:cursor + 2], 'big')
            size = int.from_bytes(message[cursor + 2:cursor + 4], 'big')
            cursor += 4
            if kind in seen or cursor + size > len(message):
                raise ValueError('Invalid ServerHello extension')
            seen.add(kind)
            value = message[cursor:cursor + size]
            cursor += size
            if kind == 51 and not retry:
                if len(value) < 4 or int.from_bytes(value[2:4], 'big') != len(value) - 4:
                    raise ValueError('Invalid ServerHello key share')
                self.group = int.from_bytes(value[:2], 'big')


def observe(host, address, port=443, *, checkpoint=lambda: None, require_hybrid=False):
    if type(require_hybrid) is not bool:
        raise ValueError('Hybrid policy selection must be boolean')
    from agent.assessment.cryptography import assessment_tls_context, certificate_inventory
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    context = assessment_tls_context()
    if require_hybrid:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    tls = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=host)
    hello = PublicHello()
    deadline = time.monotonic() + 10
    checkpoint()
    with socket.create_connection((address, port), timeout=5) as transport:
        while True:
            checkpoint()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('TLS handshake deadline exceeded')
            transport.settimeout(remaining)
            needs_read = False
            try:
                tls.do_handshake()
                complete = True
            except ssl.SSLWantReadError:
                needs_read, complete = True, False
            except ssl.SSLWantWriteError:
                complete = False
            while outgoing.pending:
                transport.sendall(outgoing.read())
            if complete:
                break
            if needs_read:
                data = transport.recv(16384)
                if not data:
                    raise ConnectionError('Peer closed before verified TLS handshake')
                hello.feed(data)
                incoming.write(data)
        group = hello.group if tls.version() == 'TLSv1.3' else None
        checkpoint()
        certificate = certificate_inventory(tls.getpeercert(binary_form=True))
        if require_hybrid:
            enforce_hybrid(tls.version(), group)
        return {'state': 'verified_handshake_observed', 'observed_at': datetime.now(timezone.utc).isoformat(),
                'host': host, 'address': address, 'port': port, 'tls_version': tls.version(),
                'cipher': tls.cipher(), 'certificate_and_hostname_verified': True,
                'finished_verified': True, 'key_exchange_group_id': group,
                'hybrid_only_policy': 'accepted' if require_hybrid else 'not_requested',
                'application_data_sent': False, 'fallback_attempted': False,
                'key_exchange_group': GROUPS.get(group, 'unknown_or_not_observed'),
                'post_quantum_hybrid_exchange': 'observed' if group in HYBRID else 'not_observed',
                'peer_certificate': certificate, 'post_quantum_authentication': 'not_established_by_this_observer',
                'private_keys_saved': False, 'traffic_secrets_saved': False,
                'scope': 'One actual TLS handshake; no HTTP or policy mutation', 'mutations': []}


