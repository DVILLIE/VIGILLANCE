"""Observed certificate algorithms; no invented negotiated PQ properties."""
from __future__ import annotations

import hmac
import time
import ssl

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa


def assessment_tls_context() -> ssl.SSLContext:
    """Verified TLS without inheriting SSLKEYLOGFILE secret export."""
    # create_default_context opens SSLKEYLOGFILE before it can be disabled.
    # Construct the client context directly to avoid even creating that file.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def post_quantum_provider_checks() -> dict:
    """Execute ephemeral provider checks, not a network protocol or certification.

    Secrets stay in memory and are never serialized or included in reports.
    CPython does not guarantee erasure of immutable Python bytes.
    """
    started = time.monotonic()
    result = {'state': 'observed', 'scope': 'Local cryptographic primitive execution only',
              'negotiated_key_exchange': 'not_measured',
              'negotiated_authentication': 'not_measured', 'private_keys_saved': False}
    try:
        from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
        key = MLKEM768PrivateKey.generate()
        secret, ciphertext = key.public_key().encapsulate()
        recovered = key.decapsulate(ciphertext)
        matched = hmac.compare_digest(secret, recovered)
        try:
            key.decapsulate(ciphertext[:-1])
            malformed_rejected = False
        except ValueError:
            malformed_rejected = True
        result['ml_kem_768'] = {'state': 'passed' if matched and malformed_rejected else 'failed',
            'encapsulation_decapsulation_matched': matched,
            'invalid_length_rejected': malformed_rejected}
        del key, secret, recovered, ciphertext
    except (ImportError, UnsupportedAlgorithm) as exc:
        result['ml_kem_768'] = {'state': 'unavailable', 'error_type': type(exc).__name__}
    try:
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
        signing_key = MLDSA65PrivateKey.generate()
        message = b'DVielle local provider check'
        context = b'DVielle-provider-check-v1'
        signature = signing_key.sign(message, context)
        public = signing_key.public_key()
        public.verify(signature, message, context)
        failures = []
        for bad_message, bad_context in [(message + b'changed', context), (message, context + b'changed')]:
            try:
                public.verify(signature, bad_message, bad_context)
                failures.append(False)
            except InvalidSignature:
                failures.append(True)
        result['ml_dsa_65'] = {'state': 'passed' if all(failures) else 'failed',
            'signature_verified': True, 'modified_message_rejected': failures[0],
            'wrong_context_rejected': failures[1]}
        del signing_key, public, signature
    except (ImportError, UnsupportedAlgorithm) as exc:
        result['ml_dsa_65'] = {'state': 'unavailable', 'error_type': type(exc).__name__}
    result['elapsed_seconds'] = time.monotonic() - started
    return result


def certificate_inventory(der: bytes) -> dict:
    if not isinstance(der, bytes) or not 0 < len(der) <= 262144:
        raise ValueError("Certificate inventory exceeded its bounded input.")
    certificate = x509.load_der_x509_certificate(der)
    try:
        key = certificate.public_key()
    except UnsupportedAlgorithm as exc:
        raise ValueError("The certificate key algorithm is not supported by this parser.") from exc
    families = ((rsa.RSAPublicKey, "RSA"), (ec.EllipticCurvePublicKey, "EC"),
                (dsa.DSAPublicKey, "DSA"), (ed25519.Ed25519PublicKey, "Ed25519"),
                (ed448.Ed448PublicKey, "Ed448"))
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        families += ((mldsa.MLDSA44PublicKey, 'ML-DSA-44'),
                     (mldsa.MLDSA65PublicKey, 'ML-DSA-65'),
                     (mldsa.MLDSA87PublicKey, 'ML-DSA-87'))
    except ImportError:
        pass
    algorithm = next((name for kind, name in families if isinstance(key, kind)), "unclassified")
    result = {"state": "observed", "public_key_algorithm": algorithm,
              "public_key_size_bits": getattr(key, "key_size", None),
              "certificate_signature_oid": certificate.signature_algorithm_oid.dotted_string,
              "certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
              "quantum_migration": ('post_quantum_certificate_key_observed' if algorithm.startswith('ML-DSA-')
                  else "review_classical_certificate_key" if algorithm != "unclassified" else "unknown"),
              "negotiated_key_exchange": "not_measured", "negotiated_authentication": "not_measured"}
    if isinstance(key, ec.EllipticCurvePublicKey):
        result["curve"] = key.curve.name
    return result
