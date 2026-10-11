"""Parser fixtures are not evidence of a real website's quantum readiness."""
from datetime import datetime, timedelta, timezone
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from agent.assessment.cryptography import certificate_inventory


def test_actual_post_quantum_provider_execution_has_no_protocol_claim():
    from agent.assessment.cryptography import post_quantum_provider_checks
    result = post_quantum_provider_checks()
    for name in ('ml_kem_768', 'ml_dsa_65'):
        assert result[name]['state'] in {'passed', 'unavailable'}
    assert result['negotiated_key_exchange'] == 'not_measured'
    assert result['negotiated_authentication'] == 'not_measured'
    assert result['private_keys_saved'] is False
    assert 'secret' not in result and 'signature' not in result


def test_assessment_tls_never_inherits_secret_key_log(tmp_path, monkeypatch):
    import ssl
    from agent.assessment.cryptography import assessment_tls_context
    monkeypatch.setenv('SSLKEYLOGFILE', str(tmp_path / 'secrets.log'))
    context = assessment_tls_context()
    assert context.keylog_filename is None
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert not (tmp_path / 'secrets.log').exists()


def test_actual_certificate_bytes_inventory_without_subject_or_pq_inference():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture-only.invalid")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    inventory = certificate_inventory(certificate.public_bytes(serialization.Encoding.DER))
    assert inventory["public_key_algorithm"] == "EC"
    assert inventory["public_key_size_bits"] == 256 and inventory["curve"] == "secp256r1"
    assert inventory["quantum_migration"] == "review_classical_certificate_key"
    assert inventory["negotiated_key_exchange"] == inventory["negotiated_authentication"] == "not_measured"
    assert "fixture-only.invalid" not in str(inventory)


def test_actual_ml_dsa_certificate_key_is_identified_without_negotiation_claim():
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    key = MLDSA65PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'parser-fixture-only.invalid')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(2).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, None))
    result = certificate_inventory(certificate.public_bytes(serialization.Encoding.DER))
    assert result['public_key_algorithm'] == 'ML-DSA-65'
    assert result['quantum_migration'] == 'post_quantum_certificate_key_observed'
    assert result['negotiated_key_exchange'] == result['negotiated_authentication'] == 'not_measured'


@pytest.mark.parametrize("der", [b"", b"invalid", b"x" * 262145, None],
                         ids=["empty", "malformed", "oversized", "wrong-type"])
def test_invalid_or_oversized_certificate_is_not_classified(der):
    with pytest.raises(ValueError):
        certificate_inventory(der)
