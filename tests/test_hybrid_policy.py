"""Fail-closed acceptance contract; these inputs are not live handshake evidence."""
import pytest
from agent.assessment import AssessmentScope
from agent.assessment.tls_observer import enforce_hybrid, HybridPolicyRejected
from agent.assessment.tls_observer import PublicHello


@pytest.mark.parametrize('version,group', [('TLSv1.2', 4588), ('TLSv1.3', 29),
    ('TLSv1.3', None), ('TLSv1.3', True), ('TLSv1.3', '4588'), ('TLSv1.3', 9999)])
def test_gate_rejects_downgrade_classical_and_unknown(version, group):
    with pytest.raises(HybridPolicyRejected):
        enforce_hybrid(version, group)


@pytest.mark.parametrize('group', [4587, 4588, 4589])
def test_gate_accepts_recognized_tls13_hybrid(group):
    enforce_hybrid('TLSv1.3', group)


@pytest.mark.parametrize('selection,handshake', [(1, True), ('yes', True), (True, False)])
def test_invalid_policy_cannot_start_an_assessment(selection, handshake):
    with pytest.raises(ValueError):
        AssessmentScope(require_hybrid=selection, tls_handshake_only=handshake).origin()


def test_encrypted_tls12_finished_is_not_parsed_as_plaintext():
    # Parser contract bytes; actual badssl handshake is recorded separately.
    hello = PublicHello()
    hello.feed(bytes.fromhex('1403030001011603030004ffffffff'))
    assert hello.cipher_started and not hello.handshake and hello.group is None
