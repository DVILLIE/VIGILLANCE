"""One explicit real TLS handshake; see agent.assessment.tls_observer."""
import argparse
import ipaddress
import json
import sys
from pathlib import Path
if "__file__" in globals():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.assessment.tls_observer import observe

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--address', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-hybrid', action='store_true',
                        help='Require verified TLS 1.3 hybrid exchange; fail without fallback.')
    args = parser.parse_args()
    address = str(ipaddress.ip_address(args.address))
    host = args.host.encode('idna').decode('ascii')
    if not host or len(host) > 253 or any(ord(c) <= 32 for c in host):
        parser.error('Require a bounded explicit TLS hostname')
    try:
        report = observe(host, address, require_hybrid=args.require_hybrid)
    except (OSError, ValueError) as exc:
        report = {'state': 'connection_not_accepted', 'error_type': type(exc).__name__,
                  'reason': str(exc), 'require_hybrid': args.require_hybrid,
                  'host': host, 'address': address, 'fallback_attempted': False,
                  'application_data_sent': False, 'mutations': []}
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(report, output, indent=2)
    print(json.dumps({key: report.get(key) for key in ('state', 'tls_version', 'key_exchange_group', 'post_quantum_hybrid_exchange')}))
    raise SystemExit(0 if report['state'] == 'verified_handshake_observed' else 2)
