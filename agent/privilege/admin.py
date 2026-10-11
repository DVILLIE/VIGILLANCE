"""Trusted installed administrative mediation; never launched from the GUI.

Approve creates permission only. Apply remains the authenticated service's job.
This entry point does not elevate, install, download or run an arbitrary command.
"""
from __future__ import annotations

import argparse
import json

from agent.privilege.grants import GrantStore
from agent.privilege.helper import _is_elevated
from agent.privilege.recovery import reconcile
from agent.privilege.service_host import assert_runtime_trust, installed_configuration


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Installed D\'Vielle administrative scoped approval')
    commands = parser.add_subparsers(dest='command', required=True)
    approve = commands.add_parser('approve', help='Approve one exact executable network restriction for five minutes')
    approve.add_argument('--program', required=True)
    approve.add_argument('--profile', choices=['Domain', 'Private', 'Public', 'Any'], required=True)
    approve.add_argument('--family', choices=['IPv4', 'IPv6'], action='append', required=True)
    approve.add_argument('--remote', action='append', default=[])
    revoke = commands.add_parser('revoke', help='Revoke an unused grant')
    revoke.add_argument('grant_id')
    recover = commands.add_parser('recover', help='Conditionally restore an exact recorded operation')
    recover.add_argument('operation_id')
    args = parser.parse_args(argv)
    if not _is_elevated():
        raise PermissionError('Use the trusted installed administrative approval program under an administrative token.')
    assert_runtime_trust(require_system=False)
    directory, sid = installed_configuration()
    store = GrantStore(directory, sid)
    if args.command == 'approve':
        params = {'program': args.program, 'profile': args.profile,
                  'address_families': args.family, 'remote_addresses': args.remote}
        grant = store.issue(params)
        print(json.dumps({'grant_id': grant, 'expires_within_seconds': 300,
                          'operation': 'restrict_network', 'requested_scope': params,
                          'performed': False, 'message': 'Approval created. No firewall rule was added.'}))
    elif args.command == 'revoke':
        store.revoke(args.grant_id)
        print(json.dumps({'ok': True, 'performed': False,
                          'message': 'Any matching unused grant was revoked; no firewall rule was changed.'}))
    else:
        result = reconcile(store, args.operation_id)
        print(json.dumps(result, allow_nan=False))
        return 0 if result.get('ok') else 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
