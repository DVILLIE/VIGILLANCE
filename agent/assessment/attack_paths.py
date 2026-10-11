"""Evidence-linked potential routes and deterministic investigation ordering.

No exploitability probability, live reachability, or action authority is inferred.
"""
from __future__ import annotations

from agent.assessment.evidence import digest, freshness


def investigation_paths(report: dict) -> dict:
    age = freshness(report)
    observations = report.get('observations', {})
    records = report.get('evidence_records', {})

    def reference(key):
        row = records.get('observations.' + key, {})
        payload = row.get('payload', {})
        try:
            valid = (payload.get('source_path') == 'observations.' + key
                     and key in observations and payload.get('sha256') == digest(observations[key]))
        except (ValueError, TypeError):
            valid = False
        return row.get('id') if valid else None

    paths, controls = [], {}

    def add(kind, evidence, missing, control, recommendation, observed):
        path_id = 'route-' + str(len(paths) + 1)
        supported = bool(evidence) and all(evidence)
        paths.append({'id': path_id, 'kind': kind, 'observed': observed,
                      'evidence_ids': [ref for ref in evidence if ref],
                      'state': 'potential_route' if supported and age['state'] == 'recent_snapshot' else 'reobserve_first',
                      'unverified_prerequisites': missing, 'exploitability': 'not_established',
                      'control_review': control})
        entry = controls.setdefault(control, {'id': control, 'recommendation': recommendation,
                                              'routes_to_investigate': [], 'authorization': 'none', 'executed': False})
        entry['routes_to_investigate'].append(path_id)

    listeners = observations.get('listeners', [])
    if isinstance(listeners, list):
        for row in listeners[:200]:
            if not isinstance(row, dict) or row.get('address') not in {'0.0.0.0', '::'}:
                continue
            owner = row.get('owner_identity', {})
            missing = ['Remote reachability and effective per-listener firewall policy.',
                       'A reachable vulnerability or unsafe authentication.',
                       'Socket-to-process association revalidated at action time.']
            if not isinstance(owner, dict) or owner.get('state') != 'observed':
                missing.append('Stable process ownership has not been observed.')
            add('network_to_listener', [reference('listeners')], missing,
                'review_listener_scope', 'Review intended listener clients and firewall scope; preserve required services.',
                'A TCP listener binds all interfaces; this does not prove Internet exposure.')
    posture = observations.get('windows_posture', {})
    if isinstance(posture, dict):
        for key, label in [('realtime_enabled', 'Real-time antivirus'), ('firewall_enabled', 'Windows firewall')]:
            if posture.get(key) is False:
                add('protection_gap', [reference('windows_posture')],
                    ['Managed policy and alternate protection.', 'A relevant attack attempt and vulnerable asset.'],
                    'review_' + key, 'Review managed policy and alternate protection before restoring ' + label + '.',
                    label + ' was reported disabled at this checkpoint.')
        cfa = posture.get('asr_cfa', {})
        if isinstance(cfa, dict) and cfa.get('cfa_mode') == 0:
            add('file_modification_control_gap', [reference('windows_posture')],
                ['An unauthorized writer, its permissions, and affected files.', 'Backup integrity and application compatibility.'],
                'review_cfa_compatibility', 'Review backups and Controlled Folder Access audit compatibility.',
                'Controlled Folder Access was reported disabled; an infection is not inferred.')
    dependencies = observations.get('dependency_review', {})
    if isinstance(dependencies, dict):
        packages = dependencies.get('packages', [])
        if isinstance(packages, list) and any(isinstance(row, dict) and row.get('advisory_ids') for row in packages[:100]):
            add('dependency_advisory', [reference('dependency_review')],
                ['Exact affected-version and reachable-function applicability.', 'Trusted compatible fix and rollback.'],
                'review_dependency_fixes', 'Check upstream applicability and a trusted compatible dependency update.',
                'Version advisory matches were recorded; exploitability is unverified.')
    # Greedy set cover orders investigations, not security effectiveness. Stable
    # tie breaking and no guessed attack probabilities or dollar loss values.
    uncovered = {row['id'] for row in paths}
    ordered = []
    while uncovered and controls:
        best = min(controls.values(), key=lambda row: (-len(set(row['routes_to_investigate']) & uncovered), row['id']))
        selected = set(best['routes_to_investigate']) & uncovered
        if not selected:
            break
        ordered.append(dict(best, newly_covered_route_count=len(selected)))
        uncovered -= selected
        controls.pop(best['id'])
    return {'schema_version': 1, 'freshness': age['state'], 'paths': paths, 'investigation_order': ordered,
            'uncovered_route_ids': sorted(uncovered), 'automation': 'recommendations_only',
            'method': 'Greedy grouping of observed review routes; not an optimal prevention or probability model.',
            'claims': 'Potential routes with explicit unknown prerequisites; no confirmed attack or containment inferred.'}
