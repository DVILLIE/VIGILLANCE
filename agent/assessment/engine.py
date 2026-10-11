"""Real local observations and one explicitly authorized origin review.

The assessment ledger is user-owned evidence, never privileged authorization.
No exploit runner, broad scanner, external upload or OS mutation is performed.
"""
from __future__ import annotations

import http.client
import importlib.metadata
import ipaddress
import json
import math
import platform
import queue
import socket
import sqlite3
import ssl
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import psutil

from agent.local_files import atomic_text, file_lock


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


class AssessmentStopped(RuntimeError):
    pass


_resolver_slot = threading.BoundedSemaphore(1)


def resolve_origin(host: str, port: int, scope, stop) -> list[str]:
    """Bound waiting and resolver concurrency even when an OS DNS call hangs."""
    if not _resolver_slot.acquire(blocking=False):
        raise TimeoutError("A previous DNS resolution has not returned.")
    results = queue.Queue(maxsize=1)

    def worker():
        try:
            results.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except Exception as exc:
            results.put(exc)
        finally:
            _resolver_slot.release()

    threading.Thread(target=worker, daemon=True, name="dvielle-scoped-dns").start()
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        scope.check(stop)
        try:
            result = results.get(timeout=0.1)
        except queue.Empty:
            continue
        if isinstance(result, Exception):
            raise result
        return sorted({row[4][0] for row in result})
    raise TimeoutError("Origin resolution exceeded eight seconds.")


@dataclass(frozen=True)
class AssessmentScope:
    """Immutable per-run scope; no saved grant can auto-start another run."""

    target: str = "local"
    authority: str = "Local computer read-only review"
    authorized: bool = False
    expires_at: float = 0
    share_runtime_versions: bool = False
    tls_handshake_only: bool = False
    require_hybrid: bool = False

    def origin(self) -> tuple[str, str, int]:
        if type(self.require_hybrid) is not bool or (self.require_hybrid and not self.tls_handshake_only):
            raise ValueError('Hybrid-only gate requires the HTTPS handshake measurement.')
        if type(self.tls_handshake_only) is not bool:
            raise ValueError('TLS measurement selection must be boolean.')
        if self.tls_handshake_only and not self.target.startswith('https://'):
            raise ValueError('TLS key exchange measurement requires an authorized HTTPS origin.')
        if self.target == "local":
            return "local", "", 0
        if self.authorized is not True or not isinstance(self.authority, str) or not self.authority.strip():
            raise ValueError("Confirm authority to assess this exact origin.")
        if (len(self.authority) > 1000 or not isinstance(self.target, str)
                or len(self.target) > 2048 or any(ord(c) < 33 for c in self.target)
                or not isinstance(self.expires_at, (int, float)) or not math.isfinite(self.expires_at)):
            raise ValueError("Invalid or unbounded authorization scope.")
        parsed = urlsplit(self.target)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            raise ValueError("Enter one HTTP(S) origin only, without credentials, paths or queries.")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        if len(host) > 253 or any(ord(c) < 33 for c in host):
            raise ValueError("Invalid origin host.")
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError("Invalid origin port.")
        return parsed.scheme, host, port

    def check(self, stop: threading.Event) -> None:
        if stop.is_set():
            raise AssessmentStopped("Stopped; no further checks initiated.")
        if self.share_runtime_versions and (self.authorized is not True
                or not isinstance(self.expires_at, (int, float)) or not math.isfinite(self.expires_at)):
            raise ValueError("Version-sharing authorization is unavailable.")
        if (self.target != "local" or self.share_runtime_versions) and datetime.now(timezone.utc).timestamp() >= self.expires_at:
            raise AssessmentStopped("Assessment authorization expired.")


def finding(kind: str, severity: str, observed: str, resolution: str,
            state: str = "observed") -> dict:
    sources = {"listener": "observations.listeners", "posture": "observations.windows_posture",
               "quantum_readiness": "observations.cryptography", "dependency": "observations.dependency_review",
               "web_header": "observations.security_headers", "transport": "scope.target"}
    return {"id": str(uuid4()), "kind": kind, "severity": severity,
            "state": state, "observed_at": utc(), "observation": observed,
            "resolution": resolution, "executed": False,
            "evidence_refs": [sources[kind]] if kind in sources else [],
            "confidence": "No statistical probability assigned"}


class AssessmentEngine:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.db = self.directory / "assessments.db"
        with self._conn() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, "
                         "started TEXT NOT NULL, finished TEXT, state TEXT NOT NULL, "
                         "scope TEXT NOT NULL, report TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS assessment_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute('CREATE INDEX IF NOT EXISTS assessment_started_idx ON runs(started DESC,id DESC)')

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db, timeout=5)
        conn.execute("PRAGMA synchronous=FULL")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def history(self, limit: int = 20) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT id,started,finished,state FROM runs "
                                "ORDER BY started DESC LIMIT ?", (max(1, min(limit, 100)),)).fetchall()
        return [dict(zip(("id", "started", "finished", "state"), row)) for row in rows]

    def report(self, run_id: str) -> dict:
        with self._conn() as conn:
            row = conn.execute("SELECT report FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown assessment.")
        return json.loads(row[0])

    def _save(self, report: dict, *, insert: bool = False) -> None:
        with self._conn() as conn:
            if insert:
                conn.execute("INSERT INTO runs VALUES (?,?,?,?,?,?)", (
                    report["id"], report["started"], None, report["state"],
                    json.dumps(report["scope"]), json.dumps(report)))
            else:
                conn.execute("UPDATE runs SET finished=?,state=?,report=? WHERE id=?", (
                    report.get("finished"), report["state"], json.dumps(report), report["id"]))

    def run(self, scope: AssessmentScope, stop: threading.Event | None = None) -> dict:
        stop = stop if stop is not None else threading.Event()
        scope.origin()  # fail closed before creating a run or initiating any request
        scope.check(stop)
        with file_lock(self.directory / "assessment.lock", timeout=0.1):
            from agent.assessment.resources import ProcessTreeSampler
            sampler = ProcessTreeSampler()
            sampler.sample()
            self._sampler = sampler
            self._reconcile_interrupted()
            report = {"schema_version": 1, "id": str(uuid4()), "started": utc(),
                      "state": "running", "scope": asdict(scope), "findings": [],
                      "observations": {}, "coverage": [], "mutations": [],
                      "claims": "Observed assessment only; no enforcement or exploitability certification."}
            self._save(report, insert=True)
            try:
                if scope.target == "local":
                    self._local(scope, stop, report)
                else:
                    self._web(scope, stop, report)
                scope.check(stop)
                report["state"] = "completed"
            except AssessmentStopped as exc:
                report["state"] = "stopped"
                report["detail"] = str(exc)
            except Exception as exc:
                report["state"] = "failed"
                report["detail"] = f"{type(exc).__name__}: assessment did not complete."
            report["finished"] = utc()
            sampler.sample()
            report['observations']['assessment_resources'] = sampler.report()
            from agent.assessment.evidence import update_evidence
            update_evidence(report)
            from agent.assessment.attack_paths import investigation_paths
            report['attack_path_review'] = investigation_paths(report)
            report["findings"].sort(key=lambda item: {"high": 0, "review": 1}.get(item["severity"], 2))
            self._save(report)
            from agent.assessment.history import HistoryPrivacy
            # A maintenance failure must not relabel successful observations or
            # silently discard their durable record.
            try:
                report['history_maintenance'] = HistoryPrivacy(self).maintain_locked(preserve_run_id=report['id'])
            except (OSError, sqlite3.Error, ValueError, TimeoutError):
                report['history_maintenance'] = {'state': 'unavailable', 'deleted_count': 'unknown'}
            self._save(report)
            return report

    def _reconcile_interrupted(self) -> None:
        # Called only while holding the exclusive run lock; another live run
        # cannot be mislabelled interrupted by a newly opened console.
        with self._conn() as conn:
            for run_id, encoded in conn.execute("SELECT id,report FROM runs WHERE state='running'").fetchall():
                prior = json.loads(encoded)
                prior.update(state="interrupted", finished=utc(),
                             detail="Previous worker ended before completion; findings are partial.")
                conn.execute("UPDATE runs SET state=?,finished=?,report=? WHERE id=?", (
                    prior["state"], prior["finished"], json.dumps(prior), run_id))

    def _checkpoint(self, scope, stop, report):
        scope.check(stop)
        self._sampler.sample()
        from agent.assessment.evidence import update_evidence
        update_evidence(report)
        self._save(report)

    def _local(self, scope, stop, report):
        obs = report["observations"]
        obs["platform"] = {"system": platform.system(), "release": platform.release(),
                           "version": platform.version(), "python": platform.python_version()}
        packages = []
        for name in ("cryptography", "psutil", "Pillow", "customtkinter", "PyYAML", "pywin32"):
            try:
                version = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                version = None
            packages.append({"name": name, "version": version, "ecosystem": "PyPI"})
        obs["runtime_packages"] = packages
        obs["cryptography"] = {"python_ssl_provider": ssl.OPENSSL_VERSION,
                               "tls13_runtime_support": ssl.HAS_TLSv1_3,
                               "post_quantum_exchange": "not_measured",
                               "post_quantum_authentication": "not_measured"}
        from agent.assessment.cryptography import post_quantum_provider_checks
        obs['cryptography']['local_provider_checks'] = post_quantum_provider_checks()
        report["coverage"].append("Runtime package inventory only; not an all-software census.")
        self._checkpoint(scope, stop, report)
        if scope.share_runtime_versions:
            from agent.assessment.dependencies import query_versions
            try:
                obs["dependency_review"] = query_versions(packages, scope, stop)
                for row in obs["dependency_review"]["packages"]:
                    if row["advisory_ids"]:
                        report["findings"].append(finding("dependency", "review",
                            f"OSV reports advisories for {row['name']} {row['version']}: "
                            + ", ".join(row["advisory_ids"]),
                            "Review upstream advisory applicability and fixed versions; validate a trusted update "
                            "before installing. Exploitability is not established."))
            except AssessmentStopped:
                raise
            except Exception as exc:
                obs["dependency_review"] = {"state": "unavailable", "error": type(exc).__name__}
                report["coverage"].append("Dependency lookup incomplete; no clean-dependency inference.")
        else:
            obs["dependency_review"] = {"state": "not_queried", "reason": "Version sharing was not authorized."}
        self._checkpoint(scope, stop, report)
        try:
            connections = psutil.net_connections(kind="inet")
            listeners = []
            from agent.assessment.process_identity import observe_process
            owner_observations = {}
            for connection in connections:
                if connection.status == psutil.CONN_LISTEN and connection.laddr:
                    address, port = connection.laddr.ip, connection.laddr.port
                    if connection.pid not in owner_observations:
                        owner_observations[connection.pid] = observe_process(connection.pid)
                    listeners.append({"address": address, "port": port, "pid": connection.pid,
                                      'owner_identity': dict(owner_observations[connection.pid])})
                    if address in {"0.0.0.0", "::"}:
                        report["findings"].append(finding("listener", "review",
                            f"A listener on port {port} binds all interfaces.",
                            "Identify the owning application and intended clients; review firewall scope. "
                            "A wildcard listener alone does not establish internet reachability."))
                if len(listeners) >= 200:
                    break
            obs["listeners"] = listeners
            report["coverage"].append("TCP listeners observed; UDP exposure and external reachability not established.")
        except (psutil.AccessDenied, OSError):
            report["coverage"].append("Listener observation unavailable; no clean-network inference.")
        self._checkpoint(scope, stop, report)
        if platform.system() == "Windows":
            from agent.modules.security import _query_firewall
            from agent.modules.defender_health import query_defender_health
            from agent.modules.prevention import query_prevention_posture, DRIVER_GUID, LSASS_GUID
            health = query_defender_health()
            antivirus, realtime = health.antivirus_enabled, health.realtime_protection
            self._checkpoint(scope, stop, report)
            firewall, profiles = _query_firewall()
            obs["windows_posture"] = {"antivirus_enabled": antivirus,
                                      "realtime_enabled": realtime,
                                      "firewall_enabled": firewall, "profiles": profiles}
            health_fields = ("coverage", "am_running_mode", "signature_age_days", "signature_last_updated",
                             "signature_version", "engine_version", "product_version", "signatures_out_of_date",
                             "active_mode", "realtime", "query_state")
            obs["windows_posture"]["defender_health"] = {key: getattr(health, key) for key in health_fields}
            if health.coverage != "complete":
                report["coverage"].append("Defender health observation is incomplete; unread fields remain unknown.")
            if health.signatures_out_of_date is True:
                report["findings"].append(finding("posture", "high",
                    "Defender reports its signatures out of date.",
                    "Review the installed antivirus and managed update policy; obtain a trusted definition update."))
            for label, value in (("Defender real-time protection", realtime), ("Windows firewall", firewall)):
                if value is False:
                    report["findings"].append(finding("posture", "high",
                        f"{label} reports disabled.",
                        "Check managed policy and third-party protection before changing settings."))
                elif value is None:
                    report["coverage"].append(f"{label}: query unavailable; state unknown.")
            self._checkpoint(scope, stop, report)
            posture = query_prevention_posture()
            obs["windows_posture"]["asr_cfa"] = {"coverage": posture.coverage, "rules": posture.rules,
                                                  "cfa_mode": posture.cfa_mode, "cfa_mode_name": posture.cfa_mode_name}
            if posture.coverage != "complete":
                report["coverage"].append("ASR/CFA collection incomplete; no complete-prevention inference.")
            if posture.cfa_mode == 0:
                report["findings"].append(finding("posture", "review",
                    "Controlled folder access reports Disabled.",
                    "Review application compatibility and recovery backups before considering Audit or Enabled mode. "
                    "This control does not prevent reading or exfiltration."))
            for guid, label in ((DRIVER_GUID, "Vulnerable signed-driver ASR rule"),
                                (LSASS_GUID, "LSASS credential-access ASR rule")):
                action = posture.rules.get(guid)
                if action in {0, 2, 5, 6}:
                    report["findings"].append(finding("posture", "review",
                        f"{label} has observed action {action}; it is not configured in Block mode.",
                        "Review effective protection, managed policy and audit compatibility before changing this rule."))
            self._checkpoint(scope, stop, report)
        report["findings"].append(finding("quantum_readiness", "review",
            "Runtime cryptographic provider recorded; post-quantum exchange and authentication were not measured.",
            "Inventory actual protocols and peers, then verify supported negotiated exchange and authentication separately."))
        report["coverage"].append("Privileged remediation unavailable in this workspace; no Windows policy was changed.")

    def _web(self, scope, stop, report):
        scheme, host, port = scope.origin()
        scope.check(stop)
        addresses = resolve_origin(host, port, scope, stop)
        if not addresses or len(addresses) > 16:
            raise ValueError("Origin resolution exceeded its allowed address set.")
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if ip.is_multicast or ip.is_unspecified or ip.is_link_local:
                raise ValueError("Unsupported address scope.")
        # Pin the connection to one resolved address. No second DNS resolution,
        # proxy environment, redirect following, crawl, or authentication upload.
        scope.check(stop)
        address = addresses[0]
        if scope.tls_handshake_only:
            from agent.assessment.tls_observer import observe
            observed = observe(host, address, port, checkpoint=lambda: scope.check(stop),
                               require_hybrid=scope.require_hybrid)
            report['observations']['tls'] = {key: value for key, value in observed.items()
                if key not in {'host', 'address', 'mutations', 'observed_at'}}
            report['observations'].update(resolved_addresses=addresses, connected_address=address)
            report['coverage'].append('One verified TLS handshake to the authorized origin; no HTTP request or policy mutation.')
            if observed['peer_certificate'].get('quantum_migration') == 'review_classical_certificate_key':
                item = finding('quantum_readiness', 'review',
                    'The measured TLS connection presents a classical certificate key.',
                    'Treat hybrid key exchange and certificate authentication as separate migration requirements.')
                item['evidence_refs'] = ['observations.tls']
                report['findings'].append(item)
            return
        connection = http.client.HTTPConnection(host, port, timeout=8)
        try:
            raw = socket.create_connection((address, port), timeout=8)
            connection.sock = raw
            if scheme == "https":
                from agent.assessment.cryptography import assessment_tls_context
                connection.sock = assessment_tls_context().wrap_socket(raw, server_hostname=host)
                report["observations"]["tls"] = {
                    "version": connection.sock.version(), "cipher": connection.sock.cipher(),
                    "certificate_expires": connection.sock.getpeercert().get("notAfter"),
                    "certificate_chain": "verified_by_default_provider",
                    "post_quantum_exchange": "not_exposed_by_this_adapter",
                    "post_quantum_authentication": "not_measured"}
                try:
                    from agent.assessment.cryptography import certificate_inventory
                    certificate = certificate_inventory(connection.sock.getpeercert(binary_form=True))
                    report["observations"]["tls"]["peer_certificate"] = certificate
                    if certificate["quantum_migration"] == "review_classical_certificate_key":
                        item = finding("quantum_readiness", "review",
                            f"The observed certificate uses a classical {certificate['public_key_algorithm']} public key.",
                            "Review certificate authentication migration alongside key exchange; "
                            "do not infer post-quantum negotiation from TLS version or cipher name.")
                        item["evidence_refs"] = ["observations.tls.peer_certificate"]
                        report["findings"].append(item)
                except (ValueError, TypeError, ImportError, NotImplementedError):
                    report["observations"]["tls"]["peer_certificate"] = {"state": "unavailable"}
                    report["coverage"].append("Certificate algorithm inventory unavailable; quantum properties unknown.")
            scope.check(stop)
            connection.request("HEAD", "/", headers={"User-Agent": "DVielle-Authorized-Assessment/1", "Connection": "close"})
            response = connection.getresponse()
            allowed = ("strict-transport-security", "content-security-policy", "x-content-type-options",
                       "x-frame-options", "referrer-policy", "permissions-policy")
            headers = {key: response.getheader(key, "")[:2048] for key in allowed}
            report["observations"].update(http_status=response.status, security_headers=headers,
                                           resolved_addresses=addresses, connected_address=address)
            report["coverage"].append("One HEAD request to the authorized origin root; no redirects or exploitation.")
            if 300 <= response.status < 400:
                report["coverage"].append("Redirect observed but not followed; destination was not assessed.")
            for key in ("content-security-policy", "x-content-type-options", "referrer-policy"):
                if not headers[key]:
                    report["findings"].append(finding("web_header", "review",
                        f"{key} absent in this HEAD response.",
                        "Review application context and representative GET responses before changing configuration."))
            if scheme == "http":
                report["findings"].append(finding("transport", "high",
                    "This authorized origin uses unencrypted HTTP.", "Enable a supported HTTPS endpoint and verify its certificate."))
            report["coverage"].append("Header observations do not establish exploitability or application-wide coverage.")
        finally:
            connection.close()
        self._checkpoint(scope, stop, report)

    def export(self, run_id: str, destination: Path, *, include_identifiers: bool = False) -> None:
        report = self.report(run_id)
        if not include_identifiers:
            report["scope"]["target"] = "local" if report["scope"]["target"] == "local" else "[redacted origin]"
            report["scope"]["authority"] = "[redacted]"
            obs = report["observations"]
            obs.pop("resolved_addresses", None)
            obs.pop("connected_address", None)
            obs.get("tls", {}).get("peer_certificate", {}).pop("certificate_sha256", None)
            if "security_headers" in obs:
                obs["security_headers"] = {key: "present" if value else "absent"
                                           for key, value in obs["security_headers"].items()}
            for listener in obs.get("listeners", []):
                listener["address"] = "[redacted]"
                listener["pid"] = None
                if 'owner_identity' in listener:
                    listener['owner_identity'] = {'state': 'redacted',
                        'meaning': 'Process identifiers, creation time and name removed from export.'}
            # Re-derive payload digests after redaction so raw private-value
            # hashes are not retained in a public export.
            from agent.assessment.evidence import update_evidence
            update_evidence(report)
        report["export"] = {"created": utc(), "identifiers_included": include_identifiers}
        from agent.assessment.attack_paths import investigation_paths
        report['attack_path_review'] = investigation_paths(report)
        atomic_text(Path(destination), json.dumps(report, indent=2, ensure_ascii=False))
