"""Run the finite safety model and a deliberately unsafe model negative control.

Neither execution mutates Windows policy. Model traces are not real attacks.
"""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    tools = ROOT / 'dist' / 'formal-tools-20261010'
    provenance = json.loads((ROOT / 'docs/implementation/FORMAL_TOOL_PROVENANCE_2026-10-10.json').read_text())
    jar = tools / 'tla2tools.jar'
    if hashlib.sha256(jar.read_bytes()).hexdigest() != provenance['tla']['sha256']:
        raise ValueError('TLC development artifact changed')
    java = next(tools.glob('*/bin/java.exe'))
    model_dir = ROOT / 'docs/formal'
    evidence = ROOT / 'docs/implementation'
    def run(directory, name, log):
        result = subprocess.run([str(java), '-Xmx256m', '-cp', str(jar), 'tlc2.TLC',
            '-workers', '1', '-config', name + '.cfg', name + '.tla'],
            cwd=directory, capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr
        (evidence / log).write_text(output, encoding='utf-8')
        return result.returncode, output
    code, output = run(model_dir, 'ScopedMutation', 'TLC_SCOPED_MUTATION_FINAL_2026-10-10.txt')
    if code != 0 or 'Model checking completed. No error has been found.' not in output:
        raise ValueError('Finite safety model did not pass')
    negative = ROOT / 'dist/formal-negative-control'
    negative.mkdir(exist_ok=True)
    model = (model_dir / 'ScopedMutation.tla').read_text()
    guard = "effect' = IF effect = g THEN \"absent\" ELSE effect"
    if model.count(guard) != 1:
        raise ValueError('Expected exact modeled restoration guard')
    unsafe = model.replace('MODULE ScopedMutation', 'MODULE UnsafeRestore').replace(guard, "effect' = \"absent\"")
    (negative / 'UnsafeRestore.tla').write_text(unsafe)
    (negative / 'UnsafeRestore.cfg').write_text((model_dir / 'ScopedMutation.cfg').read_text())
    bad_code, bad_output = run(negative, 'UnsafeRestore', 'TLC_UNSAFE_RESTORE_NEGATIVE_CONTROL_2026-10-10.txt')
    if bad_code == 0 or 'Action property ExternalOwnershipPreserved is violated.' not in bad_output:
        raise ValueError('Unsafe model negative control was not detected')
    result = {'finite_model': 'passed', 'unsafe_restore_negative_control': 'counterexample_detected',
        'production_changes': False, 'windows_enforcement': 'not_measured',
        'source_sha256': hashlib.sha256(model.encode()).hexdigest(),
        'config_sha256': hashlib.sha256((model_dir / 'ScopedMutation.cfg').read_bytes()).hexdigest()}
    (evidence / 'FORMAL_VERIFICATION_RESULT_2026-10-10.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
