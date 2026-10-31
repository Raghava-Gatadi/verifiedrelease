"""Run focused scanners and preserve raw reports; scanner errors always block."""
import argparse
import hashlib
import importlib.metadata
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from policy import SCHEMA, canonical_sha256, require, sha256_file


def run(command, output=None, allowed=(0,)):
    result = subprocess.run(command, text=True, capture_output=True, timeout=900, check=False)
    if output:
        Path(output).write_text(result.stdout)
    if result.returncode not in allowed:
        raise RuntimeError(f'{command[0]} failed ({result.returncode}): {result.stderr[-3000:]}')
    return result.stdout


def scan(image, commit, output):
    output.mkdir(parents=True, exist_ok=True)
    # Remove old evidence first so a failed rerun cannot leave an apparently valid result.
    for filename in ['security.json', 'bandit.json', 'dependencies.json', 'secrets-history.json',
                     'secrets-tree.json', 'secrets.json', 'sbom.spdx.json', 'container.json', 'container-config.json']:
        (output / filename).unlink(missing_ok=True)
    reports, findings = {}, []

    def record(name, filename, version):
        reports[name] = {'completed': True, 'version': version, 'reportSha256': sha256_file(output / filename)}

    def finding(scanner, identifier, package, version, severity):
        findings.append({'scanner': scanner, 'id': identifier, 'package': package or '(unknown)',
                         'version': version or '(unknown)', 'severity': severity.upper()})

    run([sys.executable, '-m', 'bandit', '-r', 'app', 'alembic', '-f', 'json', '-o', str(output / 'bandit.json')], allowed=(0, 1))
    bandit = json.loads((output / 'bandit.json').read_text())
    require(bandit['errors'] == [] and bandit['metrics']['_totals']['loc'] > 0, 'Bandit failed to scan source')
    for item in bandit['results']:
        finding('bandit', item['test_id'], item['filename'], str(item['line_number']), item['issue_severity'])
    record('bandit', 'bandit.json', importlib.metadata.version('bandit'))

    run([sys.executable, '-m', 'pip_audit', '-r', 'requirements.lock', '--require-hashes', '--no-deps',
         '--disable-pip', '--cache-dir', str(output / 'audit-cache'), '--format', 'json', '--output', str(output / 'dependencies.json')], allowed=(0, 1))
    dependencies = json.loads((output / 'dependencies.json').read_text())['dependencies']
    require(len(dependencies) > 0, 'Dependency report is empty')
    for item in dependencies:
        require('skip_reason' not in item and isinstance(item['vulns'], list), 'Dependency was not audited')
        for vuln in item['vulns']:
            # pip-audit does not supply consistent severity. Every advisory is blocking by default.
            finding('pip-audit', vuln['id'], item['name'], item['version'], 'UNKNOWN')
    record('pip-audit', 'dependencies.json', importlib.metadata.version('pip-audit'))

    # Scan full Git history and a clean snapshot of the current source tree.
    run(['gitleaks', 'git', '.', '--log-opts=--all', '--redact', '--report-format', 'json',
         '--report-path', str(output / 'secrets-history.json'), '--no-banner'], allowed=(0, 1))
    source_hash = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='tenantledger-source-') as temporary:
        files = run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard']).split('\0')
        for filename in sorted(filter(None, files)):
            source = Path(filename)
            if source.is_file() and not source.is_symlink():
                target = Path(temporary) / source
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                source_hash.update(filename.encode() + b'\0' + hashlib.sha256(source.read_bytes()).digest())
        run(['gitleaks', 'dir', temporary, '--redact', '--report-format', 'json',
             '--report-path', str(output / 'secrets-tree.json'), '--no-banner'], allowed=(0, 1))
    history = json.loads((output / 'secrets-history.json').read_text())
    tree = json.loads((output / 'secrets-tree.json').read_text())
    require(isinstance(history, list) and isinstance(tree, list), 'Invalid secret report')
    (output / 'secrets.json').write_text(json.dumps(history + tree, indent=2))
    for item in history + tree:
        finding('gitleaks', item['RuleID'], item['File'], item.get('Commit') or 'working-tree', 'CRITICAL')
    record('gitleaks', 'secrets.json', run(['gitleaks', 'version']).strip())

    run(['syft', 'scan', f'registry:{image}', '-o', 'spdx-json'], output / 'sbom.spdx.json')
    sbom = json.loads((output / 'sbom.spdx.json').read_text())
    require(sbom.get('spdxVersion', '').startswith('SPDX-2.') and len(sbom.get('packages', [])) > 0, 'Incomplete SBOM')
    run(['grype', f'registry:{image}', '-o', 'json'], output / 'container.json')
    container = json.loads((output / 'container.json').read_text())
    require(isinstance(container['matches'], list) and container['descriptor']['name'] == 'grype', 'Invalid container report')
    for item in container['matches']:
        finding('grype', item['vulnerability']['id'], item['artifact']['name'], item['artifact']['version'], item['vulnerability']['severity'])
    database = container['descriptor']['db']['status']
    require(database.get('valid') is True, 'Vulnerability database is invalid')
    record('grype', 'container.json', container['descriptor']['version'])
    reports['grype']['databaseBuiltAt'] = database['built']

    run(['docker', 'pull', image])
    run(['docker', 'image', 'inspect', image], output / 'container-config.json')
    config = json.loads((output / 'container-config.json').read_text())[0]['Config']
    checks = {'non-root': config.get('User') == '10001:10001',
              'healthcheck': bool(config.get('Healthcheck', {}).get('Test')),
              'entrypoint': (config.get('Cmd') or [None])[0] == 'uvicorn'}
    for name, passed in checks.items():
        if not passed:
            finding('container-config', name, 'runtime', '1', 'CRITICAL')
    record('container-config', 'container-config.json', '1')
    evidence = {'schemaVersion': SCHEMA, 'image': image, 'sourceCommit': commit,
                'scannedAt': datetime.now(UTC).isoformat(), 'scanners': reports, 'findings': findings,
                'sbomSha256': sha256_file(output / 'sbom.spdx.json'), 'sbomCanonicalSha256': canonical_sha256(sbom),
                'sourceTreeSha256': source_hash.hexdigest(),
                'workingTreeDirty': bool(run(['git', 'status', '--porcelain']).strip())}
    (output / 'security.json').write_text(json.dumps(evidence, indent=2) + '\n')
    return evidence


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', type=Path, default=Path('artifacts/release'))
    args = parser.parse_args()
    scan(args.image, args.commit, args.output)
