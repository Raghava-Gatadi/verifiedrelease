"""Fail-closed release policy. Cryptographic verification belongs in verify.py."""
import argparse
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCHEMA = 1
SECURITY_TYPE = 'https://tenantledger.dev/attestations/security/v1'
PROVENANCE_TYPE = 'https://slsa.dev/provenance/v1'
SBOM_TYPE = 'https://spdx.dev/Document'
SCANNERS = {'bandit', 'pip-audit', 'gitleaks', 'grype', 'container-config'}


class Denied(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Denied(reason)


def read_json(path):
    return json.loads(Path(path).read_text())


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def timestamp(value):
    require(isinstance(value, str), 'Timestamp must be an RFC3339 string')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Denied('Invalid timestamp') from exc
    require(parsed.tzinfo is not None, 'Timestamp requires a timezone')
    return parsed.astimezone(UTC)


def image_parts(image):
    require(isinstance(image, str), 'Image must be a string')
    match = re.fullmatch(r'([a-z0-9][a-z0-9.:/_-]*)@sha256:([0-9a-f]{64})', image)
    require(match is not None, 'A repository@sha256:digest is required; tags are forbidden')
    return match.group(1), match.group(2)


def validate_exceptions(document, policy, now):
    require(document.get('schemaVersion') == SCHEMA, 'Unsupported exception schema')
    entries = document.get('exceptions')
    require(isinstance(entries, list), 'Missing exceptions list')
    ids = set()
    for entry in entries:
        require(isinstance(entry, dict), 'Malformed exception')
        for field in ['id', 'owner', 'reason', 'approvedBy', 'ticket', 'scanner', 'findingId', 'package', 'version', 'imageDigest']:
            require(isinstance(entry.get(field), str) and entry[field].strip(), f'Exception requires {field}')
        require(entry['id'] not in ids, 'Duplicate exception ID')
        ids.add(entry['id'])
        require(entry['owner'] != entry['approvedBy'], 'Exception requires an independent approver')
        require(entry['ticket'].startswith('https://'), 'Exception requires a review ticket URL')
        require(entry['scanner'] in policy['exceptionScanners'], 'This scanner cannot be exempted')
        require(re.fullmatch(r'sha256:[0-9a-f]{64}', entry['imageDigest']) is not None, 'Exception must match one image digest')
        issued, expires = timestamp(entry.get('createdAt')), timestamp(entry.get('expiresAt'))
        require(issued <= now < expires, f'Exception {entry["id"]} is expired or not yet active')
        require(timedelta(0) < expires - issued <= timedelta(days=policy['maxExceptionDays']), 'Exception lifetime exceeds policy')
    return entries


def evaluate(evidence, policy, exceptions, image, commit, now=None):
    now = now or datetime.now(UTC)
    require(policy.get('schemaVersion') == SCHEMA, 'Unsupported policy schema')
    repository, digest = image_parts(image)
    require(repository == policy['imageRepository'], 'Unexpected image repository')
    require(re.fullmatch(r'[0-9a-f]{40}', commit) is not None, 'Expected commit must be a full Git SHA')
    require(evidence.get('schemaVersion') == SCHEMA, 'Unsupported security evidence schema')
    require(evidence.get('image') == image, 'Security evidence image digest mismatch')
    require(evidence.get('sourceCommit') == commit, 'Security evidence source commit mismatch')
    age = now - timestamp(evidence.get('scannedAt'))
    require(timedelta(minutes=-5) <= age <= timedelta(hours=policy['maxEvidenceAgeHours']), 'Security evidence is stale or from the future')
    scans = evidence.get('scanners')
    require(isinstance(scans, dict) and set(scans) == SCANNERS, 'Required scanner evidence is missing or unknown')
    require(set(policy['requiredScanners']) == SCANNERS, 'Policy cannot silently remove required scanners')
    for name, scan in scans.items():
        require(scan.get('completed') is True, f'{name}: scan did not complete')
        require(isinstance(scan.get('version'), str) and scan['version'].strip(), f'{name}: scanner version missing')
        require(re.fullmatch(r'[0-9a-f]{64}', scan.get('reportSha256', '')) is not None, f'{name}: raw report digest missing')
    database_age = now - timestamp(scans['grype'].get('databaseBuiltAt'))
    require(timedelta(minutes=-5) <= database_age <= timedelta(hours=policy['maxVulnerabilityDatabaseAgeHours']), 'Vulnerability database is stale or from the future')
    require(re.fullmatch(r'[0-9a-f]{64}', evidence.get('sbomCanonicalSha256', '')) is not None, 'SBOM digest is missing')
    findings = evidence.get('findings')
    require(isinstance(findings, list), 'Missing findings list')
    entries = validate_exceptions(exceptions, policy, now)
    denied, waived = [], []
    for finding in findings:
        require(isinstance(finding, dict), 'Malformed finding')
        for field in ['scanner', 'id', 'package', 'version', 'severity']:
            require(isinstance(finding.get(field), str) and finding[field].strip(), f'Finding requires {field}')
        scanner, severity = finding['scanner'], finding['severity']
        require(scanner in SCANNERS, 'Unknown scanner finding')
        require(severity in {'NEGLIGIBLE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'}, 'Unknown severity')
        if severity not in policy['denySeverities'][scanner]:
            continue
        matches = [e for e in entries if scanner in policy['exceptionScanners']
                   and severity in policy['exceptionSeverities']
                   and e['scanner'] == scanner and e['findingId'] == finding['id']
                   and e['package'] == finding['package'] and e['version'] == finding['version']
                   and e['imageDigest'] == f'sha256:{digest}']
        if matches:
            waived.append({'finding': finding['id'], 'exception': matches[0]['id'], 'expiresAt': matches[0]['expiresAt']})
        else:
            denied.append(f'{scanner}:{finding["id"]}:{finding["package"]}:{severity}')
    require(not denied, 'Release policy denied: ' + ', '.join(denied))
    return {'decision': 'allow', 'image': image, 'sourceCommit': commit, 'exceptionsApplied': waived,
            'evaluatedAt': now.isoformat()}


def validate_statement(statement, predicate_type, image):
    repository, digest = image_parts(image)
    require(statement.get('_type') in {'https://in-toto.io/Statement/v1', 'https://in-toto.io/Statement/v0.1'}, 'Invalid in-toto statement')
    require(statement.get('predicateType') == predicate_type, 'Wrong predicate type')
    subjects = statement.get('subject')
    require(isinstance(subjects, list) and len(subjects) == 1, 'Exactly one artifact subject is required')
    require(subjects[0].get('name') == repository and subjects[0].get('digest') == {'sha256': digest}, 'Attestation subject digest/repository mismatch')
    require(isinstance(statement.get('predicate'), dict), 'Missing attestation predicate')
    return statement['predicate']


def validate_provenance(predicate, policy, commit):
    definition = predicate.get('buildDefinition', {})
    require(definition.get('buildType') == policy['buildType'], 'Unexpected build type')
    expected = {'repository': policy['repository'], 'ref': policy['sourceRef'], 'commit': commit}
    require(definition.get('externalParameters') == expected, 'Unexpected provenance source/ref/commit')
    require({'uri': policy['repository'], 'digest': {'gitCommit': commit}} in definition.get('resolvedDependencies', []), 'Source material missing from provenance')
    require(predicate.get('runDetails', {}).get('builder', {}).get('id') == policy['certificateIdentity'], 'Unexpected provenance builder')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--policy', default='security/release-policy.json')
    parser.add_argument('--exceptions', default='security/exceptions.json')
    args = parser.parse_args()
    try:
        print(json.dumps(evaluate(read_json(args.evidence), read_json(args.policy), read_json(args.exceptions), args.image, args.commit), indent=2))
    except (Denied, KeyError, TypeError, ValueError) as exc:
        raise SystemExit(f'DENY: {exc}') from exc


if __name__ == '__main__':
    main()
