"""Adversarial tests for admission decisions; no database fixtures required."""
import base64
import copy
import json
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts/release'))
from policy import (
    PROVENANCE_TYPE,
    SCANNERS,
    Denied,
    evaluate,
    read_json,
    validate_provenance,
    validate_statement,
)
from provenance import create
from verify import VerificationError, production_flags, statements, verify

ROOT = Path(__file__).resolve().parents[1]


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 30, 12, tzinfo=UTC)
        self.policy = read_json(ROOT / 'security/release-policy.json')
        self.image = self.policy['imageRepository'] + '@sha256:' + 'a' * 64
        self.commit = 'b' * 40
        self.exceptions = {'schemaVersion': 1, 'exceptions': []}
        self.evidence = {
            'schemaVersion': 1, 'image': self.image, 'sourceCommit': self.commit,
            'scannedAt': self.now.isoformat(), 'findings': [], 'sbomCanonicalSha256': 'd' * 64,
            'scanners': {s: {'completed': True, 'version': '1', 'reportSha256': 'c' * 64} for s in SCANNERS},
        }
        self.evidence['scanners']['grype']['databaseBuiltAt'] = self.now.isoformat()
        self.finding = {'scanner': 'grype', 'id': 'CVE-TEST-001', 'package': 'demo', 'version': '1', 'severity': 'HIGH'}
        self.exception = {
            'id': 'EX-001', 'owner': '@service-owner', 'approvedBy': '@security-reviewer',
            'reason': 'Temporary controlled test; remediation is tracked.', 'ticket': 'https://example.test/review/1',
            'scanner': 'grype', 'findingId': 'CVE-TEST-001', 'package': 'demo', 'version': '1',
            'imageDigest': 'sha256:' + 'a' * 64, 'createdAt': self.now.isoformat(),
            'expiresAt': (self.now + timedelta(days=2)).isoformat(),
        }

    def decision(self):
        return evaluate(self.evidence, self.policy, self.exceptions, self.image, self.commit, self.now)

    def test_clean_artifact_is_allowed(self):
        self.assertEqual(self.decision()['decision'], 'allow')

    def test_tags_are_never_admitted(self):
        self.image = self.policy['imageRepository'] + ':latest'
        with self.assertRaisesRegex(Denied, 'tags are forbidden'):
            self.decision()

    def test_wrong_registry_is_rejected(self):
        self.image = 'attacker.test/tenantledger@sha256:' + 'a' * 64
        with self.assertRaisesRegex(Denied, 'Unexpected image repository'):
            self.decision()

    def test_wrong_artifact_digest_is_rejected(self):
        self.evidence['image'] = self.image[:-1] + 'd'
        with self.assertRaisesRegex(Denied, 'digest mismatch'):
            self.decision()

    def test_wrong_commit_is_rejected(self):
        self.evidence['sourceCommit'] = 'e' * 40
        with self.assertRaisesRegex(Denied, 'commit mismatch'):
            self.decision()

    def test_all_scanners_are_mandatory(self):
        for name in SCANNERS:
            with self.subTest(name=name):
                original = self.evidence['scanners'].pop(name)
                with self.assertRaisesRegex(Denied, 'scanner evidence'):
                    self.decision()
                self.evidence['scanners'][name] = original

    def test_scanner_errors_and_missing_hashes_are_rejected(self):
        for field, value in [('completed', False), ('completed', 'true'), ('reportSha256', ''), ('version', '')]:
            with self.subTest(field=field, value=value):
                original = self.evidence['scanners']['grype'][field]
                self.evidence['scanners']['grype'][field] = value
                with self.assertRaises(Denied):
                    self.decision()
                self.evidence['scanners']['grype'][field] = original

    def test_stale_future_and_timezone_free_reports_are_rejected(self):
        for value in [(self.now - timedelta(hours=25)).isoformat(), (self.now + timedelta(hours=1)).isoformat(), '2026-10-30T12:00:00']:
            with self.subTest(value=value):
                self.evidence['scannedAt'] = value
                with self.assertRaises(Denied):
                    self.decision()

    def test_stale_vulnerability_database_blocks(self):
        self.evidence['scanners']['grype']['databaseBuiltAt'] = (self.now - timedelta(days=4)).isoformat()
        with self.assertRaisesRegex(Denied, 'database is stale'):
            self.decision()

    def test_missing_sbom_digest_blocks(self):
        self.evidence.pop('sbomCanonicalSha256')
        with self.assertRaisesRegex(Denied, 'SBOM digest'):
            self.decision()

    def test_high_vulnerability_blocks(self):
        self.evidence['findings'] = [self.finding]
        with self.assertRaisesRegex(Denied, 'Release policy denied'):
            self.decision()

    def test_exact_exception_allows_and_records_waiver(self):
        self.evidence['findings'] = [self.finding]
        self.exceptions['exceptions'] = [self.exception]
        self.assertEqual(self.decision()['exceptionsApplied'][0]['exception'], 'EX-001')

    def test_expired_exception_blocks_even_without_findings(self):
        self.exception['expiresAt'] = self.now.isoformat()
        self.exceptions['exceptions'] = [self.exception]
        with self.assertRaisesRegex(Denied, 'expired'):
            self.decision()

    def test_overlong_exception_blocks(self):
        self.exception['expiresAt'] = (self.now + timedelta(days=15)).isoformat()
        self.exceptions['exceptions'] = [self.exception]
        with self.assertRaisesRegex(Denied, 'lifetime'):
            self.decision()

    def test_exception_requires_owner_reason_and_independent_review(self):
        for field in ['owner', 'reason', 'ticket', 'approvedBy']:
            with self.subTest(field=field):
                item = copy.deepcopy(self.exception)
                item.pop(field)
                self.exceptions['exceptions'] = [item]
                with self.assertRaises(Denied):
                    self.decision()
        self.exception['approvedBy'] = self.exception['owner']
        self.exceptions['exceptions'] = [self.exception]
        with self.assertRaisesRegex(Denied, 'independent'):
            self.decision()

    def test_exception_cannot_cover_other_digest_package_version_or_id(self):
        self.evidence['findings'] = [self.finding]
        for field, value in [('imageDigest', 'sha256:' + 'f' * 64), ('package', 'other'), ('version', '2'), ('findingId', 'other')]:
            with self.subTest(field=field):
                item = {**self.exception, field: value}
                self.exceptions['exceptions'] = [item]
                with self.assertRaisesRegex(Denied, 'policy denied'):
                    self.decision()

    def test_critical_vulnerability_cannot_be_excepted(self):
        self.finding['severity'] = 'CRITICAL'
        self.evidence['findings'] = [self.finding]
        self.exceptions['exceptions'] = [self.exception]
        with self.assertRaisesRegex(Denied, 'policy denied'):
            self.decision()

    def test_secrets_cannot_be_excepted(self):
        self.exception['scanner'] = 'gitleaks'
        self.exceptions['exceptions'] = [self.exception]
        with self.assertRaisesRegex(Denied, 'cannot be exempted'):
            self.decision()

    def test_malformed_finding_is_not_treated_as_clean(self):
        for item in [{}, {'severity': 'UNRECOGNIZED'}, None]:
            self.evidence['findings'] = [item]
            with self.assertRaises(Denied):
                self.decision()

    def test_provenance_binds_builder_source_and_commit(self):
        predicate = create(self.policy, self.commit, 'https://example.test/run/1')
        validate_provenance(predicate, self.policy, self.commit)
        for field in ['repository', 'ref', 'commit']:
            modified = copy.deepcopy(predicate)
            modified['buildDefinition']['externalParameters'][field] = 'unexpected'
            with self.assertRaises(Denied):
                validate_provenance(modified, self.policy, self.commit)
        predicate['runDetails']['builder']['id'] = 'attacker'
        with self.assertRaisesRegex(Denied, 'builder'):
            validate_provenance(predicate, self.policy, self.commit)

    def test_attestation_subject_binds_digest(self):
        statement = {'_type': 'https://in-toto.io/Statement/v1', 'predicateType': PROVENANCE_TYPE,
                     'subject': [{'name': self.policy['imageRepository'], 'digest': {'sha256': 'f' * 64}}], 'predicate': {}}
        with self.assertRaisesRegex(Denied, 'subject digest'):
            validate_statement(statement, PROVENANCE_TYPE, self.image)

    def test_cosign_dsse_output_is_decoded(self):
        value = {'_type': 'https://in-toto.io/Statement/v1'}
        raw = json.dumps({'payload': base64.b64encode(json.dumps(value).encode()).decode()})
        self.assertEqual(statements(raw), [value])
        with self.assertRaises(Denied):
            statements('{}')

    def test_exact_identity_issuer_and_source_sha_are_passed_to_cosign(self):
        flags = production_flags(self.policy, self.commit)
        self.assertIn(self.policy['certificateIdentity'], flags)
        self.assertIn(self.policy['oidcIssuer'], flags)
        self.assertIn(self.commit, flags)
        self.assertNotIn('--certificate-identity-regexp', flags)
        self.assertFalse(any('insecure' in f for f in flags))

    @patch('verify.cosign')
    def test_unsigned_and_wrong_signer_abort_before_policy(self, mock_cosign):
        mock_cosign.side_effect = VerificationError('SIGNATURE', 'no matching signatures')
        with self.assertRaisesRegex(VerificationError, 'no matching'):
            verify(self.image, self.commit, self.policy, self.exceptions, production_flags(self.policy, self.commit))
        self.assertEqual(mock_cosign.call_count, 1)


if __name__ == '__main__':
    unittest.main()
