"""Real registry/Cosign rejection lab. Local keys are never accepted by deploy.py."""
import argparse
import copy
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from policy import PROVENANCE_TYPE, SBOM_TYPE, SECURITY_TYPE, Denied, image_parts, read_json, require
from provenance import create
from verify import VerificationError, verify


def run(command, env, log):
    result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=300, check=False)
    with log.open('a') as stream:
        stream.write('$ ' + ' '.join(str(c) for c in command) + '\n' + result.stdout + result.stderr + '\n')
    if result.returncode:
        raise RuntimeError(f'{command[0]} failed; see {log}')
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-image', default='tenantledger:release-candidate', help='Already-built local image')
    parser.add_argument('--evidence', type=Path, default=Path('artifacts/release/security.json'))
    parser.add_argument('--sbom', type=Path, default=Path('artifacts/release/sbom.spdx.json'))
    parser.add_argument('--registry', default='localhost:5055')
    parser.add_argument('--output', type=Path, default=Path('artifacts/rejection-demo'))
    args = parser.parse_args()
    require(args.registry == 'localhost:5055', 'Lab is deliberately restricted to the loopback registry')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / 'report.json').unlink(missing_ok=True)
    log = output / 'commands.log'
    log.write_text('Local disposable-key lab; not GitHub OIDC evidence.\n')
    source_evidence = read_json(args.evidence)
    commit = source_evidence['sourceCommit']
    policy = read_json('security/release-policy.json')
    exceptions = {'schemaVersion': 1, 'exceptions': []}
    results = []
    with tempfile.TemporaryDirectory(prefix='tenantledger-signing-') as temporary:
        directory = Path(temporary)
        env = {**os.environ, 'COSIGN_PASSWORD': ''}
        keys = {}
        for name in ['trusted', 'unexpected']:
            prefix = directory / name
            run(['cosign', 'generate-key-pair', '--output-key-prefix', str(prefix)], env, log)
            keys[name] = str(prefix) + '.key'
        # Publish the trusted public key as evidence; private keys are deleted on exit.
        (output / 'trusted.pub').write_bytes((directory / 'trusted.pub').read_bytes())
        run_id = datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')
        for case in ['allowed', 'unsigned', 'unexpected-signer', 'policy-failure']:
            repository = f'{args.registry}/lab-{run_id}/{case}'
            tag = repository + ':candidate'
            run(['docker', 'tag', args.source_image, tag], env, log)
            run(['docker', 'push', tag], env, log)
            inspection = json.loads(run(['docker', 'image', 'inspect', tag], env, log))[0]
            refs = [x for x in inspection['RepoDigests'] if x.startswith(repository + '@sha256:')]
            require(len(refs) == 1, 'Registry digest missing or ambiguous')
            image = refs[0]
            # All cases use exactly the scanned image bytes, in separate registry repositories.
            require(image_parts(image)[1] == image_parts(source_evidence['image'])[1], 'Demo image differs from scanned artifact')
            lab_policy = {**policy, 'imageRepository': repository}
            evidence = copy.deepcopy(source_evidence)
            evidence['image'] = image
            if case == 'policy-failure':
                evidence['findings'].append({'scanner': 'grype', 'id': 'DEMO-CRITICAL-001',
                                             'package': 'synthetic-policy-test', 'version': '1', 'severity': 'CRITICAL'})
            if case != 'unsigned':
                key = keys['unexpected' if case == 'unexpected-signer' else 'trusted']
                run(['cosign', 'sign', '--yes', '--key', key, '--bundle', str(output / f'{case}-image.sigstore.json'), image], env, log)
                if case != 'unexpected-signer':
                    predicates = {
                        PROVENANCE_TYPE: create(lab_policy, commit, f'urn:tenantledger:local-demo:{run_id}'),
                        SBOM_TYPE: read_json(args.sbom), SECURITY_TYPE: evidence,
                    }
                    predicates[PROVENANCE_TYPE]['buildDefinition']['internalParameters'] = {
                        'localDemo': True, 'workingTreeDirty': source_evidence.get('workingTreeDirty'),
                        'sourceTreeSha256': source_evidence.get('sourceTreeSha256'),
                    }
                    for index, (kind, predicate) in enumerate(predicates.items()):
                        path = output / f'{case}-{index}.predicate.json'
                        path.write_text(json.dumps(predicate))
                        run(['cosign', 'attest', '--yes', '--key', key, '--type', kind, '--predicate', str(path), '--bundle', str(output / f'{case}-{index}.sigstore.json'), image], env, log)
            try:
                decision = verify(image, commit, lab_policy, exceptions, ['--key', str(output / 'trusted.pub')])
                stage = 'ALLOWED'
            except VerificationError as exc:
                stage = exc.stage
                decision = {'decision': 'deny', 'stage': stage, 'reason': str(exc)}
            except Denied as exc:
                raise RuntimeError(f'Unexpected lab setup/validation error: {exc}') from exc
            expected = {'allowed': 'ALLOWED', 'unsigned': 'SIGNATURE', 'unexpected-signer': 'SIGNATURE', 'policy-failure': 'POLICY'}[case]
            require(stage == expected, f'{case}: expected {expected}, observed {stage}; {decision}')
            if case == 'unsigned':
                require('no signatures found' in decision.get('reason', '').lower(), 'Unsigned case failed for an infrastructure error')
            if case == 'unexpected-signer':
                reason = decision.get('reason', '').lower()
                require(('no matching signatures' in reason or 'no matching attestations' in reason)
                        and ('verif' in reason or 'match' in reason), 'Unexpected-signer case failed for an infrastructure error')
            results.append({'case': case, 'image': image, 'expectedStage': expected, 'observedStage': stage,
                            'passed': True, 'decision': decision})
            print(f'PASS {case}: {stage}', flush=True)
        report = {'schemaVersion': 1, 'mode': 'local-keys-with-real-cosign-and-registry',
                  'sourceCommit': commit, 'ranAt': datetime.now(UTC).isoformat(), 'cases': results}
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'Evidence: {output / "report.json"}')


if __name__ == '__main__':
    try:
        main()
    except (Denied, RuntimeError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
