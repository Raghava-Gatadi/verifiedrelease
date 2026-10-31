"""Verify registry signatures and attestations before admitting an immutable image."""
import argparse
import base64
import json
import subprocess
from pathlib import Path

from policy import (
    PROVENANCE_TYPE,
    SBOM_TYPE,
    SECURITY_TYPE,
    Denied,
    canonical_sha256,
    evaluate,
    image_parts,
    read_json,
    require,
    validate_provenance,
    validate_statement,
)


class VerificationError(Denied):
    def __init__(self, stage, detail):
        self.stage = stage
        super().__init__(detail)


def cosign(arguments, stage):
    result = subprocess.run(['cosign', *arguments], text=True, capture_output=True, timeout=240, check=False)
    if result.returncode != 0:
        raise VerificationError(stage, f'Cosign rejected verification: {result.stderr[-1500:]}')
    return result.stdout


def statements(raw):
    # Cosign emits one DSSE envelope per JSON object; do not parse stderr or download unsigned metadata.
    decoder, offset, values = json.JSONDecoder(), 0, []
    while offset < len(raw):
        if raw[offset].isspace():
            offset += 1
            continue
        value, offset = decoder.raw_decode(raw, offset)
        values.extend(value if isinstance(value, list) else [value])
    decoded = []
    for value in values:
        if 'payload' in value:
            decoded.append(json.loads(base64.b64decode(value['payload'], validate=True)))
        elif '_type' in value:
            decoded.append(value)
        else:
            raise Denied('Unrecognized Cosign attestation output')
    require(bool(decoded), 'Cosign returned no attestations')
    return decoded


def verified_predicates(image, flags, predicate_type):
    raw = cosign(['verify-attestation', *flags, '--type', predicate_type, image], 'ATTESTATION')
    return [validate_statement(s, predicate_type, image) for s in statements(raw)]


def verify(image, commit, policy, exceptions, flags):
    repository, _ = image_parts(image)
    require(repository == policy['imageRepository'], 'Unexpected image repository')
    cosign(['verify', *flags, image], 'SIGNATURE')
    provenances = verified_predicates(image, flags, PROVENANCE_TYPE)
    errors = []
    for predicate in provenances:
        try:
            validate_provenance(predicate, policy, commit)
            break
        except Denied as exc:
            errors.append(str(exc))
    else:
        raise VerificationError('PROVENANCE', '; '.join(errors))
    sboms = verified_predicates(image, flags, SBOM_TYPE)
    require(any(p.get('spdxVersion', '').startswith('SPDX-2.') and p.get('packages') for p in sboms), 'Signed SBOM is empty or invalid')
    evidences = verified_predicates(image, flags, SECURITY_TYPE)
    errors = []
    for predicate in evidences:
        try:
            decision = evaluate(predicate, policy, exceptions, image, commit)
            require(any(canonical_sha256(sbom) == predicate['sbomCanonicalSha256'] for sbom in sboms), 'Signed SBOM does not match the security assessment')
            return decision
        except (Denied, KeyError, TypeError, ValueError) as exc:
            errors.append(str(exc))
    raise VerificationError('POLICY', '; '.join(errors))


def production_flags(policy, commit):
    return ['--certificate-identity', policy['certificateIdentity'],
            '--certificate-oidc-issuer', policy['oidcIssuer'],
            '--certificate-github-workflow-sha', commit]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--commit', required=True, help='Expected full source commit from a trusted release record')
    parser.add_argument('--policy', default='security/release-policy.json')
    parser.add_argument('--exceptions', default='security/exceptions.json')
    parser.add_argument('--output', type=Path, default=Path('artifacts/release/decision.json'))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        policy = read_json(args.policy)
        decision = verify(args.image, args.commit, policy, read_json(args.exceptions), production_flags(policy, args.commit))
    except (Denied, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        decision = {'decision': 'deny', 'stage': getattr(exc, 'stage', 'INPUT'), 'reason': str(exc)}
        args.output.write_text(json.dumps(decision, indent=2) + '\n')
        raise SystemExit(json.dumps(decision)) from exc
    args.output.write_text(json.dumps(decision, indent=2) + '\n')
    print(json.dumps(decision, indent=2))


if __name__ == '__main__':
    main()
