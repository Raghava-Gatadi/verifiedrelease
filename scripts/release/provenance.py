"""Create a SLSA v1 predicate for the workflow's own build (not a SLSA level claim)."""
import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from policy import read_json, require


def create(policy, commit, invocation):
    require(re.fullmatch(r'[0-9a-f]{40}', commit) is not None, 'Full source commit required')
    return {
        'buildDefinition': {
            'buildType': policy['buildType'],
            'externalParameters': {'repository': policy['repository'], 'ref': policy['sourceRef'], 'commit': commit},
            'internalParameters': {},
            'resolvedDependencies': [{'uri': policy['repository'], 'digest': {'gitCommit': commit}}],
        },
        'runDetails': {
            'builder': {'id': policy['certificateIdentity']},
            'metadata': {'invocationId': invocation, 'finishedOn': datetime.now(UTC).isoformat()},
        },
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--invocation', required=True)
    parser.add_argument('--output', type=Path, default=Path('artifacts/release/provenance.json'))
    parser.add_argument('--policy', default='security/release-policy.json')
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(create(read_json(args.policy), args.commit, args.invocation), indent=2) + '\n')
