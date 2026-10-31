"""GitHub-only real certificate-identity rejection test against a released digest."""
import argparse
import json
import subprocess
from pathlib import Path

from policy import read_json, require
from verify import cosign, production_flags


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    policy = read_json('security/release-policy.json')
    flags = production_flags(policy, args.commit)
    cosign(['verify', *flags, args.image], 'BASELINE')
    wrong = flags.copy()
    wrong[wrong.index('--certificate-identity') + 1] = policy['certificateIdentity'].replace('/release.yml@', '/unexpected-workflow.yml@')
    result = subprocess.run(['cosign', 'verify', *wrong, args.image], capture_output=True, text=True, timeout=240, check=False)
    require(result.returncode != 0 and 'identit' in result.stderr.lower(), 'Expected certificate identity rejection was not observed')
    # A second successful baseline prevents a persistent network outage from passing this lab.
    cosign(['verify', *flags, args.image], 'BASELINE')
    output = Path('artifacts/deployment')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'identity-rejection.json').write_text(json.dumps({
        'case': 'unexpected-github-workflow', 'passed': True, 'image': args.image,
        'expectedIdentity': policy['certificateIdentity'], 'rejectedIdentity': wrong[1],
        'verifierError': result.stderr,
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
