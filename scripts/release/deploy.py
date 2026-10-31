"""Verify immediately before deploying the SAME digest to the local Compose demo."""
import argparse
import json
import subprocess
from pathlib import Path

from policy import Denied, read_json
from verify import production_flags, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    policy = read_json('security/release-policy.json')
    output = Path('artifacts/deployment')
    output.mkdir(parents=True, exist_ok=True)
    try:
        decision = verify(args.image, args.commit, policy, read_json('security/exceptions.json'), production_flags(policy, args.commit))
    except (Denied, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        decision = {'decision': 'deny', 'stage': getattr(exc, 'stage', 'INPUT'), 'reason': str(exc)}
        (output / 'decision.json').write_text(json.dumps(decision, indent=2) + '\n')
        raise SystemExit(json.dumps(decision)) from exc
    (output / 'decision.json').write_text(json.dumps(decision, indent=2) + '\n')
    # JSON is valid YAML. Both API and migration must run the verified artifact, with no rebuild.
    override = output / 'verified.compose.json'
    override.write_text(json.dumps({'services': {name: {'image': args.image, 'pull_policy': 'always'} for name in ['api', 'migrate']}}, indent=2))
    subprocess.run(['python3', 'scripts/setup.py'], check=True)
    subprocess.run(['docker', 'compose', '-f', 'compose.yaml', '-f', str(override),
                    'up', '--no-build', '-d', '--wait', 'api'], check=True)
    print(f'Deployed verified digest: {args.image}')


if __name__ == '__main__':
    main()
