"""Build, scan and exercise release admission without GitHub credentials."""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from policy import evaluate, read_json
from scan import scan

REGISTRY_IMAGE = 'registry:3@sha256:d4032d4cc323c1731c707931ecada07a53076eac38e3b61ae57533f170f2c6c3'


def run(*arguments):
    return subprocess.check_output(arguments, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skip-build', action='store_true', help='Use an existing tenantledger:release-candidate image')
    args = parser.parse_args()
    output = Path('artifacts/release')
    output.mkdir(parents=True, exist_ok=True)
    name = f'tenantledger-registry-{os.getpid()}'
    started = False
    try:
        # Refuse port collisions; never reuse or remove someone else's registry.
        run('docker', 'run', '-d', '--name', name, '-p', '127.0.0.1:5055:5000', REGISTRY_IMAGE)
        started = True
        for _ in range(30):
            ready = subprocess.run(['curl', '--fail', '--silent', 'http://127.0.0.1:5055/v2/'], capture_output=True, check=False)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Local registry did not become ready')
        if not args.skip_build:
            run('docker', 'build', '--target', 'runtime', '-t', 'tenantledger:release-candidate', '.')
        run('docker', 'tag', 'tenantledger:release-candidate', 'localhost:5055/tenantledger:candidate')
        run('docker', 'push', 'localhost:5055/tenantledger:candidate')
        inspection = json.loads(run('docker', 'image', 'inspect', 'localhost:5055/tenantledger:candidate'))[0]
        image = next(x for x in inspection['RepoDigests'] if x.startswith('localhost:5055/tenantledger@'))
        commit = run('git', 'rev-parse', 'HEAD')
        evidence = scan(image, commit, output)
        local_policy = {**read_json('security/release-policy.json'), 'imageRepository': 'localhost:5055/tenantledger'}
        decision = evaluate(evidence, local_policy, read_json('security/exceptions.json'), image, commit)
        (output / 'local-decision.json').write_text(json.dumps(decision, indent=2) + '\n')
        subprocess.run([sys.executable, 'scripts/release/demo.py'], check=True)
    finally:
        if started:
            subprocess.run(['docker', 'rm', '-f', name], check=False)


if __name__ == '__main__':
    main()
