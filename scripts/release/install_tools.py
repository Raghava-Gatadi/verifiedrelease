"""Install reviewed tool bytes; never execute a downloaded installer script."""
import argparse
import hashlib
import io
import json
import os
import platform
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dest', type=Path, default=ROOT / '.tools')
    parser.add_argument('tools', nargs='*')
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'security/toolchain.json').read_text())
    machine = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(platform.machine(), platform.machine())
    target = f'{platform.system().lower()}_{machine}'
    args.dest.mkdir(parents=True, exist_ok=True)
    for name in args.tools or manifest:
        entry = manifest[name]['platforms'][target]
        with urllib.request.urlopen(entry['url'], timeout=120) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise SystemExit(f'Checksum mismatch: {name}')
        if entry['url'].endswith('.tar.gz'):
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                members = [m for m in archive.getmembers() if m.isfile() and Path(m.name).name == name]
                if len(members) != 1:
                    raise SystemExit(f'Ambiguous archive: {name}')
                data = archive.extractfile(members[0]).read()
        temporary = args.dest / f'.{name}.tmp'
        temporary.write_bytes(data)
        temporary.chmod(0o755)
        os.replace(temporary, args.dest / name)
        print(f'Installed {name} {manifest[name]["version"]} ({target}, SHA-256 verified)')


if __name__ == '__main__':
    main()
