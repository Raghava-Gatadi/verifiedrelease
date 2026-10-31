# Release runbook

## Local prerequisites

Docker Engine/Desktop with Compose and Buildx, Python 3.13, Git and curl. The first
scan downloads a vulnerability database which may use several GB of disk. Internet
access is needed for vulnerability databases, package registries and Sigstore.
macOS arm64 and Linux amd64 security-tool packages are pinned in `security/toolchain.json`.

From the repository root:

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r security/requirements.lock
python3 scripts/release/install_tools.py
export PATH="$PWD/.venv/bin:$PWD/.tools:$PATH"
make release-unit
python scripts/release/local_check.py
```

`local_check.py` starts its own registry on loopback port 5055, builds the image,
scans it by registry digest, enforces policy and runs the real rejection demo. It
removes only its own registry container on exit. Port 5055 must be free. Evidence
remains under `artifacts/release/` and `artifacts/rejection-demo/`.

The existing application remains available with `make up`, `make test`, and `make lab`.
Generated `.env`, private demo keys, tool binaries and scan caches are not committed.

## GitHub activation

1. Review and push this branch; merge through a pull request after CI passes.
2. In repository settings, permit Actions and GHCR writes via `GITHUB_TOKEN`. Do not
   create a personal access token or store a long-lived signing key.
3. Protect `main` and require application CI and the supply-chain lab. Require code-owner
   review for `.github`, `security`, release scripts, Dockerfile and dependency locks.
   Restrict who can modify rulesets or run the release workflow.
4. Under Actions, run **Verified release** on **main**. Other branches/repositories are
   intentionally skipped. This publishes a GHCR candidate, signs only after policy
   passes, then verifies and deploys to an ephemeral runner for a health check.
5. Download the release and deployment evidence artifacts. Record the immutable
   `image.txt`, source commit and workflow run URL. Set GHCR package visibility if you
   want unauthenticated public verification; otherwise authenticate the verifier.

No cloud account or paid Kubernetes cluster is required. Publishing a pipeline file
does not prove a GitHub OIDC release has run; retain the first successful run URL as
separate portfolio evidence.

## Verify or deploy a released artifact

Use the digest and commit from a trusted release record. Replace both example values:

```sh
export IMAGE='ghcr.io/raghava-gatadi/verifiedrelease@sha256:REPLACE_WITH_DIGEST'
export COMMIT='REPLACE_WITH_FULL_40_CHARACTER_COMMIT'
python scripts/release/verify.py --image "$IMAGE" --commit "$COMMIT"
python scripts/release/deploy.py --image "$IMAGE" --commit "$COMMIT"
```

The deployment command verifies again immediately before invoking Compose. Its output
is a loopback-only **development demonstration**, using the repository's synthetic
accounts and local database. Production deployment requires external secrets, TLS,
a production identity provider, backup/restore procedures and separately governed
admission policy. Never expose the development Compose stack to the internet.

## Maintenance and failure handling

- Scanner failures are failures, not “zero findings.” Inspect raw reports and logs.
- Do not add `continue-on-error`, skip transparency verification, accept `.*` identities,
  switch deployment back to tags, or change evidence timestamps to make a release pass.
- Update base digests and tool checksums by reviewed PR, then rebuild, rescan and rerun
  application and rejection tests. Dependabot tracks action and Docker updates.
- Runtime requirements are exact versions with allowed release-file hashes. Use a trusted
  dependency resolver to regenerate hashes, review version changes and audit the result.
  Scanner dependencies are pinned in `security/requirements.in` and its hash lock.
- Rollback means selecting a previously trusted digest and repeating verification under
  current policy. Old evidence may need a new scan/attestation; an old green run is not sufficient.
- On signature or provenance failure, quarantine the candidate and investigate source,
  workflow, package and runner history. Do not create a security exception for identity failures.
