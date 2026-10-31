# Release security verification record

Verified locally on **October 30, 2026**. These are observed results, not a claim of a
hosted GitHub release or production deployment.

| Check | Observed result |
| --- | --- |
| Runtime build | Linux arm64 and Linux amd64 builds succeeded |
| Runtime dependencies | `pip check` passed in both architectures |
| Existing application suite | 86 passed; 91% statement coverage |
| Existing authorization mutation lab | 5/5 deliberately introduced defects detected |
| Browser flow on Alpine | 8 checks passed; zero JavaScript errors |
| Release policy/deployment unit tests | 25 passed |
| Workflow/static lint | Actionlint and Ruff passed; `git diff --check` passed |
| Fresh host CI dependency installation | Hash-locked test and browser dependencies installed successfully |
| Focused SAST | 0 medium/high; 2 low findings about public development credential comparisons |
| Python dependency audit | 0 known vulnerabilities |
| Secret scanning | 0 findings in Git history and the source snapshot |
| Container vulnerability scan | 0 high/critical; 5 medium findings retained |
| Runtime configuration | Non-root UID/GID 10001, default application command and health check passed |
| SBOM | 83 packages in SPDX JSON; signed attestation verified |
| Provenance | Real Cosign-signed SLSA v1 predicate; portable bundle verified after registry removal |
| Trusted artifact | Allowed after real signature, provenance, SBOM and policy verification |
| Unsigned image | Rejected at SIGNATURE with “no signatures found” |
| Unexpected signer | Rejected at SIGNATURE with cryptographic verification failure |
| Signed policy-failing artifact | Rejected at POLICY for a labeled synthetic critical finding |
| Active exceptions | None |

The final arm64 artifact digest is:

```text
sha256:0b26407e4070936b8b77d6a032b0c24ce2e03071a0edbcecece216e8b1d3b744
```

The Linux amd64 build digest is:

```text
sha256:37df42330b09a17252de10a2e739104d017985286589399ae6900cc6cfd6bf2c
```

The full scans, application/browser tests and real signature lab used **arm64**.
The amd64 build and dependency consistency check passed; its hosted GitHub scan and
OIDC signing/deployment remain to be executed. These digests are evidence for these
builds, not promises that future builds produce identical bytes.

## Remediation evidence

The initial Debian Bookworm candidate had 73 high and 3 critical package/advisory
matches, above the release threshold. No ignore flags or blanket exceptions were added.
The runtime was changed to a digest-pinned Alpine base, then rebuilt and checked with
the application, identity, mutation and browser suites. The resulting image has five
medium findings: two Python advisories and one BusyBox advisory matched to three
packages. Medium container findings are allowed by the explicit current policy.

The [initial assessment](evidence/rejected-debian-assessment.json) retains the original
findings. It predates the final evidence fields for database age and canonical SBOM
binding, so it is an historical scanner record, not a deployable current attestation.

## Evidence and limits

- [Machine-readable summary](evidence/local-summary.json)
- [Real rejection report](evidence/rejection-report.json)
- [Release unit-test output](evidence/release-unit-tests.txt)
- Raw current reports: `artifacts/release/` in the delivered evidence archive.
- Portable signed bundles and public key: `artifacts/rejection-demo/`.
- Application test XML, coverage, mutation reports and browser report: `artifacts/`.

Local provenance records upstream commit
`0a497a6fa7e10b433a1f2e6c2198d09a9bac2cf3`, the scanned working-tree hash, and
`workingTreeDirty: true`. This distinguishes the local implementation from its upstream
baseline. It was signed with disposable lab keys, not a GitHub workflow certificate.
The production pipeline uses a clean committed source and GitHub OIDC identity.

This local verification snapshot predates publication to
[VerifiedRelease](https://github.com/Raghava-Gatadi/verifiedrelease). It does not record
a GitHub OIDC release, GHCR publication, or production deployment. Follow the
[runbook](runbook.md) for the first hosted release and record its run URL separately.
