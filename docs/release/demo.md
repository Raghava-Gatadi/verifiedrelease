# Five-minute interview demonstration

Open the [architecture](README.md) first. Explain the trust boundary: an image in a
registry is only a candidate; deployment requires verified claims about that exact digest.

## Real rejection lab

Run the commands in the [runbook](runbook.md). The demo performs four registry scenarios:

| Case | Signature/evidence | Expected result |
| --- | --- | --- |
| Allowed | Trusted disposable key; real passing scan; signed provenance and SBOM | `ALLOWED` |
| Unsigned image | No signature or attestations in a fresh repository | `SIGNATURE` rejection |
| Unexpected signer | Real signature from a different disposable key | `SIGNATURE` rejection |
| Release-policy failure | Trusted signature and attestations, with a clearly labeled synthetic critical finding | `POLICY` rejection |

The last case deliberately signs a failing assessment **inside the lab only** to prove
that signature validity is insufficient. The production workflow refuses to sign a
candidate that fails policy. No intentionally vulnerable service is exposed.

The lab first proves a trusted artifact can pass, so a global registry or verifier outage
cannot count as a successful rejection demonstration. The policy-failure case must get
past real signature/provenance/SBOM verification and fail specifically at `POLICY`.
Disposable private keys live in a temporary directory and are deleted at exit. The
trusted public key, timestamped case report, predicate files, portable Sigstore bundles
and command log are retained. Local evidence records the upstream commit, a hash of
the scanned working tree and whether it had uncommitted changes. The lab
uses public Sigstore transparency services and requires network access.

Open `artifacts/rejection-demo/report.json` and show the expected/observed stage per case.
Then run `make release-unit` to demonstrate wrong digest, wrong source commit, stale
scan, absent scanner, overlong exception and expired exception rejection.

## GitHub identity demonstration

A local public key is an analogue of signer allowlisting, not an OIDC identity test.
After the GitHub release workflow succeeds, verify the image with the exact workflow
identity and issuer from `security/release-policy.json`. The release workflow also
checks that substituting an unexpected workflow identity is rejected; its evidence
is retained with the deployment artifacts.

## Suggested résumé wording

After local verification:

> Built a container release security gate for a multi-tenant FastAPI application,
> combining SAST, dependency/secret/container scanning, signed SBOM/provenance checks,
> digest-based admission and expiring risk exceptions; demonstrated rejection of
> unsigned, incorrectly signed and policy-failing images with real Cosign signatures.

After the GitHub workflow actually succeeds, add:

> Implemented GitHub Actions OIDC signing and independently verified the expected
> workflow identity and source commit before deploying the immutable GHCR artifact.

Use actual test and finding counts from the verification record. Do not claim production
adoption, SLSA certification, zero risk or an OIDC run that has not happened.

## Verify the saved provenance after registry cleanup

The saved Sigstore bundle includes the DSSE statement and transparency-log material.
Use the digest from the report; this verifies its signature **and** subject digest:

```sh
cosign verify-blob-attestation \
  --key artifacts/rejection-demo/trusted.pub \
  --bundle artifacts/rejection-demo/allowed-0.sigstore.json \
  --type slsaprovenance1 \
  --digest REPLACE_WITH_64_HEX_DIGEST_FROM_REPORT \
  --digestAlg sha256
```

A saved local public key is a lab trust root, not a substitute for the production
workflow identity. The registry gate also validates source and policy semantics.
