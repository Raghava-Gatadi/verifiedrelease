# Time-limited release exceptions

The default exception file is empty. Fix or upgrade the vulnerable component first.
An exception accepts one documented residual risk for one immutable artifact; it is
not a scanner suppression and does not remove the finding from evidence.

## Required process

1. The service owner opens a review ticket with the raw scan, affected execution path,
   exposure analysis, compensating controls and a dated remediation task.
2. Add an entry to `security/exceptions.json` in a pull request. Include the exact
   scanner, finding ID, package, installed version and image digest. Assign an owner,
   explain the reason, and select an expiration no more than 14 days after creation.
3. A different named reviewer approves the risk. Record that reviewer and the ticket
   URL. Protect the exception path with required code-owner approval and rulesets.
4. CI and deployment both validate the exception and record its ID/expiry when used.
   The signature, expected signer, digest, provenance and evidence freshness must
   still pass. Critical vulnerabilities and secret/configuration findings cannot be waived.
5. The owner ships the fix and removes the entry before expiry. An expired entry fails
   closed, including when its finding disappears, so forgotten waivers must be cleaned up.
   Extensions require a new review with updated evidence; do not silently edit dates.

The validator checks completeness and distinct owner/reviewer names. It cannot prove
that a human approved the ticket. GitHub's review/ruleset controls supply that governance.
No independent approval has been simulated or claimed for this portfolio project.

## Example (illustrative, intentionally not installed)

```json
{
  "id": "EX-2026-001",
  "owner": "@service-owner",
  "approvedBy": "@security-reviewer",
  "reason": "Affected parser is inaccessible in this deployment; upgrade is scheduled in the linked ticket.",
  "ticket": "https://github.com/OWNER/REPO/issues/123",
  "scanner": "grype",
  "findingId": "CVE-EXAMPLE",
  "package": "example-library",
  "version": "1.2.3",
  "imageDigest": "sha256:REPLACE_WITH_64_HEX_CHARACTERS",
  "createdAt": "2026-10-30T12:00:00Z",
  "expiresAt": "2026-11-06T12:00:00Z"
}
```

Allowed exception scanners are `pip-audit` and `grype`. pip-audit's advisories are
normalized to `UNKNOWN` because its JSON does not consistently contain severity;
all are blocked by default. An exception must document the actual advisory severity
and risk assessment in its review ticket. Never use this normalization to waive a
known critical vulnerability; container findings with severity `CRITICAL` are rejected
unconditionally.
