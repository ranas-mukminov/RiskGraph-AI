# Responsible disclosure template — lab / authorised systems only

Use this template only for a system you own, or where you hold written
authorisation to test. Do not use it to report a finding obtained
without authorisation, and do not publish details before the owner
has had a chance to fix the issue.

- **System tested:** (name, environment — lab or authorised scope only)
- **Authorisation:** (owner, date, written scope reference)
- **Finding class:** (for this lab: SSRF, CWE-918)
- **Affected component:** (lab asset / component, version if known)
- **Reproduction in the lab:** (detector output and lab steps only —
  no live exploit, no credentials, no internal data)
- **Impact if unmitigated:** (what an attacker could reach, in general
  terms, without disclosing sensitive data)
- **Suggested mitigation:** (see `ssrf_mitigation_checklist.md`)
- **Disclosure timeline:** (date reported, date fixed, date agreed
  for any public note — all to be filled in by the reporter and owner)
- **What is NOT claimed:** no CVE number, no bounty, and no
  third-party testing is claimed unless separately documented by the
  issuing authority.

No finding from this lab is, by itself, Red-team evidence, a CVE, or
a bug-bounty credit.
