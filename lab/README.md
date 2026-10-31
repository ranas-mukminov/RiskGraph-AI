# Lab: SSRF detection (CWE-918) — defensive, lab-only

**Scope — read this first.** This lab is for systems you own, or for a
deliberately vulnerable local lab container you control. It is NOT for
third-party systems, production services, or anyone else's infrastructure.
If you do not own the target and do not have written authorisation for
it, do not test it. See `SECURITY.md` at the repository root.

**What this is.** One vulnerability class, chosen for detection
practice: Server-Side Request Forgery, CWE-918 (OWASP Top 10 2021, A10:
Server-Side Request Forgery). No specific CVE is claimed for this lab
and no exploit is included. The goal is to *detect* the pattern and
*mitigate* it, and to feed a finding into RiskGraph-AI's attack-graph
model as a vulnerability node — not to exploit a real system.

**What is included**

- `ssrf_detector.py` — static detector, standard library only. It reads
  Python source as text and flags fetch calls whose URL is dynamic
  (a variable, parameter, f-string, or concatenation) without a nearby
  allowlist/validation marker. It never fetches a URL and never runs
  the scanned code.
- `sample_lab_input.py` — lab-only detector input. Not a server, not
  deployed, and no function in it is called at import time. It contains
  one unsafe pattern (for the detector to flag) and one allowlisted
  pattern (reported as review-needed, not as a clean pass).
- `ssrf_mitigation_checklist.md` — what to fix, in order.
- `riskgraph_ssrf_example.json` — an ingestion-bundle example in the
  format documented in `docs/ingestion_format.md`, showing how an SSRF
  finding becomes a vulnerability node on a lab asset. The asset IDs
  are fictional lab IDs, not a real system.
- `DISCLOSURE_TEMPLATE.md` — a responsible-disclosure template for
  use only where you own the system or hold written authorisation.

**How to run the detector (local only)**

```bash
python lab/ssrf_detector.py --path lab/sample_lab_input.py
python lab/ssrf_detector.py --path lab --format json
python -m unittest discover -s tests -v   # detector unit tests
```

**Example (lab) output**

```
Scanned files: 1
Findings (unvalidated dynamic fetch): 1
Review-needed (validation marker present): 1
- lab/sample_lab_input.py:14 in fetch_user_url() [finding, url arg: Name]
- lab/sample_lab_input.py:22 in fetch_allowlisted_url() [review-needed, url arg: Name]
```

**What was NOT run against a live lab.** No live lab server was
started or probed in this change. The detector was checked locally
only: syntax check, `--help`, a scan of the sample file, and unit
tests. Running it against a real lab container you control is the
next step for the user — see the checklist.

**Not Red-tier evidence.** This lab demonstrates defensive detection
and mitigation. It is not a penetration-test engagement, not a CVE,
and not a bug-bounty credit, and must not be presented as such.
