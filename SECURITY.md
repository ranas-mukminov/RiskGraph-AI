# Security policy

## Scope: lab-only, defensive

This repository's vulnerability-lab section (`lab/`) is for defensive
security research on systems you own, or on a deliberately vulnerable
local lab container you control. Testing third-party systems,
production services, or any system without written authorisation is
out of scope and must not be done using anything in this repository.

## What the lab does and does not do

- It detects vulnerability *patterns* in local source code, statically,
  without fetching any URL or running target code: SSRF (CWE-918) and
  IDOR / broken access control (CWE-639 / CWE-862).
- It documents mitigation and a responsible-disclosure template.
- It does **not** include exploits for real-world production systems,
  ready-made phishing templates, or tooling for unauthorised access.
- It does **not** claim any CVE, bug-bounty credit, or Red-team
  eligibility. A lab finding is not, by itself, any of those things.

## Reporting a vulnerability in this repository

If you find a security issue in this repository's own code, report it
privately to the repository owner with: the affected file and version,
a lab-only reproduction (no live exploit, no credentials, no internal
data), and your suggested fix. Do not open a public issue with
exploit details before the owner has had a chance to fix it.

## Responsible disclosure for findings made with this lab

Use `lab/DISCLOSURE_TEMPLATE.md`, only for systems you own or hold
written authorisation for, and agree a fix timeline with the owner
before any public note.
