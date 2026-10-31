# SSRF mitigation checklist (defensive)

Apply in order. Each item is a fix, not a bypass.

1. **Allowlist, not denylist.** Accept only specific hosts and paths
   your feature actually needs. Reject everything else by default.
2. **Validate after redirects.** Re-check the final destination after
   every redirect; an allowlisted start URL can redirect elsewhere.
3. **Block private destinations.** Reject loopback, RFC 1918 private,
   link-local (including cloud metadata ranges), and unspecified
   addresses, resolved at request time — not just by string matching,
   because DNS can change between check and fetch.
4. **Resolve, then check, then fetch.** Resolve the hostname, check
   every resolved IP, and fetch only the checked address. Re-check on
   redirect.
5. **No user-controlled scheme/host surprises.** Do not let a caller
   switch schemes (for example, from `https` to `file` or `gopher`)
   or smuggle credentials in the URL.
6. **Least privilege for the fetcher.** The fetching service should
   have no access to internal services or credentials it does not
   need, and its outbound network should be segmented.
7. **Log and alert.** Log the requested host, the resolved IP, and
   the outcome; alert on blocked private-destination attempts.
8. **Test in the lab only.** Verify the fix against your own lab
   sample and the detector in this folder. Do not probe third-party
   systems to "confirm" the fix.
9. **Feed the graph.** Record the finding as a vulnerability node in
   RiskGraph-AI (see `riskgraph_ssrf_example.json`) so the attack
   path through the affected asset is visible and its risk score
   reflects the control coverage.
