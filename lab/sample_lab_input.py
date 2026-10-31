"""LAB-ONLY detector input. NOT a server. NOT deployable code.

This file exists only so lab/ssrf_detector.py has something to scan.
Nothing in this file is executed by the detector (it reads source text),
and no function here is called at import time. Never deploy this file,
never point it at a real service, and never use it against a system
you do not own. See lab/README.md for the scope.
"""


def fetch_user_url(url):
    # UNSAFE PATTERN (lab sample): a caller-supplied URL used directly.
    # The detector should flag this as a finding.
    import requests  # noqa: F401  (import shown for pattern clarity only)
    return requests.get(url)


def fetch_allowlisted_url(url, allowed_hosts):
    # SAFER PATTERN (lab sample): host checked against an allowlist
    # before any fetch. The detector reports this as review-needed,
    # not as a clean pass -- a human must still verify the check.
    from urllib.parse import urlparse
    host = urlparse(url).hostname
    if host not in allowed_hosts:
        raise ValueError("host not in allowlist")
    import requests  # noqa: F401
    return requests.get(url)
