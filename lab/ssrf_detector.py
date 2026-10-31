#!/usr/bin/env python3
"""Lab-only, defensive SSRF detector (CWE-918).

Static analysis only. This tool READS Python source files as text and
reports fetch calls whose URL comes from a variable, a parameter, an
f-string, or string concatenation without a nearby allowlist/validation
marker. It NEVER fetches a URL, NEVER runs the scanned code, and NEVER
contacts any server. It is a detection aid, not an exploit tool.

Usage:
    python lab/ssrf_detector.py --path lab/sample_lab_input.py
    python lab/ssrf_detector.py --path some_dir --format json

Exit code is always 0 when the scan itself succeeds, even if findings
are present, so CI can parse the report instead of relying on exit codes.
"""
import argparse
import ast
import json
import sys
from pathlib import Path

VALIDATION_MARKERS = (
    "allowlist", "allowed_hosts", "allowed_domains", "allowed_urls",
    "validate_url", "is_private", "is_global", "urlparse", "ipaddress",
)
FETCH_NAMES = {"get", "post", "put", "delete", "head", "request", "urlopen", "fetch"}


def _is_fetch_call(node):
    if isinstance(node.func, ast.Attribute):
        return node.func.attr in FETCH_NAMES
    if isinstance(node.func, ast.Name):
        return node.func.id in FETCH_NAMES
    return False


def _url_is_dynamic(node):
    if not node.args:
        return False, "no-url-arg"
    url = node.args[0]
    if isinstance(url, ast.Constant) and isinstance(url.value, str):
        return False, "constant-url"
    return True, type(url).__name__


def _function_has_validation(func_node, source_lines):
    start = func_node.lineno - 1
    end = getattr(func_node, "end_lineno", func_node.lineno) or func_node.lineno
    text = "\n".join(source_lines[start:end]).lower()
    return [m for m in VALIDATION_MARKERS if m in text]


def scan_file(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return {"path": str(path), "error": f"syntax error: {exc}", "findings": []}
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        markers = _function_has_validation(node, lines)
        for child in ast.walk(node):
            if not isinstance(child, ast.Call) or not _is_fetch_call(child):
                continue
            dynamic, kind = _url_is_dynamic(child)
            if not dynamic:
                continue
            findings.append({
                "path": str(path),
                "line": child.lineno,
                "function": node.name,
                "url_arg_kind": kind,
                "status": "review-needed" if markers else "finding",
                "validation_markers": markers,
                "recommendation": (
                    "Add an allowlist of hosts/paths and reject private, "
                    "loopback and link-local destinations before fetching. "
                    "See lab/ssrf_mitigation_checklist.md."
                ),
            })
    return {"path": str(path), "error": None, "findings": findings}


def scan_path(path):
    p = Path(path)
    files = sorted(p.rglob("*.py")) if p.is_dir() else [p]
    results = [scan_file(f) for f in files]
    all_findings = [f for r in results for f in r["findings"]]
    return {
        "scanned_files": len(results),
        "findings": [f for f in all_findings if f["status"] == "finding"],
        "review_needed": [f for f in all_findings if f["status"] == "review-needed"],
        "errors": [r for r in results if r["error"]],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Lab-only SSRF detector (static, no network).")
    parser.add_argument("--path", required=True, help="Python file or directory to scan (local only).")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)
    report = scan_path(args.path)
    if args.format == "json":
        print(json.dumps(report, indent=2))
        return 0
    print(f"Scanned files: {report['scanned_files']}")
    print(f"Findings (unvalidated dynamic fetch): {len(report['findings'])}")
    print(f"Review-needed (validation marker present): {len(report['review_needed'])}")
    for item in report["findings"] + report["review_needed"]:
        print(f"- {item['path']}:{item['line']} in {item['function']}() "
              f"[{item['status']}, url arg: {item['url_arg_kind']}]")
    for err in report["errors"]:
        print(f"! {err['path']}: {err['error']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
