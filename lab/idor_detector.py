#!/usr/bin/env python3
"""Lab-only, defensive IDOR detector (CWE-639 / CWE-862).

Static analysis only. This tool READS Python source files as text and
reports object lookups by a caller-supplied ID (for example
``documents.get(doc_id)``) where the enclosing function shows no nearby
ownership/authorization marker. It NEVER fetches a URL, NEVER runs the
scanned code, and NEVER contacts any server. It is a detection aid,
not an exploit tool.

Usage:
    python lab/idor_detector.py --path lab/sample_idor_input.py
    python lab/idor_detector.py --path some_dir --format json

Exit code is always 0 when the scan itself succeeds, even if findings
are present, so CI can parse the report instead of relying on exit codes.
"""
import argparse
import ast
import json
import sys
from pathlib import Path

AUTHORIZATION_MARKERS = (
    "authorize", "authorization", "check_permission", "has_permission",
    "require_permission", "permission_required", "is_owner", "check_owner",
    "verify_owner", "owner_id", "owned_by", "current_user",
    "authenticated_user", "can_access", "check_access", "ensure_owner",
)
LOOKUP_NAMES = {
    "get", "get_by_id", "find_by_id", "get_object", "get_item",
    "get_document", "get_record", "fetch_by_id", "load", "load_by_id",
}


def _is_lookup_call(node):
    if isinstance(node.func, ast.Attribute):
        return node.func.attr in LOOKUP_NAMES
    if isinstance(node.func, ast.Name):
        return node.func.id in LOOKUP_NAMES
    return False


def _id_is_dynamic(node):
    if not node.args:
        return False, "no-id-arg"
    id_arg = node.args[0]
    if isinstance(id_arg, ast.Constant):
        return False, "constant-id"
    return True, type(id_arg).__name__


def _function_has_authorization(func_node, source_lines):
    start = func_node.lineno - 1
    end = getattr(func_node, "end_lineno", func_node.lineno) or func_node.lineno
    text = "\n".join(source_lines[start:end]).lower()
    return [m for m in AUTHORIZATION_MARKERS if m in text]


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
        markers = _function_has_authorization(node, lines)
        for child in ast.walk(node):
            if not isinstance(child, ast.Call) or not _is_lookup_call(child):
                continue
            dynamic, kind = _id_is_dynamic(child)
            if not dynamic:
                continue
            findings.append({
                "path": str(path),
                "line": child.lineno,
                "function": node.name,
                "id_arg_kind": kind,
                "status": "review-needed" if markers else "finding",
                "authorization_markers": markers,
                "recommendation": (
                    "Load the object, then verify the caller owns it or "
                    "holds an explicit permission for it, before returning "
                    "or mutating it. Deny by default. "
                    "See lab/idor_mitigation_checklist.md."
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
    parser = argparse.ArgumentParser(description="Lab-only IDOR detector (static, no network).")
    parser.add_argument("--path", required=True, help="Python file or directory to scan (local only).")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)
    report = scan_path(args.path)
    if args.format == "json":
        print(json.dumps(report, indent=2))
        return 0
    print(f"Scanned files: {report['scanned_files']}")
    print(f"Findings (unvalidated object access by ID): {len(report['findings'])}")
    print(f"Review-needed (authorization marker present): {len(report['review_needed'])}")
    for item in report["findings"] + report["review_needed"]:
        print(f"- {item['path']}:{item['line']} in {item['function']}() "
              f"[{item['status']}, id arg: {item['id_arg_kind']}]")
    for err in report["errors"]:
        print(f"! {err['path']}: {err['error']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
