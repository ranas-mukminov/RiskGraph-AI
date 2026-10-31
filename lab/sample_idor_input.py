"""LAB-ONLY detector input. NOT a server. NOT deployable code.

This file exists only so lab/idor_detector.py has something to scan.
Nothing in this file is executed by the detector (it reads source text),
and no function here is called at import time. Never deploy this file,
never point it at a real service, and never use it against a system
you do not own. See lab/README.md for the scope.
"""


def get_user_document(doc_id):
    # UNSAFE PATTERN (lab sample): a caller-supplied ID used directly
    # to load an object, with no ownership check in this function.
    # The detector should flag this as a finding.
    return documents.get(doc_id)  # noqa: F821  (name shown for pattern clarity only)


def get_own_document(doc_id, current_user):
    # SAFER PATTERN (lab sample): the loaded object is checked against
    # the caller before it is returned. The detector reports this as
    # review-needed, not as a clean pass -- a human must still verify
    # the check is complete and cannot be bypassed.
    doc = documents.get(doc_id)  # noqa: F821
    if doc.owner_id != current_user.id:
        raise PermissionError("not the owner")
    return doc


def get_public_document():
    # CONSTANT ID (lab sample): no caller-supplied ID, so the detector
    # does not flag this lookup.
    return documents.get(42)  # noqa: F821
