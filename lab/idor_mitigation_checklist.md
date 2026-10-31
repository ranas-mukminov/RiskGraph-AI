# IDOR / broken access control — mitigation checklist (lab-only)

Applies to the pattern flagged by `lab/idor_detector.py`: an object
loaded by a caller-supplied ID without a nearby ownership or
authorization check. Work through the list in order, in your own lab
code only.

1. **Check ownership on the server, after loading.** Load the object,
   then verify the caller owns it or holds an explicit permission for
   it, before returning or mutating it. Never trust a client-supplied
   ID, role flag, or hidden field as proof of ownership.
2. **Deny by default.** If the object does not exist, or the caller
   has no permission for it, return the same generic "not found" /
   "forbidden" response you use for other failures. Do not leak, via
   timing or error text, whether the object exists.
3. **Apply the check to every path, not just reads.** Writes, deletes,
   downloads, and state changes on the same object need the same
   ownership check. A read check does not cover a delete endpoint.
4. **Do not rely on unguessable IDs alone.** Random, unguessable IDs
   reduce enumeration, but they are not an authorization control. Keep
   the ownership check even when IDs are not sequential.
5. **Scope queries to the caller where possible.** Prefer queries of
   the form "object owned by this caller" over "object by ID, then
   check". The check is still required; scoping is defence in depth.
6. **Log access decisions in the lab.** Record the caller, the object
   ID, and the allow/deny outcome (without recording the object
   contents or credentials), so a lab test with a second user's ID can
   be reviewed.
7. **Test in the lab with a second user.** Create two lab users, have
   user B request user A's object ID, and confirm the request is
   denied. Repeat for every endpoint that takes an object ID.
8. **Review the detector's review-needed items by hand.** A marker
   such as `owner_id` or `current_user` in the function text does not
   prove the check is correct or complete. Read the check, and confirm
   it cannot be bypassed by a missing, null, or mismatched owner.

Out of scope: testing any system you do not own or hold written
authorisation for. See `SECURITY.md` at the repository root.
