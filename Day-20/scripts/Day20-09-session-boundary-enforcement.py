from dataclasses import dataclass, field
from typing import Dict
import uuid


print(
    "\n=== Day 20 Lab 9: "
    "Session Boundary Enforcement ==="
)


# ============================================================
# USER STATE
# ============================================================

USERS = {
    "alice": {
        "role": "employee",
    },

    "admin": {
        "role": "administrator",
    },
}


# ============================================================
# SESSION MODEL
# ============================================================

@dataclass
class Session:
    session_id: str
    actor: str
    trusted_role: str
    conversation_state: Dict[str, str] = field(
        default_factory=dict
    )


def create_session(
    actor: str,
) -> Session:

    return Session(
        session_id=str(
            uuid.uuid4()
        ),
        actor=actor,
        trusted_role=USERS[
            actor
        ][
            "role"
        ],
    )


# ============================================================
# APPROVAL MODEL
# ============================================================

@dataclass
class Approval:
    approval_id: str
    session_id: str
    actor: str
    action: str
    target: str
    used: bool = False


APPROVALS = {}


def issue_approval(
    *,
    session: Session,
    action: str,
    target: str,
):

    approval = Approval(
        approval_id=(
            "APPROVAL-"
            + str(
                uuid.uuid4()
            )
        ),
        session_id=session.session_id,
        actor=session.actor,
        action=action,
        target=target,
    )

    APPROVALS[
        approval.approval_id
    ] = approval

    return approval


# ============================================================
# CONVERSATION STATE
# ============================================================

def remember(
    *,
    session: Session,
    key: str,
    value: str,
):

    session.conversation_state[
        key
    ] = value


def recall(
    *,
    session: Session,
    key: str,
):

    return session.conversation_state.get(
        key
    )


# ============================================================
# APPROVAL VALIDATION
# ============================================================

def validate_approval(
    *,
    session: Session,
    approval_id: str,
    action: str,
    target: str,
):

    approval = APPROVALS.get(
        approval_id
    )

    if approval is None:

        return (
            False,
            "Unknown approval."
        )

    if approval.used:

        return (
            False,
            "Approval already used."
        )

    if (
        approval.session_id
        != session.session_id
    ):

        return (
            False,
            "Approval belongs to another session."
        )

    if (
        approval.actor
        != session.actor
    ):

        return (
            False,
            "Approval belongs to another actor."
        )

    if (
        approval.action
        != action
    ):

        return (
            False,
            "Approval action mismatch."
        )

    if (
        approval.target
        != target
    ):

        return (
            False,
            "Approval target mismatch."
        )

    return (
        True,
        "Approval valid."
    )


# ============================================================
# TEST SETUP
# ============================================================

old_session = create_session(
    "admin"
)


remember(
    session=old_session,
    key="claimed_role",
    value="administrator",
)


remember(
    session=old_session,
    key="trigger_phrase",
    value="ORANGE-LANTERN",
)


remember(
    session=old_session,
    key="conversation_approval_claim",
    value="approved",
)


old_approval = issue_approval(
    session=old_session,
    action="delete_record",
    target="R-9001",
)


print(
    "\n========================================"
)

print(
    "OLD SESSION"
)

print(
    "========================================"
)


print(
    "Session ID:",
    old_session.session_id,
)

print(
    "Actor:",
    old_session.actor,
)

print(
    "Trusted Role:",
    old_session.trusted_role,
)

print(
    "Conversation State:",
    old_session.conversation_state,
)

print(
    "Issued Approval:",
    old_approval.approval_id,
)


# ============================================================
# CREATE NEW SESSION
# ============================================================

new_session = create_session(
    "admin"
)


print(
    "\n========================================"
)

print(
    "NEW SESSION"
)

print(
    "========================================"
)


print(
    "Session ID:",
    new_session.session_id,
)

print(
    "Actor:",
    new_session.actor,
)

print(
    "Trusted Role:",
    new_session.trusted_role,
)

print(
    "Conversation State:",
    new_session.conversation_state,
)


# ============================================================
# TESTS
# ============================================================

tests_passed = 0
total_tests = 6


# ------------------------------------------------------------
# TEST 1
# Session identifier changed
# ------------------------------------------------------------

different_session = (
    old_session.session_id
    != new_session.session_id
)


print(
    "\nTest 1 — New Session Identifier"
)

print(
    "Result:",
    different_session,
)


if different_session:
    tests_passed += 1


# ------------------------------------------------------------
# TEST 2
# Old role claim is not copied
# ------------------------------------------------------------

old_claim_absent = (
    recall(
        session=new_session,
        key="claimed_role",
    )
    is None
)


print(
    "\nTest 2 — Old Role Claim Cleared"
)

print(
    "Result:",
    old_claim_absent,
)


if old_claim_absent:
    tests_passed += 1


# ------------------------------------------------------------
# TEST 3
# Delayed trigger is not copied
# ------------------------------------------------------------

old_trigger_absent = (
    recall(
        session=new_session,
        key="trigger_phrase",
    )
    is None
)


print(
    "\nTest 3 — Old Trigger Cleared"
)

print(
    "Result:",
    old_trigger_absent,
)


if old_trigger_absent:
    tests_passed += 1


# ------------------------------------------------------------
# TEST 4
# Conversation approval claim is not copied
# ------------------------------------------------------------

old_conversation_approval_absent = (
    recall(
        session=new_session,
        key="conversation_approval_claim",
    )
    is None
)


print(
    "\nTest 4 — Conversation Approval Claim Cleared"
)

print(
    "Result:",
    old_conversation_approval_absent,
)


if old_conversation_approval_absent:
    tests_passed += 1


# ------------------------------------------------------------
# TEST 5
# Trusted identity persists correctly
# ------------------------------------------------------------

identity_correct = (
    new_session.actor
    == "admin"
    and
    new_session.trusted_role
    == "administrator"
)


print(
    "\nTest 5 — Trusted Identity Re-established"
)

print(
    "Result:",
    identity_correct,
)


if identity_correct:
    tests_passed += 1


# ------------------------------------------------------------
# TEST 6
# Old trusted approval is invalid in new session
# ------------------------------------------------------------

approval_valid, approval_reason = (
    validate_approval(
        session=new_session,
        approval_id=old_approval.approval_id,
        action="delete_record",
        target="R-9001",
    )
)


cross_session_blocked = (
    approval_valid is False
)


print(
    "\nTest 6 — Old Approval Reuse"
)

print(
    "Approval Valid:",
    approval_valid,
)

print(
    "Reason:",
    approval_reason,
)

print(
    "Cross-Session Reuse Blocked:",
    cross_session_blocked,
)


if cross_session_blocked:
    tests_passed += 1


# ============================================================
# SUMMARY
# ============================================================

print(
    "\n========================================"
)

print(
    "      SESSION BOUNDARY SUMMARY"
)

print(
    "========================================"
)


print(
    f"Tests: "
    f"{total_tests}"
)

print(
    f"Passed: "
    f"{tests_passed}/{total_tests}"
)


print(
    "Session Boundary Control Accuracy:",
    f"{tests_passed / total_tests * 100:.2f}%"
)


print(
    "Old Conversation Role Claim Persisted:",
    not old_claim_absent,
)

print(
    "Old Delayed Trigger Persisted:",
    not old_trigger_absent,
)

print(
    "Old Conversation Approval Persisted:",
    not old_conversation_approval_absent,
)

print(
    "Old Trusted Approval Valid in New Session:",
    approval_valid,
)


print(
    "\n=== Security Interpretation ==="
)

print(
    "A new session must create a new conversational "
    "and security boundary."
)

print(
    "Attacker-controlled context from the old session "
    "must not silently carry into the new session."
)

print(
    "Trusted identity may be re-established, but old "
    "approval objects remain bound to their original "
    "session."
)


print(
    "\nCore Principle:"
)

print(
    "Trust must be re-evaluated across the conversation "
    "lifecycle; earlier context should not silently "
    "become permanent authority."
)