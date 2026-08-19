from dataclasses import dataclass
from typing import Optional
import uuid


print(
    "\n=== Day 20 Lab 7: "
    "Authorization & Approval Reuse ==="
)


# ============================================================
# TRUSTED APPLICATION STATE
# ============================================================

USERS = {
    "alice": {
        "role": "employee"
    },

    "admin": {
        "role": "administrator"
    }
}


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


# ============================================================
# SESSION MODEL
# ============================================================

@dataclass
class Session:
    session_id: str
    actor: str
    trusted_role: str


def create_session(
    actor: str
) -> Session:

    if actor not in USERS:
        raise ValueError(
            "Unknown synthetic user."
        )

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
# APPROVAL STORE
# ============================================================

APPROVALS = {}


def issue_approval(
    *,
    session: Session,
    action: str,
    target: str,
) -> Approval:

    approval_id = (
        "APPROVAL-"
        + str(
            uuid.uuid4()
        )
    )

    approval = Approval(
        approval_id=approval_id,
        session_id=session.session_id,
        actor=session.actor,
        action=action,
        target=target,
        used=False,
    )

    APPROVALS[
        approval_id
    ] = approval

    return approval


# ============================================================
# AUTHORIZATION
# ============================================================

def authorized_for_action(
    *,
    session: Session,
    action: str,
) -> bool:

    if action == "read_record":
        return True

    if action == "delete_record":
        return (
            session.trusted_role
            == "administrator"
        )

    return False


# ============================================================
# APPROVAL VALIDATION
# ============================================================

def validate_approval(
    *,
    session: Session,
    approval_id: Optional[str],
    action: str,
    target: str,
):

    if approval_id is None:

        return (
            False,
            "Approval required."
        )

    if approval_id not in APPROVALS:

        return (
            False,
            "Unknown approval identifier."
        )

    approval = APPROVALS[
        approval_id
    ]

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
            "Approval belongs to a different session."
        )

    if (
        approval.actor
        != session.actor
    ):

        return (
            False,
            "Approval belongs to a different actor."
        )

    if (
        approval.action
        != action
    ):

        return (
            False,
            "Approval action scope mismatch."
        )

    if (
        approval.target
        != target
    ):

        return (
            False,
            "Approval target scope mismatch."
        )

    return (
        True,
        "Approval valid."
    )


# ============================================================
# SECURITY PIPELINE
# ============================================================

def execute_sensitive_action(
    *,
    session: Session,
    action: str,
    target: str,
    approval_id: Optional[str],
):

    # --------------------------------------------------------
    # Authorization
    # --------------------------------------------------------

    if not authorized_for_action(
        session=session,
        action=action,
    ):

        return {
            "executed": False,
            "stage": "AUTHORIZATION",
            "reason":
                "Actor not authorized for action.",
        }


    # --------------------------------------------------------
    # Approval required for high-impact delete
    # --------------------------------------------------------

    if action == "delete_record":

        valid, reason = validate_approval(
            session=session,
            approval_id=approval_id,
            action=action,
            target=target,
        )

        if not valid:

            return {
                "executed": False,
                "stage": "APPROVAL",
                "reason": reason,
            }


        APPROVALS[
            approval_id
        ].used = True


    return {
        "executed": True,
        "stage": None,
        "reason":
            "Trusted security checks passed.",
    }


# ============================================================
# TEST ENVIRONMENT
# ============================================================

admin_session = create_session(
    "admin"
)

alice_session = create_session(
    "alice"
)


print(
    "\n========================================"
)

print(
    "Trusted Sessions"
)

print(
    "========================================"
)

print(
    "Admin Session:",
    admin_session.session_id
)

print(
    "Alice Session:",
    alice_session.session_id
)


# ============================================================
# ISSUE VALID APPROVAL
# ============================================================

approval = issue_approval(
    session=admin_session,
    action="delete_record",
    target="R-7001",
)


print(
    "\nIssued Approval:"
)

print(
    approval
)


# ============================================================
# CASE DEFINITIONS
# ============================================================

TESTS = [

    {
        "case_id": 1,
        "name":
            "Correct first use",

        "session":
            admin_session,

        "action":
            "delete_record",

        "target":
            "R-7001",

        "approval_id":
            approval.approval_id,

        "expected":
            True,
    },

    {
        "case_id": 2,
        "name":
            "Replay consumed approval",

        "session":
            admin_session,

        "action":
            "delete_record",

        "target":
            "R-7001",

        "approval_id":
            approval.approval_id,

        "expected":
            False,
    },

    {
        "case_id": 3,
        "name":
            "Target substitution",

        "session":
            admin_session,

        "action":
            "delete_record",

        "target":
            "R-7002",

        "approval_id":
            None,

        "expected":
            False,
    },

    {
        "case_id": 4,
        "name":
            "Action substitution",

        "session":
            admin_session,

        "action":
            "read_record",

        "target":
            "R-7001",

        "approval_id":
            approval.approval_id,

        "expected":
            True,
    },

    {
        "case_id": 5,
        "name":
            "Employee attempts approval reuse",

        "session":
            alice_session,

        "action":
            "delete_record",

        "target":
            "R-7001",

        "approval_id":
            approval.approval_id,

        "expected":
            False,
    },
]


# ============================================================
# NEW VALID APPROVAL FOR CROSS-SESSION TEST
# ============================================================

cross_session_approval = issue_approval(
    session=admin_session,
    action="delete_record",
    target="R-7003",
)


new_admin_session = create_session(
    "admin"
)


TESTS.append(
    {
        "case_id": 6,
        "name":
            "Cross-session approval reuse",

        "session":
            new_admin_session,

        "action":
            "delete_record",

        "target":
            "R-7003",

        "approval_id":
            cross_session_approval.approval_id,

        "expected":
            False,
    }
)


# ============================================================
# TARGET-SUBSTITUTION APPROVAL
# ============================================================

target_scope_approval = issue_approval(
    session=admin_session,
    action="delete_record",
    target="R-7004",
)


TESTS.append(
    {
        "case_id": 7,
        "name":
            "Valid approval wrong target",

        "session":
            admin_session,

        "action":
            "delete_record",

        "target":
            "R-7999",

        "approval_id":
            target_scope_approval.approval_id,

        "expected":
            False,
    }
)


# ============================================================
# ACTION-SUBSTITUTION APPROVAL
# ============================================================

action_scope_approval = issue_approval(
    session=admin_session,
    action="delete_record",
    target="R-7005",
)


TESTS.append(
    {
        "case_id": 8,
        "name":
            "Valid approval wrong action",

        "session":
            admin_session,

        "action":
            "archive_record",

        "target":
            "R-7005",

        "approval_id":
            action_scope_approval.approval_id,

        "expected":
            False,
    }
)


# ============================================================
# BENCHMARK
# ============================================================

correct_decisions = 0

unsafe_reuse_successes = 0

replay_blocks = 0

scope_blocks = 0

session_blocks = 0

authorization_blocks = 0

successful_executions = 0


for case in TESTS:

    print(
        "\n========================================"
    )

    print(
        f"Case {case['case_id']}: "
        f"{case['name']}"
    )

    print(
        "========================================"
    )


    print(
        "Actor:",
        case[
            "session"
        ].actor,
    )

    print(
        "Session:",
        case[
            "session"
        ].session_id,
    )

    print(
        "Action:",
        case[
            "action"
        ],
    )

    print(
        "Target:",
        case[
            "target"
        ],
    )

    print(
        "Approval:",
        case[
            "approval_id"
        ],
    )


    result = execute_sensitive_action(
        session=case[
            "session"
        ],
        action=case[
            "action"
        ],
        target=case[
            "target"
        ],
        approval_id=case[
            "approval_id"
        ],
    )


    print(
        "\nSecurity Result:"
    )

    print(
        result
    )


    executed = result[
        "executed"
    ]


    expected_match = (
        executed
        == case[
            "expected"
        ]
    )


    if expected_match:

        correct_decisions += 1


    if executed:

        successful_executions += 1


    # --------------------------------------------------------
    # Unsafe reuse success
    # --------------------------------------------------------

    if (
        case[
            "case_id"
        ] != 1
        and executed
        and case[
            "action"
        ] == "delete_record"
    ):

        unsafe_reuse_successes += 1


    reason = result[
        "reason"
    ].lower()


    if (
        "already used"
        in reason
    ):

        replay_blocks += 1


    if (
        "scope mismatch"
        in reason
    ):

        scope_blocks += 1


    if (
        "different session"
        in reason
    ):

        session_blocks += 1


    if (
        result[
            "stage"
        ]
        == "AUTHORIZATION"
    ):

        authorization_blocks += 1


    print(
        "Expected Execution:",
        case[
            "expected"
        ],
    )

    print(
        "Test Match:",
        expected_match,
    )


# ============================================================
# SUMMARY
# ============================================================

total_tests = len(
    TESTS
)


print(
    "\n========================================"
)

print(
    "    APPROVAL REUSE SUMMARY"
)

print(
    "========================================"
)


print(
    f"Tests: "
    f"{total_tests}"
)

print(
    f"Correct security decisions: "
    f"{correct_decisions}/{total_tests}"
)

print(
    f"Successful executions: "
    f"{successful_executions}"
)

print(
    f"Unsafe approval-reuse successes: "
    f"{unsafe_reuse_successes}"
)

print(
    f"Replay blocks: "
    f"{replay_blocks}"
)

print(
    f"Scope-mismatch blocks: "
    f"{scope_blocks}"
)

print(
    f"Cross-session blocks: "
    f"{session_blocks}"
)

print(
    f"Authorization blocks: "
    f"{authorization_blocks}"
)


decision_accuracy = (
    correct_decisions
    / total_tests
    * 100
)


print(
    "Control Decision Accuracy:",
    f"{decision_accuracy:.2f}%"
)


reuse_attack_cases = sum(
    case[
        "case_id"
    ] != 1
    and case[
        "action"
    ] == "delete_record"
    for case in TESTS
)


if reuse_attack_cases:

    reuse_success_rate = (
        unsafe_reuse_successes
        / reuse_attack_cases
        * 100
    )

else:

    reuse_success_rate = 0.0


print(
    "Approval Reuse Attack Success Rate:",
    f"{reuse_success_rate:.2f}%"
)


print(
    "\n=== Security Interpretation ==="
)

print(
    "Approval is scoped security state."
)

print(
    "A previously valid approval must not automatically "
    "remain valid for another action, target, actor, or session."
)

print(
    "Consumed approvals must not be replayable."
)


print(
    "\nCore Principle:"
)

print(
    "Trust must be re-evaluated across the conversation "
    "lifecycle; earlier context should not silently "
    "become permanent authority."
)