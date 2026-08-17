from copy import deepcopy
from dataclasses import dataclass, asdict
from typing import Any


print(
    "\n=== Day 18 Lab 5: "
    "High-Impact Action Approval ==="
)


# ============================================================
# USERS
# ============================================================

USERS = {
    "alice": {
        "role": "employee",
    },
    "bob": {
        "role": "manager",
    },
    "admin": {
        "role": "administrator",
    },
}


# ============================================================
# SYNTHETIC RECORDS
# ============================================================

INITIAL_RECORDS = {
    "R-1001": {
        "owner": "alice",
        "title": "Quarterly Notes",
        "content": "Synthetic quarterly notes.",
        "classification": "internal",
    },

    "R-1002": {
        "owner": "bob",
        "title": "Team Budget",
        "content": "Synthetic budget data.",
        "classification": "restricted",
    },

    "R-1003": {
        "owner": "admin",
        "title": "Security Configuration",
        "content": "Synthetic security configuration.",
        "classification": "restricted",
    },
}


records = deepcopy(
    INITIAL_RECORDS
)


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class AuthorizationResult:
    allowed: bool
    reason: str


@dataclass
class ApprovalResult:
    approved: bool
    required: bool
    reason: str


@dataclass
class ToolResult:
    success: bool
    tool: str
    record_id: str | None
    message: str
    data: Any = None


# ============================================================
# TRUSTED APPROVAL STORE
# ============================================================

# These are synthetic one-time approval identifiers.
# They are issued by trusted application logic,
# NOT created by the model.

APPROVALS = {
    "APPROVAL-DELETE-R1003": {
        "actor": "admin",
        "tool": "delete_record",
        "record_id": "R-1003",
        "used": False,
    }
}


# ============================================================
# AUDIT LOG
# ============================================================

audit_log = []


# ============================================================
# AUTHORIZATION
# ============================================================

def authorize(
    *,
    actor,
    tool,
    record_id,
):

    if actor not in USERS:

        return AuthorizationResult(
            False,
            "Unknown actor.",
        )

    if record_id not in records:

        return AuthorizationResult(
            False,
            "Record not found.",
        )

    if tool not in {
        "read_record",
        "update_record",
        "delete_record",
    }:

        return AuthorizationResult(
            False,
            "Unknown tool.",
        )

    role = USERS[
        actor
    ][
        "role"
    ]

    owner = records[
        record_id
    ][
        "owner"
    ]

    if role == "administrator":

        return AuthorizationResult(
            True,
            "Administrator authorized.",
        )

    if tool == "read_record":

        if actor == owner:

            return AuthorizationResult(
                True,
                "Owner may read own record.",
            )

        return AuthorizationResult(
            False,
            "Read not authorized.",
        )

    if tool == "update_record":

        if actor == owner:

            return AuthorizationResult(
                True,
                "Owner may update own record.",
            )

        return AuthorizationResult(
            False,
            "Update not authorized.",
        )

    if tool == "delete_record":

        return AuthorizationResult(
            False,
            "Delete requires administrator role.",
        )

    return AuthorizationResult(
        False,
        "Policy denied.",
    )


# ============================================================
# APPROVAL POLICY
# ============================================================

def requires_approval(
    tool,
):

    return (
        tool == "delete_record"
    )


def validate_approval(
    *,
    actor,
    tool,
    record_id,
    approval_id,
):

    if not requires_approval(
        tool
    ):

        return ApprovalResult(
            True,
            False,
            "Approval not required.",
        )

    if approval_id is None:

        return ApprovalResult(
            False,
            True,
            "Explicit approval required.",
        )

    if approval_id not in APPROVALS:

        return ApprovalResult(
            False,
            True,
            "Unknown approval identifier.",
        )

    approval = APPROVALS[
        approval_id
    ]

    if approval[
        "used"
    ]:

        return ApprovalResult(
            False,
            True,
            "Approval has already been used.",
        )

    if (
        approval["actor"] != actor
        or approval["tool"] != tool
        or approval["record_id"] != record_id
    ):

        return ApprovalResult(
            False,
            True,
            "Approval scope mismatch.",
        )

    return ApprovalResult(
        True,
        True,
        "Valid explicit approval.",
    )


# ============================================================
# LOW-LEVEL TOOLS
# ============================================================

def read_record(
    actor,
    record_id,
):

    return ToolResult(
        True,
        "read_record",
        record_id,
        "Record retrieved.",
        deepcopy(
            records[
                record_id
            ]
        ),
    )


def update_record(
    actor,
    record_id,
    new_content,
):

    records[
        record_id
    ][
        "content"
    ] = new_content

    return ToolResult(
        True,
        "update_record",
        record_id,
        "Record updated.",
        deepcopy(
            records[
                record_id
            ]
        ),
    )


def delete_record(
    actor,
    record_id,
):

    deleted = records.pop(
        record_id
    )

    return ToolResult(
        True,
        "delete_record",
        record_id,
        "Record deleted.",
        deleted,
    )


# ============================================================
# TRUSTED EXECUTION PIPELINE
# ============================================================

def execute_securely(
    *,
    actor,
    tool,
    record_id,
    new_content=None,
    approval_id=None,
):

    auth = authorize(
        actor=actor,
        tool=tool,
        record_id=record_id,
    )

    if not auth.allowed:

        audit_log.append({
            "actor": actor,
            "tool": tool,
            "record_id": record_id,
            "authorized": False,
            "approved": False,
            "executed": False,
            "reason": auth.reason,
        })

        return ToolResult(
            False,
            tool,
            record_id,
            f"BLOCKED: {auth.reason}",
        )

    approval = validate_approval(
        actor=actor,
        tool=tool,
        record_id=record_id,
        approval_id=approval_id,
    )

    if not approval.approved:

        audit_log.append({
            "actor": actor,
            "tool": tool,
            "record_id": record_id,
            "authorized": True,
            "approved": False,
            "executed": False,
            "reason": approval.reason,
        })

        return ToolResult(
            False,
            tool,
            record_id,
            f"BLOCKED: {approval.reason}",
        )

    if tool == "read_record":

        result = read_record(
            actor,
            record_id,
        )

    elif tool == "update_record":

        result = update_record(
            actor,
            record_id,
            new_content,
        )

    elif tool == "delete_record":

        result = delete_record(
            actor,
            record_id,
        )

    else:

        result = ToolResult(
            False,
            tool,
            record_id,
            "Unknown tool.",
        )

    # Consume one-time approval.
    if (
        result.success
        and requires_approval(tool)
        and approval_id in APPROVALS
    ):

        APPROVALS[
            approval_id
        ][
            "used"
        ] = True

    audit_log.append({
        "actor": actor,
        "tool": tool,
        "record_id": record_id,
        "authorized": True,
        "approved": True,
        "executed": result.success,
        "reason": approval.reason,
    })

    return result


# ============================================================
# TEST CASES
# ============================================================

TESTS = [

    {
        "id": 1,
        "name": "Normal authorized read",
        "actor": "alice",
        "tool": "read_record",
        "record": "R-1001",
        "approval": None,
        "expected_execution": True,
    },

    {
        "id": 2,
        "name": "Normal authorized update",
        "actor": "alice",
        "tool": "update_record",
        "record": "R-1001",
        "content":
            "Updated quarterly notes.",
        "approval": None,
        "expected_execution": True,
    },

    {
        "id": 3,
        "name":
            "Unauthorized employee delete",
        "actor": "alice",
        "tool": "delete_record",
        "record": "R-1003",
        "approval": None,
        "expected_execution": False,
    },

    {
        "id": 4,
        "name":
            "Authorized admin delete without approval",
        "actor": "admin",
        "tool": "delete_record",
        "record": "R-1003",
        "approval": None,
        "expected_execution": False,
    },

    {
        "id": 5,
        "name":
            "Authorized admin delete with fake approval",
        "actor": "admin",
        "tool": "delete_record",
        "record": "R-1003",
        "approval":
            "MODEL-GENERATED-APPROVAL",
        "expected_execution": False,
    },

    {
        "id": 6,
        "name":
            "Authorized admin delete with valid approval",
        "actor": "admin",
        "tool": "delete_record",
        "record": "R-1003",
        "approval":
            "APPROVAL-DELETE-R1003",
        "expected_execution": True,
    },

]


# ============================================================
# RUN TESTS
# ============================================================

passed = 0

approval_required_blocks = 0

unauthorized_blocks = 0

high_impact_executions = 0


for test in TESTS:

    print(
        "\n========================================"
    )

    print(
        f"Case {test['id']}: "
        f"{test['name']}"
    )

    print(
        "========================================"
    )

    print(
        "Actor:",
        test["actor"],
    )

    print(
        "Tool:",
        test["tool"],
    )

    print(
        "Record:",
        test["record"],
    )

    print(
        "Approval:",
        test["approval"],
    )

    result = execute_securely(
        actor=test[
            "actor"
        ],
        tool=test[
            "tool"
        ],
        record_id=test[
            "record"
        ],
        new_content=test.get(
            "content"
        ),
        approval_id=test[
            "approval"
        ],
    )

    print(
        "\nResult:"
    )

    print(
        asdict(
            result
        )
    )

    execution = (
        result.success
    )

    expected = test[
        "expected_execution"
    ]

    match = (
        execution
        == expected
    )

    print(
        "Expected Execution:",
        expected,
    )

    print(
        "Policy Match:",
        match,
    )

    if match:
        passed += 1

    if (
        "approval" in result.message.lower()
        and not result.success
    ):

        approval_required_blocks += 1

    if (
        "administrator role"
        in result.message.lower()
        and not result.success
    ):

        unauthorized_blocks += 1

    if (
        test["tool"]
        == "delete_record"
        and result.success
    ):

        high_impact_executions += 1


# ============================================================
# SUMMARY
# ============================================================

print(
    "\n========================================"
)

print(
    "     APPROVAL CONTROL SUMMARY"
)

print(
    "========================================"
)

print(
    f"Tests: "
    f"{len(TESTS)}"
)

print(
    f"Correct security decisions: "
    f"{passed}/{len(TESTS)}"
)

print(
    f"Unauthorized delete blocks: "
    f"{unauthorized_blocks}"
)

print(
    f"Approval-related blocks: "
    f"{approval_required_blocks}"
)

print(
    f"High-impact executions: "
    f"{high_impact_executions}"
)

accuracy = (
    passed
    / len(TESTS)
    * 100
)

print(
    "Control Decision Accuracy:",
    f"{accuracy:.2f}%"
)


# ============================================================
# AUDIT LOG
# ============================================================

print(
    "\n=== Audit Log ==="
)

for index, event in enumerate(
    audit_log,
    start=1,
):

    print(
        f"{index}. "
        f"actor={event['actor']} "
        f"tool={event['tool']} "
        f"record={event['record_id']} "
        f"authorized={event['authorized']} "
        f"approved={event['approved']} "
        f"executed={event['executed']} "
        f"reason={event['reason']}"
    )


# ============================================================
# REPLAY TEST
# ============================================================

print(
    "\n========================================"
)

print(
    "Approval Replay Test"
)

print(
    "========================================"
)

if "R-1003" not in records:

    # Re-create only for the replay-control test.
    records[
        "R-1003"
    ] = deepcopy(
        INITIAL_RECORDS[
            "R-1003"
        ]
    )


replay_result = execute_securely(
    actor="admin",
    tool="delete_record",
    record_id="R-1003",
    approval_id=
        "APPROVAL-DELETE-R1003",
)


print(
    asdict(
        replay_result
    )
)


print(
    "\n=== Security Finding ==="
)

print(
    "Authorization does not equal approval."
)

print(
    "High-impact actions require an explicit "
    "trusted approval generated outside the model."
)

print(
    "Model-generated approval identifiers are not trusted."
)

print(
    "Consumed approvals cannot be replayed."
)