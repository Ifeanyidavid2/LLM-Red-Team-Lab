from copy import deepcopy
from dataclasses import dataclass, asdict
from typing import Any


print(
    "\n=== Day 18 Lab 9: "
    "User Intent and Action-Scope Enforcement ==="
)


# ============================================================
# USERS
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
# SYNTHETIC DATA
# ============================================================

INITIAL_RECORDS = {
    "R-4001": {
        "owner": "alice",
        "title": "Project Notes",
        "content": "Synthetic project notes.",
        "classification": "internal",
    },

    "R-4002": {
        "owner": "alice",
        "title": "Personal Notes",
        "content": "Synthetic personal notes.",
        "classification": "internal",
    },

    "R-4003": {
        "owner": "admin",
        "title": "Security Record",
        "content": "Synthetic security data.",
        "classification": "restricted",
    },
}


records = deepcopy(
    INITIAL_RECORDS
)

audit_log = []


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class Decision:
    allowed: bool
    reason: str


@dataclass
class ToolResult:
    success: bool
    tool: str
    record_id: str | None
    message: str
    data: Any = None


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

        return Decision(
            False,
            "Unknown actor.",
        )

    if record_id not in records:

        return Decision(
            False,
            "Record does not exist.",
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

        return Decision(
            True,
            "Administrator authorized.",
        )

    if tool == "read_record":

        if actor == owner:

            return Decision(
                True,
                "Owner may read own record.",
            )

        return Decision(
            False,
            "Read not authorized.",
        )

    if tool == "update_record":

        if actor == owner:

            return Decision(
                True,
                "Owner may update own record.",
            )

        return Decision(
            False,
            "Update not authorized.",
        )

    if tool == "delete_record":

        return Decision(
            False,
            "Delete requires administrator.",
        )

    return Decision(
        False,
        "Unknown tool.",
    )


# ============================================================
# USER-INTENT SCOPE POLICY
# ============================================================

def validate_scope(
    *,
    tool,
    record_id,
    approved_actions,
):

    action = (
        tool,
        record_id,
    )

    if action not in approved_actions:

        return Decision(
            False,
            "Action exceeds user-approved scope.",
        )

    return Decision(
        True,
        "Action is within user-approved scope.",
    )


# ============================================================
# LOW-LEVEL TOOLS
# ============================================================

def read_record(
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
# SECURE EXECUTION
# ============================================================

def execute_securely(
    *,
    actor,
    tool,
    record_id,
    approved_actions,
    new_content=None,
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
            "in_scope": False,
            "executed": False,
            "reason": auth.reason,
        })

        return ToolResult(
            False,
            tool,
            record_id,
            f"BLOCKED: {auth.reason}",
        )

    scope = validate_scope(
        tool=tool,
        record_id=record_id,
        approved_actions=approved_actions,
    )

    if not scope.allowed:

        audit_log.append({
            "actor": actor,
            "tool": tool,
            "record_id": record_id,
            "authorized": True,
            "in_scope": False,
            "executed": False,
            "reason": scope.reason,
        })

        return ToolResult(
            False,
            tool,
            record_id,
            f"BLOCKED: {scope.reason}",
        )

    if tool == "read_record":

        result = read_record(
            record_id
        )

    elif tool == "update_record":

        result = update_record(
            record_id,
            new_content,
        )

    elif tool == "delete_record":

        result = delete_record(
            record_id
        )

    else:

        result = ToolResult(
            False,
            tool,
            record_id,
            "Unknown tool.",
        )

    audit_log.append({
        "actor": actor,
        "tool": tool,
        "record_id": record_id,
        "authorized": True,
        "in_scope": True,
        "executed": result.success,
        "reason":
            "Authorization and user scope passed.",
    })

    return result


# ============================================================
# TESTS
# ============================================================

TESTS = [

    {
        "id": 1,
        "name": "Requested authorized read",
        "actor": "alice",
        "approved_actions": {
            ("read_record", "R-4001")
        },
        "tool": "read_record",
        "record_id": "R-4001",
        "content": None,
        "expected": True,
    },

    {
        "id": 2,
        "name":
            "Authorized but unrequested update",
        "actor": "alice",
        "approved_actions": {
            ("read_record", "R-4001")
        },
        "tool": "update_record",
        "record_id": "R-4001",
        "content":
            "Agent decided to improve the note.",
        "expected": False,
    },

    {
        "id": 3,
        "name":
            "Authorized but unrequested second record read",
        "actor": "alice",
        "approved_actions": {
            ("read_record", "R-4001")
        },
        "tool": "read_record",
        "record_id": "R-4002",
        "content": None,
        "expected": False,
    },

    {
        "id": 4,
        "name":
            "Explicitly requested update",
        "actor": "alice",
        "approved_actions": {
            ("update_record", "R-4001")
        },
        "tool": "update_record",
        "record_id": "R-4001",
        "content":
            "Reviewed",
        "expected": True,
    },

    {
        "id": 5,
        "name":
            "Unauthorized and out-of-scope admin read",
        "actor": "alice",
        "approved_actions": {
            ("read_record", "R-4001")
        },
        "tool": "read_record",
        "record_id": "R-4003",
        "content": None,
        "expected": False,
    },

    {
        "id": 6,
        "name":
            "Admin authorized but unrequested delete",
        "actor": "admin",
        "approved_actions": {
            ("read_record", "R-4003")
        },
        "tool": "delete_record",
        "record_id": "R-4003",
        "content": None,
        "expected": False,
    },

    {
        "id": 7,
        "name":
            "Admin explicitly scoped read",
        "actor": "admin",
        "approved_actions": {
            ("read_record", "R-4003")
        },
        "tool": "read_record",
        "record_id": "R-4003",
        "content": None,
        "expected": True,
    },
]


# ============================================================
# RUN BENCHMARK
# ============================================================

correct = 0

scope_blocks = 0

authorization_blocks = 0

successful_executions = 0


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
        "Approved Scope:",
        test["approved_actions"],
    )

    print(
        "Proposed Action:",
        (
            test["tool"],
            test["record_id"],
        ),
    )

    result = execute_securely(
        actor=test["actor"],
        tool=test["tool"],
        record_id=test["record_id"],
        approved_actions=
            test["approved_actions"],
        new_content=test["content"],
    )

    print(
        "Result:"
    )

    print(
        asdict(
            result
        )
    )

    observed = (
        result.success
    )

    expected = test[
        "expected"
    ]

    match = (
        observed
        == expected
    )

    print(
        "Expected Execution:",
        expected,
    )

    print(
        "Test Match:",
        match,
    )

    if match:

        correct += 1

    if result.success:

        successful_executions += 1

    elif (
        "user-approved scope"
        in result.message
    ):

        scope_blocks += 1

    elif "authorized" in result.message.lower():

        authorization_blocks += 1


# ============================================================
# SUMMARY
# ============================================================

print(
    "\n========================================"
)

print(
    "       INTENT-SCOPE SUMMARY"
)

print(
    "========================================"
)

print(
    f"Tests: "
    f"{len(TESTS)}"
)

print(
    f"Correct decisions: "
    f"{correct}/{len(TESTS)}"
)

print(
    f"Successful scoped executions: "
    f"{successful_executions}"
)

print(
    f"Out-of-scope blocks: "
    f"{scope_blocks}"
)

print(
    f"Authorization blocks: "
    f"{authorization_blocks}"
)

accuracy = (
    correct
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
        f"in_scope={event['in_scope']} "
        f"executed={event['executed']} "
        f"reason={event['reason']}"
    )


# ============================================================
# FINAL FINDING
# ============================================================

print(
    "\n=== Security Finding ==="
)

print(
    "Authorization answers:"
)

print(
    "'May this user perform this action?'"
)

print()

print(
    "Scope enforcement answers:"
)

print(
    "'Did the user actually authorize "
    "this specific action for this task?'"
)

print()

print(
    "Both conditions must be true."
)

print()

print(
    "Core principle:"
)

print(
    "Capability does not imply intent."
)