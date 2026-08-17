from copy import deepcopy
from dataclasses import dataclass, asdict
from typing import Any


print(
    "\n=== Day 18 Lab 3: "
    "Authorization Policy Engine ==="
)


# ============================================================
# SYNTHETIC USERS
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
        "content":
            "Draft notes for the quarterly planning meeting.",
        "classification": "internal",
    },

    "R-1002": {
        "owner": "bob",
        "title": "Team Budget",
        "content":
            "Synthetic budget information for training purposes.",
        "classification": "restricted",
    },

    "R-1003": {
        "owner": "admin",
        "title": "Security Configuration",
        "content":
            "Synthetic configuration record.",
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
class ToolResult:
    success: bool
    tool: str
    record_id: str | None
    message: str
    data: Any = None


# ============================================================
# AUDIT LOG
# ============================================================

audit_log = []


def log_event(
    *,
    actor,
    tool,
    record_id,
    authorized,
    executed,
    reason,
):

    audit_log.append({
        "actor": actor,
        "tool": tool,
        "record_id": record_id,
        "authorized": authorized,
        "executed": executed,
        "reason": reason,
    })


# ============================================================
# TRUSTED AUTHORIZATION POLICY
# ============================================================

def authorize(
    *,
    actor: str,
    tool: str,
    record_id: str,
) -> AuthorizationResult:

    # ------------------------------------------
    # Validate actor
    # ------------------------------------------

    if actor not in USERS:

        return AuthorizationResult(
            False,
            "Unknown actor.",
        )

    # ------------------------------------------
    # Validate tool
    # ------------------------------------------

    allowed_tools = {
        "read_record",
        "update_record",
        "delete_record",
    }

    if tool not in allowed_tools:

        return AuthorizationResult(
            False,
            "Unknown or unauthorized tool.",
        )

    # ------------------------------------------
    # Validate record
    # ------------------------------------------

    if record_id not in records:

        return AuthorizationResult(
            False,
            "Record does not exist.",
        )

    role = USERS[
        actor
    ][
        "role"
    ]

    record = records[
        record_id
    ]

    owner = record[
        "owner"
    ]

    classification = record[
        "classification"
    ]

    # ------------------------------------------
    # Administrator policy
    # ------------------------------------------

    if role == "administrator":

        return AuthorizationResult(
            True,
            "Administrator authorized.",
        )

    # ------------------------------------------
    # READ POLICY
    # ------------------------------------------

    if tool == "read_record":

        # Owner may read own records.
        if actor == owner:

            return AuthorizationResult(
                True,
                "Owner may read own record.",
            )

        # Managers may read internal records,
        # but not restricted records belonging
        # to another user.
        if (
            role == "manager"
            and classification == "internal"
        ):

            return AuthorizationResult(
                True,
                "Manager may read internal record.",
            )

        return AuthorizationResult(
            False,
            "Actor is not authorized to read "
            "this record.",
        )

    # ------------------------------------------
    # UPDATE POLICY
    # ------------------------------------------

    if tool == "update_record":

        # Users may update only their own records.
        if actor == owner:

            return AuthorizationResult(
                True,
                "Owner may update own record.",
            )

        return AuthorizationResult(
            False,
            "Actor may not update another "
            "user's record.",
        )

    # ------------------------------------------
    # DELETE POLICY
    # ------------------------------------------

    if tool == "delete_record":

        # Delete is high impact.
        # Only administrators may delete.
        return AuthorizationResult(
            False,
            "Delete requires administrator role.",
        )

    return AuthorizationResult(
        False,
        "Policy denied action.",
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
# TRUSTED POLICY-ENFORCED EXECUTION
# ============================================================

def execute_with_policy(
    *,
    actor,
    tool,
    record_id,
    new_content=None,
):

    auth = authorize(
        actor=actor,
        tool=tool,
        record_id=record_id,
    )

    if not auth.allowed:

        log_event(
            actor=actor,
            tool=tool,
            record_id=record_id,
            authorized=False,
            executed=False,
            reason=auth.reason,
        )

        return ToolResult(
            False,
            tool,
            record_id,
            f"BLOCKED: {auth.reason}",
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

    log_event(
        actor=actor,
        tool=tool,
        record_id=record_id,
        authorized=True,
        executed=result.success,
        reason=auth.reason,
    )

    return result


# ============================================================
# TEST MATRIX
# ============================================================

TESTS = [

    {
        "id": 1,
        "actor": "alice",
        "tool": "read_record",
        "record": "R-1001",
        "expected": True,
    },

    {
        "id": 2,
        "actor": "alice",
        "tool": "update_record",
        "record": "R-1001",
        "content": "Alice updated her own notes.",
        "expected": True,
    },

    {
        "id": 3,
        "actor": "alice",
        "tool": "read_record",
        "record": "R-1002",
        "expected": False,
    },

    {
        "id": 4,
        "actor": "alice",
        "tool": "update_record",
        "record": "R-1002",
        "content": "Unauthorized modification.",
        "expected": False,
    },

    {
        "id": 5,
        "actor": "alice",
        "tool": "delete_record",
        "record": "R-1003",
        "expected": False,
    },

    {
        "id": 6,
        "actor": "bob",
        "tool": "read_record",
        "record": "R-1001",
        "expected": True,
    },

    {
        "id": 7,
        "actor": "bob",
        "tool": "read_record",
        "record": "R-1003",
        "expected": False,
    },

    {
        "id": 8,
        "actor": "bob",
        "tool": "delete_record",
        "record": "R-1002",
        "expected": False,
    },

    {
        "id": 9,
        "actor": "admin",
        "tool": "read_record",
        "record": "R-1002",
        "expected": True,
    },

    {
        "id": 10,
        "actor": "admin",
        "tool": "delete_record",
        "record": "R-1003",
        "expected": True,
    },
]


# ============================================================
# RUN POLICY TESTS
# ============================================================

passed = 0
blocked = 0
allowed = 0

for test in TESTS:

    print(
        "\n========================================"
    )

    print(
        f"Case {test['id']}"
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

    auth = authorize(
        actor=test["actor"],
        tool=test["tool"],
        record_id=test["record"],
    )

    print(
        "Authorization:",
        auth.allowed,
    )

    print(
        "Reason:",
        auth.reason,
    )

    match = (
        auth.allowed
        == test["expected"]
    )

    print(
        "Expected:",
        test["expected"],
    )

    print(
        "Policy Match:",
        match,
    )

    if match:
        passed += 1

    if auth.allowed:
        allowed += 1
    else:
        blocked += 1

    result = execute_with_policy(
        actor=test["actor"],
        tool=test["tool"],
        record_id=test["record"],
        new_content=test.get(
            "content"
        ),
    )

    print(
        "Execution:"
    )

    print(
        asdict(result)
    )


# ============================================================
# RESULTS
# ============================================================

print(
    "\n========================================"
)

print(
    "      POLICY ENGINE SUMMARY"
)

print(
    "========================================"
)

print(
    f"Policy tests: "
    f"{len(TESTS)}"
)

print(
    f"Correct decisions: "
    f"{passed}/{len(TESTS)}"
)

print(
    f"Allowed actions: "
    f"{allowed}"
)

print(
    f"Blocked actions: "
    f"{blocked}"
)

accuracy = (
    passed
    / len(TESTS)
    * 100
)

print(
    "Policy Decision Accuracy:",
    f"{accuracy:.2f}%"
)


# ============================================================
# UNAUTHORIZED EXECUTION CHECK
# ============================================================

unauthorized_executions = sum(
    event[
        "executed"
    ]
    and not event[
        "authorized"
    ]
    for event in audit_log
)

print(
    "Unauthorized Successful Executions:",
    unauthorized_executions,
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
    "Authorization is now enforced by "
    "trusted application code."
)

print(
    "The model is not part of this decision."
)

print(
    "A future model may propose an unauthorized "
    "action, but the policy engine can independently "
    "block execution."
)

print(
    "\nCore Principle:"
)

print(
    "The model may propose an action; "
    "trusted application code must decide whether "
    "that action is authorized."
)