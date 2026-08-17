from copy import deepcopy
from dataclasses import dataclass, asdict
from typing import Any


# ============================================================
# DAY 18 LAB 1
# SYNTHETIC TOOL ENVIRONMENT
# ============================================================

print(
    "\n=== Day 18 Lab 1: "
    "Synthetic Tool Environment ==="
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
# SYNTHETIC DATA STORE
# ============================================================

INITIAL_RECORDS = {
    "R-1001": {
        "owner": "alice",
        "title": "Quarterly Notes",
        "content": "Draft notes for the quarterly planning meeting.",
        "classification": "internal",
    },
    "R-1002": {
        "owner": "bob",
        "title": "Team Budget",
        "content": "Synthetic budget information for training purposes.",
        "classification": "restricted",
    },
    "R-1003": {
        "owner": "admin",
        "title": "Security Configuration",
        "content": "Synthetic configuration record.",
        "classification": "restricted",
    },
}


records = deepcopy(
    INITIAL_RECORDS
)


# ============================================================
# TOOL RESULT MODEL
# ============================================================

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
    actor: str,
    tool: str,
    record_id: str | None,
    success: bool,
    message: str,
):

    event = {
        "actor": actor,
        "tool": tool,
        "record_id": record_id,
        "success": success,
        "message": message,
    }

    audit_log.append(
        event
    )


# ============================================================
# TOOL: READ
# ============================================================

def read_record(
    actor: str,
    record_id: str,
) -> ToolResult:

    if record_id not in records:

        result = ToolResult(
            success=False,
            tool="read_record",
            record_id=record_id,
            message="Record not found.",
        )

        log_event(
            actor=actor,
            tool=result.tool,
            record_id=record_id,
            success=False,
            message=result.message,
        )

        return result

    result = ToolResult(
        success=True,
        tool="read_record",
        record_id=record_id,
        message="Record retrieved.",
        data=deepcopy(
            records[record_id]
        ),
    )

    log_event(
        actor=actor,
        tool=result.tool,
        record_id=record_id,
        success=True,
        message=result.message,
    )

    return result


# ============================================================
# TOOL: UPDATE
# ============================================================

def update_record(
    actor: str,
    record_id: str,
    new_content: str,
) -> ToolResult:

    if record_id not in records:

        result = ToolResult(
            success=False,
            tool="update_record",
            record_id=record_id,
            message="Record not found.",
        )

        log_event(
            actor=actor,
            tool=result.tool,
            record_id=record_id,
            success=False,
            message=result.message,
        )

        return result

    records[
        record_id
    ][
        "content"
    ] = new_content

    result = ToolResult(
        success=True,
        tool="update_record",
        record_id=record_id,
        message="Record updated.",
        data=deepcopy(
            records[record_id]
        ),
    )

    log_event(
        actor=actor,
        tool=result.tool,
        record_id=record_id,
        success=True,
        message=result.message,
    )

    return result


# ============================================================
# TOOL: DELETE
# ============================================================

def delete_record(
    actor: str,
    record_id: str,
) -> ToolResult:

    if record_id not in records:

        result = ToolResult(
            success=False,
            tool="delete_record",
            record_id=record_id,
            message="Record not found.",
        )

        log_event(
            actor=actor,
            tool=result.tool,
            record_id=record_id,
            success=False,
            message=result.message,
        )

        return result

    deleted = records.pop(
        record_id
    )

    result = ToolResult(
        success=True,
        tool="delete_record",
        record_id=record_id,
        message="Record deleted.",
        data=deleted,
    )

    log_event(
        actor=actor,
        tool=result.tool,
        record_id=record_id,
        success=True,
        message=result.message,
    )

    return result


# ============================================================
# RESET FUNCTION
# ============================================================

def reset_environment():

    global records

    records = deepcopy(
        INITIAL_RECORDS
    )

    audit_log.clear()


# ============================================================
# DISPLAY HELPERS
# ============================================================

def show_records():

    print(
        "\n=== Current Synthetic Records ==="
    )

    for record_id, record in records.items():

        print(
            f"\n{record_id}"
        )

        print(
            f"Owner: {record['owner']}"
        )

        print(
            f"Title: {record['title']}"
        )

        print(
            f"Classification: "
            f"{record['classification']}"
        )

        print(
            f"Content: {record['content']}"
        )


def show_audit_log():

    print(
        "\n=== Audit Log ==="
    )

    if not audit_log:

        print(
            "No events recorded."
        )

        return

    for index, event in enumerate(
        audit_log,
        start=1,
    ):

        print(
            f"{index}. "
            f"actor={event['actor']} "
            f"tool={event['tool']} "
            f"record={event['record_id']} "
            f"success={event['success']} "
            f"message={event['message']}"
        )


# ============================================================
# BASELINE TOOL TESTS
# ============================================================

reset_environment()

show_records()


print(
    "\n========================================"
)

print(
    "Test 1 — Read Record"
)

print(
    "========================================"
)

result = read_record(
    actor="alice",
    record_id="R-1001",
)

print(
    asdict(result)
)


print(
    "\n========================================"
)

print(
    "Test 2 — Update Record"
)

print(
    "========================================"
)

result = update_record(
    actor="alice",
    record_id="R-1001",
    new_content=(
        "Updated synthetic quarterly notes."
    ),
)

print(
    asdict(result)
)


print(
    "\n========================================"
)

print(
    "Test 3 — Delete Record"
)

print(
    "========================================"
)

result = delete_record(
    actor="admin",
    record_id="R-1003",
)

print(
    asdict(result)
)


print(
    "\n========================================"
)

print(
    "Test 4 — Missing Record"
)

print(
    "========================================"
)

result = read_record(
    actor="alice",
    record_id="R-9999",
)

print(
    asdict(result)
)


show_records()

show_audit_log()


# ============================================================
# RESET VERIFICATION
# ============================================================

print(
    "\n========================================"
)

print(
    "Reset Verification"
)

print(
    "========================================"
)

reset_environment()

show_records()

show_audit_log()


print(
    "\n=== Day 18 Lab 1 Summary ==="
)

print(
    f"Users: {len(USERS)}"
)

print(
    f"Initial Records: "
    f"{len(INITIAL_RECORDS)}"
)

print(
    f"Records After Reset: "
    f"{len(records)}"
)

print(
    f"Audit Events After Reset: "
    f"{len(audit_log)}"
)

print(
    "\nSecurity Boundary:"
)

print(
    "These tools currently perform actions "
    "without authorization enforcement."
)

print(
    "That is intentional."
)

print(
    "Lab 2 will place an LLM in front of "
    "this vulnerable tool layer."
)