from copy import deepcopy
from dataclasses import dataclass, asdict
from typing import Any
import re


print(
    "\n=== Day 18 Lab 6: "
    "Tool Argument Validation ==="
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
        "content": "Synthetic quarterly notes.",
        "classification": "internal",
    },

    "R-1002": {
        "owner": "bob",
        "title": "Team Budget",
        "content": "Synthetic budget information.",
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
class ValidationResult:
    valid: bool
    reason: str


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


# ============================================================
# ARGUMENT VALIDATION
# ============================================================

RECORD_ID_PATTERN = re.compile(
    r"^R-\d{4}$"
)

MAX_CONTENT_LENGTH = 200


def validate_record_id(
    record_id,
):

    if not isinstance(
        record_id,
        str,
    ):

        return ValidationResult(
            False,
            "record_id must be a string.",
        )

    if not RECORD_ID_PATTERN.fullmatch(
        record_id
    ):

        return ValidationResult(
            False,
            "record_id format is invalid.",
        )

    if record_id not in records:

        return ValidationResult(
            False,
            "record_id does not exist.",
        )

    return ValidationResult(
        True,
        "record_id valid.",
    )


def validate_new_content(
    new_content,
):

    if not isinstance(
        new_content,
        str,
    ):

        return ValidationResult(
            False,
            "new_content must be a string.",
        )

    if not new_content.strip():

        return ValidationResult(
            False,
            "new_content may not be empty.",
        )

    if len(
        new_content
    ) > MAX_CONTENT_LENGTH:

        return ValidationResult(
            False,
            "new_content exceeds maximum length.",
        )

    # Synthetic control characters only.
    forbidden_sequences = [
        "\x00",
        "\r",
    ]

    if any(
        sequence in new_content
        for sequence in forbidden_sequences
    ):

        return ValidationResult(
            False,
            "new_content contains forbidden control characters.",
        )

    return ValidationResult(
        True,
        "new_content valid.",
    )


def validate_tool_arguments(
    *,
    tool,
    record_id,
    new_content=None,
):

    record_check = validate_record_id(
        record_id
    )

    if not record_check.valid:

        return record_check

    if tool == "update_record":

        content_check = validate_new_content(
            new_content
        )

        if not content_check.valid:

            return content_check

    if tool not in {
        "read_record",
        "update_record",
        "delete_record",
    }:

        return ValidationResult(
            False,
            "Unknown tool.",
        )

    return ValidationResult(
        True,
        "All tool arguments valid.",
    )


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
            "Delete requires administrator.",
        )

    return AuthorizationResult(
        False,
        "Unknown tool.",
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
# SECURE EXECUTION PIPELINE
# ============================================================

def execute_securely(
    *,
    actor,
    tool,
    record_id,
    new_content=None,
):

    validation = validate_tool_arguments(
        tool=tool,
        record_id=record_id,
        new_content=new_content,
    )

    if not validation.valid:

        audit_log.append({
            "actor": actor,
            "tool": tool,
            "record_id": record_id,
            "validated": False,
            "authorized": False,
            "executed": False,
            "reason": validation.reason,
        })

        return ToolResult(
            False,
            tool,
            record_id,
            f"BLOCKED: {validation.reason}",
        )

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
            "validated": True,
            "authorized": False,
            "executed": False,
            "reason": auth.reason,
        })

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

    audit_log.append({
        "actor": actor,
        "tool": tool,
        "record_id": record_id,
        "validated": True,
        "authorized": True,
        "executed": result.success,
        "reason": "Validation and authorization passed.",
    })

    return result


# ============================================================
# TEST CASES
# ============================================================

TESTS = [

    {
        "id": 1,
        "name": "Valid authorized read",
        "actor": "alice",
        "tool": "read_record",
        "record_id": "R-1001",
        "new_content": None,
        "expected": True,
    },

    {
        "id": 2,
        "name": "Valid authorized update",
        "actor": "alice",
        "tool": "update_record",
        "record_id": "R-1001",
        "new_content": "Quarterly notes reviewed.",
        "expected": True,
    },

    {
        "id": 3,
        "name": "Malformed record identifier",
        "actor": "alice",
        "tool": "read_record",
        "record_id": "../../../R-1003",
        "new_content": None,
        "expected": False,
    },

    {
        "id": 4,
        "name": "Unknown record identifier",
        "actor": "alice",
        "tool": "read_record",
        "record_id": "R-9999",
        "new_content": None,
        "expected": False,
    },

    {
        "id": 5,
        "name": "Empty update content",
        "actor": "alice",
        "tool": "update_record",
        "record_id": "R-1001",
        "new_content": "",
        "expected": False,
    },

    {
        "id": 6,
        "name": "Oversized update content",
        "actor": "alice",
        "tool": "update_record",
        "record_id": "R-1001",
        "new_content": "A" * 500,
        "expected": False,
    },

    {
        "id": 7,
        "name": "Control-character content",
        "actor": "alice",
        "tool": "update_record",
        "record_id": "R-1001",
        "new_content":
            "Quarterly notes\x00hidden",
        "expected": False,
    },

    {
        "id": 8,
        "name": "Valid but unauthorized cross-user update",
        "actor": "alice",
        "tool": "update_record",
        "record_id": "R-1002",
        "new_content":
            "Attempted modification.",
        "expected": False,
    },

    {
        "id": 9,
        "name": "Unknown tool name",
        "actor": "alice",
        "tool": "export_all_records",
        "record_id": "R-1001",
        "new_content": None,
        "expected": False,
    },

    {
        "id": 10,
        "name": "Non-string record identifier",
        "actor": "alice",
        "tool": "read_record",
        "record_id": 1001,
        "new_content": None,
        "expected": False,
    },
]


# ============================================================
# RUN TESTS
# ============================================================

correct = 0
validation_blocks = 0
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
        "Tool:",
        test["tool"],
    )

    print(
        "Record ID:",
        repr(
            test["record_id"]
        ),
    )

    result = execute_securely(
        actor=test[
            "actor"
        ],
        tool=test[
            "tool"
        ],
        record_id=test[
            "record_id"
        ],
        new_content=test[
            "new_content"
        ],
    )

    print(
        "Result:"
    )

    print(
        asdict(
            result
        )
    )

    execution = result.success

    expected = test[
        "expected"
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
        "Test Match:",
        match,
    )

    if match:
        correct += 1

    if result.success:
        successful_executions += 1

    elif "not authorized" in result.message.lower():

        authorization_blocks += 1

    elif "blocked:" in result.message.lower():

        validation_blocks += 1


# ============================================================
# SUMMARY
# ============================================================

print(
    "\n========================================"
)

print(
    "     ARGUMENT VALIDATION SUMMARY"
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
    f"Successful executions: "
    f"{successful_executions}"
)

print(
    f"Validation / policy blocks: "
    f"{validation_blocks}"
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
        f"validated={event['validated']} "
        f"authorized={event['authorized']} "
        f"executed={event['executed']} "
        f"reason={event['reason']}"
    )


# ============================================================
# FINAL SECURITY FINDING
# ============================================================

print(
    "\n=== Security Finding ==="
)

print(
    "Authorization alone is insufficient."
)

print(
    "Every tool argument must be validated by "
    "trusted application code before authorization "
    "and execution."
)

print(
    "The model does not control the validation policy."
)

print(
    "\nSecure pipeline:"
)

print(
    "MODEL PROPOSAL"
)

print(
    "      ↓"
)

print(
    "ARGUMENT VALIDATION"
)

print(
    "      ↓"
)

print(
    "AUTHORIZATION"
)

print(
    "      ↓"
)

print(
    "APPROVAL IF REQUIRED"
)

print(
    "      ↓"
)

print(
    "TOOL EXECUTION"
)