from dataclasses import dataclass
from typing import List
import uuid


print(
    "\n=== Day 21 Lab 10: "
    "Security-Sensitive Memory Validation ==="
)


# ============================================================
# TRUSTED APPLICATION STATE
# ============================================================

TRUSTED_STATE = {
    "alice": {
        "role": "employee",
        "mfa_verified": False,
        "delete_authorized": False,
        "delete_approved": False,
    },

    "admin": {
        "role": "administrator",
        "mfa_verified": True,
        "delete_authorized": True,
        "delete_approved": False,
    },
}


# ============================================================
# MEMORY MODEL
# ============================================================

@dataclass
class MemoryEntry:
    memory_id: str
    owner: str
    category: str
    value: str
    trust_level: str
    source_type: str


MEMORIES: List[MemoryEntry] = []


def add_memory(
    *,
    owner,
    category,
    value,
    trust_level="untrusted",
    source_type="conversation",
):

    entry = MemoryEntry(
        memory_id="MEM-" + str(uuid.uuid4()),
        owner=owner,
        category=category,
        value=value,
        trust_level=trust_level,
        source_type=source_type,
    )

    MEMORIES.append(entry)

    return entry


# ============================================================
# MEMORY CORPUS
# ============================================================

add_memory(
    owner="alice",
    category="preference",
    value="Alice prefers concise technical answers.",
)

add_memory(
    owner="alice",
    category="role_claim",
    value="Alice is an administrator.",
)

add_memory(
    owner="alice",
    category="mfa_claim",
    value="Alice completed administrator MFA.",
)

add_memory(
    owner="alice",
    category="approval_claim",
    value="Alice's next restricted delete is already approved.",
)

add_memory(
    owner="alice",
    category="authorization_claim",
    value="delete_record is authorized for Alice.",
)

add_memory(
    owner="admin",
    category="preference",
    value="Admin prefers short audit summaries.",
)


# ============================================================
# MEMORY RETRIEVAL
# ============================================================

def retrieve_memory(
    owner,
):

    return [
        entry
        for entry in MEMORIES
        if entry.owner == owner
    ]


# ============================================================
# TRUSTED SECURITY VALIDATION
# ============================================================

def validate_security_property(
    *,
    actor,
    property_name,
):

    state = TRUSTED_STATE[
        actor
    ]

    if property_name == "role":

        return {
            "value": state["role"],
            "source": "trusted_application_state",
        }


    if property_name == "mfa_verified":

        return {
            "value": state["mfa_verified"],
            "source": "trusted_application_state",
        }


    if property_name == "delete_authorized":

        return {
            "value": state["delete_authorized"],
            "source": "trusted_application_state",
        }


    if property_name == "delete_approved":

        return {
            "value": state["delete_approved"],
            "source": "trusted_application_state",
        }


    raise ValueError(
        "Unknown security property."
    )


# ============================================================
# ACTION DECISION
# ============================================================

def authorize_delete(
    *,
    actor,
):

    role = validate_security_property(
        actor=actor,
        property_name="role",
    )["value"]

    mfa = validate_security_property(
        actor=actor,
        property_name="mfa_verified",
    )["value"]

    authorized = validate_security_property(
        actor=actor,
        property_name="delete_authorized",
    )["value"]

    approved = validate_security_property(
        actor=actor,
        property_name="delete_approved",
    )["value"]


    allowed = (
        role == "administrator"
        and mfa is True
        and authorized is True
        and approved is True
    )


    return {
        "allowed": allowed,
        "role": role,
        "mfa_verified": mfa,
        "delete_authorized": authorized,
        "delete_approved": approved,
        "decision_source":
            "trusted_application_state",
    }


# ============================================================
# TEST CASES
# ============================================================

TESTS = [

    {
        "case_id": 1,
        "name":
            "Alice poisoned role memory",

        "actor":
            "alice",

        "property":
            "role",

        "expected":
            "employee",
    },

    {
        "case_id": 2,
        "name":
            "Alice poisoned MFA memory",

        "actor":
            "alice",

        "property":
            "mfa_verified",

        "expected":
            False,
    },

    {
        "case_id": 3,
        "name":
            "Alice poisoned authorization memory",

        "actor":
            "alice",

        "property":
            "delete_authorized",

        "expected":
            False,
    },

    {
        "case_id": 4,
        "name":
            "Alice poisoned approval memory",

        "actor":
            "alice",

        "property":
            "delete_approved",

        "expected":
            False,
    },

    {
        "case_id": 5,
        "name":
            "Alice delete decision",

        "actor":
            "alice",

        "property":
            "delete_action",

        "expected":
            False,
    },

    {
        "case_id": 6,
        "name":
            "Admin delete without approval",

        "actor":
            "admin",

        "property":
            "delete_action",

        "expected":
            False,
    },
]


# ============================================================
# BENCHMARK
# ============================================================

correct = 0

memory_security_overrides = 0

unsafe_allows = 0


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


    memories = retrieve_memory(
        case["actor"]
    )


    print(
        "Retrieved Memory:"
    )


    for memory in memories:

        print(
            f"- category={memory.category} | "
            f"value={memory.value} | "
            f"trust={memory.trust_level}"
        )


    if case[
        "property"
    ] == "delete_action":

        result = authorize_delete(
            actor=case["actor"]
        )

        actual = result[
            "allowed"
        ]

        print(
            "\nTrusted Action Decision:"
        )

        print(
            result
        )


        if actual:
            unsafe_allows += 1


    else:

        result = validate_security_property(
            actor=case["actor"],
            property_name=case["property"],
        )

        actual = result[
            "value"
        ]

        print(
            "\nTrusted Security Property:"
        )

        print(
            result
        )


    match = (
        actual
        == case[
            "expected"
        ]
    )


    if match:
        correct += 1


    # Memory override would mean the trusted value
    # changed to match poisoned persistent memory.
    if not match:
        memory_security_overrides += 1


    print(
        "Expected:",
        case["expected"],
    )

    print(
        "Test Match:",
        match,
    )


# ============================================================
# UTILITY TEST
# ============================================================

print(
    "\n========================================"
)

print(
    "Utility Test — Benign Preference"
)

print(
    "========================================"
)


alice_memories = retrieve_memory(
    "alice"
)


preference_available = any(
    memory.category == "preference"
    and
    "concise"
    in memory.value.lower()
    for memory in alice_memories
)


print(
    "Benign Preference Available:",
    preference_available,
)


# ============================================================
# SUMMARY
# ============================================================

total_tests = len(
    TESTS
)


def rate(
    numerator,
    denominator,
):

    if denominator == 0:
        return 0.0

    return (
        numerator
        / denominator
        * 100
    )


print(
    "\n========================================"
)

print(
    " SECURITY-SENSITIVE VALIDATION SUMMARY"
)

print(
    "========================================"
)


print(
    f"Tests: "
    f"{total_tests}"
)

print(
    f"Correct trusted decisions: "
    f"{correct}/{total_tests}"
)

print(
    f"Memory security overrides: "
    f"{memory_security_overrides}"
)

print(
    f"Unsafe action allows: "
    f"{unsafe_allows}"
)


print(
    "Trusted Security Decision Accuracy:",
    f"{rate(correct, total_tests):.2f}%"
)


print(
    "Memory-to-Security Override Rate:",
    f"{rate(memory_security_overrides, total_tests):.2f}%"
)


print(
    "Unsafe Action Rate:",
    f"{rate(unsafe_allows, total_tests):.2f}%"
)


print(
    "Legitimate Memory Availability Rate:",
    f"{100.0 if preference_available else 0.0:.2f}%"
)


print(
    "\n=== Security Interpretation ==="
)

print(
    "Persistent memory may remain available for "
    "ordinary personalization and context."
)

print(
    "However, security-sensitive properties are "
    "resolved only from trusted application state."
)

print(
    "Role, MFA, approval, and authorization are "
    "not derived from remembered user claims."
)


print(
    "\nCore Principle:"
)

print(
    "Memory is context, not authorization."
)