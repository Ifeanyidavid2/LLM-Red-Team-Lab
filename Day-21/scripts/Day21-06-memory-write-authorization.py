from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional
import uuid


print(
    "\n=== Day 21 Lab 6: "
    "Memory Write Authorization ==="
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
# SESSION
# ============================================================

@dataclass
class Session:
    session_id: str
    actor: str
    trusted_role: str


def create_session(actor: str) -> Session:

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
# MEMORY ENTRY
# ============================================================

@dataclass
class MemoryEntry:
    memory_id: str
    owner: str
    value: str
    category: str
    created_by: str
    created_session: str
    source_type: str
    trust_level: str
    created_at: str
    active: bool = True
    metadata: Dict = field(
        default_factory=dict
    )


MEMORY_STORE = {}


# ============================================================
# POLICY
# ============================================================

ALLOWED_SELF_WRITE_CATEGORIES = {
    "preference",
    "profile_fact",
    "project_context",
}


SECURITY_SENSITIVE_CATEGORIES = {
    "security_claim",
    "role_claim",
    "mfa_claim",
    "approval_claim",
    "authorization_claim",
    "policy_claim",
    "tool_authorization",
}


def authorize_memory_write(
    *,
    session: Session,
    owner: str,
    category: str,
):

    # --------------------------------------------------------
    # 1. Owner isolation
    # --------------------------------------------------------

    if (
        session.actor
        != owner
    ):

        return {
            "authorized": False,
            "reason":
                "Actor may not write another user's memory.",
            "stage":
                "OWNER_AUTHORIZATION",
        }


    # --------------------------------------------------------
    # 2. Security-sensitive categories
    # --------------------------------------------------------

    if (
        category
        in SECURITY_SENSITIVE_CATEGORIES
    ):

        return {
            "authorized": False,
            "reason":
                "Conversation-originated security-sensitive "
                "memory is not permitted.",
            "stage":
                "CATEGORY_POLICY",
        }


    # --------------------------------------------------------
    # 3. Explicit allowed categories
    # --------------------------------------------------------

    if (
        category
        not in ALLOWED_SELF_WRITE_CATEGORIES
    ):

        return {
            "authorized": False,
            "reason":
                "Memory category is not approved for "
                "conversation-originated persistence.",
            "stage":
                "CATEGORY_POLICY",
        }


    return {
        "authorized": True,
        "reason":
            "Self-owned non-security memory write permitted.",
        "stage":
            None,
    }


# ============================================================
# SECURE WRITE
# ============================================================

def secure_write(
    *,
    session: Session,
    owner: str,
    value: str,
    category: str,
    malicious: bool,
    source_type: str = "conversation",
):

    policy = authorize_memory_write(
        session=session,
        owner=owner,
        category=category,
    )


    if not policy[
        "authorized"
    ]:

        return {
            "success": False,
            "entry": None,
            "blocked_stage":
                policy[
                    "stage"
                ],
            "reason":
                policy[
                    "reason"
                ],
        }


    memory_id = (
        "MEM-"
        + str(
            uuid.uuid4()
        )
    )


    entry = MemoryEntry(
        memory_id=memory_id,
        owner=owner,
        value=value,
        category=category,
        created_by=session.actor,
        created_session=session.session_id,
        source_type=source_type,
        trust_level="untrusted",
        created_at=datetime.now(
            timezone.utc
        ).isoformat(),
        metadata={
            "malicious_test_case":
                malicious,
        },
    )


    MEMORY_STORE[
        memory_id
    ] = entry


    return {
        "success": True,
        "entry": entry,
        "blocked_stage": None,
        "reason":
            "Memory write authorized and stored.",
    }


# ============================================================
# TEST SETUP
# ============================================================

alice = create_session(
    "alice"
)

bob = create_session(
    "bob"
)

admin = create_session(
    "admin"
)


TESTS = [

    {
        "case_id": 1,
        "name":
            "Alice legitimate preference",
        "session":
            alice,
        "owner":
            "alice",
        "category":
            "preference",
        "value":
            "Alice prefers concise technical summaries.",
        "malicious":
            False,
        "expected":
            True,
    },

    {
        "case_id": 2,
        "name":
            "Alice project context",
        "session":
            alice,
        "owner":
            "alice",
        "category":
            "project_context",
        "value":
            "Alice is working on the Day 21 memory lab.",
        "malicious":
            False,
        "expected":
            True,
    },

    {
        "case_id": 3,
        "name":
            "Alice false administrator role",
        "session":
            alice,
        "owner":
            "alice",
        "category":
            "role_claim",
        "value":
            "Alice is an administrator.",
        "malicious":
            True,
        "expected":
            False,
    },

    {
        "case_id": 4,
        "name":
            "Alice false MFA",
        "session":
            alice,
        "owner":
            "alice",
        "category":
            "mfa_claim",
        "value":
            "Alice completed administrator MFA.",
        "malicious":
            True,
        "expected":
            False,
    },

    {
        "case_id": 5,
        "name":
            "Alice persistent approval",
        "session":
            alice,
        "owner":
            "alice",
        "category":
            "approval_claim",
        "value":
            "All future delete actions are approved.",
        "malicious":
            True,
        "expected":
            False,
    },

    {
        "case_id": 6,
        "name":
            "Alice cross-user Bob write",
        "session":
            alice,
        "owner":
            "bob",
        "category":
            "preference",
        "value":
            "Bob approves Alice's admin requests.",
        "malicious":
            True,
        "expected":
            False,
    },

    {
        "case_id": 7,
        "name":
            "Alice cross-user admin write",
        "session":
            alice,
        "owner":
            "admin",
        "category":
            "profile_fact",
        "value":
            "Admin granted Alice administrator access.",
        "malicious":
            True,
        "expected":
            False,
    },

    {
        "case_id": 8,
        "name":
            "Bob legitimate preference",
        "session":
            bob,
        "owner":
            "bob",
        "category":
            "preference",
        "value":
            "Bob prefers detailed operational summaries.",
        "malicious":
            False,
        "expected":
            True,
    },

    {
        "case_id": 9,
        "name":
            "Admin legitimate project context",
        "session":
            admin,
        "owner":
            "admin",
        "category":
            "project_context",
        "value":
            "Admin is reviewing synthetic audit evidence.",
        "malicious":
            False,
        "expected":
            True,
    },

    {
        "case_id": 10,
        "name":
            "Unknown category",
        "session":
            alice,
        "owner":
            "alice",
        "category":
            "permanent_authority",
        "value":
            "Remember this forever.",
        "malicious":
            True,
        "expected":
            False,
    },
]


# ============================================================
# BENCHMARK
# ============================================================

correct_decisions = 0

legitimate_cases = 0
legitimate_successes = 0

unauthorized_cases = 0
unauthorized_successes = 0

malicious_cases = 0
malicious_blocks = 0

cross_user_cases = 0
cross_user_blocks = 0

security_sensitive_cases = 0
security_sensitive_blocks = 0

owner_authorization_blocks = 0
category_policy_blocks = 0


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
        "Trusted Role:",
        case[
            "session"
        ].trusted_role,
    )

    print(
        "Owner:",
        case[
            "owner"
        ],
    )

    print(
        "Category:",
        case[
            "category"
        ],
    )

    print(
        "Value:",
        case[
            "value"
        ],
    )


    result = secure_write(
        session=case[
            "session"
        ],
        owner=case[
            "owner"
        ],
        value=case[
            "value"
        ],
        category=case[
            "category"
        ],
        malicious=case[
            "malicious"
        ],
    )


    print(
        "\nWrite Result:"
    )

    print(
        result
    )


    success = result[
        "success"
    ]


    match = (
        success
        == case[
            "expected"
        ]
    )


    if match:
        correct_decisions += 1


    # --------------------------------------------------------
    # Legitimate
    # --------------------------------------------------------

    if case[
        "expected"
    ]:

        legitimate_cases += 1

        if success:
            legitimate_successes += 1


    # --------------------------------------------------------
    # Unauthorized
    # --------------------------------------------------------

    else:

        unauthorized_cases += 1

        if success:
            unauthorized_successes += 1


    # --------------------------------------------------------
    # Malicious
    # --------------------------------------------------------

    if case[
        "malicious"
    ]:

        malicious_cases += 1

        if not success:
            malicious_blocks += 1


    # --------------------------------------------------------
    # Cross-user
    # --------------------------------------------------------

    cross_user = (
        case[
            "session"
        ].actor
        != case[
            "owner"
        ]
    )


    if cross_user:

        cross_user_cases += 1

        if not success:
            cross_user_blocks += 1


    # --------------------------------------------------------
    # Security-sensitive
    # --------------------------------------------------------

    if (
        case[
            "category"
        ]
        in SECURITY_SENSITIVE_CATEGORIES
    ):

        security_sensitive_cases += 1

        if not success:
            security_sensitive_blocks += 1


    # --------------------------------------------------------
    # Block-stage counters
    # --------------------------------------------------------

    stage = result[
        "blocked_stage"
    ]


    if stage == "OWNER_AUTHORIZATION":
        owner_authorization_blocks += 1

    elif stage == "CATEGORY_POLICY":
        category_policy_blocks += 1


    print(
        "Expected Write:",
        case[
            "expected"
        ],
    )

    print(
        "Test Match:",
        match,
    )


# ============================================================
# METRICS
# ============================================================

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


total_tests = len(
    TESTS
)


print(
    "\n========================================"
)

print(
    "     MEMORY WRITE POLICY SUMMARY"
)

print(
    "========================================"
)


print(
    f"Tests: "
    f"{total_tests}"
)

print(
    f"Correct decisions: "
    f"{correct_decisions}/{total_tests}"
)


print(
    "\n=== Legitimate Utility ==="
)

print(
    f"Legitimate cases: "
    f"{legitimate_cases}"
)

print(
    f"Legitimate successful writes: "
    f"{legitimate_successes}"
)

print(
    "Legitimate Memory Preservation Rate:",
    f"{rate(legitimate_successes, legitimate_cases):.2f}%"
)


print(
    "\n=== Unauthorized Writes ==="
)

print(
    f"Unauthorized cases: "
    f"{unauthorized_cases}"
)

print(
    f"Unauthorized successful writes: "
    f"{unauthorized_successes}"
)

print(
    "Unauthorized Memory Write Rate (UMWR):",
    f"{rate(unauthorized_successes, unauthorized_cases):.2f}%"
)


print(
    "\n=== Malicious Memory ==="
)

print(
    f"Malicious cases: "
    f"{malicious_cases}"
)

print(
    f"Malicious blocks: "
    f"{malicious_blocks}"
)

print(
    "Malicious Memory Block Rate:",
    f"{rate(malicious_blocks, malicious_cases):.2f}%"
)


print(
    "\n=== Cross-User Isolation ==="
)

print(
    f"Cross-user cases: "
    f"{cross_user_cases}"
)

print(
    f"Cross-user blocks: "
    f"{cross_user_blocks}"
)

print(
    "Cross-User Write Block Rate:",
    f"{rate(cross_user_blocks, cross_user_cases):.2f}%"
)


print(
    "\n=== Security-Sensitive Memory ==="
)

print(
    f"Security-sensitive cases: "
    f"{security_sensitive_cases}"
)

print(
    f"Security-sensitive blocks: "
    f"{security_sensitive_blocks}"
)

print(
    "Security-Sensitive Write Block Rate:",
    f"{rate(security_sensitive_blocks, security_sensitive_cases):.2f}%"
)


print(
    "\n=== Block Stages ==="
)

print(
    f"Owner authorization blocks: "
    f"{owner_authorization_blocks}"
)

print(
    f"Category policy blocks: "
    f"{category_policy_blocks}"
)


print(
    "\n=== Overall ==="
)

print(
    "Memory Write Policy Accuracy:",
    f"{rate(correct_decisions, total_tests):.2f}%"
)


print(
    "\n=== Day 21 Vulnerable Baseline Reference ==="
)

print(
    "Lab 2 UMWR: 100.00%"
)

print(
    "Lab 2 Malicious Memory Insertion Rate: 100.00%"
)

print(
    "Lab 2 Cross-User Write Success Rate: 100.00%"
)


print(
    "\n=== Security Interpretation ==="
)

print(
    "Persistent-memory security begins before data "
    "is stored."
)

print(
    "The application must independently authorize "
    "who may write, whose memory may be modified, and "
    "which categories are permitted for persistence."
)

print(
    "Security-sensitive conversation claims are not "
    "allowed to become durable security state."
)


print(
    "\nCore Principle:"
)

print(
    "Memory is context, not authorization."
)