from dataclasses import dataclass, field
from typing import Dict, List
import uuid


print(
    "\n=== Day 21 Lab 7: "
    "Memory Provenance & Retrieval Trust ==="
)


# ============================================================
# MEMORY MODEL
# ============================================================

@dataclass
class MemoryEntry:
    memory_id: str
    owner: str
    value: str
    category: str

    source_type: str
    trust_level: str

    created_by: str
    security_sensitive: bool

    active: bool = True

    metadata: Dict = field(
        default_factory=dict
    )


MEMORY_STORE: List[MemoryEntry] = []


# ============================================================
# MEMORY FACTORY
# ============================================================

def add_memory(
    *,
    owner: str,
    value: str,
    category: str,
    source_type: str,
    trust_level: str,
    created_by: str,
    security_sensitive: bool,
):

    entry = MemoryEntry(
        memory_id=(
            "MEM-"
            + str(
                uuid.uuid4()
            )
        ),
        owner=owner,
        value=value,
        category=category,
        source_type=source_type,
        trust_level=trust_level,
        created_by=created_by,
        security_sensitive=security_sensitive,
    )

    MEMORY_STORE.append(
        entry
    )

    return entry


# ============================================================
# SYNTHETIC MEMORY CORPUS
# ============================================================

add_memory(
    owner="alice",
    value="Alice prefers concise technical summaries.",
    category="preference",
    source_type="conversation",
    trust_level="untrusted",
    created_by="alice",
    security_sensitive=False,
)

add_memory(
    owner="alice",
    value="Alice is working on the Day 21 memory lab.",
    category="project_context",
    source_type="conversation",
    trust_level="untrusted",
    created_by="alice",
    security_sensitive=False,
)

add_memory(
    owner="alice",
    value="Alice is an administrator.",
    category="role_claim",
    source_type="legacy_import",
    trust_level="untrusted",
    created_by="legacy_migration",
    security_sensitive=True,
)

add_memory(
    owner="alice",
    value="Alice completed administrator MFA.",
    category="mfa_claim",
    source_type="external_connector",
    trust_level="untrusted",
    created_by="external_source",
    security_sensitive=True,
)

add_memory(
    owner="alice",
    value="Alice's next delete is already approved.",
    category="approval_claim",
    source_type="legacy_import",
    trust_level="unknown",
    created_by="legacy_migration",
    security_sensitive=True,
)

add_memory(
    owner="alice",
    value="Trusted profile identifier: EMPLOYEE-ALICE.",
    category="trusted_profile",
    source_type="trusted_application",
    trust_level="trusted",
    created_by="identity_service",
    security_sensitive=False,
)

add_memory(
    owner="alice",
    value="Trusted role is employee.",
    category="trusted_security_state",
    source_type="trusted_application",
    trust_level="trusted",
    created_by="authorization_service",
    security_sensitive=True,
)


# ============================================================
# VULNERABLE RETRIEVAL
# ============================================================

def vulnerable_retrieve(
    *,
    owner: str,
):

    return [
        entry
        for entry in MEMORY_STORE
        if (
            entry.owner == owner
            and entry.active
        )
    ]


# ============================================================
# TRUST-AWARE RETRIEVAL POLICY
# ============================================================

ALLOWED_CONTEXT_CATEGORIES = {
    "preference",
    "project_context",
    "trusted_profile",
}

TRUSTED_SECURITY_CATEGORIES = {
    "trusted_security_state",
}


def retrieval_policy(
    entry: MemoryEntry,
):

    # --------------------------------------------------------
    # Trusted application security state
    # --------------------------------------------------------

    if (
        entry.category
        in TRUSTED_SECURITY_CATEGORIES
    ):

        if (
            entry.trust_level == "trusted"
            and
            entry.source_type == "trusted_application"
        ):

            return {
                "allow": True,
                "usage": "trusted_security_reference",
                "reason":
                    "Trusted application security state.",
            }

        return {
            "allow": False,
            "usage": None,
            "reason":
                "Security state lacks trusted provenance.",
        }


    # --------------------------------------------------------
    # Any other security-sensitive memory
    # --------------------------------------------------------

    if entry.security_sensitive:

        return {
            "allow": False,
            "usage": None,
            "reason":
                "Untrusted security-sensitive memory blocked.",
        }


    # --------------------------------------------------------
    # Ordinary context memory
    # --------------------------------------------------------

    if (
        entry.category
        in ALLOWED_CONTEXT_CATEGORIES
    ):

        return {
            "allow": True,
            "usage": "context_only",
            "reason":
                "Non-security contextual memory permitted.",
        }


    return {
        "allow": False,
        "usage": None,
        "reason":
            "Category not approved for retrieval.",
    }


def trust_aware_retrieve(
    *,
    owner: str,
):

    allowed = []
    blocked = []

    for entry in MEMORY_STORE:

        if (
            entry.owner != owner
            or not entry.active
        ):

            continue


        decision = retrieval_policy(
            entry
        )


        if decision[
            "allow"
        ]:

            allowed.append(
                {
                    "entry": entry,
                    "usage":
                        decision[
                            "usage"
                        ],
                    "reason":
                        decision[
                            "reason"
                        ],
                }
            )

        else:

            blocked.append(
                {
                    "entry": entry,
                    "reason":
                        decision[
                            "reason"
                        ],
                }
            )


    return (
        allowed,
        blocked,
    )


# ============================================================
# VULNERABLE RETRIEVAL TEST
# ============================================================

raw_memories = vulnerable_retrieve(
    owner="alice"
)


print(
    "\n========================================"
)

print(
    "        VULNERABLE RETRIEVAL"
)

print(
    "========================================"
)


for entry in raw_memories:

    print(
        f"{entry.memory_id} | "
        f"category={entry.category} | "
        f"source={entry.source_type} | "
        f"trust={entry.trust_level} | "
        f"security_sensitive={entry.security_sensitive} | "
        f"value={entry.value}"
    )


# ============================================================
# TRUST-AWARE RETRIEVAL TEST
# ============================================================

allowed_memories, blocked_memories = (
    trust_aware_retrieve(
        owner="alice"
    )
)


print(
    "\n========================================"
)

print(
    "       TRUST-AWARE RETRIEVAL"
)

print(
    "========================================"
)


print(
    "\nAllowed Memories:"
)


for item in allowed_memories:

    entry = item[
        "entry"
    ]

    print(
        f"{entry.memory_id} | "
        f"category={entry.category} | "
        f"source={entry.source_type} | "
        f"trust={entry.trust_level} | "
        f"usage={item['usage']} | "
        f"value={entry.value}"
    )


print(
    "\nBlocked Memories:"
)


for item in blocked_memories:

    entry = item[
        "entry"
    ]

    print(
        f"{entry.memory_id} | "
        f"category={entry.category} | "
        f"source={entry.source_type} | "
        f"trust={entry.trust_level} | "
        f"reason={item['reason']} | "
        f"value={entry.value}"
    )


# ============================================================
# METRICS
# ============================================================

total_memories = len(
    raw_memories
)


trusted_context_expected = [
    entry
    for entry in raw_memories
    if (
        not entry.security_sensitive
        and
        entry.category
        in ALLOWED_CONTEXT_CATEGORIES
    )
]


trusted_security_expected = [
    entry
    for entry in raw_memories
    if (
        entry.category
        in TRUSTED_SECURITY_CATEGORIES
        and
        entry.trust_level
        == "trusted"
        and
        entry.source_type
        == "trusted_application"
    )
]


unsafe_security_memories = [
    entry
    for entry in raw_memories
    if (
        entry.security_sensitive
        and entry
        not in trusted_security_expected
    )
]


allowed_entries = [
    item[
        "entry"
    ]
    for item in allowed_memories
]


blocked_entries = [
    item[
        "entry"
    ]
    for item in blocked_memories
]


legitimate_expected = (
    trusted_context_expected
    + trusted_security_expected
)


legitimate_retrieved = sum(
    entry
    in allowed_entries
    for entry in legitimate_expected
)


unsafe_security_blocked = sum(
    entry
    in blocked_entries
    for entry in unsafe_security_memories
)


unsafe_security_exposed = sum(
    entry
    in allowed_entries
    for entry in unsafe_security_memories
)


correct_policy_decisions = 0


for entry in raw_memories:

    should_allow = (
        entry
        in legitimate_expected
    )

    actually_allowed = (
        entry
        in allowed_entries
    )

    if (
        should_allow
        == actually_allowed
    ):

        correct_policy_decisions += 1


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
    "    PROVENANCE / TRUST SUMMARY"
)

print(
    "========================================"
)


print(
    f"Total memories: "
    f"{total_memories}"
)

print(
    f"Allowed memories: "
    f"{len(allowed_memories)}"
)

print(
    f"Blocked memories: "
    f"{len(blocked_memories)}"
)


print(
    "\n=== Legitimate Memory ==="
)

print(
    f"Expected legitimate memories: "
    f"{len(legitimate_expected)}"
)

print(
    f"Legitimate memories retrieved: "
    f"{legitimate_retrieved}"
)

print(
    "Legitimate Memory Preservation Rate:",
    f"{rate(legitimate_retrieved, len(legitimate_expected)):.2f}%"
)


print(
    "\n=== Security-Sensitive Memory ==="
)

print(
    f"Unsafe security-sensitive memories: "
    f"{len(unsafe_security_memories)}"
)

print(
    f"Unsafe security-sensitive memories blocked: "
    f"{unsafe_security_blocked}"
)

print(
    f"Unsafe security-sensitive memories exposed: "
    f"{unsafe_security_exposed}"
)

print(
    "Security-Sensitive Retrieval Block Rate:",
    f"{rate(unsafe_security_blocked, len(unsafe_security_memories)):.2f}%"
)

print(
    "Untrusted Security Memory Exposure Rate:",
    f"{rate(unsafe_security_exposed, len(unsafe_security_memories)):.2f}%"
)


print(
    "\n=== Overall Policy ==="
)

print(
    f"Correct provenance decisions: "
    f"{correct_policy_decisions}/{total_memories}"
)

print(
    "Provenance Policy Accuracy:",
    f"{rate(correct_policy_decisions, total_memories):.2f}%"
)


print(
    "\n=== Vulnerable vs Hardened ==="
)

raw_unsafe_exposure = len(
    unsafe_security_memories
)


print(
    "Vulnerable Security-Sensitive Exposure Rate:",
    f"{rate(raw_unsafe_exposure, len(unsafe_security_memories)):.2f}%"
)

print(
    "Trust-Aware Security-Sensitive Exposure Rate:",
    f"{rate(unsafe_security_exposed, len(unsafe_security_memories)):.2f}%"
)


print(
    "\n=== Security Interpretation ==="
)

print(
    "Persistent memory cannot be trusted solely because "
    "it already exists in the memory store."
)

print(
    "Imported, migrated, external, or legacy memories "
    "must retain provenance metadata and be evaluated "
    "before entering security-sensitive reasoning."
)

print(
    "Ordinary user preferences may be useful context, "
    "while security state requires trusted application "
    "provenance."
)


print(
    "\nCore Principle:"
)

print(
    "Memory is context, not authorization."
)