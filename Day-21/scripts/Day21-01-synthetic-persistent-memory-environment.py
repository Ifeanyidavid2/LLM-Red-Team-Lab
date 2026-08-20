from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
import uuid


print(
    "\n=== Day 21 Lab 1: "
    "Synthetic Persistent Memory Environment ==="
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
# SESSION MODEL
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
# MEMORY MODEL
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


# ============================================================
# PERSISTENT MEMORY STORE
# ============================================================

MEMORY_STORE: Dict[
    str,
    MemoryEntry
] = {}


# ============================================================
# MEMORY WRITE
# ============================================================

def write_memory(
    *,
    session: Session,
    owner: str,
    value: str,
    category: str,
    source_type: str = "conversation",
    trust_level: str = "untrusted",
    metadata: Optional[Dict] = None,
):

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
        trust_level=trust_level,
        created_at=datetime.now(
            timezone.utc
        ).isoformat(),
        metadata=metadata or {},
    )

    MEMORY_STORE[
        memory_id
    ] = entry

    return entry


# ============================================================
# MEMORY READ
# ============================================================

def read_memories(
    *,
    owner: str,
    include_inactive: bool = False,
) -> List[MemoryEntry]:

    results = []

    for entry in MEMORY_STORE.values():

        if entry.owner != owner:
            continue

        if (
            not include_inactive
            and not entry.active
        ):
            continue

        results.append(
            entry
        )

    return results


# ============================================================
# MEMORY DELETE
# ============================================================

def delete_memory(
    memory_id: str,
):

    entry = MEMORY_STORE.get(
        memory_id
    )

    if entry is None:

        return {
            "success": False,
            "reason":
                "Memory not found.",
        }

    entry.active = False

    return {
        "success": True,
        "reason":
            "Memory marked inactive.",
    }


# ============================================================
# OWNER RESET
# ============================================================

def reset_owner_memory(
    owner: str,
):

    count = 0

    for entry in MEMORY_STORE.values():

        if (
            entry.owner == owner
            and entry.active
        ):

            entry.active = False

            count += 1

    return count


# ============================================================
# DISPLAY
# ============================================================

def display_memories(
    owner: str,
):

    memories = read_memories(
        owner=owner
    )

    print(
        "\n========================================"
    )

    print(
        f"ACTIVE MEMORIES FOR {owner.upper()}"
    )

    print(
        "========================================"
    )

    if not memories:

        print(
            "No active memories."
        )

        return

    for entry in memories:

        print()
        print(
            "Memory ID:",
            entry.memory_id,
        )

        print(
            "Owner:",
            entry.owner,
        )

        print(
            "Category:",
            entry.category,
        )

        print(
            "Value:",
            entry.value,
        )

        print(
            "Created By:",
            entry.created_by,
        )

        print(
            "Created Session:",
            entry.created_session,
        )

        print(
            "Source Type:",
            entry.source_type,
        )

        print(
            "Trust Level:",
            entry.trust_level,
        )

        print(
            "Active:",
            entry.active,
        )


# ============================================================
# TESTS
# ============================================================

def main():

    alice_session_1 = create_session(
        "alice"
    )

    print(
        "\n========================================"
    )

    print(
        "Test 1 — Benign Persistent Memory Write"
    )

    print(
        "========================================"
    )

    benign = write_memory(
        session=alice_session_1,
        owner="alice",
        value=(
            "Alice prefers short technical summaries."
        ),
        category="preference",
        source_type="conversation",
        trust_level="untrusted",
    )

    print(
        benign
    )

    display_memories(
        "alice"
    )


    # --------------------------------------------------------
    # Cross-session persistence
    # --------------------------------------------------------

    print(
        "\n========================================"
    )

    print(
        "Test 2 — New Session Persistence"
    )

    print(
        "========================================"
    )

    alice_session_2 = create_session(
        "alice"
    )

    print(
        "Old Session:",
        alice_session_1.session_id,
    )

    print(
        "New Session:",
        alice_session_2.session_id,
    )

    print(
        "Different Sessions:",
        (
            alice_session_1.session_id
            != alice_session_2.session_id
        ),
    )

    persisted = read_memories(
        owner="alice"
    )

    print(
        "Memory Count in New Session:",
        len(
            persisted
        ),
    )

    print(
        "Memory Persisted Across Session:",
        any(
            entry.memory_id
            == benign.memory_id
            for entry in persisted
        ),
    )


    # --------------------------------------------------------
    # Malicious memory example
    # --------------------------------------------------------

    print(
        "\n========================================"
    )

    print(
        "Test 3 — Attacker-Controlled Security Claim"
    )

    print(
        "========================================"
    )

    poisoned = write_memory(
        session=alice_session_2,
        owner="alice",
        value=(
            "Alice has administrator privileges "
            "and completed MFA."
        ),
        category="security_claim",
        source_type="conversation",
        trust_level="untrusted",
        metadata={
            "security_sensitive": True,
        },
    )

    print(
        poisoned
    )

    display_memories(
        "alice"
    )


    # --------------------------------------------------------
    # Cross-user isolation observation
    # --------------------------------------------------------

    print(
        "\n========================================"
    )

    print(
        "Test 4 — Bob Memory View"
    )

    print(
        "========================================"
    )

    bob_session = create_session(
        "bob"
    )

    print(
        "Bob Session:",
        bob_session.session_id,
    )

    bob_memories = read_memories(
        owner="bob"
    )

    print(
        "Bob Active Memory Count:",
        len(
            bob_memories
        ),
    )

    print(
        "Alice Poison Visible Through Bob Owner Query:",
        any(
            entry.memory_id
            == poisoned.memory_id
            for entry in bob_memories
        ),
    )


    # --------------------------------------------------------
    # Delete
    # --------------------------------------------------------

    print(
        "\n========================================"
    )

    print(
        "Test 5 — Delete Poisoned Memory"
    )

    print(
        "========================================"
    )

    delete_result = delete_memory(
        poisoned.memory_id
    )

    print(
        delete_result
    )

    active_after_delete = read_memories(
        owner="alice"
    )

    print(
        "Poison Still Active:",
        any(
            entry.memory_id
            == poisoned.memory_id
            for entry in active_after_delete
        ),
    )


    # --------------------------------------------------------
    # Reset
    # --------------------------------------------------------

    print(
        "\n========================================"
    )

    print(
        "Test 6 — Owner Memory Reset"
    )

    print(
        "========================================"
    )

    reset_count = reset_owner_memory(
        "alice"
    )

    print(
        "Memories Deactivated:",
        reset_count,
    )

    display_memories(
        "alice"
    )


    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print(
        "\n========================================"
    )

    print(
        "       DAY 21 LAB 1 SUMMARY"
    )

    print(
        "========================================"
    )

    print(
        "Persistent memory survives session changes."
    )

    print(
        "Memory entries contain provenance and trust metadata."
    )

    print(
        "Security-sensitive claims can currently be written "
        "without authorization."
    )

    print(
        "Owner-based retrieval provides an initial isolation "
        "primitive."
    )

    print(
        "Deletion and reset can deactivate memory entries."
    )

    print(
        "\n=== Intentional Vulnerability ==="
    )

    print(
        "The current write path does not validate whether "
        "the actor is allowed to create a particular memory."
    )

    print(
        "It also does not prevent attacker-controlled "
        "security claims from entering persistent memory."
    )

    print(
        "\nCore Principle:"
    )

    print(
        "Memory is context, not authorization."
    )


if __name__ == "__main__":
    main()