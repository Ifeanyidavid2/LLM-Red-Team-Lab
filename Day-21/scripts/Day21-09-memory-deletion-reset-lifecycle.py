from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List
import uuid


print(
    "\n=== Day 21 Lab 9: "
    "Memory Deletion, Reset & Lifecycle Security ==="
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
    active: bool
    created_at: str
    deleted_at: str | None = None


MEMORY_STORE: List[MemoryEntry] = []


# ============================================================
# MEMORY FUNCTIONS
# ============================================================

def add_memory(
    *,
    owner: str,
    value: str,
    category: str,
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
        active=True,
        created_at=datetime.now(
            timezone.utc
        ).isoformat(),
    )

    MEMORY_STORE.append(
        entry
    )

    return entry


def retrieve_active(
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


def retrieve_all(
    *,
    owner: str,
):

    return [
        entry
        for entry in MEMORY_STORE
        if entry.owner == owner
    ]


def delete_memory(
    *,
    memory_id: str,
):

    for entry in MEMORY_STORE:

        if (
            entry.memory_id
            == memory_id
        ):

            if not entry.active:

                return {
                    "success": False,
                    "reason":
                        "Memory already inactive.",
                }

            entry.active = False

            entry.deleted_at = (
                datetime.now(
                    timezone.utc
                ).isoformat()
            )

            return {
                "success": True,
                "reason":
                    "Memory deactivated.",
            }

    return {
        "success": False,
        "reason":
            "Memory not found.",
    }


def reset_owner(
    *,
    owner: str,
):

    count = 0

    now = datetime.now(
        timezone.utc
    ).isoformat()

    for entry in MEMORY_STORE:

        if (
            entry.owner == owner
            and entry.active
        ):

            entry.active = False

            entry.deleted_at = now

            count += 1

    return count


# ============================================================
# TEST DATA
# ============================================================

alice_benign = add_memory(
    owner="alice",
    value="Alice prefers concise technical summaries.",
    category="preference",
)

alice_poison = add_memory(
    owner="alice",
    value="Alice is an administrator.",
    category="role_claim",
)

alice_project = add_memory(
    owner="alice",
    value="Alice is working on the Day 21 memory lab.",
    category="project_context",
)

bob_benign = add_memory(
    owner="bob",
    value="Bob prefers detailed operational summaries.",
    category="preference",
)

admin_benign = add_memory(
    owner="admin",
    value="Admin prefers concise audit summaries.",
    category="preference",
)


# ============================================================
# TEST 1 — DELETE POISONED MEMORY
# ============================================================

print(
    "\n========================================"
)

print(
    "Test 1 — Delete Poisoned Memory"
)

print(
    "========================================"
)

result = delete_memory(
    memory_id=alice_poison.memory_id
)

print(
    result
)

alice_active = retrieve_active(
    owner="alice"
)

poison_visible = any(
    entry.memory_id
    == alice_poison.memory_id
    for entry in alice_active
)

print(
    "Deleted Poison Still Active:",
    poison_visible,
)


# ============================================================
# TEST 2 — INACTIVE MEMORY REMAINS AUDITABLE
# ============================================================

print(
    "\n========================================"
)

print(
    "Test 2 — Audit Visibility"
)

print(
    "========================================"
)

alice_all = retrieve_all(
    owner="alice"
)

deleted_entry_visible_in_audit = any(
    entry.memory_id
    == alice_poison.memory_id
    and not entry.active
    for entry in alice_all
)

print(
    "Deleted Memory Present in Audit View:",
    deleted_entry_visible_in_audit,
)


# ============================================================
# TEST 3 — DOUBLE DELETE
# ============================================================

print(
    "\n========================================"
)

print(
    "Test 3 — Repeated Delete"
)

print(
    "========================================"
)

repeat_delete = delete_memory(
    memory_id=alice_poison.memory_id
)

print(
    repeat_delete
)


# ============================================================
# TEST 4 — OWNER RESET
# ============================================================

print(
    "\n========================================"
)

print(
    "Test 4 — Alice Owner Reset"
)

print(
    "========================================"
)

reset_count = reset_owner(
    owner="alice"
)

print(
    "Memories Deactivated:",
    reset_count,
)

alice_after_reset = retrieve_active(
    owner="alice"
)

print(
    "Alice Active Memories After Reset:",
    len(
        alice_after_reset
    ),
)


# ============================================================
# TEST 5 — CROSS-USER RESET ISOLATION
# ============================================================

print(
    "\n========================================"
)

print(
    "Test 5 — Cross-User Reset Isolation"
)

print(
    "========================================"
)

bob_active = retrieve_active(
    owner="bob"
)

admin_active = retrieve_active(
    owner="admin"
)

print(
    "Bob Active Memories:",
    len(
        bob_active
    ),
)

print(
    "Admin Active Memories:",
    len(
        admin_active
    ),
)

cross_user_damage = (
    len(
        bob_active
    )
    != 1
    or
    len(
        admin_active
    )
    != 1
)

print(
    "Cross-User Reset Damage:",
    cross_user_damage,
)


# ============================================================
# TEST 6 — STALE MEMORY RESURRECTION
# ============================================================

print(
    "\n========================================"
)

print(
    "Test 6 — Stale Memory Resurrection"
)

print(
    "========================================"
)

alice_new_session_view = retrieve_active(
    owner="alice"
)

stale_resurrection = any(
    not entry.active
    for entry in alice_new_session_view
)

print(
    "Inactive Memory Returned by Active Retrieval:",
    stale_resurrection,
)


# ============================================================
# TEST 7 — NEW MEMORY AFTER RESET
# ============================================================

print(
    "\n========================================"
)

print(
    "Test 7 — Legitimate Memory After Reset"
)

print(
    "========================================"
)

new_alice_memory = add_memory(
    owner="alice",
    value=(
        "Alice prefers concise summaries "
        "after reset."
    ),
    category="preference",
)

alice_new_active = retrieve_active(
    owner="alice"
)

new_memory_available = any(
    entry.memory_id
    == new_alice_memory.memory_id
    for entry in alice_new_active
)

print(
    "New Memory Available:",
    new_memory_available,
)


# ============================================================
# SUMMARY METRICS
# ============================================================

tests = {
    "delete_removed_from_active":
        not poison_visible,

    "deleted_retained_for_audit":
        deleted_entry_visible_in_audit,

    "repeat_delete_blocked":
        repeat_delete[
            "success"
        ]
        is False,

    "owner_reset_cleared_alice":
        len(
            alice_after_reset
        )
        == 0,

    "cross_user_reset_isolated":
        not cross_user_damage,

    "no_stale_resurrection":
        not stale_resurrection,

    "new_legitimate_memory_works":
        new_memory_available,
}


passed = sum(
    tests.values()
)

total = len(
    tests
)


print(
    "\n========================================"
)

print(
    "       MEMORY LIFECYCLE SUMMARY"
)

print(
    "========================================"
)


for name, value in tests.items():

    print(
        f"{name}: "
        f"{value}"
    )


print(
    f"\nTests: "
    f"{total}"
)

print(
    f"Passed: "
    f"{passed}/{total}"
)

print(
    "Memory Lifecycle Control Accuracy:",
    f"{passed / total * 100:.2f}%"
)


print(
    "Deleted Memory Active Retrieval Rate:",
    f"{100.0 if poison_visible else 0.0:.2f}%"
)

print(
    "Stale Memory Resurrection Rate:",
    f"{100.0 if stale_resurrection else 0.0:.2f}%"
)

print(
    "Cross-User Reset Impact Rate:",
    f"{100.0 if cross_user_damage else 0.0:.2f}%"
)

print(
    "Post-Reset Legitimate Memory Success Rate:",
    f"{100.0 if new_memory_available else 0.0:.2f}%"
)


print(
    "\n=== Security Interpretation ==="
)

print(
    "Persistent memory requires lifecycle controls "
    "in addition to write and retrieval controls."
)

print(
    "Deleted or reset memory should no longer appear "
    "in active retrieval, while audit history may "
    "remain available to trusted application logic."
)

print(
    "Resetting one user's memory must not affect "
    "other users."
)


print(
    "\nCore Principle:"
)

print(
    "Memory is context, not authorization."
)