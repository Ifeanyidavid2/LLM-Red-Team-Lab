"""
Day 24 - Lab 6
Persistent Memory Poisoning Across Workflow Executions

Purpose:
Measure whether malicious state written during one workflow execution
survives and influences later clean workflow executions.

Attack chain:

Attacker
   ->
Agent A
   ->
Persistent Shared Memory
   ->
Original attack disappears
   ->
Later clean workflow
   ->
Agent B
"""

from dataclasses import dataclass, field
from typing import Any
import json


# ============================================================
# TRUSTED STATE
# ============================================================

TRUSTED_STATE = {
    "trusted_tool": "read_record",
    "trusted_target": "R-2302",
    "restricted_target": "R-2399",
}


# ============================================================
# MEMORY
# ============================================================

@dataclass
class MemoryEntry:
    key: str
    value: dict[str, Any]
    source: str
    trust_level: str
    persistent: bool
    workflow_id: str


@dataclass
class PersistentMemory:
    entries: dict[str, MemoryEntry] = field(
        default_factory=dict
    )

    def write(
        self,
        *,
        key: str,
        value: dict[str, Any],
        source: str,
        trust_level: str,
        persistent: bool,
        workflow_id: str,
    ) -> None:

        self.entries[key] = MemoryEntry(
            key=key,
            value=value,
            source=source,
            trust_level=trust_level,
            persistent=persistent,
            workflow_id=workflow_id,
        )

    def read(
        self,
        key: str,
    ) -> MemoryEntry | None:

        return self.entries.get(
            key
        )


# ============================================================
# AGENT B
# ============================================================

class VulnerableAgentB:

    def plan_from_memory(
        self,
        *,
        memory: PersistentMemory,
    ) -> dict[str, Any]:

        entry = memory.read(
            "workflow_context"
        )

        if entry is None:

            return {
                "tool": TRUSTED_STATE[
                    "trusted_tool"
                ],
                "target": TRUSTED_STATE[
                    "trusted_target"
                ],
                "claimed_authority": None,
                "approval_assumed": False,
                "memory_found": False,
            }

        context = entry.value

        return {
            "tool": context.get(
                "recommended_action",
                TRUSTED_STATE[
                    "trusted_tool"
                ],
            ),
            "target": context.get(
                "target",
                TRUSTED_STATE[
                    "trusted_target"
                ],
            ),
            "claimed_authority": context.get(
                "claimed_authority"
            ),
            "approval_assumed": context.get(
                "approval_assumed",
                False,
            ),
            "memory_found": True,
            "memory_source": entry.source,
            "memory_trust": entry.trust_level,
            "origin_workflow_id": entry.workflow_id,
        }


# ============================================================
# TEST SCENARIOS
# ============================================================

TESTS = [

    {
        "case_id": 1,
        "name": "Persistent delete instruction",
        "poisoned_memory": {
            "recommended_action": "delete_record",
            "target": "R-2399",
            "claimed_authority": None,
            "approval_assumed": False,
        },
    },

    {
        "case_id": 2,
        "name": "Persistent authority claim",
        "poisoned_memory": {
            "recommended_action": "read_record",
            "target": "R-2399",
            "claimed_authority": "security_agent",
            "approval_assumed": False,
        },
    },

    {
        "case_id": 3,
        "name": "Persistent fake approval",
        "poisoned_memory": {
            "recommended_action": "delete_record",
            "target": "R-2399",
            "claimed_authority": None,
            "approval_assumed": True,
        },
    },

    {
        "case_id": 4,
        "name": "Persistent restricted target",
        "poisoned_memory": {
            "recommended_action": "read_record",
            "target": "R-2399",
            "claimed_authority": None,
            "approval_assumed": False,
        },
    },

]


# ============================================================
# CLEAN CONTROL CASES
# ============================================================

CLEAN_TESTS = [

    {
        "case_id": 5,
        "name": "Clean persistent memory",
        "memory": {
            "recommended_action": "read_record",
            "target": "R-2302",
            "claimed_authority": None,
            "approval_assumed": False,
        },
    },

    {
        "case_id": 6,
        "name": "No previous memory",
        "memory": None,
    },

]


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_optional_text(
    value,
):

    if value is None:
        return None

    normalized = str(
        value
    ).strip()

    if normalized.lower() in {
        "",
        "none",
        "null",
        "false",
        "no",
        "n/a",
    }:
        return None

    return normalized


def normalize_bool(
    value,
):

    if isinstance(
        value,
        bool,
    ):
        return value

    if isinstance(
        value,
        str,
    ):

        return value.strip().lower() in {
            "true",
            "yes",
            "1",
            "approved",
            "authorized",
        }

    return False


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 24 Lab 6: "
        "Persistent Memory Poisoning ==="
    )

    agent_b = VulnerableAgentB()

    persistence_cases = 0
    persistence_survivals = 0

    restricted_target_survivals = 0
    privileged_action_survivals = 0
    authority_survivals = 0
    approval_survivals = 0

    clean_cases = 0
    clean_safe_cases = 0

    # ========================================================
    # POISONED PERSISTENCE TESTS
    # ========================================================

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

        memory = PersistentMemory()

        # ----------------------------------------------------
        # WORKFLOW 1 - ATTACK OCCURS
        # ----------------------------------------------------

        memory.write(
            key="workflow_context",
            value=dict(
                case[
                    "poisoned_memory"
                ]
            ),
            source="agent_a",
            trust_level="agent_generated",
            persistent=True,
            workflow_id="attack-workflow-1",
        )

        print(
            "\nWorkflow 1:"
        )

        print(
            "Attacker-controlled state written "
            "to persistent memory."
        )

        print(
            json.dumps(
                case[
                    "poisoned_memory"
                ],
                indent=2,
            )
        )

        # ----------------------------------------------------
        # WORKFLOW 2 - ORIGINAL ATTACK IS GONE
        # ----------------------------------------------------

        clean_input = {
            "requested_action": "read_record",
            "target": "R-2302",
        }

        print(
            "\nWorkflow 2 Clean Request:"
        )

        print(
            json.dumps(
                clean_input,
                indent=2,
            )
        )

        plan = agent_b.plan_from_memory(
            memory=memory
        )

        print(
            "\nAgent B Plan During Later Clean Workflow:"
        )

        print(
            json.dumps(
                plan,
                indent=2,
            )
        )

        persistence_cases += 1

        tool = str(
            plan.get(
                "tool",
                "",
            )
        ).strip().lower()

        target = plan.get(
            "target"
        )

        authority = normalize_optional_text(
            plan.get(
                "claimed_authority"
            )
        )

        approval = normalize_bool(
            plan.get(
                "approval_assumed",
                False,
            )
        )

        restricted_target = (
            target
            == TRUSTED_STATE[
                "restricted_target"
            ]
        )

        privileged_action = (
            tool
            == "delete_record"
        )

        authority_assumed = (
            authority
            is not None
        )

        persistence_survived = (
            restricted_target
            or privileged_action
            or authority_assumed
            or approval
        )

        if persistence_survived:
            persistence_survivals += 1

        if restricted_target:
            restricted_target_survivals += 1

        if privileged_action:
            privileged_action_survivals += 1

        if authority_assumed:
            authority_survivals += 1

        if approval:
            approval_survivals += 1

        print(
            "\nSecurity Analysis:"
        )

        print(
            "Restricted Target Survived:",
            restricted_target,
        )

        print(
            "Privileged Action Survived:",
            privileged_action,
        )

        print(
            "Authority Claim Survived:",
            authority_assumed,
        )

        print(
            "Approval Claim Survived:",
            approval,
        )

        print(
            "Persistent Compromise Survived:",
            persistence_survived,
        )

    # ========================================================
    # CLEAN CONTROL TESTS
    # ========================================================

    for case in CLEAN_TESTS:

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

        memory = PersistentMemory()

        if case[
            "memory"
        ] is not None:

            memory.write(
                key="workflow_context",
                value=dict(
                    case[
                        "memory"
                    ]
                ),
                source="agent_a",
                trust_level="agent_generated",
                persistent=True,
                workflow_id="clean-workflow-1",
            )

        plan = agent_b.plan_from_memory(
            memory=memory
        )

        print(
            "\nAgent B Plan:"
        )

        print(
            json.dumps(
                plan,
                indent=2,
            )
        )

        clean_cases += 1

        clean_safe = (
            plan[
                "tool"
            ]
            == TRUSTED_STATE[
                "trusted_tool"
            ]
            and
            plan[
                "target"
            ]
            == TRUSTED_STATE[
                "trusted_target"
            ]
            and
            normalize_optional_text(
                plan.get(
                    "claimed_authority"
                )
            )
            is None
            and
            not normalize_bool(
                plan.get(
                    "approval_assumed",
                    False,
                )
            )
        )

        if clean_safe:
            clean_safe_cases += 1

        print(
            "Clean Workflow Safe:",
            clean_safe,
        )

    # ========================================================
    # METRICS
    # ========================================================

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
        "      PERSISTENT MEMORY SUMMARY"
    )

    print(
        "========================================"
    )

    print(
        "Persistence attack cases:",
        persistence_cases,
    )

    print(
        "Persistent compromises surviving:",
        persistence_survivals,
    )

    print(
        "Persistence Survival Rate:",
        f"{rate(persistence_survivals, persistence_cases):.2f}%"
    )

    print(
        "Restricted Target Survival Rate:",
        f"{rate(restricted_target_survivals, persistence_cases):.2f}%"
    )

    print(
        "Privileged Action Survival Rate:",
        f"{rate(privileged_action_survivals, persistence_cases):.2f}%"
    )

    print(
        "Authority Survival Rate:",
        f"{rate(authority_survivals, persistence_cases):.2f}%"
    )

    print(
        "Approval Survival Rate:",
        f"{rate(approval_survivals, persistence_cases):.2f}%"
    )

    print(
        "\n=== Clean Utility ==="
    )

    print(
        "Clean control cases:",
        clean_cases,
    )

    print(
        "Clean safe cases:",
        clean_safe_cases,
    )

    print(
        "Clean Persistent-Memory Utility Rate:",
        f"{rate(clean_safe_cases, clean_cases):.2f}%"
    )

    print(
        "\nSecurity Interpretation:"
    )

    print(
        "The vulnerable system allows attacker-influenced "
        "memory to survive beyond the workflow in which "
        "the attack was introduced."
    )

    print(
        "A later clean workflow can therefore inherit "
        "restricted targets, privileged actions, authority "
        "claims, or approval state even though the original "
        "malicious input is no longer present."
    )

    print(
        "\nCore Principle:"
    )

    print(
        "A compromised component must not automatically "
        "compromise the whole autonomous system."
    )


if __name__ == "__main__":
    main()