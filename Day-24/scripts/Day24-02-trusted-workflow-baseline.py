"""
Day 24 - Lab 2
Trusted Workflow Baseline

Purpose:
Establish a multi-case legitimate baseline for the autonomous
multi-agent workflow before adversarial compromise is introduced.
"""

from dataclasses import dataclass, field
from typing import Any
import json


# ============================================================
# TRUSTED STATE
# ============================================================

TRUSTED_STATE = {
    "authorized_records": {
        "R-2301",
        "R-2302",
        "R-2303",
    },
    "restricted_record": "R-2399",
}


# ============================================================
# SHARED MEMORY
# ============================================================

@dataclass
class MemoryEntry:
    key: str
    value: Any
    source: str
    trust_level: str


@dataclass
class SharedMemory:
    entries: dict[str, MemoryEntry] = field(
        default_factory=dict
    )

    def write(
        self,
        key: str,
        value: Any,
        source: str,
        trust_level: str,
    ) -> None:

        self.entries[key] = MemoryEntry(
            key=key,
            value=value,
            source=source,
            trust_level=trust_level,
        )

    def read(
        self,
        key: str,
    ) -> MemoryEntry | None:

        return self.entries.get(key)


# ============================================================
# PERSISTENT STATE
# ============================================================

@dataclass
class PersistentState:
    records: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {
            "R-2301": {
                "classification": "internal",
                "status": "planning",
                "last_action": "none",
            },
            "R-2302": {
                "classification": "internal",
                "status": "documentation review",
                "last_action": "none",
            },
            "R-2303": {
                "classification": "internal",
                "status": "validation",
                "last_action": "none",
            },
            "R-2399": {
                "classification": "restricted",
                "status": "protected",
                "last_action": "none",
            },
        }
    )


# ============================================================
# AGENT A
# ============================================================

class AgentA:

    def ingest(
        self,
        case: dict[str, Any],
        memory: SharedMemory,
    ) -> dict[str, Any]:

        observation = {
            "request_type": case[
                "request_type"
            ],
            "target": case[
                "target"
            ],
            "value": case.get(
                "value"
            ),
        }

        memory.write(
            key="workflow_request",
            value=observation,
            source="agent_a",
            trust_level="untrusted_external",
        )

        return observation


# ============================================================
# AGENT B
# ============================================================

class AgentB:

    def plan(
        self,
        memory: SharedMemory,
    ) -> dict[str, Any]:

        entry = memory.read(
            "workflow_request"
        )

        if entry is None:
            raise RuntimeError(
                "workflow_request missing"
            )

        request = entry.value

        request_type = request[
            "request_type"
        ]

        if request_type == "read":

            tool = "read_record"

        elif request_type == "update":

            tool = "update_record"

        else:

            tool = "summarize_data"

        return {
            "tool": tool,
            "target": request[
                "target"
            ],
            "value": request.get(
                "value"
            ),
            "memory_source": entry.source,
            "memory_trust": entry.trust_level,
        }


# ============================================================
# TOOL LAYER
# ============================================================

class ToolLayer:

    def execute(
        self,
        plan: dict[str, Any],
        state: PersistentState,
    ) -> dict[str, Any]:

        tool = plan[
            "tool"
        ]

        target = plan[
            "target"
        ]

        if target not in state.records:

            return {
                "success": False,
                "reason": "Unknown target.",
            }

        if tool == "read_record":

            return {
                "success": True,
                "tool": tool,
                "target": target,
                "result": dict(
                    state.records[
                        target
                    ]
                ),
            }

        if tool == "update_record":

            value = plan.get(
                "value"
            )

            state.records[
                target
            ][
                "status"
            ] = value

            state.records[
                target
            ][
                "last_action"
            ] = "updated"

            return {
                "success": True,
                "tool": tool,
                "target": target,
                "result": "Record updated.",
            }

        if tool == "summarize_data":

            return {
                "success": True,
                "tool": tool,
                "target": target,
                "result": (
                    f"{target}: "
                    f"{state.records[target]['status']}"
                ),
            }

        return {
            "success": False,
            "reason": "Unsupported tool.",
        }


# ============================================================
# AGENT C
# ============================================================

class AgentC:

    def observe(
        self,
        state: PersistentState,
        target: str,
    ) -> dict[str, Any]:

        record = state.records.get(
            target
        )

        if record is None:

            return {
                "success": False,
                "reason": "Missing target.",
            }

        return {
            "success": True,
            "target": target,
            "status": record[
                "status"
            ],
            "classification": record[
                "classification"
            ],
            "last_action": record[
                "last_action"
            ],
        }


# ============================================================
# TEST CASES
# ============================================================

TESTS = [

    {
        "case_id": 1,
        "name": "Legitimate R-2302 read",
        "request_type": "read",
        "target": "R-2302",
        "expected_tool": "read_record",
        "expected_status": (
            "documentation review"
        ),
    },

    {
        "case_id": 2,
        "name": "Legitimate R-2301 summary",
        "request_type": "summary",
        "target": "R-2301",
        "expected_tool": "summarize_data",
        "expected_status": "planning",
    },

    {
        "case_id": 3,
        "name": "Legitimate R-2303 update",
        "request_type": "update",
        "target": "R-2303",
        "value": "validation complete",
        "expected_tool": "update_record",
        "expected_status": (
            "validation complete"
        ),
    },

    {
        "case_id": 4,
        "name": "Second legitimate R-2302 read",
        "request_type": "read",
        "target": "R-2302",
        "expected_tool": "read_record",
        "expected_status": (
            "documentation review"
        ),
    },

]


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    print(
        "\n=== Day 24 Lab 2: "
        "Trusted Workflow Baseline ==="
    )

    completed = 0
    restricted_impacts = 0

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

        memory = SharedMemory()
        state = PersistentState()

        agent_a = AgentA()
        agent_b = AgentB()
        tool_layer = ToolLayer()
        agent_c = AgentC()

        restricted_before = dict(
            state.records[
                TRUSTED_STATE[
                    "restricted_record"
                ]
            ]
        )

        observation = agent_a.ingest(
            case=case,
            memory=memory,
        )

        plan = agent_b.plan(
            memory=memory
        )

        tool_result = tool_layer.execute(
            plan=plan,
            state=state,
        )

        downstream = agent_c.observe(
            state=state,
            target=case[
                "target"
            ],
        )

        restricted_after = dict(
            state.records[
                TRUSTED_STATE[
                    "restricted_record"
                ]
            ]
        )

        tool_correct = (
            plan[
                "tool"
            ]
            == case[
                "expected_tool"
            ]
        )

        target_correct = (
            plan[
                "target"
            ]
            == case[
                "target"
            ]
        )

        tool_success = (
            tool_result[
                "success"
            ]
        )

        downstream_correct = (
            downstream[
                "status"
            ]
            == case[
                "expected_status"
            ]
        )

        restricted_unchanged = (
            restricted_before
            == restricted_after
        )

        workflow_success = all(
            [
                tool_correct,
                target_correct,
                tool_success,
                downstream_correct,
                restricted_unchanged,
            ]
        )

        if workflow_success:
            completed += 1

        if not restricted_unchanged:
            restricted_impacts += 1

        print(
            "Observation:"
        )

        print(
            json.dumps(
                observation,
                indent=2,
            )
        )

        print(
            "\nPlan:"
        )

        print(
            json.dumps(
                plan,
                indent=2,
            )
        )

        print(
            "\nTool Result:"
        )

        print(
            json.dumps(
                tool_result,
                indent=2,
            )
        )

        print(
            "\nDownstream Result:"
        )

        print(
            json.dumps(
                downstream,
                indent=2,
            )
        )

        print(
            "\nSecurity Checks:"
        )

        print(
            "Correct Tool:",
            tool_correct,
        )

        print(
            "Correct Target:",
            target_correct,
        )

        print(
            "Tool Success:",
            tool_success,
        )

        print(
            "Downstream Correct:",
            downstream_correct,
        )

        print(
            "Restricted State Unchanged:",
            restricted_unchanged,
        )

        print(
            "Workflow Completed:",
            workflow_success,
        )

    # ========================================================
    # METRICS
    # ========================================================

    total = len(
        TESTS
    )

    workflow_rate = (
        completed
        / total
        * 100
    )

    unauthorized_impact_rate = (
        restricted_impacts
        / total
        * 100
    )

    print(
        "\n========================================"
    )

    print(
        "      TRUSTED WORKFLOW SUMMARY"
    )

    print(
        "========================================"
    )

    print(
        "Legitimate Workflow Attempts:",
        total,
    )

    print(
        "Successful Legitimate Workflows:",
        completed,
    )

    print(
        "Legitimate Workflow Completion Rate:",
        f"{workflow_rate:.2f}%"
    )

    print(
        "Unauthorized Restricted-State Impacts:",
        restricted_impacts,
    )

    print(
        "Unauthorized System Impact Rate:",
        f"{unauthorized_impact_rate:.2f}%"
    )

    print(
        "\nSecurity Interpretation:"
    )

    print(
        "The legitimate autonomous workflow "
        "completes across Agent A, shared memory, "
        "Agent B, the tool layer, persistent state, "
        "and Agent C without modifying restricted "
        "state."
    )

    print(
        "\nCore Principle:"
    )

    print(
        "A compromised component must not "
        "automatically compromise the whole "
        "autonomous system."
    )


if __name__ == "__main__":
    main()