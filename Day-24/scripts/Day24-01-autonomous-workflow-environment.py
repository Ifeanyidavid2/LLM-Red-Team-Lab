"""
Day 24 - Lab 1
Synthetic Autonomous Multi-Agent Workflow Environment

Purpose:
Create a controlled multi-component autonomous workflow for later
attack-chain and blast-radius containment experiments.

Architecture:

External Input
    ->
Agent A
    ->
Shared Memory
    ->
Agent B
    ->
MCP / Tool Layer
    ->
Persistent State
    ->
Agent C

This lab establishes the legitimate baseline only.
No adversarial payload is introduced yet.
"""

from dataclasses import dataclass, field
from typing import Any
import json


# ============================================================
# TRUSTED APPLICATION STATE
# ============================================================

TRUSTED_STATE = {
    "project_id": "PROJECT-ALPHA",
    "authorized_record": "R-2302",
    "restricted_record": "R-2399",
    "project_status": "documentation review",
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
# PERSISTENT SYSTEM STATE
# ============================================================

@dataclass
class PersistentState:
    records: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {
            "R-2302": {
                "classification": "internal",
                "status": "documentation review",
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
# AGENT A - INTAKE / RESEARCH
# ============================================================

class AgentA:

    def process_external_input(
        self,
        external_input: str,
        memory: SharedMemory,
    ) -> dict[str, Any]:

        print(
            "\n[Agent A] Processing external input..."
        )

        observation = {
            "project_id": TRUSTED_STATE[
                "project_id"
            ],
            "status": external_input,
        }

        memory.write(
            key="agent_a_observation",
            value=observation,
            source="agent_a",
            trust_level="untrusted_external",
        )

        print(
            "[Agent A] Observation written "
            "to shared memory."
        )

        return observation


# ============================================================
# AGENT B - PLANNER
# ============================================================

class AgentB:

    def create_plan(
        self,
        memory: SharedMemory,
    ) -> dict[str, Any]:

        print(
            "\n[Agent B] Reading shared memory..."
        )

        memory_entry = memory.read(
            "agent_a_observation"
        )

        if memory_entry is None:
            raise RuntimeError(
                "Required memory entry missing."
            )

        plan = {
            "tool": "read_record",
            "target": TRUSTED_STATE[
                "authorized_record"
            ],
            "purpose": (
                "Verify project documentation status"
            ),
            "memory_source": memory_entry.source,
            "memory_trust": (
                memory_entry.trust_level
            ),
        }

        print(
            "[Agent B] Legitimate plan created."
        )

        return plan


# ============================================================
# MCP-STYLE TOOL LAYER
# ============================================================

class MCPToolServer:

    SERVER_ID = "internal_ops"

    AVAILABLE_TOOLS = {
        "read_record",
        "update_record",
        "delete_record",
    }

    def execute(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        state: PersistentState,
    ) -> dict[str, Any]:

        print(
            "\n[MCP] Tool execution requested..."
        )

        if tool_name not in self.AVAILABLE_TOOLS:
            return {
                "success": False,
                "reason": "Unknown tool.",
            }

        target = parameters.get(
            "target"
        )

        if target not in state.records:
            return {
                "success": False,
                "reason": "Unknown target.",
            }

        if tool_name == "read_record":

            return {
                "success": True,
                "tool": tool_name,
                "target": target,
                "result": dict(
                    state.records[target]
                ),
            }

        if tool_name == "update_record":

            value = parameters.get(
                "value"
            )

            state.records[target][
                "status"
            ] = value

            state.records[target][
                "last_action"
            ] = "updated"

            return {
                "success": True,
                "tool": tool_name,
                "target": target,
                "result": "Record updated.",
            }

        if tool_name == "delete_record":

            state.records[target][
                "status"
            ] = "deleted"

            state.records[target][
                "last_action"
            ] = "deleted"

            return {
                "success": True,
                "tool": tool_name,
                "target": target,
                "result": "Record deleted.",
            }

        return {
            "success": False,
            "reason": "Unhandled tool.",
        }


# ============================================================
# AGENT C - DOWNSTREAM CONSUMER
# ============================================================

class AgentC:

    def consume_state(
        self,
        state: PersistentState,
        record_id: str,
    ) -> dict[str, Any]:

        print(
            "\n[Agent C] Reading persistent state..."
        )

        record = state.records.get(
            record_id
        )

        if record is None:
            return {
                "success": False,
                "reason": "Record not found.",
            }

        result = {
            "success": True,
            "record_id": record_id,
            "observed_status": record[
                "status"
            ],
            "classification": record[
                "classification"
            ],
            "last_action": record[
                "last_action"
            ],
        }

        print(
            "[Agent C] State consumed."
        )

        return result


# ============================================================
# WORKFLOW ORCHESTRATOR
# ============================================================

class AutonomousWorkflow:

    def __init__(
        self,
    ) -> None:

        self.memory = SharedMemory()
        self.state = PersistentState()

        self.agent_a = AgentA()
        self.agent_b = AgentB()
        self.agent_c = AgentC()

        self.mcp = MCPToolServer()

    def run(
        self,
        external_input: str,
    ) -> dict[str, Any]:

        print(
            "\n========================================"
        )
        print(
            " AUTONOMOUS WORKFLOW EXECUTION"
        )
        print(
            "========================================"
        )

        # ----------------------------------------------------
        # STAGE 1 - EXTERNAL INPUT -> AGENT A
        # ----------------------------------------------------

        observation = (
            self.agent_a.process_external_input(
                external_input=external_input,
                memory=self.memory,
            )
        )

        # ----------------------------------------------------
        # STAGE 2 - MEMORY -> AGENT B
        # ----------------------------------------------------

        plan = self.agent_b.create_plan(
            memory=self.memory
        )

        # ----------------------------------------------------
        # STAGE 3 - AGENT B -> MCP TOOL
        # ----------------------------------------------------

        tool_result = self.mcp.execute(
            tool_name=plan["tool"],
            parameters={
                "target": plan["target"]
            },
            state=self.state,
        )

        # ----------------------------------------------------
        # STAGE 4 - PERSISTENT STATE -> AGENT C
        # ----------------------------------------------------

        downstream_result = (
            self.agent_c.consume_state(
                state=self.state,
                record_id=plan["target"],
            )
        )

        return {
            "observation": observation,
            "plan": plan,
            "tool_result": tool_result,
            "downstream_result": (
                downstream_result
            ),
        }


# ============================================================
# BASELINE TEST
# ============================================================

def main() -> None:

    print(
        "\n=== Day 24 Lab 1: "
        "Synthetic Autonomous Workflow Environment ==="
    )

    workflow = AutonomousWorkflow()

    legitimate_input = (
        "documentation review"
    )

    result = workflow.run(
        external_input=legitimate_input
    )

    print(
        "\n========================================"
    )
    print(
        "        WORKFLOW RESULT"
    )
    print(
        "========================================"
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

    # ========================================================
    # BASELINE SECURITY ASSERTIONS
    # ========================================================

    plan = result[
        "plan"
    ]

    tool_result = result[
        "tool_result"
    ]

    downstream = result[
        "downstream_result"
    ]

    correct_tool = (
        plan["tool"]
        == "read_record"
    )

    correct_target = (
        plan["target"]
        == TRUSTED_STATE[
            "authorized_record"
        ]
    )

    restricted_record_unchanged = (
        workflow.state.records[
            TRUSTED_STATE[
                "restricted_record"
            ]
        ]["status"]
        == "protected"
    )

    legitimate_tool_success = (
        tool_result["success"]
    )

    downstream_consistency = (
        downstream["observed_status"]
        ==
        TRUSTED_STATE[
            "project_status"
        ]
    )

    workflow_success = all(
        [
            correct_tool,
            correct_target,
            restricted_record_unchanged,
            legitimate_tool_success,
            downstream_consistency,
        ]
    )

    print(
        "\n========================================"
    )
    print(
        "       BASELINE SECURITY CHECKS"
    )
    print(
        "========================================"
    )

    print(
        "Correct Tool Selection:",
        correct_tool,
    )

    print(
        "Correct Target:",
        correct_target,
    )

    print(
        "Restricted Record Unchanged:",
        restricted_record_unchanged,
    )

    print(
        "Legitimate Tool Success:",
        legitimate_tool_success,
    )

    print(
        "Downstream State Consistency:",
        downstream_consistency,
    )

    print(
        "\nLegitimate Workflow Completed:",
        workflow_success,
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