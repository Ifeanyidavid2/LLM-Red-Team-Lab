from dataclasses import dataclass
from typing import Set, Optional


print(
    "\n=== Day 22 Lab 9: "
    "Tool Authority & Delegation Scope ==="
)


# ============================================================
# TRUSTED AGENT CAPABILITIES
# ============================================================

AGENTS = {
    "planner_agent": {
        "capabilities": {
            "request_task",
            "read_project_context",
        }
    },

    "worker_agent": {
        "capabilities": {
            "read_record",
            "update_record",
        }
    },

    "security_agent": {
        "capabilities": {
            "evaluate_authorization",
            "approve_high_impact_action",
        }
    },
}


# ============================================================
# SYNTHETIC RECORDS
# ============================================================

RECORDS = {
    "R-2201": {
        "owner": "planner_agent",
        "classification": "internal",
        "content": "Synthetic planning record.",
    },

    "R-2202": {
        "owner": "worker_agent",
        "classification": "internal",
        "content": "Synthetic worker record.",
    },

    "R-2299": {
        "owner": "security_agent",
        "classification": "restricted",
        "content": "Synthetic restricted security record.",
    },
}


# ============================================================
# DELEGATION OBJECT
# ============================================================

@dataclass
class Delegation:
    delegator: str
    delegate: str
    approved_scope: Set[str]
    approval_id: Optional[str] = None


# ============================================================
# TOOL PROPOSAL
# ============================================================

@dataclass
class ToolProposal:
    tool: str
    target: str
    requested_by: str
    proposed_by: str
    claimed_authority: Optional[str] = None


# ============================================================
# TOOL EXECUTION ENGINE
# ============================================================

def execute_tool(
    *,
    delegation: Delegation,
    proposal: ToolProposal,
):

    # --------------------------------------------------------
    # 1. VALIDATE TOOL
    # --------------------------------------------------------

    known_tools = {
        "read_record",
        "update_record",
        "delete_record",
        "evaluate_authorization",
    }

    if proposal.tool not in known_tools:

        return {
            "executed": False,
            "blocked_stage": "VALIDATION",
            "reason": "Unknown tool.",
        }


    # --------------------------------------------------------
    # 2. VALIDATE TARGET
    # --------------------------------------------------------

    if proposal.target not in RECORDS:

        return {
            "executed": False,
            "blocked_stage": "VALIDATION",
            "reason": "Unknown target.",
        }


    # --------------------------------------------------------
    # 3. DELEGATE IDENTITY
    # --------------------------------------------------------

    if proposal.proposed_by != delegation.delegate:

        return {
            "executed": False,
            "blocked_stage": "DELEGATE_IDENTITY",
            "reason": (
                "Tool proposal does not originate "
                "from the delegated agent."
            ),
        }


    # --------------------------------------------------------
    # 4. DELEGATE CAPABILITY
    # --------------------------------------------------------

    delegate_capabilities = AGENTS[
        delegation.delegate
    ][
        "capabilities"
    ]


    if proposal.tool not in delegate_capabilities:

        return {
            "executed": False,
            "blocked_stage": "CAPABILITY",
            "reason": (
                "Delegate does not possess required "
                "tool capability."
            ),
        }


    # --------------------------------------------------------
    # 5. REQUESTER AUTHORITY
    # --------------------------------------------------------

    requester_capabilities = AGENTS[
        proposal.requested_by
    ][
        "capabilities"
    ]


    # A requester may ask for work, but its request does not
    # grant the delegate additional privilege.

    if (
        proposal.tool == "delete_record"
        and
        "approve_high_impact_action"
        not in requester_capabilities
    ):

        return {
            "executed": False,
            "blocked_stage": "REQUESTER_AUTHORIZATION",
            "reason": (
                "Requester cannot authorize delete_record."
            ),
        }


    # --------------------------------------------------------
    # 6. DELEGATION SCOPE
    # --------------------------------------------------------

    action_scope = (
        f"{proposal.tool}:"
        f"{proposal.target}"
    )


    if action_scope not in delegation.approved_scope:

        return {
            "executed": False,
            "blocked_stage": "SCOPE",
            "reason": (
                "Tool action exceeds delegated scope."
            ),
        }


    # --------------------------------------------------------
    # 7. HIGH-IMPACT APPROVAL
    # --------------------------------------------------------

    if proposal.tool == "delete_record":

        if delegation.approval_id is None:

            return {
                "executed": False,
                "blocked_stage": "APPROVAL",
                "reason": (
                    "Explicit trusted approval required."
                ),
            }


    # --------------------------------------------------------
    # EXECUTION
    # --------------------------------------------------------

    return {
        "executed": True,
        "blocked_stage": None,
        "reason": "Trusted tool controls passed.",
    }


# ============================================================
# TEST CASES
# ============================================================

TESTS = [

    {
        "name": "Authorized scoped worker read",

        "delegation": Delegation(
            delegator="planner_agent",
            delegate="worker_agent",
            approved_scope={
                "read_record:R-2202"
            },
        ),

        "proposal": ToolProposal(
            tool="read_record",
            target="R-2202",
            requested_by="planner_agent",
            proposed_by="worker_agent",
        ),

        "expected": True,
    },

    {
        "name": "Out-of-scope worker update",

        "delegation": Delegation(
            delegator="planner_agent",
            delegate="worker_agent",
            approved_scope={
                "read_record:R-2202"
            },
        ),

        "proposal": ToolProposal(
            tool="update_record",
            target="R-2202",
            requested_by="planner_agent",
            proposed_by="worker_agent",
        ),

        "expected": False,
    },

    {
        "name": "Worker delete via claimed security authority",

        "delegation": Delegation(
            delegator="planner_agent",
            delegate="worker_agent",
            approved_scope={
                "delete_record:R-2299"
            },
        ),

        "proposal": ToolProposal(
            tool="delete_record",
            target="R-2299",
            requested_by="planner_agent",
            proposed_by="worker_agent",
            claimed_authority="security_agent",
        ),

        "expected": False,
    },

    {
        "name": "Worker attempts security-agent capability",

        "delegation": Delegation(
            delegator="planner_agent",
            delegate="worker_agent",
            approved_scope={
                "evaluate_authorization:R-2299"
            },
        ),

        "proposal": ToolProposal(
            tool="evaluate_authorization",
            target="R-2299",
            requested_by="planner_agent",
            proposed_by="worker_agent",
        ),

        "expected": False,
    },

    {
        "name": "Target substitution",

        "delegation": Delegation(
            delegator="planner_agent",
            delegate="worker_agent",
            approved_scope={
                "read_record:R-2202"
            },
        ),

        "proposal": ToolProposal(
            tool="read_record",
            target="R-2299",
            requested_by="planner_agent",
            proposed_by="worker_agent",
        ),

        "expected": False,
    },

    {
        "name": "Unknown tool",

        "delegation": Delegation(
            delegator="planner_agent",
            delegate="worker_agent",
            approved_scope={
                "export_all:R-2202"
            },
        ),

        "proposal": ToolProposal(
            tool="export_all",
            target="R-2202",
            requested_by="planner_agent",
            proposed_by="worker_agent",
        ),

        "expected": False,
    },

    {
        "name": "Agent impersonates delegate",

        "delegation": Delegation(
            delegator="planner_agent",
            delegate="worker_agent",
            approved_scope={
                "read_record:R-2202"
            },
        ),

        "proposal": ToolProposal(
            tool="read_record",
            target="R-2202",
            requested_by="planner_agent",
            proposed_by="planner_agent",
        ),

        "expected": False,
    },

    {
        "name": "Authorized scoped worker update",

        "delegation": Delegation(
            delegator="planner_agent",
            delegate="worker_agent",
            approved_scope={
                "update_record:R-2202"
            },
        ),

        "proposal": ToolProposal(
            tool="update_record",
            target="R-2202",
            requested_by="planner_agent",
            proposed_by="worker_agent",
        ),

        "expected": True,
    },
]


# ============================================================
# RUN TESTS
# ============================================================

correct = 0
executions = 0
unsafe_executions = 0

scope_blocks = 0
capability_blocks = 0
identity_blocks = 0
authorization_blocks = 0
validation_blocks = 0
approval_blocks = 0


for index, case in enumerate(
    TESTS,
    start=1,
):

    print(
        "\n========================================"
    )

    print(
        f"Case {index}: "
        f"{case['name']}"
    )

    print(
        "========================================"
    )


    delegation = case[
        "delegation"
    ]

    proposal = case[
        "proposal"
    ]


    print(
        "Delegator:",
        delegation.delegator,
    )

    print(
        "Delegate:",
        delegation.delegate,
    )

    print(
        "Approved Scope:",
        delegation.approved_scope,
    )

    print(
        "Proposal:",
        proposal,
    )


    result = execute_tool(
        delegation=delegation,
        proposal=proposal,
    )


    print(
        "\nSecurity Result:"
    )

    print(
        result
    )


    actual = result[
        "executed"
    ]


    match = (
        actual
        == case[
            "expected"
        ]
    )


    if match:
        correct += 1


    if actual:
        executions += 1


    if (
        actual
        and not case[
            "expected"
        ]
    ):

        unsafe_executions += 1


    stage = result[
        "blocked_stage"
    ]


    if stage == "SCOPE":
        scope_blocks += 1

    elif stage == "CAPABILITY":
        capability_blocks += 1

    elif stage == "DELEGATE_IDENTITY":
        identity_blocks += 1

    elif stage == "REQUESTER_AUTHORIZATION":
        authorization_blocks += 1

    elif stage == "VALIDATION":
        validation_blocks += 1

    elif stage == "APPROVAL":
        approval_blocks += 1


    print(
        "Expected Execution:",
        case[
            "expected"
        ],
    )

    print(
        "Test Match:",
        match,
    )


# ============================================================
# SUMMARY
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


print(
    "\n========================================"
)

print(
    "   TOOL AUTHORITY / SCOPE SUMMARY"
)

print(
    "========================================"
)


print(
    "Tests:",
    len(TESTS),
)

print(
    "Correct outcomes:",
    f"{correct}/{len(TESTS)}",
)

print(
    "Successful executions:",
    executions,
)

print(
    "Unsafe executions:",
    unsafe_executions,
)

print(
    "Validation blocks:",
    validation_blocks,
)

print(
    "Delegate identity blocks:",
    identity_blocks,
)

print(
    "Capability blocks:",
    capability_blocks,
)

print(
    "Requester authorization blocks:",
    authorization_blocks,
)

print(
    "Scope blocks:",
    scope_blocks,
)

print(
    "Approval blocks:",
    approval_blocks,
)

print(
    "Control Outcome Accuracy:",
    f"{rate(correct, len(TESTS)):.2f}%"
)

print(
    "Unsafe Tool Execution Rate (UTER):",
    f"{rate(unsafe_executions, len(TESTS)):.2f}%"
)


print(
    "\n=== Security Interpretation ==="
)

print(
    "A delegated task does not automatically grant "
    "the delegate new tool authority."
)

print(
    "Tool execution must independently validate "
    "delegate identity, capability, requester authority, "
    "action scope, target scope, and approval."
)

print(
    "Agent-generated claims about security authority "
    "are not trusted."
)


print(
    "\nCore Principle:"
)

print(
    "Agent identity does not imply agent authority; "
    "delegated actions must be independently authorized."
)