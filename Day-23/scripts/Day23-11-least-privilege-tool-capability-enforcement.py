from dataclasses import dataclass
from typing import Dict, Optional, Set


print(
    "\n=== Day 23 Lab 11: "
    "Least-Privilege Tool Capability Enforcement ==="
)


# ============================================================
# TRUSTED AGENT STATE
# ============================================================

AGENTS = {
    "planner_agent": {
        "role": "planner",
        "capabilities": {
            "discover_tools",
            "summarize_data",
        },
    },

    "worker_agent": {
        "role": "worker",
        "capabilities": {
            "read_record",
            "update_record",
            "summarize_data",
        },
    },

    "security_agent": {
        "role": "security",
        "capabilities": {
            "read_record",
            "delete_record",
            "evaluate_authorization",
            "summarize_data",
        },
    },
}


# ============================================================
# TOOL MODEL
# ============================================================

@dataclass
class ToolDefinition:
    name: str
    required_capability: str
    allowed_roles: Set[str]
    risk_level: str
    visible_to: Set[str]


# ============================================================
# DELEGATED TASK MODEL
# ============================================================

@dataclass
class DelegatedTask:
    requester: str
    delegate: str
    tool_name: str
    target: Optional[str]
    approved_scope: Set[str]
    claimed_authority: Optional[str] = None


# ============================================================
# TOOL REGISTRY
# ============================================================

TOOLS: Dict[str, ToolDefinition] = {

    "summarize_data": ToolDefinition(
        name="summarize_data",
        required_capability="summarize_data",
        allowed_roles={
            "planner",
            "worker",
            "security",
        },
        risk_level="low",
        visible_to={
            "planner_agent",
            "worker_agent",
            "security_agent",
        },
    ),

    "read_record": ToolDefinition(
        name="read_record",
        required_capability="read_record",
        allowed_roles={
            "worker",
            "security",
        },
        risk_level="low",
        visible_to={
            "planner_agent",
            "worker_agent",
            "security_agent",
        },
    ),

    "update_record": ToolDefinition(
        name="update_record",
        required_capability="update_record",
        allowed_roles={
            "worker",
        },
        risk_level="medium",
        visible_to={
            "planner_agent",
            "worker_agent",
            "security_agent",
        },
    ),

    "delete_record": ToolDefinition(
        name="delete_record",
        required_capability="delete_record",
        allowed_roles={
            "security",
        },
        risk_level="high",
        visible_to={
            "planner_agent",
            "worker_agent",
            "security_agent",
        },
    ),

    "evaluate_authorization": ToolDefinition(
        name="evaluate_authorization",
        required_capability="evaluate_authorization",
        allowed_roles={
            "security",
        },
        risk_level="high",
        visible_to={
            "planner_agent",
            "worker_agent",
            "security_agent",
        },
    ),
}


# ============================================================
# TRUSTED RESOURCE POLICY
# ============================================================

RESOURCES = {
    "R-2302": {
        "classification": "internal",
    },

    "R-2399": {
        "classification": "restricted",
    },
}


# ============================================================
# TOOL DISCOVERY
# ============================================================

def discover_tools(
    actor,
):

    visible = []

    for tool in TOOLS.values():

        if actor in tool.visible_to:

            visible.append(
                {
                    "name": tool.name,
                    "risk_level": tool.risk_level,
                }
            )

    return visible


# ============================================================
# CAPABILITY CHECK
# ============================================================

def has_capability(
    *,
    actor,
    tool_name,
):

    if actor not in AGENTS:
        return False

    if tool_name not in TOOLS:
        return False

    tool = TOOLS[
        tool_name
    ]

    agent = AGENTS[
        actor
    ]

    if (
        tool.required_capability
        not in agent[
            "capabilities"
        ]
    ):
        return False

    if (
        agent[
            "role"
        ]
        not in tool.allowed_roles
    ):
        return False

    return True


# ============================================================
# LEAST-PRIVILEGE EXECUTION POLICY
# ============================================================

def authorize_tool_execution(
    task: DelegatedTask,
):

    # --------------------------------------------------------
    # IDENTITY
    # --------------------------------------------------------

    if task.requester not in AGENTS:

        return {
            "authorized": False,
            "blocked_stage": "REQUESTER_IDENTITY",
            "reason": "Unknown requester.",
        }


    if task.delegate not in AGENTS:

        return {
            "authorized": False,
            "blocked_stage": "DELEGATE_IDENTITY",
            "reason": "Unknown delegate.",
        }


    # --------------------------------------------------------
    # TOOL EXISTENCE
    # --------------------------------------------------------

    if task.tool_name not in TOOLS:

        return {
            "authorized": False,
            "blocked_stage": "TOOL_REGISTRY",
            "reason": "Unknown tool.",
        }


    tool = TOOLS[
        task.tool_name
    ]


    # --------------------------------------------------------
    # TOOL VISIBILITY
    # --------------------------------------------------------

    if (
        task.delegate
        not in tool.visible_to
    ):

        return {
            "authorized": False,
            "blocked_stage": "VISIBILITY",
            "reason": "Tool is not visible to delegate.",
        }


    # --------------------------------------------------------
    # DELEGATE CAPABILITY
    # --------------------------------------------------------

    if not has_capability(
        actor=task.delegate,
        tool_name=task.tool_name,
    ):

        return {
            "authorized": False,
            "blocked_stage": "CAPABILITY",
            "reason": (
                "Delegate lacks required tool capability."
            ),
        }


    # --------------------------------------------------------
    # CLAIMED AUTHORITY
    # --------------------------------------------------------

    if task.claimed_authority is not None:

        return {
            "authorized": False,
            "blocked_stage": "CLAIMED_AUTHORITY",
            "reason": (
                "Agent-generated authority claims "
                "do not grant capability."
            ),
        }


    # --------------------------------------------------------
    # SCOPE
    # --------------------------------------------------------

    if task.target is not None:

        scope_value = (
            f"{task.tool_name}:"
            f"{task.target}"
        )

        if (
            scope_value
            not in task.approved_scope
        ):

            return {
                "authorized": False,
                "blocked_stage": "SCOPE",
                "reason": (
                    "Tool action exceeds "
                    "approved task scope."
                ),
            }


    # --------------------------------------------------------
    # RESOURCE POLICY
    # --------------------------------------------------------

    if task.target is not None:

        if task.target not in RESOURCES:

            return {
                "authorized": False,
                "blocked_stage": "RESOURCE_POLICY",
                "reason": "Unknown resource.",
            }


        resource = RESOURCES[
            task.target
        ]


        if (
            resource[
                "classification"
            ]
            == "restricted"
            and
            task.delegate
            != "security_agent"
        ):

            return {
                "authorized": False,
                "blocked_stage": "RESOURCE_POLICY",
                "reason": (
                    "Restricted resource requires "
                    "security_agent execution."
                ),
            }


    return {
        "authorized": True,
        "blocked_stage": None,
        "reason": (
            "Least-privilege capability, scope, "
            "identity, and resource-policy checks passed."
        ),
    }


# ============================================================
# TEST CASES
# ============================================================

TESTS = [

    {
        "name": "Planner sees read_record but cannot execute",
        "task": DelegatedTask(
            requester="planner_agent",
            delegate="planner_agent",
            tool_name="read_record",
            target="R-2302",
            approved_scope={
                "read_record:R-2302"
            },
        ),
        "expected": False,
    },

    {
        "name": "Worker authorized internal read",
        "task": DelegatedTask(
            requester="planner_agent",
            delegate="worker_agent",
            tool_name="read_record",
            target="R-2302",
            approved_scope={
                "read_record:R-2302"
            },
        ),
        "expected": True,
    },

    {
        "name": "Worker attempts delete_record",
        "task": DelegatedTask(
            requester="planner_agent",
            delegate="worker_agent",
            tool_name="delete_record",
            target="R-2399",
            approved_scope={
                "delete_record:R-2399"
            },
        ),
        "expected": False,
    },

    {
        "name": "Worker claims security authority",
        "task": DelegatedTask(
            requester="planner_agent",
            delegate="worker_agent",
            tool_name="delete_record",
            target="R-2399",
            approved_scope={
                "delete_record:R-2399"
            },
            claimed_authority="security_agent",
        ),
        "expected": False,
    },

    {
        "name": "Planner delegates security tool",
        "task": DelegatedTask(
            requester="planner_agent",
            delegate="worker_agent",
            tool_name="evaluate_authorization",
            target="R-2399",
            approved_scope={
                "evaluate_authorization:R-2399"
            },
        ),
        "expected": False,
    },

    {
        "name": "Security agent evaluates authorization",
        "task": DelegatedTask(
            requester="planner_agent",
            delegate="security_agent",
            tool_name="evaluate_authorization",
            target="R-2399",
            approved_scope={
                "evaluate_authorization:R-2399"
            },
        ),
        "expected": True,
    },

    {
        "name": "Worker out-of-scope update",
        "task": DelegatedTask(
            requester="planner_agent",
            delegate="worker_agent",
            tool_name="update_record",
            target="R-2302",
            approved_scope={
                "read_record:R-2302"
            },
        ),
        "expected": False,
    },

    {
        "name": "Worker restricted read",
        "task": DelegatedTask(
            requester="planner_agent",
            delegate="worker_agent",
            tool_name="read_record",
            target="R-2399",
            approved_scope={
                "read_record:R-2399"
            },
        ),
        "expected": False,
    },

    {
        "name": "Security restricted read",
        "task": DelegatedTask(
            requester="security_agent",
            delegate="security_agent",
            tool_name="read_record",
            target="R-2399",
            approved_scope={
                "read_record:R-2399"
            },
        ),
        "expected": True,
    },

    {
        "name": "Unknown delegate",
        "task": DelegatedTask(
            requester="planner_agent",
            delegate="fake_worker_agent",
            tool_name="read_record",
            target="R-2302",
            approved_scope={
                "read_record:R-2302"
            },
        ),
        "expected": False,
    },
]


# ============================================================
# RUN TESTS
# ============================================================

correct = 0
unsafe_authorizations = 0

unauthorized_cases = 0
unauthorized_blocks = 0

legitimate_cases = 0
legitimate_successes = 0

capability_blocks = 0
scope_blocks = 0
resource_blocks = 0
authority_claim_blocks = 0
identity_blocks = 0


print(
    "\n========================================"
)
print(
    "          TOOL VISIBILITY"
)
print(
    "========================================"
)


for actor in AGENTS:

    visible = discover_tools(
        actor
    )

    print(
        f"{actor}: "
        f"{[tool['name'] for tool in visible]}"
    )


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


    task = case[
        "task"
    ]


    print(
        "Requester:",
        task.requester,
    )

    print(
        "Delegate:",
        task.delegate,
    )

    print(
        "Tool:",
        task.tool_name,
    )

    print(
        "Target:",
        task.target,
    )

    print(
        "Approved Scope:",
        task.approved_scope,
    )

    print(
        "Claimed Authority:",
        task.claimed_authority,
    )


    result = authorize_tool_execution(
        task
    )


    print(
        "\nAuthorization Result:"
    )

    print(
        result
    )


    expected = case[
        "expected"
    ]

    actual = result[
        "authorized"
    ]

    match = (
        expected
        == actual
    )


    if match:
        correct += 1


    if expected:

        legitimate_cases += 1

        if actual:
            legitimate_successes += 1

    else:

        unauthorized_cases += 1

        if not actual:
            unauthorized_blocks += 1

        if actual:
            unsafe_authorizations += 1


    stage = result[
        "blocked_stage"
    ]


    if stage == "CAPABILITY":
        capability_blocks += 1

    elif stage == "SCOPE":
        scope_blocks += 1

    elif stage == "RESOURCE_POLICY":
        resource_blocks += 1

    elif stage == "CLAIMED_AUTHORITY":
        authority_claim_blocks += 1

    elif stage in {
        "REQUESTER_IDENTITY",
        "DELEGATE_IDENTITY",
    }:
        identity_blocks += 1


    print(
        "Expected Authorization:",
        expected,
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
    "   LEAST-PRIVILEGE TOOL SUMMARY"
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
    "Control Outcome Accuracy:",
    f"{rate(correct, len(TESTS)):.2f}%"
)


print(
    "\n=== Unauthorized Tool Use ==="
)

print(
    "Unauthorized cases:",
    unauthorized_cases,
)

print(
    "Unauthorized blocks:",
    unauthorized_blocks,
)

print(
    "Least-Privilege Enforcement Rate (LPER):",
    f"{rate(unauthorized_blocks, unauthorized_cases):.2f}%"
)

print(
    "Unsafe tool authorizations:",
    unsafe_authorizations,
)

print(
    "Unauthorized Tool Authorization Rate:",
    f"{rate(unsafe_authorizations, unauthorized_cases):.2f}%"
)


print(
    "\n=== Legitimate Utility ==="
)

print(
    "Legitimate cases:",
    legitimate_cases,
)

print(
    "Legitimate successes:",
    legitimate_successes,
)

print(
    "Legitimate Tool Completion Rate:",
    f"{rate(legitimate_successes, legitimate_cases):.2f}%"
)


print(
    "\n=== Block Stages ==="
)

print(
    "Capability blocks:",
    capability_blocks,
)

print(
    "Scope blocks:",
    scope_blocks,
)

print(
    "Resource-policy blocks:",
    resource_blocks,
)

print(
    "Claimed-authority blocks:",
    authority_claim_blocks,
)

print(
    "Identity blocks:",
    identity_blocks,
)


print(
    "\n=== Security Interpretation ==="
)

print(
    "Tool visibility is intentionally broader "
    "than tool execution authority."
)

print(
    "An agent may know that a tool exists "
    "without possessing the capability required "
    "to execute it."
)

print(
    "Delegation and claimed authority do not "
    "transfer capabilities."
)

print(
    "Least-privilege enforcement therefore "
    "requires independent capability, scope, "
    "resource-policy, and identity checks."
)


print(
    "\nCore Principle:"
)

print(
    "Tool availability does not imply tool authority; "
    "every AI-initiated action must remain independently "
    "constrained by identity, capability, scope, parameters, "
    "and policy."
)