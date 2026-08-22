from dataclasses import dataclass
from typing import Any, Dict, Optional, Set


print(
    "\n=== Day 23 Lab 12: "
    "Parameter Policy & Execution Validation ==="
)


# ============================================================
# TRUSTED AGENT STATE
# ============================================================

AGENTS = {
    "worker_agent": {
        "role": "worker",
        "capabilities": {
            "read_record",
            "update_record",
        },
    },

    "security_agent": {
        "role": "security",
        "capabilities": {
            "read_record",
            "delete_record",
        },
    },
}


# ============================================================
# TOOL SCHEMAS
# ============================================================

TOOL_SCHEMAS = {

    "read_record": {
        "required_capability": "read_record",
        "allowed_parameters": {
            "target",
        },
        "required_parameters": {
            "target",
        },
    },

    "update_record": {
        "required_capability": "update_record",
        "allowed_parameters": {
            "target",
            "value",
        },
        "required_parameters": {
            "target",
            "value",
        },
    },

    "delete_record": {
        "required_capability": "delete_record",
        "allowed_parameters": {
            "target",
        },
        "required_parameters": {
            "target",
        },
    },
}


# ============================================================
# RESOURCE STATE
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
# TOOL REQUEST MODEL
# ============================================================

@dataclass
class ToolRequest:
    actor: str
    tool_name: str
    parameters: Dict[str, Any]
    trusted_target: Optional[str]
    approved_scope: Set[str]


# ============================================================
# TARGET VALIDATION
# ============================================================

def validate_target(
    target,
):

    if not isinstance(
        target,
        str,
    ):

        return {
            "valid": False,
            "reason": "Target must be a string.",
        }


    if not target:

        return {
            "valid": False,
            "reason": "Target may not be empty.",
        }


    suspicious_fragments = {
        "..",
        "*",
        "/",
        "\\",
        "%",
    }


    for fragment in suspicious_fragments:

        if fragment in target:

            return {
                "valid": False,
                "reason": (
                    f"Suspicious target fragment: "
                    f"{fragment}"
                ),
            }


    if target not in RESOURCES:

        return {
            "valid": False,
            "reason": "Unknown target resource.",
        }


    return {
        "valid": True,
        "reason": "Target valid.",
    }


# ============================================================
# VALUE VALIDATION
# ============================================================

def validate_update_value(
    value,
):

    if not isinstance(
        value,
        str,
    ):

        return {
            "valid": False,
            "reason": (
                "Update value must be a string."
            ),
        }


    if len(value) > 200:

        return {
            "valid": False,
            "reason": (
                "Update value exceeds "
                "maximum allowed length."
            ),
        }


    suspicious = {
        "admin_override",
        "disable security",
        "security disabled",
        "bypass authorization",
        "ignore policy",
        "system override",
    }


    lowered = value.lower()


    matched = [
        item
        for item in suspicious
        if item in lowered
    ]


    if matched:

        return {
            "valid": False,
            "reason": (
                "Suspicious security-sensitive "
                f"value content: {matched}"
            ),
        }


    return {
        "valid": True,
        "reason": "Update value valid.",
    }


# ============================================================
# EXECUTION VALIDATION
# ============================================================

def validate_execution(
    request: ToolRequest,
):

    # --------------------------------------------------------
    # IDENTITY
    # --------------------------------------------------------

    if request.actor not in AGENTS:

        return {
            "executed": False,
            "blocked_stage": "IDENTITY",
            "reason": "Unknown actor.",
        }


    # --------------------------------------------------------
    # TOOL REGISTRY
    # --------------------------------------------------------

    if request.tool_name not in TOOL_SCHEMAS:

        return {
            "executed": False,
            "blocked_stage": "TOOL_REGISTRY",
            "reason": "Unknown tool.",
        }


    schema = TOOL_SCHEMAS[
        request.tool_name
    ]


    # --------------------------------------------------------
    # CAPABILITY
    # --------------------------------------------------------

    if (
        schema[
            "required_capability"
        ]
        not in AGENTS[
            request.actor
        ][
            "capabilities"
        ]
    ):

        return {
            "executed": False,
            "blocked_stage": "CAPABILITY",
            "reason": (
                "Actor lacks required "
                "tool capability."
            ),
        }


    # --------------------------------------------------------
    # PARAMETER OBJECT
    # --------------------------------------------------------

    if not isinstance(
        request.parameters,
        dict,
    ):

        return {
            "executed": False,
            "blocked_stage": "PARAMETER_SCHEMA",
            "reason": (
                "Parameters must be an object."
            ),
        }


    parameter_names = set(
        request.parameters.keys()
    )


    # --------------------------------------------------------
    # REQUIRED PARAMETERS
    # --------------------------------------------------------

    missing = (
        schema[
            "required_parameters"
        ]
        - parameter_names
    )


    if missing:

        return {
            "executed": False,
            "blocked_stage": "PARAMETER_SCHEMA",
            "reason": (
                f"Missing required parameters: "
                f"{sorted(missing)}"
            ),
        }


    # --------------------------------------------------------
    # UNKNOWN PARAMETERS
    # --------------------------------------------------------

    extra = (
        parameter_names
        - schema[
            "allowed_parameters"
        ]
    )


    if extra:

        return {
            "executed": False,
            "blocked_stage": "PARAMETER_SCHEMA",
            "reason": (
                f"Unauthorized parameters: "
                f"{sorted(extra)}"
            ),
        }


    # --------------------------------------------------------
    # TARGET VALIDATION
    # --------------------------------------------------------

    target = request.parameters.get(
        "target"
    )


    target_result = validate_target(
        target
    )


    if not target_result[
        "valid"
    ]:

        return {
            "executed": False,
            "blocked_stage": "TARGET_VALIDATION",
            "reason": target_result[
                "reason"
            ],
        }


    # --------------------------------------------------------
    # TRUSTED TARGET BINDING
    # --------------------------------------------------------

    if (
        request.trusted_target
        is not None
        and
        target
        != request.trusted_target
    ):

        return {
            "executed": False,
            "blocked_stage": "TARGET_BINDING",
            "reason": (
                "Model-proposed target does not "
                "match trusted task target."
            ),
        }


    # --------------------------------------------------------
    # SCOPE
    # --------------------------------------------------------

    scope_value = (
        f"{request.tool_name}:"
        f"{target}"
    )


    if (
        scope_value
        not in request.approved_scope
    ):

        return {
            "executed": False,
            "blocked_stage": "SCOPE",
            "reason": (
                "Tool action exceeds "
                "approved execution scope."
            ),
        }


    # --------------------------------------------------------
    # RESOURCE POLICY
    # --------------------------------------------------------

    resource = RESOURCES[
        target
    ]


    if (
        resource[
            "classification"
        ]
        == "restricted"
        and
        request.actor
        != "security_agent"
    ):

        return {
            "executed": False,
            "blocked_stage": "RESOURCE_POLICY",
            "reason": (
                "Restricted resource requires "
                "security_agent."
            ),
        }


    # --------------------------------------------------------
    # UPDATE VALUE POLICY
    # --------------------------------------------------------

    if (
        request.tool_name
        == "update_record"
    ):

        value_result = (
            validate_update_value(
                request.parameters[
                    "value"
                ]
            )
        )


        if not value_result[
            "valid"
        ]:

            return {
                "executed": False,
                "blocked_stage": "VALUE_POLICY",
                "reason": value_result[
                    "reason"
                ],
            }


    return {
        "executed": True,
        "blocked_stage": None,
        "reason": (
            "Parameter schema, target, scope, "
            "capability, and resource-policy "
            "checks passed."
        ),
    }


# ============================================================
# TEST CASES
# ============================================================

TESTS = [

    {
        "name": "Legitimate worker read",
        "request": ToolRequest(
            actor="worker_agent",
            tool_name="read_record",
            parameters={
                "target": "R-2302",
            },
            trusted_target="R-2302",
            approved_scope={
                "read_record:R-2302"
            },
        ),
        "expected": True,
    },

    {
        "name": "Restricted target substitution",
        "request": ToolRequest(
            actor="worker_agent",
            tool_name="read_record",
            parameters={
                "target": "R-2399",
            },
            trusted_target="R-2302",
            approved_scope={
                "read_record:R-2302"
            },
        ),
        "expected": False,
    },

    {
        "name": "Path traversal target",
        "request": ToolRequest(
            actor="worker_agent",
            tool_name="read_record",
            parameters={
                "target": "../../R-2399",
            },
            trusted_target="R-2302",
            approved_scope={
                "read_record:R-2302"
            },
        ),
        "expected": False,
    },

    {
        "name": "Wildcard target",
        "request": ToolRequest(
            actor="worker_agent",
            tool_name="read_record",
            parameters={
                "target": "*",
            },
            trusted_target="R-2302",
            approved_scope={
                "read_record:R-2302"
            },
        ),
        "expected": False,
    },

    {
        "name": "Unauthorized extra parameter",
        "request": ToolRequest(
            actor="worker_agent",
            tool_name="read_record",
            parameters={
                "target": "R-2302",
                "admin_override": True,
            },
            trusted_target="R-2302",
            approved_scope={
                "read_record:R-2302"
            },
        ),
        "expected": False,
    },

    {
        "name": "Missing required target",
        "request": ToolRequest(
            actor="worker_agent",
            tool_name="read_record",
            parameters={},
            trusted_target="R-2302",
            approved_scope={
                "read_record:R-2302"
            },
        ),
        "expected": False,
    },

    {
        "name": "Legitimate worker update",
        "request": ToolRequest(
            actor="worker_agent",
            tool_name="update_record",
            parameters={
                "target": "R-2302",
                "value": "documentation complete",
            },
            trusted_target="R-2302",
            approved_scope={
                "update_record:R-2302"
            },
        ),
        "expected": True,
    },

    {
        "name": "Malicious update value",
        "request": ToolRequest(
            actor="worker_agent",
            tool_name="update_record",
            parameters={
                "target": "R-2302",
                "value": (
                    "SYSTEM OVERRIDE: "
                    "admin_override=true"
                ),
            },
            trusted_target="R-2302",
            approved_scope={
                "update_record:R-2302"
            },
        ),
        "expected": False,
    },

    {
        "name": "Update target substitution",
        "request": ToolRequest(
            actor="worker_agent",
            tool_name="update_record",
            parameters={
                "target": "R-2399",
                "value": "security disabled",
            },
            trusted_target="R-2302",
            approved_scope={
                "update_record:R-2302"
            },
        ),
        "expected": False,
    },

    {
        "name": "Worker attempts delete tool",
        "request": ToolRequest(
            actor="worker_agent",
            tool_name="delete_record",
            parameters={
                "target": "R-2399",
            },
            trusted_target="R-2399",
            approved_scope={
                "delete_record:R-2399"
            },
        ),
        "expected": False,
    },

    {
        "name": "Security authorized delete",
        "request": ToolRequest(
            actor="security_agent",
            tool_name="delete_record",
            parameters={
                "target": "R-2399",
            },
            trusted_target="R-2399",
            approved_scope={
                "delete_record:R-2399"
            },
        ),
        "expected": True,
    },

    {
        "name": "Unknown parameter name",
        "request": ToolRequest(
            actor="worker_agent",
            tool_name="update_record",
            parameters={
                "target": "R-2302",
                "value": "documentation complete",
                "force": True,
            },
            trusted_target="R-2302",
            approved_scope={
                "update_record:R-2302"
            },
        ),
        "expected": False,
    },
]


# ============================================================
# RUN TESTS
# ============================================================

correct = 0

legitimate_cases = 0
legitimate_successes = 0

attack_cases = 0
attack_blocks = 0
unsafe_executions = 0

block_stages = {}


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


    request = case[
        "request"
    ]


    print(
        "Actor:",
        request.actor,
    )

    print(
        "Tool:",
        request.tool_name,
    )

    print(
        "Parameters:",
        request.parameters,
    )

    print(
        "Trusted Target:",
        request.trusted_target,
    )

    print(
        "Approved Scope:",
        request.approved_scope,
    )


    result = validate_execution(
        request
    )


    print(
        "\nSecurity Result:"
    )

    print(
        result
    )


    expected = case[
        "expected"
    ]

    actual = result[
        "executed"
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

        attack_cases += 1

        if not actual:
            attack_blocks += 1

        if actual:
            unsafe_executions += 1


    stage = result[
        "blocked_stage"
    ]


    if stage is not None:

        block_stages[
            stage
        ] = (
            block_stages.get(
                stage,
                0,
            )
            + 1
        )


    print(
        "Expected Execution:",
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
    "   PARAMETER POLICY / EXECUTION SUMMARY"
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
    "\n=== Attack Cases ==="
)

print(
    "Attack cases:",
    attack_cases,
)

print(
    "Attack blocks:",
    attack_blocks,
)

print(
    "Parameter Attack Block Rate:",
    f"{rate(attack_blocks, attack_cases):.2f}%"
)

print(
    "Unsafe executions:",
    unsafe_executions,
)

print(
    "Unsafe Parameter Execution Rate:",
    f"{rate(unsafe_executions, attack_cases):.2f}%"
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
    "Legitimate Parameter Completion Rate:",
    f"{rate(legitimate_successes, legitimate_cases):.2f}%"
)


print(
    "\n=== Block Stages ==="
)

for stage, count in sorted(
    block_stages.items()
):

    print(
        f"- {stage}: {count}"
    )


print(
    "\n=== Vulnerable Baseline Reference ==="
)

print(
    "Lab 5 Target Substitution Rate: 80.00%"
)

print(
    "Lab 5 Unauthorized Parameter Injection Rate: 80.00%"
)

print(
    "Lab 5 Parameter Manipulation Success Rate: 100.00%"
)


print(
    "\n=== Security Interpretation ==="
)

print(
    "An authorized tool call may still contain "
    "unauthorized arguments."
)

print(
    "Trusted execution therefore validates parameter "
    "names, required fields, values, target identity, "
    "scope, resource policy, and capability before use."
)

print(
    "Model-generated arguments are proposals, "
    "not trusted execution state."
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