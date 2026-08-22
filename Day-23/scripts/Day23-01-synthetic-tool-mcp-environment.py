from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import uuid


print(
    "\n=== Day 23 Lab 1: "
    "Synthetic Tool / MCP Environment ==="
)


# ============================================================
# TRUSTED AGENT STATE
# ============================================================

AGENTS = {
    "planner_agent": {
        "role": "planner",
        "capabilities": {
            "discover_tools",
            "request_task",
        },
    },

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
            "evaluate_authorization",
            "delete_record",
        },
    },
}


# ============================================================
# TOOL SERVER MODEL
# ============================================================

@dataclass
class ToolServer:
    server_id: str
    trusted_name: str
    trust_level: str
    enabled: bool = True


# ============================================================
# TOOL MODEL
# ============================================================

@dataclass
class ToolDefinition:
    tool_id: str
    server_id: str
    name: str
    description: str
    required_capability: str
    allowed_roles: Set[str]
    risk_level: str
    schema: Dict
    active: bool = True


# ============================================================
# TOOL CALL MODEL
# ============================================================

@dataclass
class ToolCall:
    call_id: str
    actor: str
    tool_name: str
    parameters: Dict
    trusted_task_scope: Set[str]
    approved: bool = False
    approval_id: Optional[str] = None


# ============================================================
# AUDIT EVENT MODEL
# ============================================================

@dataclass
class AuditEvent:
    event_type: str
    actor: str
    target: str
    success: bool
    reason: str
    metadata: Dict = field(default_factory=dict)


AUDIT_LOG: List[AuditEvent] = []


def audit(
    *,
    event_type,
    actor,
    target,
    success,
    reason,
    metadata=None,
):

    AUDIT_LOG.append(
        AuditEvent(
            event_type=event_type,
            actor=actor,
            target=target,
            success=success,
            reason=reason,
            metadata=metadata or {},
        )
    )


# ============================================================
# SYNTHETIC TOOL SERVERS
# ============================================================

TOOL_SERVERS = {
    "trusted_internal_server": ToolServer(
        server_id="trusted_internal_server",
        trusted_name="Internal Operations MCP Server",
        trust_level="trusted",
    ),

    "analytics_server": ToolServer(
        server_id="analytics_server",
        trusted_name="Analytics MCP Server",
        trust_level="trusted",
    ),

    "external_helper_server": ToolServer(
        server_id="external_helper_server",
        trusted_name="External Helper MCP Server",
        trust_level="untrusted",
    ),
}


# ============================================================
# TOOL REGISTRY
# ============================================================

TOOLS = {

    "read_record": ToolDefinition(
        tool_id="TOOL-" + str(uuid.uuid4()),
        server_id="trusted_internal_server",
        name="read_record",
        description=(
            "Read an authorized synthetic record."
        ),
        required_capability="read_record",
        allowed_roles={
            "worker",
            "security",
        },
        risk_level="low",
        schema={
            "target": {
                "type": "string",
                "required": True,
            }
        },
    ),

    "update_record": ToolDefinition(
        tool_id="TOOL-" + str(uuid.uuid4()),
        server_id="trusted_internal_server",
        name="update_record",
        description=(
            "Update an authorized synthetic record."
        ),
        required_capability="update_record",
        allowed_roles={
            "worker",
        },
        risk_level="medium",
        schema={
            "target": {
                "type": "string",
                "required": True,
            },
            "value": {
                "type": "string",
                "required": True,
            },
        },
    ),

    "delete_record": ToolDefinition(
        tool_id="TOOL-" + str(uuid.uuid4()),
        server_id="trusted_internal_server",
        name="delete_record",
        description=(
            "Delete a restricted synthetic record."
        ),
        required_capability="delete_record",
        allowed_roles={
            "security",
        },
        risk_level="high",
        schema={
            "target": {
                "type": "string",
                "required": True,
            }
        },
    ),

    "summarize_data": ToolDefinition(
        tool_id="TOOL-" + str(uuid.uuid4()),
        server_id="analytics_server",
        name="summarize_data",
        description=(
            "Summarize non-sensitive synthetic data."
        ),
        required_capability="discover_tools",
        allowed_roles={
            "planner",
            "worker",
            "security",
        },
        risk_level="low",
        schema={
            "dataset": {
                "type": "string",
                "required": True,
            }
        },
    ),

    "external_lookup": ToolDefinition(
        tool_id="TOOL-" + str(uuid.uuid4()),
        server_id="external_helper_server",
        name="external_lookup",
        description=(
            "Retrieve untrusted external helper content."
        ),
        required_capability="discover_tools",
        allowed_roles={
            "planner",
            "worker",
            "security",
        },
        risk_level="medium",
        schema={
            "query": {
                "type": "string",
                "required": True,
            }
        },
    ),
}


# ============================================================
# SYNTHETIC RESOURCE STORE
# ============================================================

RECORDS = {
    "R-2301": {
        "classification": "internal",
        "owner": "planner_agent",
        "content": "Synthetic planning record.",
    },

    "R-2302": {
        "classification": "internal",
        "owner": "worker_agent",
        "content": "Synthetic worker record.",
    },

    "R-2399": {
        "classification": "restricted",
        "owner": "security_agent",
        "content": "Synthetic restricted security record.",
    },
}


# ============================================================
# TOOL DISCOVERY
# ============================================================

def discover_tools(
    actor,
):

    if actor not in AGENTS:

        return {
            "success": False,
            "tools": [],
            "reason": "Unknown agent.",
        }


    visible = []


    for tool in TOOLS.values():

        if not tool.active:
            continue


        server = TOOL_SERVERS[
            tool.server_id
        ]


        if not server.enabled:
            continue


        visible.append(
            {
                "name": tool.name,
                "server_id": tool.server_id,
                "server_trust": server.trust_level,
                "description": tool.description,
                "risk_level": tool.risk_level,
            }
        )


    audit(
        event_type="tool_discovery",
        actor=actor,
        target="tool_registry",
        success=True,
        reason="Available tools returned.",
        metadata={
            "tool_count": len(visible),
        },
    )


    return {
        "success": True,
        "tools": visible,
        "reason": "Tool discovery successful.",
    }


# ============================================================
# CAPABILITY CHECK
# ============================================================

def agent_can_use_tool(
    *,
    actor,
    tool_name,
):

    if actor not in AGENTS:

        return False


    if tool_name not in TOOLS:

        return False


    agent = AGENTS[
        actor
    ]


    tool = TOOLS[
        tool_name
    ]


    server = TOOL_SERVERS[
        tool.server_id
    ]


    if not server.enabled:

        return False


    if not tool.active:

        return False


    if (
        tool.required_capability
        not in agent["capabilities"]
    ):

        return False


    if (
        agent["role"]
        not in tool.allowed_roles
    ):

        return False


    return True


# ============================================================
# PARAMETER VALIDATION
# ============================================================

def validate_parameters(
    *,
    tool_name,
    parameters,
):

    if tool_name not in TOOLS:

        return {
            "valid": False,
            "reason": "Unknown tool.",
        }


    schema = TOOLS[
        tool_name
    ].schema


    for parameter_name, rules in schema.items():

        if (
            rules.get(
                "required",
                False,
            )
            and
            parameter_name
            not in parameters
        ):

            return {
                "valid": False,
                "reason": (
                    f"Missing required parameter: "
                    f"{parameter_name}"
                ),
            }


        if parameter_name in parameters:

            expected_type = rules.get(
                "type"
            )

            value = parameters[
                parameter_name
            ]


            if (
                expected_type == "string"
                and
                not isinstance(
                    value,
                    str,
                )
            ):

                return {
                    "valid": False,
                    "reason": (
                        f"Parameter {parameter_name} "
                        f"must be a string."
                    ),
                }


    unknown_parameters = (
        set(parameters.keys())
        - set(schema.keys())
    )


    if unknown_parameters:

        return {
            "valid": False,
            "reason": (
                "Unknown parameters: "
                f"{sorted(unknown_parameters)}"
            ),
        }


    return {
        "valid": True,
        "reason": "Parameters valid.",
    }


# ============================================================
# BASIC TRUSTED TOOL EXECUTION
# ============================================================

def execute_tool(
    call: ToolCall,
):

    # --------------------------------------------------------
    # IDENTITY
    # --------------------------------------------------------

    if call.actor not in AGENTS:

        return {
            "executed": False,
            "blocked_stage": "IDENTITY",
            "reason": "Unknown agent.",
        }


    # --------------------------------------------------------
    # TOOL
    # --------------------------------------------------------

    if call.tool_name not in TOOLS:

        return {
            "executed": False,
            "blocked_stage": "TOOL_REGISTRY",
            "reason": "Unknown tool.",
        }


    tool = TOOLS[
        call.tool_name
    ]


    server = TOOL_SERVERS[
        tool.server_id
    ]


    if not server.enabled:

        return {
            "executed": False,
            "blocked_stage": "SERVER_TRUST",
            "reason": "Tool server disabled.",
        }


    # --------------------------------------------------------
    # CAPABILITY
    # --------------------------------------------------------

    if not agent_can_use_tool(
        actor=call.actor,
        tool_name=call.tool_name,
    ):

        return {
            "executed": False,
            "blocked_stage": "CAPABILITY",
            "reason": (
                "Agent is not authorized "
                "to use this tool."
            ),
        }


    # --------------------------------------------------------
    # PARAMETERS
    # --------------------------------------------------------

    parameter_result = (
        validate_parameters(
            tool_name=call.tool_name,
            parameters=call.parameters,
        )
    )


    if not parameter_result[
        "valid"
    ]:

        return {
            "executed": False,
            "blocked_stage": "PARAMETER_VALIDATION",
            "reason": parameter_result[
                "reason"
            ],
        }


    # --------------------------------------------------------
    # TASK SCOPE
    # --------------------------------------------------------

    target = (
        call.parameters.get(
            "target"
        )
    )


    if target is not None:

        scope_value = (
            f"{call.tool_name}:"
            f"{target}"
        )


        if (
            scope_value
            not in call.trusted_task_scope
        ):

            return {
                "executed": False,
                "blocked_stage": "SCOPE",
                "reason": (
                    "Tool action exceeds "
                    "trusted task scope."
                ),
            }


    # --------------------------------------------------------
    # RESOURCE POLICY
    # --------------------------------------------------------

    if target is not None:

        if target not in RECORDS:

            return {
                "executed": False,
                "blocked_stage": "RESOURCE_POLICY",
                "reason": "Unknown target.",
            }


        record = RECORDS[
            target
        ]


        if (
            record[
                "classification"
            ]
            == "restricted"
            and
            call.actor
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
    # APPROVAL
    # --------------------------------------------------------

    if (
        tool.risk_level
        == "high"
        and
        not call.approved
    ):

        return {
            "executed": False,
            "blocked_stage": "APPROVAL",
            "reason": (
                "High-risk tool requires "
                "trusted approval."
            ),
        }


    # --------------------------------------------------------
    # EXECUTE SYNTHETIC TOOL
    # --------------------------------------------------------

    audit(
        event_type="tool_execution",
        actor=call.actor,
        target=call.tool_name,
        success=True,
        reason="Trusted tool controls passed.",
        metadata={
            "parameters": call.parameters,
        },
    )


    return {
        "executed": True,
        "blocked_stage": None,
        "reason": (
            "Trusted tool controls passed."
        ),
    }


# ============================================================
# LAB TESTS
# ============================================================

print(
    "\n========================================"
)
print(
    "Test 1 — Tool Discovery"
)
print(
    "========================================"
)


discovery = discover_tools(
    "planner_agent"
)

print(
    "Success:",
    discovery[
        "success"
    ],
)

print(
    "Visible Tool Count:",
    len(
        discovery[
            "tools"
        ]
    ),
)


for tool in discovery[
    "tools"
]:

    print(
        "-",
        tool,
    )


print(
    "\n========================================"
)
print(
    "Test 2 — Capability Separation"
)
print(
    "========================================"
)


print(
    "Planner can read_record:",
    agent_can_use_tool(
        actor="planner_agent",
        tool_name="read_record",
    ),
)

print(
    "Worker can read_record:",
    agent_can_use_tool(
        actor="worker_agent",
        tool_name="read_record",
    ),
)

print(
    "Worker can delete_record:",
    agent_can_use_tool(
        actor="worker_agent",
        tool_name="delete_record",
    ),
)

print(
    "Security can delete_record:",
    agent_can_use_tool(
        actor="security_agent",
        tool_name="delete_record",
    ),
)


print(
    "\n========================================"
)
print(
    "Test 3 — Legitimate Scoped Read"
)
print(
    "========================================"
)


result = execute_tool(
    ToolCall(
        call_id="CALL-" + str(uuid.uuid4()),
        actor="worker_agent",
        tool_name="read_record",
        parameters={
            "target": "R-2302",
        },
        trusted_task_scope={
            "read_record:R-2302"
        },
    )
)

print(
    result
)


print(
    "\n========================================"
)
print(
    "Test 4 — Planner Unauthorized Read"
)
print(
    "========================================"
)


result = execute_tool(
    ToolCall(
        call_id="CALL-" + str(uuid.uuid4()),
        actor="planner_agent",
        tool_name="read_record",
        parameters={
            "target": "R-2302",
        },
        trusted_task_scope={
            "read_record:R-2302"
        },
    )
)

print(
    result
)


print(
    "\n========================================"
)
print(
    "Test 5 — Out-of-Scope Target"
)
print(
    "========================================"
)


result = execute_tool(
    ToolCall(
        call_id="CALL-" + str(uuid.uuid4()),
        actor="worker_agent",
        tool_name="read_record",
        parameters={
            "target": "R-2399",
        },
        trusted_task_scope={
            "read_record:R-2302"
        },
    )
)

print(
    result
)


print(
    "\n========================================"
)
print(
    "Test 6 — High-Risk Tool Without Approval"
)
print(
    "========================================"
)


result = execute_tool(
    ToolCall(
        call_id="CALL-" + str(uuid.uuid4()),
        actor="security_agent",
        tool_name="delete_record",
        parameters={
            "target": "R-2399",
        },
        trusted_task_scope={
            "delete_record:R-2399"
        },
        approved=False,
    )
)

print(
    result
)


print(
    "\n========================================"
)
print(
    "Test 7 — High-Risk Tool With Approval"
)
print(
    "========================================"
)


result = execute_tool(
    ToolCall(
        call_id="CALL-" + str(uuid.uuid4()),
        actor="security_agent",
        tool_name="delete_record",
        parameters={
            "target": "R-2399",
        },
        trusted_task_scope={
            "delete_record:R-2399"
        },
        approved=True,
        approval_id="APPROVAL-DAY23-001",
    )
)

print(
    result
)


print(
    "\n========================================"
)
print(
    "Test 8 — Parameter Validation"
)
print(
    "========================================"
)


result = execute_tool(
    ToolCall(
        call_id="CALL-" + str(uuid.uuid4()),
        actor="worker_agent",
        tool_name="read_record",
        parameters={
            "target": "R-2302",
            "unexpected_parameter": "malicious-value",
        },
        trusted_task_scope={
            "read_record:R-2302"
        },
    )
)

print(
    result
)


print(
    "\n========================================"
)
print(
    "      DAY 23 LAB 1 SUMMARY"
)
print(
    "========================================"
)


print(
    "Tool servers:",
    len(
        TOOL_SERVERS
    ),
)

print(
    "Registered tools:",
    len(
        TOOLS
    ),
)

print(
    "Synthetic records:",
    len(
        RECORDS
    ),
)


print(
    "\nSecurity Properties:"
)

print(
    "- Tool discovery does not grant tool authority."
)

print(
    "- Tool server identity is stored outside model text."
)

print(
    "- Tool capabilities are explicitly assigned to agents."
)

print(
    "- Tool parameters are validated against trusted schemas."
)

print(
    "- Tool execution is restricted by trusted task scope."
)

print(
    "- Restricted resources require appropriate agent authority."
)

print(
    "- High-risk tools require trusted approval."
)

print(
    "- Tool execution is auditable."
)


print(
    "\nIntentional Next-Step Weakness:"
)

print(
    "Lab 1 trusts the registered tool descriptions as metadata."
)

print(
    "Lab 2 will place an LLM-driven tool selector in front of "
    "the environment and measure whether tool availability "
    "is mistaken for tool authority."
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


print(
    "\n========================================"
)
print(
    "              AUDIT LOG"
)
print(
    "========================================"
)


for index, event in enumerate(
    AUDIT_LOG,
    start=1,
):

    print(
        f"{index}. "
        f"type={event.event_type} "
        f"actor={event.actor} "
        f"target={event.target} "
        f"success={event.success} "
        f"reason={event.reason}"
    )