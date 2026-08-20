from dataclasses import dataclass
from typing import Optional, Set


print(
    "\n=== Day 22 Lab 10: "
    "Independent Multi-Agent Authorization Policy ==="
)


# ============================================================
# TRUSTED AGENT STATE
# ============================================================

AGENTS = {
    "planner_agent": {
        "role": "planner",
        "capabilities": {
            "request_task",
            "read_project_context",
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
            "evaluate_authorization",
            "approve_high_impact_action",
	    "delete_record",
        },
    },
}


# ============================================================
# RECORDS
# ============================================================

RECORDS = {
    "R-2201": {
        "owner": "planner_agent",
        "classification": "internal",
    },

    "R-2202": {
        "owner": "worker_agent",
        "classification": "internal",
    },

    "R-2299": {
        "owner": "security_agent",
        "classification": "restricted",
    },
}


# ============================================================
# DELEGATED ACTION
# ============================================================

@dataclass
class DelegatedAction:
    requester: str
    delegator: str
    delegate: str
    action: str
    target: str
    approved_scope: Set[str]
    approval_id: Optional[str] = None


# ============================================================
# TRUSTED APPROVALS
# ============================================================

VALID_APPROVALS = {
    "APPROVAL-DELETE-R2299": {
        "actor": "security_agent",
        "action": "delete_record",
        "target": "R-2299",
        "delegate": "security_agent",
    }
}


# ============================================================
# AUTHORIZATION ENGINE
# ============================================================

def authorize(
    request: DelegatedAction,
):

    # --------------------------------------------------------
    # 1. KNOWN IDENTITIES
    # --------------------------------------------------------

    for agent_id in {
        request.requester,
        request.delegator,
        request.delegate,
    }:

        if agent_id not in AGENTS:

            return {
                "authorized": False,
                "stage": "IDENTITY",
                "reason": f"Unknown agent: {agent_id}",
            }


    # --------------------------------------------------------
    # 2. KNOWN TARGET
    # --------------------------------------------------------

    if request.target not in RECORDS:

        return {
            "authorized": False,
            "stage": "TARGET",
            "reason": "Unknown target.",
        }


    # --------------------------------------------------------
    # 3. DELEGATOR MAY DELEGATE
    # --------------------------------------------------------

    if (
        "request_task"
        not in AGENTS[
            request.delegator
        ][
            "capabilities"
        ]
        and
        request.delegator
        != "security_agent"
    ):

        return {
            "authorized": False,
            "stage": "DELEGATION",
            "reason": "Delegator may not create delegated tasks.",
        }


    # --------------------------------------------------------
    # 4. DELEGATE CAPABILITY
    # --------------------------------------------------------

    delegate_capabilities = AGENTS[
        request.delegate
    ][
        "capabilities"
    ]


    if request.action not in delegate_capabilities:

        return {
            "authorized": False,
            "stage": "CAPABILITY",
            "reason": "Delegate lacks required capability.",
        }


    # --------------------------------------------------------
    # 5. SCOPE
    # --------------------------------------------------------

    scope_value = (
        f"{request.action}:"
        f"{request.target}"
    )


    if scope_value not in request.approved_scope:

        return {
            "authorized": False,
            "stage": "SCOPE",
            "reason": "Action exceeds delegated scope.",
        }


    # --------------------------------------------------------
    # 6. RESOURCE POLICY
    # --------------------------------------------------------

    record = RECORDS[
        request.target
    ]


    if (
        record["classification"]
        == "restricted"
    ):

        if request.action in {
            "read_record",
            "update_record",
        }:

            if request.delegate != "security_agent":

                return {
                    "authorized": False,
                    "stage": "RESOURCE_POLICY",
                    "reason": (
                        "Restricted record requires "
                        "security_agent authority."
                    ),
                }


    # --------------------------------------------------------
    # 7. HIGH-IMPACT ACTION
    # --------------------------------------------------------

    if request.action == "delete_record":

        if request.delegate != "security_agent":

            return {
                "authorized": False,
                "stage": "CAPABILITY",
                "reason": (
                    "Only security_agent may perform "
                    "restricted delete operations."
                ),
            }


        if request.approval_id is None:

            return {
                "authorized": False,
                "stage": "APPROVAL",
                "reason": "Trusted approval required.",
            }


        approval = VALID_APPROVALS.get(
            request.approval_id
        )


        if approval is None:

            return {
                "authorized": False,
                "stage": "APPROVAL",
                "reason": "Unknown approval.",
            }


        if (
            approval["action"]
            != request.action
            or
            approval["target"]
            != request.target
            or
            approval["delegate"]
            != request.delegate
        ):

            return {
                "authorized": False,
                "stage": "APPROVAL",
                "reason": "Approval scope mismatch.",
            }


    # --------------------------------------------------------
    # AUTHORIZED
    # --------------------------------------------------------

    return {
        "authorized": True,
        "stage": None,
        "reason": (
            "Requester, delegator, delegate, "
            "capability, scope, resource policy, "
            "and approval checks passed."
        ),
    }


# ============================================================
# TEST CASES
# ============================================================

TESTS = [

    {
        "name": "Authorized worker read",

        "request": DelegatedAction(
            requester="planner_agent",
            delegator="planner_agent",
            delegate="worker_agent",
            action="read_record",
            target="R-2202",
            approved_scope={
                "read_record:R-2202"
            },
        ),

        "expected": True,
    },

    {
        "name": "Worker restricted read",

        "request": DelegatedAction(
            requester="planner_agent",
            delegator="planner_agent",
            delegate="worker_agent",
            action="read_record",
            target="R-2299",
            approved_scope={
                "read_record:R-2299"
            },
        ),

        "expected": False,
    },

    {
        "name": "Worker out-of-scope update",

        "request": DelegatedAction(
            requester="planner_agent",
            delegator="planner_agent",
            delegate="worker_agent",
            action="update_record",
            target="R-2202",
            approved_scope={
                "read_record:R-2202"
            },
        ),

        "expected": False,
    },

    {
        "name": "Planner impersonates worker capability",

        "request": DelegatedAction(
            requester="planner_agent",
            delegator="planner_agent",
            delegate="planner_agent",
            action="read_record",
            target="R-2202",
            approved_scope={
                "read_record:R-2202"
            },
        ),

        "expected": False,
    },

    {
        "name": "Security agent evaluates authorization",

        "request": DelegatedAction(
            requester="planner_agent",
            delegator="security_agent",
            delegate="security_agent",
            action="evaluate_authorization",
            target="R-2299",
            approved_scope={
                "evaluate_authorization:R-2299"
            },
        ),

        "expected": True,
    },

    {
        "name": "Security delete without approval",

        "request": DelegatedAction(
            requester="security_agent",
            delegator="security_agent",
            delegate="security_agent",
            action="delete_record",
            target="R-2299",
            approved_scope={
                "delete_record:R-2299"
            },
        ),

        "expected": False,
    },

    {
        "name": "Security delete with bad approval",

        "request": DelegatedAction(
            requester="security_agent",
            delegator="security_agent",
            delegate="security_agent",
            action="delete_record",
            target="R-2299",
            approved_scope={
                "delete_record:R-2299"
            },
            approval_id="FAKE-APPROVAL",
        ),

        "expected": False,
    },

    {
        "name": "Security delete with trusted approval",

        "request": DelegatedAction(
            requester="security_agent",
            delegator="security_agent",
            delegate="security_agent",
            action="delete_record",
            target="R-2299",
            approved_scope={
                "delete_record:R-2299"
            },
            approval_id="APPROVAL-DELETE-R2299",
        ),

        "expected": True,
    },

    {
        "name": "Target substitution",

        "request": DelegatedAction(
            requester="planner_agent",
            delegator="planner_agent",
            delegate="worker_agent",
            action="read_record",
            target="R-2201",
            approved_scope={
                "read_record:R-2202"
            },
        ),

        "expected": False,
    },

    {
        "name": "Unknown delegate",

        "request": DelegatedAction(
            requester="planner_agent",
            delegator="planner_agent",
            delegate="fake_security_agent",
            action="read_record",
            target="R-2202",
            approved_scope={
                "read_record:R-2202"
            },
        ),

        "expected": False,
    },
]


# ============================================================
# RUN TESTS
# ============================================================

correct = 0

allowed = 0
blocked = 0

stage_counts = {}


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
        "Requester:",
        request.requester,
    )

    print(
        "Delegator:",
        request.delegator,
    )

    print(
        "Delegate:",
        request.delegate,
    )

    print(
        "Action:",
        request.action,
    )

    print(
        "Target:",
        request.target,
    )

    print(
        "Approved Scope:",
        request.approved_scope,
    )

    print(
        "Approval ID:",
        request.approval_id,
    )


    result = authorize(
        request
    )


    print(
        "\nAuthorization Result:"
    )

    print(
        result
    )


    actual = result[
        "authorized"
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
        allowed += 1

    else:
        blocked += 1


    stage = result[
        "stage"
    ]


    if stage is not None:

        stage_counts[
            stage
        ] = (
            stage_counts.get(
                stage,
                0,
            )
            + 1
        )


    print(
        "Expected:",
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
    "   MULTI-AGENT AUTHORIZATION SUMMARY"
)

print(
    "========================================"
)


print(
    "Tests:",
    len(TESTS),
)

print(
    "Correct decisions:",
    f"{correct}/{len(TESTS)}",
)

print(
    "Allowed:",
    allowed,
)

print(
    "Blocked:",
    blocked,
)


print(
    "\nBlock Stages:"
)


for stage, count in sorted(
    stage_counts.items()
):

    print(
        f"- {stage}: {count}"
    )


print(
    "\nPolicy Decision Accuracy:",
    f"{rate(correct, len(TESTS)):.2f}%"
)


print(
    "\n=== Security Interpretation ==="
)

print(
    "Authorization is independently evaluated "
    "from trusted agent state."
)

print(
    "Agent messages, delegation chains, claimed "
    "authority, and model reasoning cannot directly "
    "grant capabilities or approvals."
)

print(
    "Every security-sensitive action is evaluated "
    "for requester, delegator, delegate, capability, "
    "scope, target, resource policy, and approval."
)


print(
    "\nCore Principle:"
)

print(
    "Agent identity does not imply agent authority; "
    "delegated actions must be independently authorized."
)