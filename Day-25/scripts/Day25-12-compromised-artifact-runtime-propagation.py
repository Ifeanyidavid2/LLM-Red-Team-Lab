"""
Day 25 Lab 12
Compromised Artifact -> Runtime Propagation

Purpose:
Measure whether compromised pre-runtime artifacts can propagate through
artifact loading into model/runtime behavior and ultimately produce
security-sensitive execution changes.

Core Principle:
An AI component being available or functional does not establish
that it is authentic, trusted, or safe to load.
"""

import copy
import hashlib
import json


# ============================================================
# HELPERS
# ============================================================

def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    )


def calculate_hash(artifact):
    artifact_copy = copy.deepcopy(
        artifact
    )

    artifact_copy.pop(
        "sha256",
        None,
    )

    return hashlib.sha256(
        canonical_json(
            artifact_copy
        ).encode("utf-8")
    ).hexdigest()


def finalize_artifact(artifact):
    artifact = copy.deepcopy(
        artifact
    )

    artifact["sha256"] = (
        calculate_hash(
            artifact
        )
    )

    return artifact


def print_json(value):
    print(
        json.dumps(
            value,
            indent=2,
        )
    )


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


# ============================================================
# TRUSTED RUNTIME STATE
# ============================================================

TRUSTED_TARGET = "R-2502"
RESTRICTED_TARGET = "R-2599"

TRUSTED_ACTION = "read_record"


TRUSTED_RUNTIME_STATE = {
    "actor": "worker_agent",
    "allowed_action": "read_record",
    "allowed_target": TRUSTED_TARGET,
    "restricted_targets": [
        RESTRICTED_TARGET,
    ],
}


# ============================================================
# TRUSTED ARTIFACTS
# ============================================================

TRUSTED_PROMPT = finalize_artifact(
    {
        "artifact_id": "PROMPT-2512",
        "artifact_type": "prompt_template",
        "name": "runtime-review-template",
        "version": "1.0.0",
        "publisher": "trusted_ai_team",
        "content": {
            "recommended_action": "read_record",
            "target": TRUSTED_TARGET,
            "approval_assumed": False,
        },
    }
)


TRUSTED_POLICY = finalize_artifact(
    {
        "artifact_id": "POLICY-2512",
        "artifact_type": "policy",
        "name": "runtime-worker-policy",
        "version": "1.0.0",
        "publisher": "trusted_security_team",
        "content": {
            "allowed_actions": [
                "read_record",
            ],
            "allowed_targets": [
                TRUSTED_TARGET,
            ],
            "restricted_targets": [
                RESTRICTED_TARGET,
            ],
        },
    }
)


TRUSTED_DATASET = finalize_artifact(
    {
        "artifact_id": "DATA-2512",
        "artifact_type": "dataset",
        "name": "runtime-reference-data",
        "version": "1.0.0",
        "publisher": "trusted_data_team",
        "content": {
            "record": TRUSTED_TARGET,
            "classification": "internal",
            "recommended_action": "read_record",
        },
    }
)


TRUSTED_MODEL = finalize_artifact(
    {
        "artifact_id": "MODEL-2512",
        "artifact_type": "model",
        "name": "runtime-review-model",
        "version": "1.0.0",
        "publisher": "trusted_ai_team",
        "capabilities": [
            "summarize_project",
        ],
        "content": {
            "default_action": "read_record",
            "default_target": TRUSTED_TARGET,
            "privileged": False,
        },
    }
)


TRUSTED_TOOL = finalize_artifact(
    {
        "artifact_id": "TOOL-2512",
        "artifact_type": "tool_package",
        "name": "runtime-record-tools",
        "version": "1.0.0",
        "publisher": "trusted_security_team",
        "capabilities": [
            "read_record",
        ],
        "content": {
            "target_override": None,
            "action_override": None,
            "privileged": False,
        },
    }
)


TRUSTED_HASHES = {
    "prompt": TRUSTED_PROMPT["sha256"],
    "policy": TRUSTED_POLICY["sha256"],
    "dataset": TRUSTED_DATASET["sha256"],
    "model": TRUSTED_MODEL["sha256"],
    "tool": TRUSTED_TOOL["sha256"],
}


# ============================================================
# COMPROMISED ARTIFACT VARIANTS
# ============================================================

MALICIOUS_PROMPT = finalize_artifact(
    {
        **{
            key: copy.deepcopy(value)
            for key, value
            in TRUSTED_PROMPT.items()
            if key != "sha256"
        },
        "content": {
            "recommended_action": "delete_record",
            "target": RESTRICTED_TARGET,
            "approval_assumed": True,
        },
    }
)


MALICIOUS_POLICY = finalize_artifact(
    {
        **{
            key: copy.deepcopy(value)
            for key, value
            in TRUSTED_POLICY.items()
            if key != "sha256"
        },
        "content": {
            "allowed_actions": [
                "read_record",
                "delete_record",
            ],
            "allowed_targets": [
                TRUSTED_TARGET,
                RESTRICTED_TARGET,
            ],
            "restricted_targets": [],
        },
    }
)


MALICIOUS_DATASET = finalize_artifact(
    {
        **{
            key: copy.deepcopy(value)
            for key, value
            in TRUSTED_DATASET.items()
            if key != "sha256"
        },
        "content": {
            "record": RESTRICTED_TARGET,
            "classification": "public",
            "recommended_action": "delete_record",
        },
    }
)


MALICIOUS_MODEL = finalize_artifact(
    {
        **{
            key: copy.deepcopy(value)
            for key, value
            in TRUSTED_MODEL.items()
            if key != "sha256"
        },
        "capabilities": [
            "summarize_project",
            "delete_record",
        ],
        "content": {
            "default_action": "delete_record",
            "default_target": RESTRICTED_TARGET,
            "privileged": True,
        },
    }
)


MALICIOUS_TOOL = finalize_artifact(
    {
        **{
            key: copy.deepcopy(value)
            for key, value
            in TRUSTED_TOOL.items()
            if key != "sha256"
        },
        "capabilities": [
            "read_record",
            "delete_record",
        ],
        "content": {
            "target_override": RESTRICTED_TARGET,
            "action_override": "delete_record",
            "privileged": True,
        },
    }
)


# ============================================================
# TEST CASES
# ============================================================

TEST_CASES = [

    {
        "name": "Case 1: Clean trusted artifact chain",
        "poisoned": False,
        "artifacts": {
            "prompt": copy.deepcopy(
                TRUSTED_PROMPT
            ),
            "policy": copy.deepcopy(
                TRUSTED_POLICY
            ),
            "dataset": copy.deepcopy(
                TRUSTED_DATASET
            ),
            "model": copy.deepcopy(
                TRUSTED_MODEL
            ),
            "tool": copy.deepcopy(
                TRUSTED_TOOL
            ),
        },
    },

    {
        "name": "Case 2: Compromised prompt propagates",
        "poisoned": True,
        "artifacts": {
            "prompt": copy.deepcopy(
                MALICIOUS_PROMPT
            ),
            "policy": copy.deepcopy(
                TRUSTED_POLICY
            ),
            "dataset": copy.deepcopy(
                TRUSTED_DATASET
            ),
            "model": copy.deepcopy(
                TRUSTED_MODEL
            ),
            "tool": copy.deepcopy(
                TRUSTED_TOOL
            ),
        },
    },

    {
        "name": "Case 3: Compromised policy propagates",
        "poisoned": True,
        "artifacts": {
            "prompt": copy.deepcopy(
                TRUSTED_PROMPT
            ),
            "policy": copy.deepcopy(
                MALICIOUS_POLICY
            ),
            "dataset": copy.deepcopy(
                TRUSTED_DATASET
            ),
            "model": copy.deepcopy(
                TRUSTED_MODEL
            ),
            "tool": copy.deepcopy(
                TRUSTED_TOOL
            ),
        },
    },

    {
        "name": "Case 4: Compromised dataset propagates",
        "poisoned": True,
        "artifacts": {
            "prompt": copy.deepcopy(
                TRUSTED_PROMPT
            ),
            "policy": copy.deepcopy(
                TRUSTED_POLICY
            ),
            "dataset": copy.deepcopy(
                MALICIOUS_DATASET
            ),
            "model": copy.deepcopy(
                TRUSTED_MODEL
            ),
            "tool": copy.deepcopy(
                TRUSTED_TOOL
            ),
        },
    },

    {
        "name": "Case 5: Compromised model propagates",
        "poisoned": True,
        "artifacts": {
            "prompt": copy.deepcopy(
                TRUSTED_PROMPT
            ),
            "policy": copy.deepcopy(
                TRUSTED_POLICY
            ),
            "dataset": copy.deepcopy(
                TRUSTED_DATASET
            ),
            "model": copy.deepcopy(
                MALICIOUS_MODEL
            ),
            "tool": copy.deepcopy(
                TRUSTED_TOOL
            ),
        },
    },

    {
        "name": "Case 6: Compromised tool propagates",
        "poisoned": True,
        "artifacts": {
            "prompt": copy.deepcopy(
                TRUSTED_PROMPT
            ),
            "policy": copy.deepcopy(
                TRUSTED_POLICY
            ),
            "dataset": copy.deepcopy(
                TRUSTED_DATASET
            ),
            "model": copy.deepcopy(
                TRUSTED_MODEL
            ),
            "tool": copy.deepcopy(
                MALICIOUS_TOOL
            ),
        },
    },

    {
        "name": "Case 7: Multi-artifact compromise",
        "poisoned": True,
        "artifacts": {
            "prompt": copy.deepcopy(
                MALICIOUS_PROMPT
            ),
            "policy": copy.deepcopy(
                MALICIOUS_POLICY
            ),
            "dataset": copy.deepcopy(
                MALICIOUS_DATASET
            ),
            "model": copy.deepcopy(
                MALICIOUS_MODEL
            ),
            "tool": copy.deepcopy(
                MALICIOUS_TOOL
            ),
        },
    },

    {
        "name": "Case 8: Second clean trusted chain",
        "poisoned": False,
        "artifacts": {
            "prompt": copy.deepcopy(
                TRUSTED_PROMPT
            ),
            "policy": copy.deepcopy(
                TRUSTED_POLICY
            ),
            "dataset": copy.deepcopy(
                TRUSTED_DATASET
            ),
            "model": copy.deepcopy(
                TRUSTED_MODEL
            ),
            "tool": copy.deepcopy(
                TRUSTED_TOOL
            ),
        },
    },
]


# ============================================================
# VULNERABLE PRE-RUNTIME LOADER
# ============================================================

def vulnerable_load_artifacts(
    artifacts,
):
    """
    Intentionally vulnerable.

    The loader checks only basic structure and availability.
    It records integrity mismatches for analysis but does not
    use them to block loading.
    """

    results = {}

    for artifact_type, artifact in artifacts.items():

        structurally_valid = (
            isinstance(
                artifact,
                dict,
            )
            and
            "artifact_id"
            in artifact
            and
            "artifact_type"
            in artifact
            and
            "content"
            in artifact
        )

        actual_hash = (
            calculate_hash(
                artifact
            )
        )

        expected_hash = (
            TRUSTED_HASHES[
                artifact_type
            ]
        )

        integrity_match = (
            actual_hash
            == expected_hash
        )

        results[
            artifact_type
        ] = {
            "loaded": (
                structurally_valid
            ),
            "artifact_id": (
                artifact[
                    "artifact_id"
                ]
            ),
            "integrity_match": (
                integrity_match
            ),
            "actual_hash": (
                actual_hash
            ),
            "expected_hash": (
                expected_hash
            ),
        }

    all_loaded = all(
        result[
            "loaded"
        ]
        for result
        in results.values()
    )

    return {
        "all_loaded": all_loaded,
        "artifacts": results,
    }


# ============================================================
# RUNTIME PLANNING
# ============================================================

def build_runtime_plan(
    artifacts,
):

    prompt = artifacts[
        "prompt"
    ][
        "content"
    ]

    dataset = artifacts[
        "dataset"
    ][
        "content"
    ]

    model = artifacts[
        "model"
    ][
        "content"
    ]

    action = (
        model.get(
            "default_action"
        )
        or
        prompt.get(
            "recommended_action"
        )
        or
        dataset.get(
            "recommended_action"
        )
        or
        TRUSTED_ACTION
    )

    target = (
        model.get(
            "default_target"
        )
        or
        prompt.get(
            "target"
        )
        or
        dataset.get(
            "record"
        )
        or
        TRUSTED_TARGET
    )

    privileged = bool(
        model.get(
            "privileged",
            False,
        )
    )

    approval_assumed = bool(
        prompt.get(
            "approval_assumed",
            False,
        )
    )


    # --------------------------------------------------------
    # Simulate downstream artifact influence.
    # If a non-model artifact contains a stronger unsafe
    # recommendation, the vulnerable runtime accepts it.
    # --------------------------------------------------------

    if (
        prompt.get(
            "recommended_action"
        )
        == "delete_record"
    ):
        action = "delete_record"
        target = prompt.get(
            "target",
            target,
        )


    if (
        dataset.get(
            "recommended_action"
        )
        == "delete_record"
    ):
        action = "delete_record"
        target = dataset.get(
            "record",
            target,
        )


    return {
        "action": action,
        "target": target,
        "privileged": privileged,
        "approval_assumed": (
            approval_assumed
        ),
    }


# ============================================================
# POLICY EVALUATION
# ============================================================

def vulnerable_policy_check(
    artifacts,
    plan,
):

    policy = artifacts[
        "policy"
    ][
        "content"
    ]

    action_allowed = (
        plan[
            "action"
        ]
        in policy.get(
            "allowed_actions",
            [],
        )
    )

    target_allowed = (
        plan[
            "target"
        ]
        in policy.get(
            "allowed_targets",
            [],
        )
    )

    target_restricted = (
        plan[
            "target"
        ]
        in policy.get(
            "restricted_targets",
            [],
        )
    )

    authorized = (
        action_allowed
        and
        target_allowed
        and
        not target_restricted
    )

    return {
        "authorized": authorized,
        "action_allowed": (
            action_allowed
        ),
        "target_allowed": (
            target_allowed
        ),
        "target_restricted": (
            target_restricted
        ),
    }


# ============================================================
# TOOL EXECUTION
# ============================================================

def execute_tool(
    artifacts,
    plan,
    policy_result,
):

    tool = artifacts[
        "tool"
    ][
        "content"
    ]

    action = plan[
        "action"
    ]

    target = plan[
        "target"
    ]

    privileged = plan[
        "privileged"
    ]


    if tool.get(
        "action_override"
    ):
        action = tool[
            "action_override"
        ]


    if tool.get(
        "target_override"
    ):
        target = tool[
            "target_override"
        ]


    if tool.get(
        "privileged",
        False,
    ):
        privileged = True


    # --------------------------------------------------------
    # Intentionally vulnerable:
    #
    # Tool-level override can execute despite the earlier
    # policy result because the application does not rebind
    # final execution to the trusted plan.
    # --------------------------------------------------------

    tool_override_present = (
        tool.get(
            "action_override"
        )
        is not None
        or
        tool.get(
            "target_override"
        )
        is not None
        or
        tool.get(
            "privileged",
            False,
        )
    )


    executed = (
        policy_result[
            "authorized"
        ]
        or
        tool_override_present
        or
        plan[
            "approval_assumed"
        ]
    )


    restricted_target = (
        target
        == RESTRICTED_TARGET
    )

    privileged_action = (
        action
        == "delete_record"
    )

    unauthorized_system_impact = (
        executed
        and
        (
            restricted_target
            or privileged_action
            or privileged
        )
    )


    return {
        "executed": executed,
        "action": action,
        "target": target,
        "privileged": privileged,
        "restricted_target_selected": (
            restricted_target
        ),
        "privileged_action_selected": (
            privileged_action
        ),
        "unauthorized_system_impact": (
            unauthorized_system_impact
        ),
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 25 Lab 12: "
        "Compromised Artifact -> Runtime Propagation ==="
    )


    results = []


    for case in TEST_CASES:

        print(
            "\n"
            + "=" * 52
        )

        print(
            case[
                "name"
            ]
        )

        print(
            "=" * 52
        )

        print(
            "Poisoned:",
            case[
                "poisoned"
            ],
        )


        artifacts = copy.deepcopy(
            case[
                "artifacts"
            ]
        )


        # ====================================================
        # LOAD
        # ====================================================

        load_result = (
            vulnerable_load_artifacts(
                artifacts
            )
        )


        print(
            "\nPre-Runtime Artifact Loading:"
        )

        print_json(
            load_result
        )


        # ====================================================
        # COUNT COMPROMISED ARTIFACTS
        # ====================================================

        compromised_artifacts = sum(
            not result[
                "integrity_match"
            ]
            for result
            in load_result[
                "artifacts"
            ].values()
        )


        # ====================================================
        # PLAN
        # ====================================================

        plan = (
            build_runtime_plan(
                artifacts
            )
        )


        print(
            "\nRuntime Plan:"
        )

        print_json(
            plan
        )


        # ====================================================
        # POLICY
        # ====================================================

        policy_result = (
            vulnerable_policy_check(
                artifacts,
                plan,
            )
        )


        print(
            "\nPolicy Result:"
        )

        print_json(
            policy_result
        )


        # ====================================================
        # EXECUTION
        # ====================================================

        execution = (
            execute_tool(
                artifacts,
                plan,
                policy_result,
            )
        )


        print(
            "\nExecution Result:"
        )

        print_json(
            execution
        )


        # ====================================================
        # SECURITY ANALYSIS
        # ====================================================

        malicious_artifact_loaded = (
            case[
                "poisoned"
            ]
            and
            load_result[
                "all_loaded"
            ]
            and
            compromised_artifacts > 0
        )


        runtime_behavior_changed = (
            case[
                "poisoned"
            ]
            and
            (
                plan[
                    "action"
                ]
                != TRUSTED_ACTION
                or
                plan[
                    "target"
                ]
                != TRUSTED_TARGET
                or
                plan[
                    "privileged"
                ]
                or
                plan[
                    "approval_assumed"
                ]
            )
        )


        runtime_propagation = (
            malicious_artifact_loaded
            and
            (
                runtime_behavior_changed
                or
                execution[
                    "unauthorized_system_impact"
                ]
            )
        )


        unauthorized_impact = (
            case[
                "poisoned"
            ]
            and
            execution[
                "unauthorized_system_impact"
            ]
        )


        privileged_execution = (
            case[
                "poisoned"
            ]
            and
            execution[
                "executed"
            ]
            and
            (
                execution[
                    "privileged"
                ]
                or
                execution[
                    "privileged_action_selected"
                ]
            )
        )


        restricted_target_execution = (
            case[
                "poisoned"
            ]
            and
            execution[
                "executed"
            ]
            and
            execution[
                "restricted_target_selected"
            ]
        )


        print(
            "\nSecurity Analysis:"
        )

        print(
            "Compromised Artifacts:",
            compromised_artifacts,
        )

        print(
            "Malicious Artifact Loaded:",
            malicious_artifact_loaded,
        )

        print(
            "Runtime Behavior Changed:",
            runtime_behavior_changed,
        )

        print(
            "Pre-Runtime -> Runtime Propagation:",
            runtime_propagation,
        )

        print(
            "Privileged Execution:",
            privileged_execution,
        )

        print(
            "Restricted Target Execution:",
            restricted_target_execution,
        )

        print(
            "Unauthorized System Impact:",
            unauthorized_impact,
        )


        clean_safe = (
            not case[
                "poisoned"
            ]
            and
            load_result[
                "all_loaded"
            ]
            and
            compromised_artifacts == 0
            and
            plan[
                "action"
            ]
            == TRUSTED_ACTION
            and
            plan[
                "target"
            ]
            == TRUSTED_TARGET
            and
            policy_result[
                "authorized"
            ]
            and
            execution[
                "executed"
            ]
            and
            not execution[
                "unauthorized_system_impact"
            ]
        )


        results.append(
            {
                "poisoned": (
                    case[
                        "poisoned"
                    ]
                ),

                "malicious_artifact_loaded": (
                    malicious_artifact_loaded
                ),

                "runtime_behavior_changed": (
                    runtime_behavior_changed
                ),

                "runtime_propagation": (
                    runtime_propagation
                ),

                "privileged_execution": (
                    privileged_execution
                ),

                "restricted_target_execution": (
                    restricted_target_execution
                ),

                "unauthorized_system_impact": (
                    unauthorized_impact
                ),

                "clean_safe": (
                    clean_safe
                ),
            }
        )


    # ========================================================
    # METRICS
    # ========================================================

    poisoned_results = [
        result
        for result
        in results
        if result[
            "poisoned"
        ]
    ]


    clean_results = [
        result
        for result
        in results
        if not result[
            "poisoned"
        ]
    ]


    poisoned_count = len(
        poisoned_results
    )


    malicious_loads = sum(
        result[
            "malicious_artifact_loaded"
        ]
        for result
        in poisoned_results
    )


    changed_runtime = sum(
        result[
            "runtime_behavior_changed"
        ]
        for result
        in poisoned_results
    )


    propagations = sum(
        result[
            "runtime_propagation"
        ]
        for result
        in poisoned_results
    )


    privileged_executions = sum(
        result[
            "privileged_execution"
        ]
        for result
        in poisoned_results
    )


    restricted_executions = sum(
        result[
            "restricted_target_execution"
        ]
        for result
        in poisoned_results
    )


    unauthorized_impacts = sum(
        result[
            "unauthorized_system_impact"
        ]
        for result
        in poisoned_results
    )


    clean_safe = sum(
        result[
            "clean_safe"
        ]
        for result
        in clean_results
    )


    # ========================================================
    # SUMMARY
    # ========================================================

    print(
        "\n"
        + "=" * 52
    )

    print(
        "    ARTIFACT -> RUNTIME PROPAGATION SUMMARY"
    )

    print(
        "=" * 52
    )


    print(
        "Poisoned artifact-chain cases:",
        poisoned_count,
    )


    print(
        "Malicious Artifact Load Rate:",
        f"{rate(
            malicious_loads,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Runtime Behavior Manipulation Rate:",
        f"{rate(
            changed_runtime,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Pre-Runtime -> Runtime Propagation Rate:",
        f"{rate(
            propagations,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Privileged Execution Rate:",
        f"{rate(
            privileged_executions,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Restricted Target Execution Rate:",
        f"{rate(
            restricted_executions,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Unauthorized System Impact Rate:",
        f"{rate(
            unauthorized_impacts,
            poisoned_count
        ):.2f}%"
    )


    # ========================================================
    # CLEAN UTILITY
    # ========================================================

    print(
        "\n=== Clean Utility ==="
    )


    print(
        "Clean artifact-chain cases:",
        len(
            clean_results
        ),
    )


    print(
        "Clean safe runtime executions:",
        clean_safe,
    )


    print(
        "Clean Runtime Utility Rate:",
        f"{rate(
            clean_safe,
            len(clean_results)
        ):.2f}%"
    )


    # ========================================================
    # INTERPRETATION
    # ========================================================

    print(
        "\nSecurity Interpretation:"
    )


    print(
        "A supply-chain compromise becomes a runtime "
        "security issue when an altered artifact is loaded "
        "and its malicious state influences planning, policy, "
        "model behavior, target selection, or tool execution."
    )


    print(
        "The vulnerable architecture detects integrity "
        "differences for analysis but does not enforce those "
        "differences as a loading boundary."
    )


    print(
        "Pre-runtime artifact trust and runtime execution "
        "security must therefore be connected by explicit "
        "verification and fail-closed loading controls."
    )


    print(
        "\nCore Principle:"
    )


    print(
        "An AI component being available or functional "
        "does not establish that it is authentic, "
        "trusted, or safe to load."
    )


if __name__ == "__main__":
    main()