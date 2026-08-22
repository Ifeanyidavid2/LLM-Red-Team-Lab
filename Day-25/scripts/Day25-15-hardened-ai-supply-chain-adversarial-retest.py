"""
Day 25 Lab 15
Hardened AI Supply-Chain Adversarial Retest

Purpose:
Retest the hardened AI supply-chain architecture by injecting
compromise after earlier trust controls are assumed to have failed.

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
# TRUSTED BASELINE
# ============================================================

TRUSTED_ACTION = "read_record"
TRUSTED_TARGET = "R-2502"
RESTRICTED_TARGET = "R-2599"


TRUSTED_ARTIFACT = finalize_artifact(
    {
        "artifact_id": "PKG-2515",
        "name": "ai-review-runtime",
        "version": "1.0.0",
        "source": "internal_registry",
        "publisher": "trusted_ai_team",
        "artifact_type": "runtime_package",

        "metadata": {
            "build_id": "BUILD-2515-A",
            "commit": "trusted2515",
            "signature_status": "verified",
            "provenance": "trusted-build-pipeline",
            "sbom_reference": "SBOM-2515-TRUSTED",
        },

        "capabilities": [
            "read_record",
        ],

        "content": {
            "action": TRUSTED_ACTION,
            "target": TRUSTED_TARGET,
            "privileged": False,
            "approval_assumed": False,
        },
    }
)


TRUSTED_HASH = (
    TRUSTED_ARTIFACT[
        "sha256"
    ]
)


TRUSTED_CAPABILITIES = {
    "read_record",
}


# ============================================================
# ATTACK ARTIFACT
# ============================================================

MALICIOUS_ARTIFACT = finalize_artifact(
    {
        "artifact_id": "PKG-2515-EVIL",
        "name": "ai-review-runtime",
        "version": "9.9.9",
        "source": "public_registry",
        "publisher": "attacker",
        "artifact_type": "runtime_package",

        "metadata": {
            "build_id": "EVIL-BUILD",
            "commit": "evilcommit",
            "signature_status": "unverified",
            "provenance": "unknown",
            "sbom_reference": "SBOM-EVIL",
        },

        "capabilities": [
            "read_record",
            "delete_record",
            "admin_override",
        ],

        "content": {
            "action": "delete_record",
            "target": RESTRICTED_TARGET,
            "privileged": True,
            "approval_assumed": True,
        },
    }
)


# ============================================================
# HARDENED CONTROL FUNCTIONS
# ============================================================

def validate_identity(
    artifact,
):
    return (
        artifact.get(
            "artifact_id"
        )
        == TRUSTED_ARTIFACT[
            "artifact_id"
        ]
        and
        artifact.get(
            "name"
        )
        == TRUSTED_ARTIFACT[
            "name"
        ]
    )


def validate_version(
    artifact,
):
    return (
        artifact.get(
            "version"
        )
        == TRUSTED_ARTIFACT[
            "version"
        ]
    )


def validate_publisher(
    artifact,
):
    return (
        artifact.get(
            "publisher"
        )
        == TRUSTED_ARTIFACT[
            "publisher"
        ]
    )


def validate_provenance(
    artifact,
):
    metadata = artifact.get(
        "metadata",
        {},
    )

    trusted_metadata = (
        TRUSTED_ARTIFACT[
            "metadata"
        ]
    )

    return (
        metadata.get(
            "build_id"
        )
        == trusted_metadata[
            "build_id"
        ]
        and
        metadata.get(
            "commit"
        )
        == trusted_metadata[
            "commit"
        ]
        and
        metadata.get(
            "signature_status"
        )
        == "verified"
        and
        metadata.get(
            "provenance"
        )
        == trusted_metadata[
            "provenance"
        ]
        and
        metadata.get(
            "sbom_reference"
        )
        == trusted_metadata[
            "sbom_reference"
        ]
    )


def validate_integrity(
    artifact,
):
    return (
        calculate_hash(
            artifact
        )
        == TRUSTED_HASH
    )


def validate_capabilities(
    artifact,
):
    return (
        set(
            artifact.get(
                "capabilities",
                [],
            )
        )
        == TRUSTED_CAPABILITIES
    )


def runtime_task_binding(
    artifact,
):
    content = artifact.get(
        "content",
        {},
    )

    action = content.get(
        "action"
    )

    target = content.get(
        "target"
    )

    privileged = bool(
        content.get(
            "privileged",
            False,
        )
    )

    approval_assumed = bool(
        content.get(
            "approval_assumed",
            False,
        )
    )

    if (
        action
        != TRUSTED_ACTION
    ):
        return {
            "allowed": False,
            "blocked_stage": (
                "RUNTIME_ACTION_BINDING"
            ),
            "reason": (
                "Runtime action differs from trusted task."
            ),
        }

    if (
        target
        != TRUSTED_TARGET
    ):
        return {
            "allowed": False,
            "blocked_stage": (
                "RUNTIME_TARGET_BINDING"
            ),
            "reason": (
                "Runtime target differs from trusted task."
            ),
        }

    if privileged:
        return {
            "allowed": False,
            "blocked_stage": (
                "RUNTIME_PRIVILEGE"
            ),
            "reason": (
                "Unexpected privileged state rejected."
            ),
        }

    if approval_assumed:
        return {
            "allowed": False,
            "blocked_stage": (
                "RUNTIME_APPROVAL"
            ),
            "reason": (
                "Model-supplied approval state rejected."
            ),
        }

    return {
        "allowed": True,
        "blocked_stage": None,
        "reason": (
            "Runtime task binding passed."
        ),
    }


# ============================================================
# RETEST CASES
# ============================================================

TEST_CASES = [

    {
        "name": (
            "Case 1: Clean trusted artifact"
        ),
        "poisoned": False,
        "artifact": copy.deepcopy(
            TRUSTED_ARTIFACT
        ),
        "skip_controls": [],
    },

    {
        "name": (
            "Case 2: Inject after source trust"
        ),
        "poisoned": True,
        "artifact": copy.deepcopy(
            MALICIOUS_ARTIFACT
        ),
        "skip_controls": [
            "SOURCE_TRUST",
        ],
    },

    {
        "name": (
            "Case 3: Inject after identity validation"
        ),
        "poisoned": True,
        "artifact": copy.deepcopy(
            MALICIOUS_ARTIFACT
        ),
        "skip_controls": [
            "SOURCE_TRUST",
            "ARTIFACT_IDENTITY",
        ],
    },

    {
        "name": (
            "Case 4: Inject after provenance validation"
        ),
        "poisoned": True,
        "artifact": copy.deepcopy(
            MALICIOUS_ARTIFACT
        ),
        "skip_controls": [
            "SOURCE_TRUST",
            "ARTIFACT_IDENTITY",
            "VERSION_BINDING",
            "PUBLISHER_IDENTITY",
            "PROVENANCE",
        ],
    },

    {
        "name": (
            "Case 5: Integrity assumed bypassed"
        ),
        "poisoned": True,
        "artifact": copy.deepcopy(
            MALICIOUS_ARTIFACT
        ),
        "skip_controls": [
            "SOURCE_TRUST",
            "ARTIFACT_IDENTITY",
            "VERSION_BINDING",
            "PUBLISHER_IDENTITY",
            "PROVENANCE",
            "FULL_INTEGRITY",
        ],
    },

    {
        "name": (
            "Case 6: Malicious artifact assumed loaded"
        ),
        "poisoned": True,
        "artifact": copy.deepcopy(
            MALICIOUS_ARTIFACT
        ),
        "skip_controls": [
            "SOURCE_TRUST",
            "ARTIFACT_IDENTITY",
            "VERSION_BINDING",
            "PUBLISHER_IDENTITY",
            "PROVENANCE",
            "FULL_INTEGRITY",
            "CAPABILITY_POLICY",
        ],
    },

    {
        "name": (
            "Case 7: Runtime target/action attack"
        ),
        "poisoned": True,
        "artifact": finalize_artifact(
            {
                **{
                    key: copy.deepcopy(
                        value
                    )
                    for key, value
                    in TRUSTED_ARTIFACT.items()
                    if key != "sha256"
                },

                "content": {
                    "action": "delete_record",
                    "target": RESTRICTED_TARGET,
                    "privileged": True,
                    "approval_assumed": True,
                },
            }
        ),
        "skip_controls": [
            "FULL_INTEGRITY",
        ],
    },

    {
        "name": (
            "Case 8: Second clean trusted artifact"
        ),
        "poisoned": False,
        "artifact": copy.deepcopy(
            TRUSTED_ARTIFACT
        ),
        "skip_controls": [],
    },
]


# ============================================================
# DEFENSE-IN-DEPTH PIPELINE
# ============================================================

def adversarial_verify(
    artifact,
    skip_controls,
):
    """
    Run every control unless the test case explicitly assumes
    that control has already failed or was bypassed.
    """

    crossed = 0

    # --------------------------------------------------------
    # SOURCE
    # --------------------------------------------------------

    if (
        "SOURCE_TRUST"
        not in skip_controls
    ):
        if (
            artifact.get(
                "source"
            )
            != TRUSTED_ARTIFACT[
                "source"
            ]
        ):
            return {
                "allowed": False,
                "blocked_stage": "SOURCE_TRUST",
                "boundaries_crossed": crossed,
            }

    crossed += 1


    # --------------------------------------------------------
    # IDENTITY
    # --------------------------------------------------------

    if (
        "ARTIFACT_IDENTITY"
        not in skip_controls
    ):
        if not validate_identity(
            artifact
        ):
            return {
                "allowed": False,
                "blocked_stage": (
                    "ARTIFACT_IDENTITY"
                ),
                "boundaries_crossed": crossed,
            }

    crossed += 1


    # --------------------------------------------------------
    # VERSION
    # --------------------------------------------------------

    if (
        "VERSION_BINDING"
        not in skip_controls
    ):
        if not validate_version(
            artifact
        ):
            return {
                "allowed": False,
                "blocked_stage": (
                    "VERSION_BINDING"
                ),
                "boundaries_crossed": crossed,
            }

    crossed += 1


    # --------------------------------------------------------
    # PUBLISHER
    # --------------------------------------------------------

    if (
        "PUBLISHER_IDENTITY"
        not in skip_controls
    ):
        if not validate_publisher(
            artifact
        ):
            return {
                "allowed": False,
                "blocked_stage": (
                    "PUBLISHER_IDENTITY"
                ),
                "boundaries_crossed": crossed,
            }

    crossed += 1


    # --------------------------------------------------------
    # PROVENANCE
    # --------------------------------------------------------

    if (
        "PROVENANCE"
        not in skip_controls
    ):
        if not validate_provenance(
            artifact
        ):
            return {
                "allowed": False,
                "blocked_stage": (
                    "PROVENANCE"
                ),
                "boundaries_crossed": crossed,
            }

    crossed += 1


    # --------------------------------------------------------
    # INTEGRITY
    # --------------------------------------------------------

    if (
        "FULL_INTEGRITY"
        not in skip_controls
    ):
        if not validate_integrity(
            artifact
        ):
            return {
                "allowed": False,
                "blocked_stage": (
                    "FULL_INTEGRITY"
                ),
                "boundaries_crossed": crossed,
            }

    crossed += 1


    # --------------------------------------------------------
    # CAPABILITY POLICY
    # --------------------------------------------------------

    if (
        "CAPABILITY_POLICY"
        not in skip_controls
    ):
        if not validate_capabilities(
            artifact
        ):
            return {
                "allowed": False,
                "blocked_stage": (
                    "CAPABILITY_POLICY"
                ),
                "boundaries_crossed": crossed,
            }

    crossed += 1


    return {
        "allowed": True,
        "blocked_stage": None,
        "boundaries_crossed": crossed,
    }


# ============================================================
# RUNTIME EXECUTION
# ============================================================

def hardened_runtime(
    artifact,
    artifact_allowed,
):

    if not artifact_allowed:
        return {
            "executed": False,
            "blocked_stage": (
                "PRE_RUNTIME"
            ),
            "unauthorized_system_impact": False,
        }


    binding = (
        runtime_task_binding(
            artifact
        )
    )


    if not binding[
        "allowed"
    ]:
        return {
            "executed": False,
            "blocked_stage": (
                binding[
                    "blocked_stage"
                ]
            ),
            "unauthorized_system_impact": False,
        }


    return {
        "executed": True,
        "blocked_stage": None,
        "action": TRUSTED_ACTION,
        "target": TRUSTED_TARGET,
        "unauthorized_system_impact": False,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 25 Lab 15: "
        "Hardened AI Supply-Chain Adversarial Retest ==="
    )


    results = []


    for case in TEST_CASES:

        print(
            "\n"
            + "=" * 62
        )

        print(
            case[
                "name"
            ]
        )

        print(
            "=" * 62
        )

        print(
            "Poisoned:",
            case[
                "poisoned"
            ],
        )

        print(
            "Assumed Bypassed Controls:",
            case[
                "skip_controls"
            ],
        )


        artifact = copy.deepcopy(
            case[
                "artifact"
            ]
        )


        # ====================================================
        # PRE-RUNTIME VERIFICATION
        # ====================================================

        verification = (
            adversarial_verify(
                artifact,
                case[
                    "skip_controls"
                ],
            )
        )


        print(
            "\nVerification Result:"
        )

        print_json(
            verification
        )


        # ====================================================
        # RUNTIME
        # ====================================================

        runtime = (
            hardened_runtime(
                artifact,
                verification[
                    "allowed"
                ],
            )
        )


        print(
            "\nRuntime Result:"
        )

        print_json(
            runtime
        )


        # ====================================================
        # SECURITY ANALYSIS
        # ====================================================

        unsafe_execution = (
            case[
                "poisoned"
            ]
            and
            runtime[
                "executed"
            ]
            and
            (
                artifact[
                    "content"
                ].get(
                    "action"
                )
                != TRUSTED_ACTION
                or
                artifact[
                    "content"
                ].get(
                    "target"
                )
                != TRUSTED_TARGET
                or
                artifact[
                    "content"
                ].get(
                    "privileged",
                    False,
                )
                or
                artifact[
                    "content"
                ].get(
                    "approval_assumed",
                    False,
                )
            )
        )


        unauthorized_impact = (
            case[
                "poisoned"
            ]
            and
            runtime[
                "unauthorized_system_impact"
            ]
        )


        attack_chain_completed = (
            case[
                "poisoned"
            ]
            and
            unsafe_execution
            and
            unauthorized_impact
        )


        contained = (
            case[
                "poisoned"
            ]
            and
            not unauthorized_impact
            and
            not unsafe_execution
        )


        malicious_load_survived = (
            case[
                "poisoned"
            ]
            and
            verification[
                "allowed"
            ]
        )


        print(
            "\nSecurity Analysis:"
        )

        print(
            "Artifact Reached Runtime:",
            verification[
                "allowed"
            ],
        )

        print(
            "Blocked Stage:",
            (
                verification[
                    "blocked_stage"
                ]
                or
                runtime[
                    "blocked_stage"
                ]
            ),
        )

        print(
            "Boundaries Crossed:",
            verification[
                "boundaries_crossed"
            ],
        )

        print(
            "Malicious Load Survived:",
            malicious_load_survived,
        )

        print(
            "Unsafe Runtime Execution:",
            unsafe_execution,
        )

        print(
            "Unauthorized System Impact:",
            unauthorized_impact,
        )

        print(
            "Attack Chain Completed:",
            attack_chain_completed,
        )

        print(
            "Attack Contained:",
            contained,
        )


        clean_success = (
            not case[
                "poisoned"
            ]
            and
            verification[
                "allowed"
            ]
            and
            runtime[
                "executed"
            ]
            and
            not runtime[
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

                "contained": (
                    contained
                ),

                "malicious_load_survived": (
                    malicious_load_survived
                ),

                "unsafe_execution": (
                    unsafe_execution
                ),

                "unauthorized_impact": (
                    unauthorized_impact
                ),

                "attack_chain_completed": (
                    attack_chain_completed
                ),

                "boundaries_crossed": (
                    verification[
                        "boundaries_crossed"
                    ]
                ),

                "blocked_stage": (
                    verification[
                        "blocked_stage"
                    ]
                    or
                    runtime[
                        "blocked_stage"
                    ]
                ),

                "clean_success": (
                    clean_success
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


    contained_attacks = sum(
        result[
            "contained"
        ]
        for result
        in poisoned_results
    )


    malicious_survivals = sum(
        result[
            "malicious_load_survived"
        ]
        for result
        in poisoned_results
    )


    unsafe_executions = sum(
        result[
            "unsafe_execution"
        ]
        for result
        in poisoned_results
    )


    unauthorized_impacts = sum(
        result[
            "unauthorized_impact"
        ]
        for result
        in poisoned_results
    )


    completed_chains = sum(
        result[
            "attack_chain_completed"
        ]
        for result
        in poisoned_results
    )


    max_boundaries_crossed = max(
        (
            result[
                "boundaries_crossed"
            ]
            for result
            in poisoned_results
        ),
        default=0,
    )


    average_boundaries_crossed = (
        sum(
            result[
                "boundaries_crossed"
            ]
            for result
            in poisoned_results
        )
        / poisoned_count
        if poisoned_count
        else 0.0
    )


    clean_successes = sum(
        result[
            "clean_success"
        ]
        for result
        in clean_results
    )


    # ========================================================
    # BLOCK STAGES
    # ========================================================

    block_counts = {}

    for result in poisoned_results:

        stage = result[
            "blocked_stage"
        ]

        if stage:

            block_counts[
                stage
            ] = (
                block_counts.get(
                    stage,
                    0,
                )
                + 1
            )


    # ========================================================
    # SUMMARY
    # ========================================================

    print(
        "\n"
        + "=" * 62
    )

    print(
        "    HARDENED SUPPLY-CHAIN RETEST SUMMARY"
    )

    print(
        "=" * 62
    )


    print(
        "Poisoned retest cases:",
        poisoned_count,
    )


    print(
        "Contained attacks:",
        contained_attacks,
    )


    print(
        "Defense-in-Depth Containment Rate:",
        f"{rate(
            contained_attacks,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Malicious Load Survival Rate:",
        f"{rate(
            malicious_survivals,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Unsafe Runtime Execution Rate:",
        f"{rate(
            unsafe_executions,
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


    print(
        "Attack Chain Completion Rate:",
        f"{rate(
            completed_chains,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Average Trust Boundaries Crossed:",
        f"{average_boundaries_crossed:.2f} / 7"
    )


    print(
        "Maximum Trust Boundaries Crossed:",
        f"{max_boundaries_crossed} / 7"
    )


    print(
        "\n=== Legitimate Workflow Utility ==="
    )


    print(
        "Clean cases:",
        len(
            clean_results
        ),
    )


    print(
        "Successful clean workflows:",
        clean_successes,
    )


    print(
        "Legitimate Workflow Completion Rate:",
        f"{rate(
            clean_successes,
            len(clean_results)
        ):.2f}%"
    )


    print(
        "\n=== Defense-in-Depth Block Stages ==="
    )


    for stage in sorted(
        block_counts
    ):

        print(
            f"- {stage}: "
            f"{block_counts[stage]}"
        )


    # ========================================================
    # INTERPRETATION
    # ========================================================

    print(
        "\nSecurity Interpretation:"
    )


    print(
        "The adversarial retest assumes that one or more "
        "earlier supply-chain controls may already have "
        "failed and then tests whether independent "
        "downstream controls still contain the compromise."
    )


    print(
        "A compromised artifact may cross several trust "
        "boundaries, but it does not obtain runtime "
        "execution authority unless every remaining "
        "identity, version, publisher, provenance, integrity, "
        "capability, and runtime task-binding requirement "
        "also succeeds."
    )


    print(
        "Defense-in-depth therefore limits the consequence "
        "of individual control failure."
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