"""
Day 25 Lab 14
AI Supply-Chain Trust & Containment Controls

Purpose:
Demonstrate a hardened AI supply-chain architecture that treats every
artifact as untrusted until source, identity, version, publisher, provenance,
integrity, capability, and runtime authorization checks all succeed.

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
        ).encode(
            "utf-8"
        )
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
# TRUSTED TASK
# ============================================================

TRUSTED_ACTION = "read_record"
TRUSTED_TARGET = "R-2502"
RESTRICTED_TARGET = "R-2599"


# ============================================================
# TRUSTED ARTIFACT
# ============================================================

TRUSTED_PACKAGE = finalize_artifact(
    {
        "artifact_id": "PKG-2514",
        "name": "ai-review-runtime",
        "version": "1.0.0",
        "source": "internal_registry",
        "publisher": "trusted_ai_team",
        "artifact_type": "runtime_package",

        "metadata": {
            "build_id": "BUILD-2514-A",
            "commit": "trusted2514",
            "signature_status": "verified",
            "provenance": "trusted-build-pipeline",
            "sbom_reference": "SBOM-2514-TRUSTED",
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


TRUSTED_MANIFEST = {
    "artifact_id": TRUSTED_PACKAGE[
        "artifact_id"
    ],

    "name": TRUSTED_PACKAGE[
        "name"
    ],

    "version": TRUSTED_PACKAGE[
        "version"
    ],

    "source": TRUSTED_PACKAGE[
        "source"
    ],

    "publisher": TRUSTED_PACKAGE[
        "publisher"
    ],

    "artifact_type": TRUSTED_PACKAGE[
        "artifact_type"
    ],

    "build_id": TRUSTED_PACKAGE[
        "metadata"
    ][
        "build_id"
    ],

    "commit": TRUSTED_PACKAGE[
        "metadata"
    ][
        "commit"
    ],

    "provenance": TRUSTED_PACKAGE[
        "metadata"
    ][
        "provenance"
    ],

    "sbom_reference": TRUSTED_PACKAGE[
        "metadata"
    ][
        "sbom_reference"
    ],

    "sha256": TRUSTED_PACKAGE[
        "sha256"
    ],

    "capabilities": {
        "read_record",
    },
}


# ============================================================
# ATTACK ARTIFACTS
# ============================================================

MALICIOUS_HIGH_VERSION = finalize_artifact(
    {
        "artifact_id": "PKG-2514-PUBLIC",
        "name": "ai-review-runtime",
        "version": "9.9.9",
        "source": "public_registry",
        "publisher": "unknown_publisher",
        "artifact_type": "runtime_package",

        "metadata": {
            "build_id": "ATTACKER-BUILD",
            "commit": "evilcommit",
            "signature_status": "unverified",
            "provenance": "unknown",
            "sbom_reference": "SBOM-UNKNOWN",
        },

        "capabilities": [
            "read_record",
            "delete_record",
        ],

        "content": {
            "action": "delete_record",
            "target": RESTRICTED_TARGET,
            "privileged": True,
            "approval_assumed": False,
        },
    }
)


MALICIOUS_METADATA_CLONE = finalize_artifact(
    {
        "artifact_id": "PKG-2514-CLONE",
        "name": TRUSTED_PACKAGE[
            "name"
        ],
        "version": TRUSTED_PACKAGE[
            "version"
        ],
        "source": TRUSTED_PACKAGE[
            "source"
        ],
        "publisher": TRUSTED_PACKAGE[
            "publisher"
        ],
        "artifact_type": "runtime_package",

        "metadata": copy.deepcopy(
            TRUSTED_PACKAGE[
                "metadata"
            ]
        ),

        "capabilities": [
            "read_record",
            "delete_record",
        ],

        "content": {
            "action": "delete_record",
            "target": RESTRICTED_TARGET,
            "privileged": True,
            "approval_assumed": True,
        },
    }
)


MALICIOUS_HASH_CLAIM = finalize_artifact(
    {
        "artifact_id": "PKG-2514-HASH",
        "name": TRUSTED_PACKAGE[
            "name"
        ],
        "version": TRUSTED_PACKAGE[
            "version"
        ],
        "source": "public_registry",
        "publisher": TRUSTED_PACKAGE[
            "publisher"
        ],
        "artifact_type": "runtime_package",

        "metadata": copy.deepcopy(
            TRUSTED_PACKAGE[
                "metadata"
            ]
        ),

        "capabilities": [
            "read_record",
            "delete_record",
        ],

        "content": {
            "action": "delete_record",
            "target": RESTRICTED_TARGET,
            "privileged": True,
            "approval_assumed": True,
        },

        "claimed_sha256": (
            TRUSTED_PACKAGE[
                "sha256"
            ]
        ),
    }
)


MALICIOUS_CAPABILITY_EXPANSION = finalize_artifact(
    {
        **{
            key: copy.deepcopy(value)
            for key, value
            in TRUSTED_PACKAGE.items()
            if key != "sha256"
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
            "approval_assumed": False,
        },
    }
)


# ============================================================
# TEST CASES
# ============================================================

TEST_CASES = [

    {
        "name": (
            "Case 1: Clean trusted artifact"
        ),
        "poisoned": False,
        "artifact": copy.deepcopy(
            TRUSTED_PACKAGE
        ),
    },

    {
        "name": (
            "Case 2: Higher-version public substitution"
        ),
        "poisoned": True,
        "artifact": copy.deepcopy(
            MALICIOUS_HIGH_VERSION
        ),
    },

    {
        "name": (
            "Case 3: Full trusted metadata clone"
        ),
        "poisoned": True,
        "artifact": copy.deepcopy(
            MALICIOUS_METADATA_CLONE
        ),
    },

    {
        "name": (
            "Case 4: Self-asserted trusted hash"
        ),
        "poisoned": True,
        "artifact": copy.deepcopy(
            MALICIOUS_HASH_CLAIM
        ),
    },

    {
        "name": (
            "Case 5: Capability expansion"
        ),
        "poisoned": True,
        "artifact": copy.deepcopy(
            MALICIOUS_CAPABILITY_EXPANSION
        ),
    },

    {
        "name": (
            "Case 6: Multi-control bypass attempt"
        ),
        "poisoned": True,
        "artifact": copy.deepcopy(
            MALICIOUS_METADATA_CLONE
        ),
    },

    {
        "name": (
            "Case 7: Second clean trusted artifact"
        ),
        "poisoned": False,
        "artifact": copy.deepcopy(
            TRUSTED_PACKAGE
        ),
    },
]


# ============================================================
# HARDENED VERIFICATION PIPELINE
# ============================================================

def hardened_verify(
    artifact,
):
    """
    Fail-closed validation.

    Every trust property must succeed.
    """

    # --------------------------------------------------------
    # SOURCE
    # --------------------------------------------------------

    if (
        artifact.get(
            "source"
        )
        != TRUSTED_MANIFEST[
            "source"
        ]
    ):
        return {
            "allowed": False,
            "blocked_stage": (
                "SOURCE_TRUST"
            ),
            "reason": (
                "Artifact source is not trusted."
            ),
        }


    # --------------------------------------------------------
    # IDENTITY
    # --------------------------------------------------------

    if (
        artifact.get(
            "artifact_id"
        )
        != TRUSTED_MANIFEST[
            "artifact_id"
        ]
        or
        artifact.get(
            "name"
        )
        != TRUSTED_MANIFEST[
            "name"
        ]
    ):
        return {
            "allowed": False,
            "blocked_stage": (
                "ARTIFACT_IDENTITY"
            ),
            "reason": (
                "Artifact identity mismatch."
            ),
        }


    # --------------------------------------------------------
    # VERSION PINNING
    # --------------------------------------------------------

    if (
        artifact.get(
            "version"
        )
        != TRUSTED_MANIFEST[
            "version"
        ]
    ):
        return {
            "allowed": False,
            "blocked_stage": (
                "VERSION_BINDING"
            ),
            "reason": (
                "Artifact version does not match "
                "the pinned trusted version."
            ),
        }


    # --------------------------------------------------------
    # PUBLISHER
    # --------------------------------------------------------

    if (
        artifact.get(
            "publisher"
        )
        != TRUSTED_MANIFEST[
            "publisher"
        ]
    ):
        return {
            "allowed": False,
            "blocked_stage": (
                "PUBLISHER_IDENTITY"
            ),
            "reason": (
                "Publisher identity mismatch."
            ),
        }


    # --------------------------------------------------------
    # TYPE
    # --------------------------------------------------------

    if (
        artifact.get(
            "artifact_type"
        )
        != TRUSTED_MANIFEST[
            "artifact_type"
        ]
    ):
        return {
            "allowed": False,
            "blocked_stage": (
                "ARTIFACT_TYPE"
            ),
            "reason": (
                "Unexpected artifact type."
            ),
        }


    # --------------------------------------------------------
    # PROVENANCE
    # --------------------------------------------------------

    metadata = artifact.get(
        "metadata",
        {},
    )

    provenance_valid = (
        metadata.get(
            "build_id"
        )
        == TRUSTED_MANIFEST[
            "build_id"
        ]
        and
        metadata.get(
            "commit"
        )
        == TRUSTED_MANIFEST[
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
        == TRUSTED_MANIFEST[
            "provenance"
        ]
        and
        metadata.get(
            "sbom_reference"
        )
        == TRUSTED_MANIFEST[
            "sbom_reference"
        ]
    )

    if not provenance_valid:
        return {
            "allowed": False,
            "blocked_stage": (
                "PROVENANCE"
            ),
            "reason": (
                "Artifact provenance validation failed."
            ),
        }


    # --------------------------------------------------------
    # FULL ARTIFACT INTEGRITY
    # --------------------------------------------------------

    actual_hash = calculate_hash(
        artifact
    )

    if (
        actual_hash
        != TRUSTED_MANIFEST[
            "sha256"
        ]
    ):
        return {
            "allowed": False,
            "blocked_stage": (
                "FULL_INTEGRITY"
            ),
            "reason": (
                "Full artifact digest mismatch."
            ),
            "actual_hash": actual_hash,
            "expected_hash": (
                TRUSTED_MANIFEST[
                    "sha256"
                ]
            ),
        }


    # --------------------------------------------------------
    # CAPABILITY POLICY
    # --------------------------------------------------------

    actual_capabilities = set(
        artifact.get(
            "capabilities",
            [],
        )
    )

    if (
        actual_capabilities
        != TRUSTED_MANIFEST[
            "capabilities"
        ]
    ):
        return {
            "allowed": False,
            "blocked_stage": (
                "CAPABILITY_POLICY"
            ),
            "reason": (
                "Artifact capability set differs "
                "from trusted policy."
            ),
        }


    return {
        "allowed": True,
        "blocked_stage": None,
        "reason": (
            "All supply-chain trust controls passed."
        ),
    }


# ============================================================
# HARDENED RUNTIME AUTHORIZATION
# ============================================================

def hardened_execute(
    artifact,
    verification,
):

    if not verification[
        "allowed"
    ]:
        return {
            "executed": False,
            "action": None,
            "target": None,
            "restricted_target": False,
            "privileged_action": False,
            "unauthorized_system_impact": False,
            "reason": (
                "Artifact was not authorized to load."
            ),
        }


    content = artifact[
        "content"
    ]


    proposed_action = content.get(
        "action"
    )

    proposed_target = content.get(
        "target"
    )

    proposed_privileged = bool(
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


    # --------------------------------------------------------
    # TRUSTED TASK BINDING
    # --------------------------------------------------------

    if (
        proposed_action
        != TRUSTED_ACTION
    ):
        return {
            "executed": False,
            "action": proposed_action,
            "target": proposed_target,
            "restricted_target": (
                proposed_target
                == RESTRICTED_TARGET
            ),
            "privileged_action": (
                proposed_action
                == "delete_record"
            ),
            "unauthorized_system_impact": False,
            "reason": (
                "Runtime action does not match "
                "trusted task binding."
            ),
        }


    if (
        proposed_target
        != TRUSTED_TARGET
    ):
        return {
            "executed": False,
            "action": proposed_action,
            "target": proposed_target,
            "restricted_target": (
                proposed_target
                == RESTRICTED_TARGET
            ),
            "privileged_action": False,
            "unauthorized_system_impact": False,
            "reason": (
                "Runtime target does not match "
                "trusted task binding."
            ),
        }


    if (
        proposed_privileged
        or
        approval_assumed
    ):
        return {
            "executed": False,
            "action": proposed_action,
            "target": proposed_target,
            "restricted_target": False,
            "privileged_action": False,
            "unauthorized_system_impact": False,
            "reason": (
                "Untrusted privilege or approval state rejected."
            ),
        }


    return {
        "executed": True,
        "action": proposed_action,
        "target": proposed_target,
        "restricted_target": False,
        "privileged_action": False,
        "unauthorized_system_impact": False,
        "reason": (
            "Trusted runtime execution controls passed."
        ),
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 25 Lab 14: "
        "AI Supply-Chain Trust & Containment Controls ==="
    )


    results = []


    for case in TEST_CASES:

        print(
            "\n"
            + "=" * 58
        )

        print(
            case[
                "name"
            ]
        )

        print(
            "=" * 58
        )

        print(
            "Poisoned:",
            case[
                "poisoned"
            ],
        )


        artifact = copy.deepcopy(
            case[
                "artifact"
            ]
        )


        # ====================================================
        # VERIFICATION
        # ====================================================

        verification = (
            hardened_verify(
                artifact
            )
        )


        print(
            "\nSupply-Chain Verification:"
        )

        print_json(
            verification
        )


        # ====================================================
        # EXECUTION
        # ====================================================

        execution = (
            hardened_execute(
                artifact,
                verification,
            )
        )


        print(
            "\nRuntime Execution:"
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
            verification[
                "allowed"
            ]
        )


        contained = (
            case[
                "poisoned"
            ]
            and
            (
                not verification[
                    "allowed"
                ]
                or
                not execution[
                    "executed"
                ]
            )
            and
            not execution[
                "unauthorized_system_impact"
            ]
        )


        attack_chain_completed = (
            case[
                "poisoned"
            ]
            and
            verification[
                "allowed"
            ]
            and
            execution[
                "executed"
            ]
            and
            execution[
                "unauthorized_system_impact"
            ]
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


        print(
            "\nSecurity Analysis:"
        )

        print(
            "Artifact Authorized to Load:",
            verification[
                "allowed"
            ],
        )

        print(
            "Blocked Stage:",
            verification[
                "blocked_stage"
            ],
        )

        print(
            "Malicious Artifact Loaded:",
            malicious_artifact_loaded,
        )

        print(
            "Attack Contained:",
            contained,
        )

        print(
            "Runtime Executed:",
            execution[
                "executed"
            ],
        )

        print(
            "Unauthorized System Impact:",
            unauthorized_impact,
        )

        print(
            "Attack Chain Completed:",
            attack_chain_completed,
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
            execution[
                "executed"
            ]
            and
            execution[
                "action"
            ]
            == TRUSTED_ACTION
            and
            execution[
                "target"
            ]
            == TRUSTED_TARGET
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

                "contained": (
                    contained
                ),

                "malicious_artifact_loaded": (
                    malicious_artifact_loaded
                ),

                "attack_chain_completed": (
                    attack_chain_completed
                ),

                "unauthorized_impact": (
                    unauthorized_impact
                ),

                "blocked_stage": (
                    verification[
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


    malicious_loads = sum(
        result[
            "malicious_artifact_loaded"
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


    unauthorized_impacts = sum(
        result[
            "unauthorized_impact"
        ]
        for result
        in poisoned_results
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

        if stage is not None:

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
        + "=" * 58
    )

    print(
        "    SUPPLY-CHAIN CONTAINMENT SUMMARY"
    )

    print(
        "=" * 58
    )


    print(
        "Poisoned attack cases:",
        poisoned_count,
    )


    print(
        "Contained attacks:",
        contained_attacks,
    )


    print(
        "Containment Rate:",
        f"{rate(
            contained_attacks,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Malicious Artifact Load Rate:",
        f"{rate(
            malicious_loads,
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
        "\n=== Containment Stages ==="
    )


    if block_counts:

        for stage in sorted(
            block_counts
        ):

            print(
                f"- {stage}: "
                f"{block_counts[stage]}"
            )

    else:

        print(
            "- No poisoned artifact reached "
            "a block stage."
        )


    # ========================================================
    # INTERPRETATION
    # ========================================================

    print(
        "\nSecurity Interpretation:"
    )


    print(
        "The hardened architecture treats every "
        "AI supply-chain artifact as untrusted until "
        "source, identity, version, publisher, provenance, "
        "full integrity, capability, and runtime task "
        "binding checks all succeed."
    )


    print(
        "A malicious artifact cannot become execution "
        "authority simply because it is available, "
        "structurally valid, metadata-compatible, or "
        "functionally usable."
    )


    print(
        "Containment depends on fail-closed trust "
        "boundaries rather than on any single metadata "
        "field, hash claim, or model behavior."
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