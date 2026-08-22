"""
Day 25 Lab 13
End-to-End AI Supply-Chain Attack

Purpose:
Combine multiple pre-runtime supply-chain weaknesses into complete
attack chains and measure whether malicious artifacts can cross trust
boundaries and cause unauthorized runtime impact.

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
# TRUSTED BASELINE
# ============================================================

TRUSTED_TARGET = "R-2502"
RESTRICTED_TARGET = "R-2599"

TRUSTED_ACTION = "read_record"


TRUSTED_PACKAGE = finalize_artifact(
    {
        "artifact_id": "PKG-2513",
        "name": "ai-review-runtime",
        "version": "1.0.0",
        "source": "internal_registry",
        "publisher": "trusted_ai_team",
        "artifact_type": "runtime_package",

        "metadata": {
            "build_id": "BUILD-2513-A",
            "commit": "trusted2513",
            "signature_status": "verified",
            "provenance": "trusted-build-pipeline",
            "sbom_reference": "SBOM-2513-TRUSTED",
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
    TRUSTED_PACKAGE[
        "sha256"
    ]
)


TRUSTED_METADATA = {
    "name": TRUSTED_PACKAGE[
        "name"
    ],
    "version": TRUSTED_PACKAGE[
        "version"
    ],
    "publisher": TRUSTED_PACKAGE[
        "publisher"
    ],
    "source": TRUSTED_PACKAGE[
        "source"
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
    "signature_status": TRUSTED_PACKAGE[
        "metadata"
    ][
        "signature_status"
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
}


# ============================================================
# MALICIOUS ARTIFACTS
# ============================================================

MALICIOUS_HIGH_VERSION = finalize_artifact(
    {
        "artifact_id": "PKG-2513-PUBLIC",
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
        "artifact_id": "PKG-2513-CLONE",
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


MALICIOUS_SELF_ASSERTED_HASH = finalize_artifact(
    {
        "artifact_id": "PKG-2513-HASH",
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

        "metadata": {
            "build_id": TRUSTED_METADATA[
                "build_id"
            ],
            "commit": TRUSTED_METADATA[
                "commit"
            ],
            "signature_status": "verified",
            "provenance": TRUSTED_METADATA[
                "provenance"
            ],
            "sbom_reference": TRUSTED_METADATA[
                "sbom_reference"
            ],
        },

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

        # Attacker-controlled claim
        "claimed_sha256": TRUSTED_HASH,
    }
)


# ============================================================
# TEST CASES
# ============================================================

TEST_CASES = [

    {
        "name": (
            "Case 1: Clean trusted supply-chain"
        ),
        "poisoned": False,
        "candidates": [
            copy.deepcopy(
                TRUSTED_PACKAGE
            ),
        ],
        "integrity_mode": (
            "full_hash"
        ),
    },

    {
        "name": (
            "Case 2: Dependency confusion "
            "higher public version"
        ),
        "poisoned": True,
        "candidates": [
            copy.deepcopy(
                TRUSTED_PACKAGE
            ),
            copy.deepcopy(
                MALICIOUS_HIGH_VERSION
            ),
        ],
        "integrity_mode": (
            "weak"
        ),
    },

    {
        "name": (
            "Case 3: Full trusted metadata clone"
        ),
        "poisoned": True,
        "candidates": [
            copy.deepcopy(
                MALICIOUS_METADATA_CLONE
            ),
        ],
        "integrity_mode": (
            "metadata_only"
        ),
    },

    {
        "name": (
            "Case 4: Self-asserted trusted hash"
        ),
        "poisoned": True,
        "candidates": [
            copy.deepcopy(
                MALICIOUS_SELF_ASSERTED_HASH
            ),
        ],
        "integrity_mode": (
            "self_asserted_hash"
        ),
    },

    {
        "name": (
            "Case 5: Public package with "
            "publisher impersonation"
        ),
        "poisoned": True,
        "candidates": [
            copy.deepcopy(
                MALICIOUS_SELF_ASSERTED_HASH
            ),
        ],
        "integrity_mode": (
            "metadata_only"
        ),
    },

    {
        "name": (
            "Case 6: Multi-control bypass chain"
        ),
        "poisoned": True,
        "candidates": [
            copy.deepcopy(
                TRUSTED_PACKAGE
            ),
            copy.deepcopy(
                MALICIOUS_SELF_ASSERTED_HASH
            ),
            copy.deepcopy(
                MALICIOUS_HIGH_VERSION
            ),
        ],
        "integrity_mode": (
            "weak"
        ),
    },

    {
        "name": (
            "Case 7: Second clean trusted supply-chain"
        ),
        "poisoned": False,
        "candidates": [
            copy.deepcopy(
                TRUSTED_PACKAGE
            ),
        ],
        "integrity_mode": (
            "full_hash"
        ),
    },
]


# ============================================================
# VULNERABLE RESOLVER
# ============================================================

def version_tuple(version):
    return tuple(
        int(part)
        for part
        in version.split(".")
    )


def vulnerable_resolve(
    candidates,
):
    """
    Select highest version with matching package name.
    Does not enforce trusted source or artifact identity.
    """

    matches = [
        artifact
        for artifact
        in candidates
        if artifact.get(
            "name"
        )
        == TRUSTED_PACKAGE[
            "name"
        ]
    ]

    if not matches:
        return {
            "resolved": False,
            "artifact": None,
        }

    selected = max(
        matches,
        key=lambda artifact:
        version_tuple(
            artifact[
                "version"
            ]
        ),
    )

    return {
        "resolved": True,
        "artifact": copy.deepcopy(
            selected
        ),
    }


# ============================================================
# VULNERABLE METADATA TRUST
# ============================================================

def metadata_trust(
    artifact,
):

    metadata = artifact.get(
        "metadata",
        {},
    )

    checks = {
        "name_match": (
            artifact.get(
                "name"
            )
            == TRUSTED_METADATA[
                "name"
            ]
        ),

        "publisher_match": (
            artifact.get(
                "publisher"
            )
            == TRUSTED_METADATA[
                "publisher"
            ]
        ),

        "signature_claim_verified": (
            metadata.get(
                "signature_status"
            )
            == "verified"
        ),

        "provenance_claim_match": (
            metadata.get(
                "provenance"
            )
            == TRUSTED_METADATA[
                "provenance"
            ]
        ),

        "sbom_claim_match": (
            metadata.get(
                "sbom_reference"
            )
            == TRUSTED_METADATA[
                "sbom_reference"
            ]
        ),
    }

    trusted = all(
        checks.values()
    )

    return {
        "trusted_by_metadata": trusted,
        **checks,
    }


# ============================================================
# VULNERABLE INTEGRITY VERIFICATION
# ============================================================

def vulnerable_integrity_check(
    artifact,
    mode,
):

    actual_hash = (
        calculate_hash(
            artifact
        )
    )


    if mode == "full_hash":

        accepted = (
            actual_hash
            == TRUSTED_HASH
        )


    elif mode == "metadata_only":

        # Weak:
        # checks metadata claims, not complete artifact digest.

        metadata = artifact.get(
            "metadata",
            {}
        )

        accepted = (
            metadata.get(
                "signature_status"
            )
            == "verified"
            and
            metadata.get(
                "provenance"
            )
            == TRUSTED_METADATA[
                "provenance"
            ]
        )


    elif mode == "self_asserted_hash":

        accepted = (
            artifact.get(
                "claimed_sha256"
            )
            == TRUSTED_HASH
        )


    elif mode == "weak":

        # Simulates a permissive integrity layer.

        accepted = True


    else:

        accepted = False


    return {
        "accepted": accepted,
        "mode": mode,
        "actual_hash": actual_hash,
        "trusted_hash": TRUSTED_HASH,
        "actual_hash_match": (
            actual_hash
            == TRUSTED_HASH
        ),
    }


# ============================================================
# VULNERABLE LOADER
# ============================================================

def vulnerable_load(
    artifact,
    metadata_result,
    integrity_result,
):

    structurally_valid = (
        artifact is not None
        and
        artifact.get(
            "artifact_type"
        )
        == "runtime_package"
        and
        isinstance(
            artifact.get(
                "content"
            ),
            dict,
        )
    )


    loaded = (
        structurally_valid
        and
        (
            metadata_result[
                "trusted_by_metadata"
            ]
            or
            integrity_result[
                "accepted"
            ]
        )
    )


    return {
        "loaded": loaded,
        "structurally_valid": (
            structurally_valid
        ),
        "metadata_trusted": (
            metadata_result[
                "trusted_by_metadata"
            ]
        ),
        "integrity_accepted": (
            integrity_result[
                "accepted"
            ]
        ),
    }


# ============================================================
# SYNTHETIC RUNTIME
# ============================================================

def execute_runtime(
    artifact,
    loaded,
):

    if not loaded:

        return {
            "executed": False,
            "action": None,
            "target": None,
            "privileged": False,
            "restricted_target": False,
            "privileged_action": False,
            "unauthorized_system_impact": False,
        }


    content = artifact[
        "content"
    ]


    action = content.get(
        "action",
        TRUSTED_ACTION,
    )


    target = content.get(
        "target",
        TRUSTED_TARGET,
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


    restricted_target = (
        target
        == RESTRICTED_TARGET
    )


    privileged_action = (
        action
        == "delete_record"
    )


    executed = True


    unauthorized_impact = (
        executed
        and
        (
            restricted_target
            or
            privileged_action
            or
            privileged
            or
            approval_assumed
        )
    )


    return {
        "executed": executed,
        "action": action,
        "target": target,
        "privileged": privileged,
        "approval_assumed": (
            approval_assumed
        ),
        "restricted_target": (
            restricted_target
        ),
        "privileged_action": (
            privileged_action
        ),
        "unauthorized_system_impact": (
            unauthorized_impact
        ),
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 25 Lab 13: "
        "End-to-End AI Supply-Chain Attack ==="
    )


    results = []


    for case in TEST_CASES:

        print(
            "\n"
            + "=" * 56
        )

        print(
            case[
                "name"
            ]
        )

        print(
            "=" * 56
        )

        print(
            "Poisoned:",
            case[
                "poisoned"
            ],
        )


        # ====================================================
        # RESOLUTION
        # ====================================================

        resolution = (
            vulnerable_resolve(
                copy.deepcopy(
                    case[
                        "candidates"
                    ]
                )
            )
        )


        artifact = (
            resolution[
                "artifact"
            ]
        )


        print(
            "\nResolution Result:"
        )

        print_json(
            {
                "resolved": (
                    resolution[
                        "resolved"
                    ]
                ),
                "artifact_id": (
                    artifact.get(
                        "artifact_id"
                    )
                    if artifact
                    else None
                ),
                "name": (
                    artifact.get(
                        "name"
                    )
                    if artifact
                    else None
                ),
                "version": (
                    artifact.get(
                        "version"
                    )
                    if artifact
                    else None
                ),
                "source": (
                    artifact.get(
                        "source"
                    )
                    if artifact
                    else None
                ),
                "publisher": (
                    artifact.get(
                        "publisher"
                    )
                    if artifact
                    else None
                ),
            }
        )


        if artifact is None:

            continue


        # ====================================================
        # METADATA TRUST
        # ====================================================

        metadata_result = (
            metadata_trust(
                artifact
            )
        )


        print(
            "\nMetadata Trust:"
        )

        print_json(
            metadata_result
        )


        # ====================================================
        # INTEGRITY
        # ====================================================

        integrity_result = (
            vulnerable_integrity_check(
                artifact,
                case[
                    "integrity_mode"
                ],
            )
        )


        print(
            "\nIntegrity Verification:"
        )

        print_json(
            integrity_result
        )


        # ====================================================
        # LOAD
        # ====================================================

        load_result = (
            vulnerable_load(
                artifact,
                metadata_result,
                integrity_result,
            )
        )


        print(
            "\nArtifact Loading:"
        )

        print_json(
            load_result
        )


        # ====================================================
        # RUNTIME
        # ====================================================

        runtime = (
            execute_runtime(
                artifact,
                load_result[
                    "loaded"
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
        # ANALYSIS
        # ====================================================

        substituted_artifact = (
            artifact[
                "artifact_id"
            ]
            != TRUSTED_PACKAGE[
                "artifact_id"
            ]
        )


        artifact_trust_bypass = (
            case[
                "poisoned"
            ]
            and
            substituted_artifact
            and
            load_result[
                "loaded"
            ]
        )


        malicious_artifact_loaded = (
            case[
                "poisoned"
            ]
            and
            substituted_artifact
            and
            load_result[
                "loaded"
            ]
        )


        supply_chain_propagation = (
            malicious_artifact_loaded
            and
            runtime[
                "executed"
            ]
        )


        runtime_compromise = (
            case[
                "poisoned"
            ]
            and
            runtime[
                "unauthorized_system_impact"
            ]
        )


        unauthorized_impact = (
            runtime_compromise
        )


        attack_chain_completed = (
            case[
                "poisoned"
            ]
            and
            substituted_artifact
            and
            load_result[
                "loaded"
            ]
            and
            runtime[
                "executed"
            ]
            and
            runtime[
                "unauthorized_system_impact"
            ]
        )


        print(
            "\nSecurity Analysis:"
        )

        print(
            "Artifact Substituted:",
            substituted_artifact,
        )

        print(
            "Artifact Trust Bypass:",
            artifact_trust_bypass,
        )

        print(
            "Malicious Artifact Loaded:",
            malicious_artifact_loaded,
        )

        print(
            "Supply-Chain Propagation:",
            supply_chain_propagation,
        )

        print(
            "Runtime Compromise:",
            runtime_compromise,
        )

        print(
            "Unauthorized System Impact:",
            unauthorized_impact,
        )

        print(
            "Attack Chain Completed:",
            attack_chain_completed,
        )


        clean_safe = (
            not case[
                "poisoned"
            ]
            and
            not substituted_artifact
            and
            load_result[
                "loaded"
            ]
            and
            integrity_result[
                "actual_hash_match"
            ]
            and
            runtime[
                "executed"
            ]
            and
            runtime[
                "action"
            ]
            == TRUSTED_ACTION
            and
            runtime[
                "target"
            ]
            == TRUSTED_TARGET
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

                "artifact_trust_bypass": (
                    artifact_trust_bypass
                ),

                "malicious_artifact_loaded": (
                    malicious_artifact_loaded
                ),

                "supply_chain_propagation": (
                    supply_chain_propagation
                ),

                "runtime_compromise": (
                    runtime_compromise
                ),

                "unauthorized_impact": (
                    unauthorized_impact
                ),

                "attack_chain_completed": (
                    attack_chain_completed
                ),

                "clean_safe": (
                    clean_safe
                ),
            }
        )


    # ========================================================
    # SUMMARY
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


    trust_bypasses = sum(
        result[
            "artifact_trust_bypass"
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


    propagation_cases = sum(
        result[
            "supply_chain_propagation"
        ]
        for result
        in poisoned_results
    )


    runtime_compromises = sum(
        result[
            "runtime_compromise"
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


    clean_safe = sum(
        result[
            "clean_safe"
        ]
        for result
        in clean_results
    )


    print(
        "\n"
        + "=" * 56
    )

    print(
        "       END-TO-END SUPPLY-CHAIN SUMMARY"
    )

    print(
        "=" * 56
    )


    print(
        "Poisoned end-to-end cases:",
        poisoned_count,
    )


    print(
        "Artifact Trust Bypass Rate:",
        f"{rate(
            trust_bypasses,
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
        "Supply-Chain Propagation Rate:",
        f"{rate(
            propagation_cases,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Runtime Compromise Rate:",
        f"{rate(
            runtime_compromises,
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
        "End-to-End Attack Chain Completion Rate:",
        f"{rate(
            completed_chains,
            poisoned_count
        ):.2f}%"
    )


    print(
        "\n=== Clean Utility ==="
    )


    print(
        "Clean end-to-end cases:",
        len(
            clean_results
        ),
    )


    print(
        "Clean safe workflows:",
        clean_safe,
    )


    print(
        "Clean Workflow Utility Rate:",
        f"{rate(
            clean_safe,
            len(clean_results)
        ):.2f}%"
    )


    print(
        "\nSecurity Interpretation:"
    )


    print(
        "The vulnerable end-to-end supply-chain "
        "architecture allows malicious artifacts to "
        "win resolution, satisfy weak metadata or "
        "integrity checks, load successfully, and "
        "influence runtime execution."
    )


    print(
        "Supply-chain security therefore cannot be "
        "implemented as isolated checks. Resolution, "
        "provenance, integrity, loading, capability, "
        "and runtime execution controls must form one "
        "continuous trust chain."
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