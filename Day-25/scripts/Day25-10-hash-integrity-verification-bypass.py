"""
Day 25 Lab 10
Hash / Integrity Verification Bypass

Purpose:
Test whether weak artifact-integrity controls can be bypassed when
hash verification is incomplete, stale, attacker-controlled, or performed
over only part of the artifact.

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


def sha256_value(value):

    return hashlib.sha256(
        canonical_json(
            value
        ).encode(
            "utf-8"
        )
    ).hexdigest()


def print_json(value):

    print(
        json.dumps(
            value,
            indent=2,
        )
    )


# ============================================================
# TRUSTED ARTIFACT
# ============================================================

TRUSTED_ARTIFACT = {

    "artifact_id": "MODEL-2510",

    "name": "integrity-review-model",

    "version": "1.0.0",

    "publisher": "trusted_ai_team",

    "artifact_type": "model",

    "metadata": {
        "build_id": "BUILD-2510-A",
        "source": "internal_registry",
    },

    "content": {
        "behavior": "safe_review",
        "default_action": "read_record",
        "default_target": "R-2502",
        "allow_privileged_action": False,
    },
}


TRUSTED_FULL_HASH = sha256_value(
    TRUSTED_ARTIFACT
)


TRUSTED_CONTENT_HASH = sha256_value(
    TRUSTED_ARTIFACT[
        "content"
    ]
)


TRUSTED_METADATA_HASH = sha256_value(
    TRUSTED_ARTIFACT[
        "metadata"
    ]
)


# ============================================================
# MALICIOUS CONTENT
# ============================================================

MALICIOUS_CONTENT = {

    "behavior": "restricted_override",

    "default_action": "delete_record",

    "default_target": "R-2599",

    "allow_privileged_action": True,
}


# ============================================================
# TEST CASES
# ============================================================

TEST_CASES = [

    {
        "name": (
            "Case 1: Clean full-hash verification"
        ),

        "poisoned": False,

        "mode": "full_hash",

        "artifact": copy.deepcopy(
            TRUSTED_ARTIFACT
        ),
    },

    {
        "name": (
            "Case 2: Metadata-only hashing"
        ),

        "poisoned": True,

        "mode": "metadata_only",

        "artifact": {
            **copy.deepcopy(
                TRUSTED_ARTIFACT
            ),

            "content": copy.deepcopy(
                MALICIOUS_CONTENT
            ),
        },
    },

    {
        "name": (
            "Case 3: Stale trusted digest reused"
        ),

        "poisoned": True,

        "mode": "stale_digest",

        "artifact": {
            **copy.deepcopy(
                TRUSTED_ARTIFACT
            ),

            "content": copy.deepcopy(
                MALICIOUS_CONTENT
            ),
        },
    },

    {
        "name": (
            "Case 4: Attacker-controlled digest field"
        ),

        "poisoned": True,

        "mode": "self_asserted_hash",

        "artifact": {
            **copy.deepcopy(
                TRUSTED_ARTIFACT
            ),

            "content": copy.deepcopy(
                MALICIOUS_CONTENT
            ),

            "sha256": TRUSTED_FULL_HASH,
        },
    },

    {
        "name": (
            "Case 5: Security-sensitive field excluded"
        ),

        "poisoned": True,

        "mode": "excluded_field",

        "artifact": {
            **copy.deepcopy(
                TRUSTED_ARTIFACT
            ),

            "content": {
                **copy.deepcopy(
                    TRUSTED_ARTIFACT[
                        "content"
                    ]
                ),

                "runtime_override": {
                    "action": "delete_record",
                    "target": "R-2599",
                    "privileged": True,
                },
            },
        },
    },

    {
        "name": (
            "Case 6: Canonicalization mismatch"
        ),

        "poisoned": True,

        "mode": "weak_canonicalization",

        "artifact": {
            **copy.deepcopy(
                TRUSTED_ARTIFACT
            ),

            "content": copy.deepcopy(
                MALICIOUS_CONTENT
            ),

            "display_hash": (
                TRUSTED_FULL_HASH
            ),
        },
    },

    {
        "name": (
            "Case 7: Content hash valid, metadata tampered"
        ),

        "poisoned": True,

        "mode": "content_only",

        "artifact": {
            **copy.deepcopy(
                TRUSTED_ARTIFACT
            ),

            "metadata": {
                "build_id": "ATTACKER-BUILD",
                "source": "public_registry",
                "runtime_target": "R-2599",
                "runtime_action": "delete_record",
            },
        },
    },

    {
        "name": (
            "Case 8: Second clean full-hash verification"
        ),

        "poisoned": False,

        "mode": "full_hash",

        "artifact": copy.deepcopy(
            TRUSTED_ARTIFACT
        ),
    },
]


# ============================================================
# VULNERABLE INTEGRITY VERIFIER
# ============================================================

def vulnerable_verify(
    artifact,
    mode,
):
    """
    Intentionally weak integrity verifier.

    Different modes simulate common design mistakes.
    """

    if mode == "full_hash":

        calculated = sha256_value(
            artifact
        )

        accepted = (
            calculated
            == TRUSTED_FULL_HASH
        )

        return {
            "accepted": accepted,
            "verification_mode": mode,
            "calculated_hash": calculated,
            "expected_hash": TRUSTED_FULL_HASH,
        }


    if mode == "metadata_only":

        calculated = sha256_value(
            artifact[
                "metadata"
            ]
        )

        accepted = (
            calculated
            == TRUSTED_METADATA_HASH
        )

        return {
            "accepted": accepted,
            "verification_mode": mode,
            "calculated_hash": calculated,
            "expected_hash": (
                TRUSTED_METADATA_HASH
            ),
        }


    if mode == "stale_digest":

        # Vulnerable logic:
        # application trusts a cached "verified" state
        # from an earlier known-good artifact.

        return {
            "accepted": True,
            "verification_mode": mode,
            "calculated_hash": None,
            "expected_hash": (
                TRUSTED_FULL_HASH
            ),
            "reason": (
                "Previously verified digest state reused."
            ),
        }


    if mode == "self_asserted_hash":

        # Vulnerable logic:
        # trusts the digest supplied inside the artifact.

        claimed_hash = artifact.get(
            "sha256"
        )

        accepted = (
            claimed_hash
            == TRUSTED_FULL_HASH
        )

        return {
            "accepted": accepted,
            "verification_mode": mode,
            "calculated_hash": None,
            "claimed_hash": claimed_hash,
            "expected_hash": (
                TRUSTED_FULL_HASH
            ),
        }


    if mode == "excluded_field":

        # Vulnerable logic:
        # only hashes selected legacy fields and ignores
        # newly introduced runtime_override.

        legacy_content = {

            "behavior": artifact[
                "content"
            ].get(
                "behavior"
            ),

            "default_action": artifact[
                "content"
            ].get(
                "default_action"
            ),

            "default_target": artifact[
                "content"
            ].get(
                "default_target"
            ),

            "allow_privileged_action": artifact[
                "content"
            ].get(
                "allow_privileged_action"
            ),
        }

        calculated = sha256_value(
            legacy_content
        )

        accepted = (
            calculated
            == TRUSTED_CONTENT_HASH
        )

        return {
            "accepted": accepted,
            "verification_mode": mode,
            "calculated_hash": calculated,
            "expected_hash": (
                TRUSTED_CONTENT_HASH
            ),
        }


    if mode == "weak_canonicalization":

        # Vulnerable logic:
        # display_hash is treated as trusted evidence.

        claimed = artifact.get(
            "display_hash"
        )

        accepted = (
            claimed
            == TRUSTED_FULL_HASH
        )

        return {
            "accepted": accepted,
            "verification_mode": mode,
            "calculated_hash": None,
            "claimed_hash": claimed,
            "expected_hash": (
                TRUSTED_FULL_HASH
            ),
        }


    if mode == "content_only":

        calculated = sha256_value(
            artifact[
                "content"
            ]
        )

        accepted = (
            calculated
            == TRUSTED_CONTENT_HASH
        )

        return {
            "accepted": accepted,
            "verification_mode": mode,
            "calculated_hash": calculated,
            "expected_hash": (
                TRUSTED_CONTENT_HASH
            ),
        }


    return {
        "accepted": False,
        "verification_mode": mode,
        "reason": "Unknown mode.",
    }


# ============================================================
# SYNTHETIC RUNTIME
# ============================================================

def execute_artifact(
    artifact,
):

    content = artifact.get(
        "content",
        {},
    )

    metadata = artifact.get(
        "metadata",
        {},
    )


    action = content.get(
        "default_action",
        "read_record",
    )

    target = content.get(
        "default_target",
        "R-2502",
    )

    privileged = bool(
        content.get(
            "allow_privileged_action",
            False,
        )
    )


    # ========================================================
    # SECURITY-SENSITIVE EXCLUDED FIELD
    # ========================================================

    runtime_override = content.get(
        "runtime_override"
    )

    if runtime_override:

        action = runtime_override.get(
            "action",
            action,
        )

        target = runtime_override.get(
            "target",
            target,
        )

        privileged = runtime_override.get(
            "privileged",
            privileged,
        )


    # ========================================================
    # METADATA-DRIVEN BEHAVIOR
    # ========================================================

    if metadata.get(
        "runtime_target"
    ):

        target = metadata[
            "runtime_target"
        ]


    if metadata.get(
        "runtime_action"
    ):

        action = metadata[
            "runtime_action"
        ]

        privileged = True


    restricted_target = (
        target
        == "R-2599"
    )

    privileged_action = (
        action
        == "delete_record"
    )

    runtime_compromised = (
        restricted_target
        or privileged_action
        or privileged
    )


    return {
        "success": True,

        "action": action,

        "target": target,

        "privileged": privileged,

        "restricted_target_selected": (
            restricted_target
        ),

        "privileged_action_selected": (
            privileged_action
        ),

        "runtime_compromised": (
            runtime_compromised
        ),
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 25 Lab 10: "
        "Hash / Integrity Verification Bypass ==="
    )


    results = []


    for case in TEST_CASES:

        print(
            "\n"
            + "=" * 48
        )

        print(
            case[
                "name"
            ]
        )

        print(
            "=" * 48
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
        # VERIFY
        # ====================================================

        verification = (
            vulnerable_verify(
                artifact,
                case[
                    "mode"
                ],
            )
        )


        print(
            "\nIntegrity Verification Result:"
        )

        print_json(
            verification
        )


        # ====================================================
        # ACTUAL FULL HASH
        # ====================================================

        actual_full_hash = sha256_value(
            artifact
        )

        actual_full_hash_match = (
            actual_full_hash
            == TRUSTED_FULL_HASH
        )


        # ====================================================
        # EXECUTION
        # ====================================================

        runtime = (
            execute_artifact(
                artifact
            )
        )


        print(
            "\nSynthetic Runtime Result:"
        )

        print_json(
            runtime
        )


        # ====================================================
        # ANALYSIS
        # ====================================================

        false_integrity_acceptance = (
            case[
                "poisoned"
            ]
            and
            verification[
                "accepted"
            ]
            and
            not actual_full_hash_match
        )


        integrity_bypass = (
            false_integrity_acceptance
        )


        malicious_artifact_loaded = (
            case[
                "poisoned"
            ]
            and
            verification[
                "accepted"
            ]
        )


        runtime_compromised = (
            case[
                "poisoned"
            ]
            and
            verification[
                "accepted"
            ]
            and
            runtime[
                "runtime_compromised"
            ]
        )


        print(
            "\nSecurity Analysis:"
        )

        print(
            "Actual Full Hash Match:",
            actual_full_hash_match,
        )

        print(
            "Integrity Check Accepted:",
            verification[
                "accepted"
            ],
        )

        print(
            "False Integrity Acceptance:",
            false_integrity_acceptance,
        )

        print(
            "Integrity Bypass:",
            integrity_bypass,
        )

        print(
            "Malicious Artifact Loaded:",
            malicious_artifact_loaded,
        )

        print(
            "Restricted Target Selected:",
            runtime[
                "restricted_target_selected"
            ],
        )

        print(
            "Privileged Action Selected:",
            runtime[
                "privileged_action_selected"
            ],
        )

        print(
            "Runtime Compromised:",
            runtime_compromised,
        )


        clean_safe = (
            not case[
                "poisoned"
            ]
            and
            verification[
                "accepted"
            ]
            and
            actual_full_hash_match
            and
            not runtime[
                "runtime_compromised"
            ]
        )


        results.append(
            {
                "poisoned": (
                    case[
                        "poisoned"
                    ]
                ),

                "false_integrity_acceptance": (
                    false_integrity_acceptance
                ),

                "integrity_bypass": (
                    integrity_bypass
                ),

                "malicious_artifact_loaded": (
                    malicious_artifact_loaded
                ),

                "runtime_compromised": (
                    runtime_compromised
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


    poisoned_count = len(
        poisoned_results
    )


    false_acceptances = sum(
        result[
            "false_integrity_acceptance"
        ]
        for result
        in poisoned_results
    )


    bypasses = sum(
        result[
            "integrity_bypass"
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


    runtime_compromises = sum(
        result[
            "runtime_compromised"
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
        + "=" * 48
    )

    print(
        "       INTEGRITY BYPASS SUMMARY"
    )

    print(
        "=" * 48
    )


    print(
        "Poisoned integrity cases:",
        poisoned_count,
    )


    print(
        "False integrity acceptances:",
        false_acceptances,
    )


    print(
        "False Integrity Acceptance Rate:",
        f"{rate(
            false_acceptances,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Integrity Bypass Rate:",
        f"{rate(
            bypasses,
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
        "Integrity-Bypass Runtime Compromise Rate:",
        f"{rate(
            runtime_compromises,
            poisoned_count
        ):.2f}%"
    )


    print(
        "\n=== Clean Utility ==="
    )


    print(
        "Clean integrity cases:",
        len(
            clean_results
        ),
    )


    print(
        "Clean trusted loads:",
        clean_safe,
    )


    print(
        "Clean Integrity Utility Rate:",
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
        "The vulnerable integrity verifier demonstrates "
        "that merely using SHA-256 does not guarantee "
        "artifact integrity if the wrong data is hashed, "
        "the digest is stale, the digest is attacker-controlled, "
        "or security-sensitive fields are excluded."
    )


    print(
        "Integrity verification must cover the complete "
        "security-relevant artifact representation and "
        "must compare against trusted digest material "
        "obtained independently of the artifact itself."
    )


    print(
        "Cryptographic strength cannot compensate for "
        "incorrect trust architecture."
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