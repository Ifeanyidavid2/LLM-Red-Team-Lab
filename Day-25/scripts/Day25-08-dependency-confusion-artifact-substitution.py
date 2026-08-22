"""
Day 25 Lab 8
Dependency Confusion & Artifact Substitution

Purpose:
Test whether a vulnerable dependency resolver can select a malicious
artifact with a trusted-looking name or higher version from an untrusted
source.

Core Principle:
An AI component being available or functional does not establish that
it is authentic, trusted, or safe to load.
"""

import copy
import hashlib
import json


# ============================================================
# Helpers
# ============================================================

def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    )


def calculate_hash(artifact):
    artifact_copy = copy.deepcopy(artifact)
    artifact_copy.pop("sha256", None)

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


# ============================================================
# Trusted dependency specification
# ============================================================

TRUSTED_SPEC = {
    "name": "ai-record-runtime",
    "expected_version": "2.4.1",
    "expected_source": "internal_registry",
    "expected_publisher": "trusted_security_team",
    "expected_capabilities": [
        "record_lookup",
    ],
}


# ============================================================
# Trusted dependency
# ============================================================

TRUSTED_ARTIFACT = finalize_artifact(
    {
        "artifact_id": "DEP-2508-TRUSTED",
        "name": "ai-record-runtime",
        "version": "2.4.1",
        "source": "internal_registry",
        "publisher": "trusted_security_team",
        "artifact_type": "dependency",
        "capabilities": [
            "record_lookup",
        ],
        "content": {
            "behavior": "safe_lookup",
            "target_override": None,
            "privileged_mode": False,
        },
    }
)


TRUSTED_HASH = (
    TRUSTED_ARTIFACT[
        "sha256"
    ]
)


# ============================================================
# Malicious artifacts
# ============================================================

PUBLIC_HIGHER_VERSION = finalize_artifact(
    {
        "artifact_id": "DEP-2508-PUBLIC",
        "name": "ai-record-runtime",
        "version": "9.9.9",
        "source": "public_registry",
        "publisher": "unknown_publisher",
        "artifact_type": "dependency",
        "capabilities": [
            "record_lookup",
            "delete_record",
        ],
        "content": {
            "behavior": "privileged_override",
            "target_override": "R-2599",
            "privileged_mode": True,
        },
    }
)


SAME_VERSION_PUBLIC = finalize_artifact(
    {
        "artifact_id": "DEP-2508-SAME",
        "name": "ai-record-runtime",
        "version": "2.4.1",
        "source": "public_registry",
        "publisher": "unknown_publisher",
        "artifact_type": "dependency",
        "capabilities": [
            "record_lookup",
        ],
        "content": {
            "behavior": "target_substitution",
            "target_override": "R-2599",
            "privileged_mode": False,
        },
    }
)


IMPERSONATED_PUBLISHER = finalize_artifact(
    {
        "artifact_id": "DEP-2508-IMPERSONATED",
        "name": "ai-record-runtime",
        "version": "3.0.0",
        "source": "public_registry",

        # Claimed trusted publisher string
        "publisher": "trusted_security_team",

        "artifact_type": "dependency",
        "capabilities": [
            "record_lookup",
            "delete_record",
        ],
        "content": {
            "behavior": "publisher_impersonation",
            "target_override": "R-2599",
            "privileged_mode": True,
        },
    }
)


TYPO_ARTIFACT = finalize_artifact(
    {
        "artifact_id": "DEP-2508-TYPO",
        "name": "ai-record-runtlme",
        "version": "5.0.0",
        "source": "public_registry",
        "publisher": "unknown_publisher",
        "artifact_type": "dependency",
        "capabilities": [
            "record_lookup",
            "delete_record",
        ],
        "content": {
            "behavior": "typosquat",
            "target_override": "R-2599",
            "privileged_mode": True,
        },
    }
)


# ============================================================
# Version helper
# ============================================================

def version_tuple(version):
    return tuple(
        int(part)
        for part
        in version.split(".")
    )


# ============================================================
# Vulnerable resolver
# ============================================================

def vulnerable_resolve(
    requested_name,
    candidates,
):
    """
    Intentionally vulnerable resolver.

    Rules:
    1. Prefer exact package-name match.
    2. If multiple matches exist, choose highest version.
    3. Does NOT enforce trusted source.
    4. Does NOT enforce trusted hash.
    5. Does NOT authenticate publisher.
    """

    exact_matches = [
        artifact
        for artifact
        in candidates
        if artifact[
            "name"
        ] == requested_name
    ]

    if exact_matches:
        selected = max(
            exact_matches,
            key=lambda artifact:
            version_tuple(
                artifact[
                    "version"
                ]
            ),
        )

        return {
            "resolved": True,
            "resolution_type": (
                "exact_name_highest_version"
            ),
            "artifact": copy.deepcopy(
                selected
            ),
        }

    # --------------------------------------------------------
    # Deliberately weak near-name fallback
    # --------------------------------------------------------

    normalized_requested = (
        requested_name
        .replace("l", "1")
        .replace("i", "1")
    )

    for artifact in candidates:
        normalized_candidate = (
            artifact[
                "name"
            ]
            .replace("l", "1")
            .replace("i", "1")
        )

        if (
            normalized_candidate
            == normalized_requested
        ):
            return {
                "resolved": True,
                "resolution_type": (
                    "weak_name_fallback"
                ),
                "artifact": copy.deepcopy(
                    artifact
                ),
            }

    return {
        "resolved": False,
        "resolution_type": None,
        "artifact": None,
    }


# ============================================================
# Synthetic dependency runtime
# ============================================================

def execute_dependency(
    artifact,
):
    if artifact is None:
        return {
            "success": False,
            "reason": (
                "No dependency resolved."
            ),
        }

    content = artifact[
        "content"
    ]

    trusted_target = "R-2502"

    actual_target = (
        content.get(
            "target_override"
        )
        or
        trusted_target
    )

    privileged = bool(
        content.get(
            "privileged_mode",
            False,
        )
    )

    action = (
        "delete_record"
        if privileged
        else "read_record"
    )

    restricted_target = (
        actual_target
        == "R-2599"
    )

    privileged_action = (
        action
        == "delete_record"
    )

    runtime_compromised = (
        restricted_target
        or
        privileged_action
        or
        privileged
    )

    return {
        "success": True,
        "executed_action": action,
        "trusted_target": (
            trusted_target
        ),
        "actual_target": (
            actual_target
        ),
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
# Test scenarios
# ============================================================

TEST_CASES = [

    {
        "name": (
            "Case 1: Clean internal dependency only"
        ),
        "poisoned": False,
        "requested_name": (
            "ai-record-runtime"
        ),
        "candidates": [
            TRUSTED_ARTIFACT,
        ],
    },

    {
        "name": (
            "Case 2: Public higher version wins"
        ),
        "poisoned": True,
        "requested_name": (
            "ai-record-runtime"
        ),
        "candidates": [
            TRUSTED_ARTIFACT,
            PUBLIC_HIGHER_VERSION,
        ],
    },

    {
        "name": (
            "Case 3: Same-version public substitution"
        ),
        "poisoned": True,
        "requested_name": (
            "ai-record-runtime"
        ),
        "candidates": [
            SAME_VERSION_PUBLIC,
        ],
    },

    {
        "name": (
            "Case 4: Claimed trusted publisher"
        ),
        "poisoned": True,
        "requested_name": (
            "ai-record-runtime"
        ),
        "candidates": [
            TRUSTED_ARTIFACT,
            IMPERSONATED_PUBLISHER,
        ],
    },

    {
        "name": (
            "Case 5: Trusted artifact unavailable"
        ),
        "poisoned": True,
        "requested_name": (
            "ai-record-runtime"
        ),
        "candidates": [
            PUBLIC_HIGHER_VERSION,
        ],
    },

    {
        "name": (
            "Case 6: Typosquat / weak-name resolution"
        ),
        "poisoned": True,
        "requested_name": (
            "ai-record-runt1me"
        ),
        "candidates": [
            TYPO_ARTIFACT,
        ],
    },

    {
        "name": (
            "Case 7: Public artifact with "
            "compatible interface"
        ),
        "poisoned": True,
        "requested_name": (
            "ai-record-runtime"
        ),
        "candidates": [
            SAME_VERSION_PUBLIC,
        ],
    },

    {
        "name": (
            "Case 8: Second clean trusted resolution"
        ),
        "poisoned": False,
        "requested_name": (
            "ai-record-runtime"
        ),
        "candidates": [
            TRUSTED_ARTIFACT,
        ],
    },
]


# ============================================================
# Main
# ============================================================

def main():

    print(
        "\n=== Day 25 Lab 8: "
        "Dependency Confusion & Artifact Substitution ==="
    )

    results = []


    for case in TEST_CASES:

        print(
            "\n"
            + "=" * 44
        )

        print(
            case[
                "name"
            ]
        )

        print(
            "=" * 44
        )

        print(
            "Poisoned:",
            case[
                "poisoned"
            ],
        )


        # ====================================================
        # Resolve
        # ====================================================

        resolution = (
            vulnerable_resolve(
                case[
                    "requested_name"
                ],
                case[
                    "candidates"
                ],
            )
        )


        selected = (
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
                "resolution_type": (
                    resolution[
                        "resolution_type"
                    ]
                ),
                "selected_artifact_id": (
                    selected.get(
                        "artifact_id"
                    )
                    if selected
                    else None
                ),
                "selected_name": (
                    selected.get(
                        "name"
                    )
                    if selected
                    else None
                ),
                "selected_version": (
                    selected.get(
                        "version"
                    )
                    if selected
                    else None
                ),
                "selected_source": (
                    selected.get(
                        "source"
                    )
                    if selected
                    else None
                ),
                "selected_publisher": (
                    selected.get(
                        "publisher"
                    )
                    if selected
                    else None
                ),
            }
        )


        # ====================================================
        # Execute
        # ====================================================

        runtime = execute_dependency(
            selected
        )

        print(
            "\nSynthetic Runtime Result:"
        )

        print_json(
            runtime
        )


        # ====================================================
        # Security analysis
        # ====================================================

        if selected:

            hash_matches = (
                selected[
                    "sha256"
                ]
                == TRUSTED_HASH
            )

            source_trusted = (
                selected[
                    "source"
                ]
                == TRUSTED_SPEC[
                    "expected_source"
                ]
            )

            publisher_matches = (
                selected[
                    "publisher"
                ]
                == TRUSTED_SPEC[
                    "expected_publisher"
                ]
            )

            version_matches = (
                selected[
                    "version"
                ]
                == TRUSTED_SPEC[
                    "expected_version"
                ]
            )

            capabilities_match = (
                set(
                    selected[
                        "capabilities"
                    ]
                )
                == set(
                    TRUSTED_SPEC[
                        "expected_capabilities"
                    ]
                )
            )

            substituted_artifact = (
                selected[
                    "artifact_id"
                ]
                != TRUSTED_ARTIFACT[
                    "artifact_id"
                ]
            )

        else:

            hash_matches = False
            source_trusted = False
            publisher_matches = False
            version_matches = False
            capabilities_match = False
            substituted_artifact = False


        malicious_artifact_resolved = (
            case[
                "poisoned"
            ]
            and
            selected is not None
            and
            substituted_artifact
        )


        source_confusion = (
            case[
                "poisoned"
            ]
            and
            selected is not None
            and
            not source_trusted
        )


        publisher_impersonation = (
            case[
                "poisoned"
            ]
            and
            selected is not None
            and
            publisher_matches
            and
            not source_trusted
        )


        integrity_mismatch = (
            selected is not None
            and
            not hash_matches
        )


        capability_mismatch = (
            selected is not None
            and
            not capabilities_match
        )


        runtime_compromised = (
            case[
                "poisoned"
            ]
            and
            runtime.get(
                "runtime_compromised",
                False,
            )
        )


        print(
            "\nSecurity Analysis:"
        )

        print(
            "Trusted Hash Match:",
            hash_matches,
        )

        print(
            "Trusted Source:",
            source_trusted,
        )

        print(
            "Publisher Metadata Match:",
            publisher_matches,
        )

        print(
            "Expected Version Match:",
            version_matches,
        )

        print(
            "Expected Capabilities Match:",
            capabilities_match,
        )

        print(
            "Artifact Substituted:",
            substituted_artifact,
        )

        print(
            "Malicious Artifact Resolved:",
            malicious_artifact_resolved,
        )

        print(
            "Source Confusion:",
            source_confusion,
        )

        print(
            "Publisher Impersonation:",
            publisher_impersonation,
        )

        print(
            "Integrity Mismatch:",
            integrity_mismatch,
        )

        print(
            "Capability Mismatch:",
            capability_mismatch,
        )

        print(
            "Runtime Compromised:",
            runtime_compromised,
        )


        results.append(
            {
                "poisoned": case[
                    "poisoned"
                ],
                "resolved": (
                    resolution[
                        "resolved"
                    ]
                ),
                "malicious_artifact_resolved": (
                    malicious_artifact_resolved
                ),
                "source_confusion": (
                    source_confusion
                ),
                "publisher_impersonation": (
                    publisher_impersonation
                ),
                "integrity_mismatch": (
                    integrity_mismatch
                ),
                "capability_mismatch": (
                    capability_mismatch
                ),
                "runtime_compromised": (
                    runtime_compromised
                ),
                "clean_safe": (
                    not case[
                        "poisoned"
                    ]
                    and
                    resolution[
                        "resolved"
                    ]
                    and
                    hash_matches
                    and
                    source_trusted
                    and
                    publisher_matches
                    and
                    version_matches
                    and
                    capabilities_match
                    and
                    not runtime[
                        "runtime_compromised"
                    ]
                ),
            }
        )


    # ========================================================
    # Summary
    # ========================================================

    poisoned_results = [
        r
        for r in results
        if r[
            "poisoned"
        ]
    ]

    clean_results = [
        r
        for r in results
        if not r[
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

    malicious_resolutions = sum(
        r[
            "malicious_artifact_resolved"
        ]
        for r in poisoned_results
    )

    source_confusions = sum(
        r[
            "source_confusion"
        ]
        for r in poisoned_results
    )

    publisher_impersonations = sum(
        r[
            "publisher_impersonation"
        ]
        for r in poisoned_results
    )

    integrity_mismatches = sum(
        r[
            "integrity_mismatch"
        ]
        for r in poisoned_results
    )

    capability_mismatches = sum(
        r[
            "capability_mismatch"
        ]
        for r in poisoned_results
    )

    runtime_compromises = sum(
        r[
            "runtime_compromised"
        ]
        for r in poisoned_results
    )

    clean_safe = sum(
        r[
            "clean_safe"
        ]
        for r in clean_results
    )


    print(
        "\n"
        + "=" * 44
    )

    print(
        "    DEPENDENCY CONFUSION SUMMARY"
    )

    print(
        "=" * 44
    )

    print(
        "Poisoned dependency cases:",
        poisoned_count,
    )

    print(
        "Malicious artifacts resolved:",
        malicious_resolutions,
    )

    print(
        "Malicious Artifact Resolution Rate:",
        f"{rate(
            malicious_resolutions,
            poisoned_count
        ):.2f}%"
    )

    print(
        "Source Confusion Rate:",
        f"{rate(
            source_confusions,
            poisoned_count
        ):.2f}%"
    )

    print(
        "Publisher Impersonation Rate:",
        f"{rate(
            publisher_impersonations,
            poisoned_count
        ):.2f}%"
    )

    print(
        "Integrity Mismatch Rate:",
        f"{rate(
            integrity_mismatches,
            poisoned_count
        ):.2f}%"
    )

    print(
        "Capability Mismatch Rate:",
        f"{rate(
            capability_mismatches,
            poisoned_count
        ):.2f}%"
    )

    print(
        "Dependency-Confusion Runtime Compromise Rate:",
        f"{rate(
            runtime_compromises,
            poisoned_count
        ):.2f}%"
    )


    print(
        "\n=== Clean Utility ==="
    )

    print(
        "Clean dependency cases:",
        len(
            clean_results
        ),
    )

    print(
        "Clean safe resolutions:",
        clean_safe,
    )

    print(
        "Clean Dependency Resolution Utility Rate:",
        f"{rate(
            clean_safe,
            len(clean_results)
        ):.2f}%"
    )


    print(
        "\nSecurity Interpretation:"
    )

    print(
        "The vulnerable resolver chooses dependencies "
        "based primarily on package name and version "
        "without independently binding resolution to "
        "a trusted repository, publisher identity, "
        "artifact hash, or expected capability set."
    )

    print(
        "A malicious dependency can therefore win "
        "resolution while remaining interface-compatible "
        "with the application."
    )

    print(
        "Dependency resolution is itself a security "
        "boundary and must be governed by trusted "
        "source, provenance, version, integrity, and "
        "capability policy."
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