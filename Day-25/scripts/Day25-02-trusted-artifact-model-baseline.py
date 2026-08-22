"""
Day 25 - Lab 2
Trusted Artifact & Model Baseline

Purpose:
Establish a richer trust baseline for AI supply-chain artifacts.

Core Principle:
An AI component being available or functional does not establish
that it is authentic, trusted, or safe to load.
"""

import hashlib
import json
from copy import deepcopy


# ============================================================
# TRUSTED PUBLISHERS
# ============================================================

TRUSTED_PUBLISHERS = {
    "trusted_ai_team",
    "trusted_security_team",
    "trusted_data_team",
}


# ============================================================
# TRUSTED ARTIFACT REGISTRY
# ============================================================

ARTIFACTS = {

    "model": {
        "artifact_id": "MODEL-2501",
        "name": "project-review-model",
        "version": "1.0.0",
        "publisher": "trusted_ai_team",
        "artifact_type": "model",

        "purpose": (
            "Analyze project documentation and produce "
            "factual summaries."
        ),

        "capabilities": {
            "summarize_project",
        },

        "dependencies": {
            "prompt_template",
            "policy",
            "dataset",
        },

        "content": {
            "behavior": "safe_review",
            "model_family": "synthetic-review-model",
        },
    },

    "prompt_template": {
        "artifact_id": "PROMPT-2501",
        "name": "project-review-template",
        "version": "1.0.0",
        "publisher": "trusted_ai_team",
        "artifact_type": "prompt_template",

        "purpose": (
            "Provide trusted instructions for "
            "project-record review."
        ),

        "capabilities": {
            "instruction_template",
        },

        "dependencies": set(),

        "content": {
            "instruction": (
                "Review the requested project record "
                "and return a factual summary."
            ),
        },
    },

    "policy": {
        "artifact_id": "POLICY-2501",
        "name": "worker-security-policy",
        "version": "1.0.0",
        "publisher": "trusted_security_team",
        "artifact_type": "policy",

        "purpose": (
            "Restrict worker workflow tool and target access."
        ),

        "capabilities": {
            "policy_enforcement",
        },

        "dependencies": set(),

        "content": {
            "allowed_tool": "read_record",
            "allowed_target": "R-2502",
            "restricted_targets": [
                "R-2599",
            ],
        },
    },

    "dataset": {
        "artifact_id": "DATA-2501",
        "name": "project-reference-data",
        "version": "1.0.0",
        "publisher": "trusted_data_team",
        "artifact_type": "dataset",

        "purpose": (
            "Provide trusted project-reference information."
        ),

        "capabilities": {
            "reference_data",
        },

        "dependencies": set(),

        "content": {
            "R-2502": {
                "classification": "internal",
                "status": "documentation review",
            },
        },
    },

    "tool_package": {
        "artifact_id": "TOOL-2501",
        "name": "internal-record-tools",
        "version": "1.0.0",
        "publisher": "trusted_security_team",
        "artifact_type": "tool_package",

        "purpose": (
            "Expose authorized internal record operations."
        ),

        "capabilities": {
            "read_record",
        },

        "dependencies": {
            "policy",
        },

        "content": {
            "server": "internal_ops",
            "tool": "read_record",
        },
    },
}


# ============================================================
# SERIALIZATION
# ============================================================

def normalize_for_json(value):

    if isinstance(
        value,
        set,
    ):
        return sorted(
            value
        )

    if isinstance(
        value,
        dict,
    ):
        return {
            key: normalize_for_json(
                item
            )
            for key, item
            in value.items()
        }

    if isinstance(
        value,
        list,
    ):
        return [
            normalize_for_json(
                item
            )
            for item in value
        ]

    return value


def canonical_json(value):

    normalized = normalize_for_json(
        value
    )

    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
    )


def calculate_hash(
    artifact,
):

    encoded = canonical_json(
        artifact
    ).encode(
        "utf-8"
    )

    return hashlib.sha256(
        encoded
    ).hexdigest()


# ============================================================
# TRUST MANIFEST
# ============================================================

def build_manifest(
    artifacts,
):

    manifest = {}

    for (
        artifact_key,
        artifact,
    ) in artifacts.items():

        manifest[
            artifact_key
        ] = {

            "artifact_id": artifact[
                "artifact_id"
            ],

            "name": artifact[
                "name"
            ],

            "version": artifact[
                "version"
            ],

            "publisher": artifact[
                "publisher"
            ],

            "artifact_type": artifact[
                "artifact_type"
            ],

            "purpose": artifact[
                "purpose"
            ],

            "capabilities": sorted(
                artifact[
                    "capabilities"
                ]
            ),

            "dependencies": sorted(
                artifact[
                    "dependencies"
                ]
            ),

            "sha256": calculate_hash(
                artifact
            ),
        }

    return manifest


# ============================================================
# VALIDATION
# ============================================================

def validate_artifact(
    artifact_key,
    artifact,
    expected,
    available_artifacts,
):

    identity_valid = (
        artifact.get(
            "artifact_id"
        )
        == expected[
            "artifact_id"
        ]
        and
        artifact.get(
            "name"
        )
        == expected[
            "name"
        ]
    )

    version_valid = (
        artifact.get(
            "version"
        )
        == expected[
            "version"
        ]
    )

    publisher_valid = (
        artifact.get(
            "publisher"
        )
        == expected[
            "publisher"
        ]
        and
        artifact.get(
            "publisher"
        )
        in TRUSTED_PUBLISHERS
    )

    type_valid = (
        artifact.get(
            "artifact_type"
        )
        == expected[
            "artifact_type"
        ]
    )

    purpose_valid = (
        artifact.get(
            "purpose"
        )
        == expected[
            "purpose"
        ]
    )

    capabilities_valid = (
        sorted(
            artifact.get(
                "capabilities",
                set(),
            )
        )
        == expected[
            "capabilities"
        ]
    )

    dependencies = set(
        artifact.get(
            "dependencies",
            set(),
        )
    )

    expected_dependencies = set(
        expected[
            "dependencies"
        ]
    )

    dependency_names_valid = (
        dependencies
        == expected_dependencies
    )

    dependencies_available = all(
        dependency
        in available_artifacts
        for dependency
        in dependencies
    )

    integrity_valid = (
        calculate_hash(
            artifact
        )
        == expected[
            "sha256"
        ]
    )

    trusted = all(
        {
            "identity": identity_valid,
            "version": version_valid,
            "publisher": publisher_valid,
            "type": type_valid,
            "purpose": purpose_valid,
            "capabilities": capabilities_valid,
            "dependency_names": (
                dependency_names_valid
            ),
            "dependencies_available": (
                dependencies_available
            ),
            "integrity": integrity_valid,
        }.values()
    )

    return {
        "artifact_key": artifact_key,
        "artifact_id": artifact.get(
            "artifact_id"
        ),
        "identity_valid": identity_valid,
        "version_valid": version_valid,
        "publisher_valid": publisher_valid,
        "type_valid": type_valid,
        "purpose_valid": purpose_valid,
        "capabilities_valid": (
            capabilities_valid
        ),
        "dependency_names_valid": (
            dependency_names_valid
        ),
        "dependencies_available": (
            dependencies_available
        ),
        "integrity_valid": integrity_valid,
        "trusted": trusted,
    }


# ============================================================
# TRUST GRAPH
# ============================================================

def build_dependency_graph(
    artifacts,
):

    graph = {}

    for (
        artifact_key,
        artifact,
    ) in artifacts.items():

        graph[
            artifact_key
        ] = sorted(
            artifact[
                "dependencies"
            ]
        )

    return graph


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 25 Lab 2: "
        "Trusted Artifact & Model Baseline ==="
    )

    artifacts = deepcopy(
        ARTIFACTS
    )

    manifest = build_manifest(
        artifacts
    )

    print(
        "\n========================================"
    )

    print(
        "       TRUSTED ARTIFACT MANIFEST"
    )

    print(
        "========================================"
    )

    print(
        json.dumps(
            manifest,
            indent=2,
        )
    )


    # ========================================================
    # DEPENDENCY GRAPH
    # ========================================================

    dependency_graph = (
        build_dependency_graph(
            artifacts
        )
    )

    print(
        "\n========================================"
    )

    print(
        "       ARTIFACT DEPENDENCY GRAPH"
    )

    print(
        "========================================"
    )

    print(
        json.dumps(
            dependency_graph,
            indent=2,
        )
    )


    # ========================================================
    # VALIDATE ALL ARTIFACTS
    # ========================================================

    validation_results = []

    for (
        artifact_key,
        artifact,
    ) in artifacts.items():

        result = validate_artifact(
            artifact_key,
            artifact,
            manifest[
                artifact_key
            ],
            artifacts,
        )

        validation_results.append(
            result
        )

        print(
            "\n========================================"
        )

        print(
            f"Artifact: {artifact_key}"
        )

        print(
            "========================================"
        )

        print(
            json.dumps(
                result,
                indent=2,
            )
        )


    # ========================================================
    # MODEL-SPECIFIC TRUST CHECK
    # ========================================================

    model_result = next(
        result
        for result
        in validation_results
        if result[
            "artifact_key"
        ]
        == "model"
    )

    model_dependencies = (
        dependency_graph[
            "model"
        ]
    )

    model_dependency_trust = all(

        next(
            result[
                "trusted"
            ]
            for result
            in validation_results
            if result[
                "artifact_key"
            ]
            == dependency
        )

        for dependency
        in model_dependencies
    )

    model_fully_trusted = (
        model_result[
            "trusted"
        ]
        and
        model_dependency_trust
    )


    # ========================================================
    # SUMMARY METRICS
    # ========================================================

    trusted_artifacts = sum(
        1
        for result
        in validation_results
        if result[
            "trusted"
        ]
    )

    total_artifacts = len(
        validation_results
    )

    trusted_rate = (
        trusted_artifacts
        / total_artifacts
        * 100
        if total_artifacts
        else 0.0
    )

    print(
        "\n========================================"
    )

    print(
        "       TRUST BASELINE SUMMARY"
    )

    print(
        "========================================"
    )

    print(
        "Registered Artifacts:",
        total_artifacts,
    )

    print(
        "Trusted Artifacts:",
        trusted_artifacts,
    )

    print(
        "Artifact Trust Validation Rate:",
        f"{trusted_rate:.2f}%"
    )

    print(
        "All Artifact Identities Valid:",
        all(
            result[
                "identity_valid"
            ]
            for result
            in validation_results
        ),
    )

    print(
        "All Publishers Valid:",
        all(
            result[
                "publisher_valid"
            ]
            for result
            in validation_results
        ),
    )

    print(
        "All Versions Valid:",
        all(
            result[
                "version_valid"
            ]
            for result
            in validation_results
        ),
    )

    print(
        "All Artifact Types Valid:",
        all(
            result[
                "type_valid"
            ]
            for result
            in validation_results
        ),
    )

    print(
        "All Purposes Valid:",
        all(
            result[
                "purpose_valid"
            ]
            for result
            in validation_results
        ),
    )

    print(
        "All Capabilities Valid:",
        all(
            result[
                "capabilities_valid"
            ]
            for result
            in validation_results
        ),
    )

    print(
        "All Dependency Declarations Valid:",
        all(
            result[
                "dependency_names_valid"
            ]
            for result
            in validation_results
        ),
    )

    print(
        "All Dependencies Available:",
        all(
            result[
                "dependencies_available"
            ]
            for result
            in validation_results
        ),
    )

    print(
        "All Integrity Checks Valid:",
        all(
            result[
                "integrity_valid"
            ]
            for result
            in validation_results
        ),
    )

    print(
        "Model Direct Trust Valid:",
        model_result[
            "trusted"
        ],
    )

    print(
        "Model Dependency Trust Valid:",
        model_dependency_trust,
    )

    print(
        "Model Fully Trusted:",
        model_fully_trusted,
    )

    print(
        "\nSecurity Interpretation:"
    )

    print(
        "Artifact trust is broader than file availability "
        "or successful loading. Trusted execution requires "
        "expected identity, publisher, version, type, purpose, "
        "capabilities, dependencies, and integrity."
    )

    print(
        "A model may itself be authentic while still depending "
        "on an untrusted prompt template, policy, dataset, or "
        "other artifact."
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