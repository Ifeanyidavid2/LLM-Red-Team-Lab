import hashlib
import json
from copy import deepcopy


# ============================================================
# DAY 25 LAB 1
# SYNTHETIC AI SUPPLY-CHAIN ENVIRONMENT
# ============================================================


TRUSTED_PUBLISHERS = {
    "trusted_ai_team",
    "trusted_security_team",
    "trusted_data_team",
}


ARTIFACT_REGISTRY = {
    "model": {
        "artifact_id": "MODEL-2501",
        "name": "project-review-model",
        "version": "1.0.0",
        "publisher": "trusted_ai_team",
        "artifact_type": "model",
        "content": {
            "purpose": "project documentation review",
            "behavior": "safe_review",
        },
    },

    "prompt_template": {
        "artifact_id": "PROMPT-2501",
        "name": "project-review-template",
        "version": "1.0.0",
        "publisher": "trusted_ai_team",
        "artifact_type": "prompt_template",
        "content": {
            "instruction": (
                "Review the requested project record "
                "and return a factual summary."
            )
        },
    },

    "policy": {
        "artifact_id": "POLICY-2501",
        "name": "worker-security-policy",
        "version": "1.0.0",
        "publisher": "trusted_security_team",
        "artifact_type": "policy",
        "content": {
            "allowed_tool": "read_record",
            "allowed_target": "R-2502",
            "restricted_targets": [
                "R-2599"
            ],
        },
    },

    "dataset": {
        "artifact_id": "DATA-2501",
        "name": "project-reference-data",
        "version": "1.0.0",
        "publisher": "trusted_data_team",
        "artifact_type": "dataset",
        "content": {
            "R-2502": {
                "classification": "internal",
                "status": "documentation review",
            }
        },
    },

    "tool_package": {
        "artifact_id": "TOOL-2501",
        "name": "internal-record-tools",
        "version": "1.0.0",
        "publisher": "trusted_security_team",
        "artifact_type": "tool_package",
        "content": {
            "server": "internal_ops",
            "tool": "read_record",
        },
    },
}


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    )


def calculate_hash(artifact):
    encoded = canonical_json(
        artifact
    ).encode("utf-8")

    return hashlib.sha256(
        encoded
    ).hexdigest()


def build_trusted_manifest(registry):
    manifest = {}

    for artifact_type, artifact in registry.items():
        manifest[artifact_type] = {
            "artifact_id": artifact[
                "artifact_id"
            ],
            "name": artifact["name"],
            "version": artifact["version"],
            "publisher": artifact[
                "publisher"
            ],
            "sha256": calculate_hash(
                artifact
            ),
        }

    return manifest


def validate_artifact_identity(
    artifact,
    expected,
):
    return (
        artifact["artifact_id"]
        == expected["artifact_id"]
        and artifact["name"]
        == expected["name"]
        and artifact["version"]
        == expected["version"]
        and artifact["publisher"]
        == expected["publisher"]
    )


def validate_artifact_integrity(
    artifact,
    expected,
):
    return (
        calculate_hash(artifact)
        == expected["sha256"]
    )


def load_artifact(
    artifact_type,
    registry,
    manifest,
):
    artifact = registry[
        artifact_type
    ]

    expected = manifest[
        artifact_type
    ]

    publisher_trusted = (
        artifact["publisher"]
        in TRUSTED_PUBLISHERS
    )

    identity_valid = (
        validate_artifact_identity(
            artifact,
            expected,
        )
    )

    integrity_valid = (
        validate_artifact_integrity(
            artifact,
            expected,
        )
    )

    allowed = (
        publisher_trusted
        and identity_valid
        and integrity_valid
    )

    return {
        "artifact_type": artifact_type,
        "artifact_id": artifact[
            "artifact_id"
        ],
        "publisher_trusted": (
            publisher_trusted
        ),
        "identity_valid": (
            identity_valid
        ),
        "integrity_valid": (
            integrity_valid
        ),
        "loaded": allowed,
    }


def execute_baseline_workflow(
    registry,
):
    policy = registry[
        "policy"
    ]["content"]

    dataset = registry[
        "dataset"
    ]["content"]

    tool_package = registry[
        "tool_package"
    ]["content"]

    request = {
        "action": "read_record",
        "target": "R-2502",
    }

    policy_valid = (
        request["action"]
        == policy["allowed_tool"]
        and request["target"]
        == policy["allowed_target"]
        and request["target"]
        not in policy[
            "restricted_targets"
        ]
    )

    tool_valid = (
        tool_package["server"]
        == "internal_ops"
        and tool_package["tool"]
        == "read_record"
    )

    record = dataset.get(
        request["target"]
    )

    workflow_completed = (
        policy_valid
        and tool_valid
        and record is not None
    )

    return {
        "request": request,
        "policy_valid": policy_valid,
        "tool_valid": tool_valid,
        "record": record,
        "workflow_completed": (
            workflow_completed
        ),
    }


def main():
    print(
        "\n=== Day 25 Lab 1: "
        "Synthetic AI Supply-Chain Environment ===\n"
    )

    registry = deepcopy(
        ARTIFACT_REGISTRY
    )

    manifest = (
        build_trusted_manifest(
            registry
        )
    )

    print("=" * 60)
    print(
        "       TRUSTED AI ARTIFACT MANIFEST"
    )
    print("=" * 60)

    print(
        json.dumps(
            manifest,
            indent=2,
        )
    )

    print(
        "\n" + "=" * 60
    )
    print(
        "       ARTIFACT LOADING CHECKS"
    )
    print("=" * 60)

    load_results = []

    for artifact_type in registry:
        result = load_artifact(
            artifact_type,
            registry,
            manifest,
        )

        load_results.append(
            result
        )

        print(
            f"\nArtifact: "
            f"{artifact_type}"
        )

        print(
            json.dumps(
                result,
                indent=2,
            )
        )

    print(
        "\n" + "=" * 60
    )
    print(
        "       TRUSTED WORKFLOW BASELINE"
    )
    print("=" * 60)

    workflow = (
        execute_baseline_workflow(
            registry
        )
    )

    print(
        json.dumps(
            workflow,
            indent=2,
        )
    )

    all_artifacts_loaded = all(
        result["loaded"]
        for result in load_results
    )

    print(
        "\n" + "=" * 60
    )
    print(
        "       BASELINE SECURITY CHECKS"
    )
    print("=" * 60)

    print(
        "Trusted Publishers: "
        f"{len(TRUSTED_PUBLISHERS)}"
    )

    print(
        "Registered AI Artifacts: "
        f"{len(registry)}"
    )

    print(
        "All Artifact Identities Valid: "
        f"{all(
            r['identity_valid']
            for r in load_results
        )}"
    )

    print(
        "All Artifact Integrity Checks Valid: "
        f"{all(
            r['integrity_valid']
            for r in load_results
        )}"
    )

    print(
        "All Trusted Artifacts Loaded: "
        f"{all_artifacts_loaded}"
    )

    print(
        "Legitimate Workflow Completed: "
        f"{workflow[
            'workflow_completed'
        ]}"
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