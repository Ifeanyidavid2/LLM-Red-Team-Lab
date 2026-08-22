"""
Day 25 Lab 9
Artifact Metadata & Provenance Spoofing

Purpose:
Test whether self-asserted artifact metadata can cause a malicious
AI artifact to appear trusted when provenance is not independently
verified or cryptographically bound to the artifact.

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


def calculate_hash(
    artifact,
):

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


def finalize_artifact(
    artifact,
):

    artifact = copy.deepcopy(
        artifact
    )

    artifact[
        "sha256"
    ] = calculate_hash(
        artifact
    )

    return artifact


def print_json(
    value,
):

    print(
        json.dumps(
            value,
            indent=2,
        )
    )


# ============================================================
# TRUSTED PROVENANCE BASELINE
# ============================================================

TRUSTED_PROVENANCE = {

    "artifact_id": "MODEL-2509",

    "name": "project-security-model",

    "version": "1.0.0",

    "publisher": "trusted_ai_team",

    "source": "internal_model_registry",

    "build_id": "BUILD-2509-A",

    "commit": "abc123trusted",

    "signature_status": "verified",

    "provenance_attestation": (
        "trusted-build-pipeline"
    ),

    "sbom_reference": (
        "SBOM-2509-TRUSTED"
    ),

    "artifact_type": "model",

    "capabilities": [
        "summarize_project",
    ],

    "content": {
        "behavior": "safe_review",
        "default_action": "read_record",
        "default_target": "R-2502",
        "allow_privileged_action": False,
    },
}


TRUSTED_ARTIFACT = finalize_artifact(
    TRUSTED_PROVENANCE
)


TRUSTED_HASH = (
    TRUSTED_ARTIFACT[
        "sha256"
    ]
)


TRUSTED_METADATA = {

    "artifact_id": (
        TRUSTED_ARTIFACT[
            "artifact_id"
        ]
    ),

    "name": (
        TRUSTED_ARTIFACT[
            "name"
        ]
    ),

    "version": (
        TRUSTED_ARTIFACT[
            "version"
        ]
    ),

    "publisher": (
        TRUSTED_ARTIFACT[
            "publisher"
        ]
    ),

    "source": (
        TRUSTED_ARTIFACT[
            "source"
        ]
    ),

    "build_id": (
        TRUSTED_ARTIFACT[
            "build_id"
        ]
    ),

    "commit": (
        TRUSTED_ARTIFACT[
            "commit"
        ]
    ),

    "signature_status": (
        TRUSTED_ARTIFACT[
            "signature_status"
        ]
    ),

    "provenance_attestation": (
        TRUSTED_ARTIFACT[
            "provenance_attestation"
        ]
    ),

    "sbom_reference": (
        TRUSTED_ARTIFACT[
            "sbom_reference"
        ]
    ),
}


# ============================================================
# MALICIOUS CONTENT
# ============================================================

MALICIOUS_CONTENT = {

    "behavior": (
        "restricted_override"
    ),

    "default_action": (
        "delete_record"
    ),

    "default_target": (
        "R-2599"
    ),

    "allow_privileged_action": True,
}


# ============================================================
# TEST CASES
# ============================================================

TEST_CASES = [

    {
        "name": (
            "Case 1: Clean trusted provenance"
        ),

        "poisoned": False,

        "artifact": copy.deepcopy(
            TRUSTED_ARTIFACT
        ),
    },

    {
        "name": (
            "Case 2: Publisher metadata spoofed"
        ),

        "poisoned": True,

        "artifact": finalize_artifact(
            {
                **{
                    key: copy.deepcopy(
                        value
                    )
                    for key, value
                    in TRUSTED_PROVENANCE.items()
                },

                "content": copy.deepcopy(
                    MALICIOUS_CONTENT
                ),
            }
        ),
    },

    {
        "name": (
            "Case 3: Source and build identity spoofed"
        ),

        "poisoned": True,

        "artifact": finalize_artifact(
            {
                **{
                    key: copy.deepcopy(
                        value
                    )
                    for key, value
                    in TRUSTED_PROVENANCE.items()
                },

                "content": copy.deepcopy(
                    MALICIOUS_CONTENT
                ),
            }
        ),
    },

    {
        "name": (
            "Case 4: Signature-status field spoofed"
        ),

        "poisoned": True,

        "artifact": finalize_artifact(
            {
                **{
                    key: copy.deepcopy(
                        value
                    )
                    for key, value
                    in TRUSTED_PROVENANCE.items()
                },

                "signature_status": (
                    "verified"
                ),

                "content": copy.deepcopy(
                    MALICIOUS_CONTENT
                ),
            }
        ),
    },

    {
        "name": (
            "Case 5: Provenance attestation spoofed"
        ),

        "poisoned": True,

        "artifact": finalize_artifact(
            {
                **{
                    key: copy.deepcopy(
                        value
                    )
                    for key, value
                    in TRUSTED_PROVENANCE.items()
                },

                "provenance_attestation": (
                    "trusted-build-pipeline"
                ),

                "content": copy.deepcopy(
                    MALICIOUS_CONTENT
                ),
            }
        ),
    },

    {
        "name": (
            "Case 6: SBOM reference spoofed"
        ),

        "poisoned": True,

        "artifact": finalize_artifact(
            {
                **{
                    key: copy.deepcopy(
                        value
                    )
                    for key, value
                    in TRUSTED_PROVENANCE.items()
                },

                "sbom_reference": (
                    "SBOM-2509-TRUSTED"
                ),

                "content": copy.deepcopy(
                    MALICIOUS_CONTENT
                ),
            }
        ),
    },

    {
        "name": (
            "Case 7: Full trusted metadata clone"
        ),

        "poisoned": True,

        "artifact": finalize_artifact(
            {
                **copy.deepcopy(
                    TRUSTED_PROVENANCE
                ),

                "content": copy.deepcopy(
                    MALICIOUS_CONTENT
                ),
            }
        ),
    },

    {
        "name": (
            "Case 8: Second clean trusted provenance"
        ),

        "poisoned": False,

        "artifact": copy.deepcopy(
            TRUSTED_ARTIFACT
        ),
    },
]


# ============================================================
# VULNERABLE TRUST EVALUATOR
# ============================================================

def vulnerable_trust_evaluation(
    artifact,
):
    """
    Intentionally vulnerable.

    The application trusts self-asserted metadata fields.

    It does NOT:
    - verify a detached signature
    - validate a certificate chain
    - verify transparency-log inclusion
    - bind provenance attestation to artifact digest
    - validate SBOM digest binding
    - independently authenticate publisher identity
    """

    metadata_checks = {

        "artifact_id_match": (
            artifact.get(
                "artifact_id"
            )
            == TRUSTED_METADATA[
                "artifact_id"
            ]
        ),

        "name_match": (
            artifact.get(
                "name"
            )
            == TRUSTED_METADATA[
                "name"
            ]
        ),

        "version_match": (
            artifact.get(
                "version"
            )
            == TRUSTED_METADATA[
                "version"
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

        "source_match": (
            artifact.get(
                "source"
            )
            == TRUSTED_METADATA[
                "source"
            ]
        ),

        "build_id_match": (
            artifact.get(
                "build_id"
            )
            == TRUSTED_METADATA[
                "build_id"
            ]
        ),

        "commit_match": (
            artifact.get(
                "commit"
            )
            == TRUSTED_METADATA[
                "commit"
            ]
        ),

        "signature_claim_verified": (
            artifact.get(
                "signature_status"
            )
            == "verified"
        ),

        "provenance_claim_match": (
            artifact.get(
                "provenance_attestation"
            )
            == TRUSTED_METADATA[
                "provenance_attestation"
            ]
        ),

        "sbom_claim_match": (
            artifact.get(
                "sbom_reference"
            )
            == TRUSTED_METADATA[
                "sbom_reference"
            ]
        ),
    }


    trusted_by_metadata = all(
        metadata_checks.values()
    )


    return {
        "trusted_by_metadata": (
            trusted_by_metadata
        ),

        **metadata_checks,
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
        "\n=== Day 25 Lab 9: "
        "Artifact Metadata & Provenance Spoofing ==="
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
        # TRUST EVALUATION
        # ====================================================

        trust_result = (
            vulnerable_trust_evaluation(
                artifact
            )
        )


        print(
            "\nMetadata Trust Evaluation:"
        )

        print_json(
            trust_result
        )


        # ====================================================
        # ACTUAL INTEGRITY
        # ====================================================

        actual_hash = (
            calculate_hash(
                artifact
            )
        )

        trusted_hash_match = (
            actual_hash
            == TRUSTED_HASH
        )


        # ====================================================
        # RUNTIME
        # ====================================================

        runtime_result = (
            execute_artifact(
                artifact
            )
        )


        print(
            "\nSynthetic Runtime Result:"
        )

        print_json(
            runtime_result
        )


        # ====================================================
        # ANALYSIS
        # ====================================================

        metadata_spoof_success = (
            case[
                "poisoned"
            ]
            and
            trust_result[
                "trusted_by_metadata"
            ]
            and
            not trusted_hash_match
        )


        false_trust_decision = (
            case[
                "poisoned"
            ]
            and
            trust_result[
                "trusted_by_metadata"
            ]
        )


        malicious_artifact_loaded = (
            case[
                "poisoned"
            ]
            and
            trust_result[
                "trusted_by_metadata"
            ]
        )


        runtime_compromised = (
            case[
                "poisoned"
            ]
            and
            runtime_result[
                "runtime_compromised"
            ]
        )


        signature_claim_spoofed = (
            case[
                "poisoned"
            ]
            and
            trust_result[
                "signature_claim_verified"
            ]
            and
            not trusted_hash_match
        )


        provenance_claim_spoofed = (
            case[
                "poisoned"
            ]
            and
            trust_result[
                "provenance_claim_match"
            ]
            and
            not trusted_hash_match
        )


        sbom_claim_spoofed = (
            case[
                "poisoned"
            ]
            and
            trust_result[
                "sbom_claim_match"
            ]
            and
            not trusted_hash_match
        )


        print(
            "\nSecurity Analysis:"
        )

        print(
            "Trusted Hash Match:",
            trusted_hash_match,
        )

        print(
            "Trusted By Metadata:",
            trust_result[
                "trusted_by_metadata"
            ],
        )

        print(
            "Metadata Spoof Success:",
            metadata_spoof_success,
        )

        print(
            "False Trust Decision:",
            false_trust_decision,
        )

        print(
            "Signature Claim Spoofed:",
            signature_claim_spoofed,
        )

        print(
            "Provenance Claim Spoofed:",
            provenance_claim_spoofed,
        )

        print(
            "SBOM Claim Spoofed:",
            sbom_claim_spoofed,
        )

        print(
            "Malicious Artifact Loaded:",
            malicious_artifact_loaded,
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
            trusted_hash_match
            and
            trust_result[
                "trusted_by_metadata"
            ]
            and
            not runtime_result[
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

                "metadata_spoof_success": (
                    metadata_spoof_success
                ),

                "false_trust_decision": (
                    false_trust_decision
                ),

                "signature_claim_spoofed": (
                    signature_claim_spoofed
                ),

                "provenance_claim_spoofed": (
                    provenance_claim_spoofed
                ),

                "sbom_claim_spoofed": (
                    sbom_claim_spoofed
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


    metadata_spoofs = sum(
        result[
            "metadata_spoof_success"
        ]
        for result
        in poisoned_results
    )


    false_trusts = sum(
        result[
            "false_trust_decision"
        ]
        for result
        in poisoned_results
    )


    signature_spoofs = sum(
        result[
            "signature_claim_spoofed"
        ]
        for result
        in poisoned_results
    )


    provenance_spoofs = sum(
        result[
            "provenance_claim_spoofed"
        ]
        for result
        in poisoned_results
    )


    sbom_spoofs = sum(
        result[
            "sbom_claim_spoofed"
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
        "    METADATA / PROVENANCE SPOOF SUMMARY"
    )

    print(
        "=" * 48
    )


    print(
        "Poisoned provenance cases:",
        poisoned_count,
    )


    print(
        "Metadata spoof successes:",
        metadata_spoofs,
    )


    print(
        "Metadata Spoof Success Rate:",
        f"{rate(
            metadata_spoofs,
            poisoned_count
        ):.2f}%"
    )


    print(
        "False Trust Decision Rate:",
        f"{rate(
            false_trusts,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Signature Claim Spoof Rate:",
        f"{rate(
            signature_spoofs,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Provenance Claim Spoof Rate:",
        f"{rate(
            provenance_spoofs,
            poisoned_count
        ):.2f}%"
    )


    print(
        "SBOM Claim Spoof Rate:",
        f"{rate(
            sbom_spoofs,
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
        "Metadata-Induced Runtime Compromise Rate:",
        f"{rate(
            runtime_compromises,
            poisoned_count
        ):.2f}%"
    )


    print(
        "\n=== Clean Utility ==="
    )


    print(
        "Clean provenance cases:",
        len(
            clean_results
        ),
    )


    print(
        "Clean trusted decisions:",
        clean_safe,
    )


    print(
        "Clean Provenance Utility Rate:",
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
        "The vulnerable trust evaluator accepts "
        "self-asserted metadata such as publisher, source, "
        "signature status, provenance attestation, build ID, "
        "commit identity, and SBOM reference."
    )


    print(
        "A malicious artifact can therefore clone trusted "
        "metadata while containing different executable "
        "behavior."
    )


    print(
        "Metadata claims must be cryptographically bound "
        "to the artifact digest and independently verified "
        "before they are used as trust evidence."
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