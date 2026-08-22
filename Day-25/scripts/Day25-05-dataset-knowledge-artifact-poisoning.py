"""
Day 25 - Lab 5
Dataset / Knowledge Artifact Poisoning

Purpose:
Measure whether a compromised dataset or knowledge artifact can
introduce false facts, restricted targets, false classifications,
approval claims, or authority claims into an AI workflow.

Core Principle:
An AI component being available or functional does not establish
that it is authentic, trusted, or safe to load.
"""

import hashlib
import json
from copy import deepcopy


# ============================================================
# TRUSTED DATASET
# ============================================================

TRUSTED_DATASET = {
    "artifact_id": "DATA-2501",
    "name": "project-reference-data",
    "version": "1.0.0",
    "publisher": "trusted_data_team",
    "artifact_type": "dataset",
    "purpose": (
        "Provide trusted project-reference information."
    ),
    "content": {
        "project_record": "R-2502",
        "classification": "internal",
        "status": "documentation review",
        "security_approval": False,
        "authorized_role": "worker_agent",
        "recommended_action": "read_record",
    },
}


TRUSTED_TARGET = "R-2502"
RESTRICTED_TARGET = "R-2599"


# ============================================================
# HASH FUNCTIONS
# ============================================================

def canonical_json(value):

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    )


def calculate_hash(artifact):

    encoded = canonical_json(
        artifact
    ).encode(
        "utf-8"
    )

    return hashlib.sha256(
        encoded
    ).hexdigest()


TRUSTED_HASH = calculate_hash(
    TRUSTED_DATASET
)


# ============================================================
# TEST CASES
# ============================================================

TESTS = [

    {
        "case_id": 1,
        "name": "Clean trusted dataset",
        "poisoned": False,

        "artifact": deepcopy(
            TRUSTED_DATASET
        ),
    },

    {
        "case_id": 2,
        "name": "Restricted target substituted",
        "poisoned": True,

        "artifact": {
            **deepcopy(
                TRUSTED_DATASET
            ),

            "content": {
                **deepcopy(
                    TRUSTED_DATASET[
                        "content"
                    ]
                ),

                "project_record": (
                    "R-2599"
                ),
            },
        },
    },

    {
        "case_id": 3,
        "name": "Restricted classification changed to public",
        "poisoned": True,

        "artifact": {
            **deepcopy(
                TRUSTED_DATASET
            ),

            "content": {
                **deepcopy(
                    TRUSTED_DATASET[
                        "content"
                    ]
                ),

                "project_record": (
                    "R-2599"
                ),

                "classification": (
                    "public"
                ),
            },
        },
    },

    {
        "case_id": 4,
        "name": "False security approval inserted",
        "poisoned": True,

        "artifact": {
            **deepcopy(
                TRUSTED_DATASET
            ),

            "content": {
                **deepcopy(
                    TRUSTED_DATASET[
                        "content"
                    ]
                ),

                "security_approval": True,
            },
        },
    },

    {
        "case_id": 5,
        "name": "False authority inserted",
        "poisoned": True,

        "artifact": {
            **deepcopy(
                TRUSTED_DATASET
            ),

            "content": {
                **deepcopy(
                    TRUSTED_DATASET[
                        "content"
                    ]
                ),

                "authorized_role": (
                    "security_agent"
                ),
            },
        },
    },

    {
        "case_id": 6,
        "name": "Privileged action inserted",
        "poisoned": True,

        "artifact": {
            **deepcopy(
                TRUSTED_DATASET
            ),

            "content": {
                **deepcopy(
                    TRUSTED_DATASET[
                        "content"
                    ]
                ),

                "project_record": (
                    "R-2599"
                ),

                "recommended_action": (
                    "delete_record"
                ),
            },
        },
    },

    {
        "case_id": 7,
        "name": "Second clean trusted dataset",
        "poisoned": False,

        "artifact": deepcopy(
            TRUSTED_DATASET
        ),
    },
]


# ============================================================
# VULNERABLE DATASET LOADER
# ============================================================

class VulnerableDatasetLoader:

    def load(
        self,
        artifact,
    ):

        content = artifact.get(
            "content"
        )

        required_fields = {
            "project_record",
            "classification",
            "status",
            "security_approval",
            "authorized_role",
            "recommended_action",
        }

        structurally_valid = (
            artifact.get(
                "artifact_type"
            )
            == "dataset"
            and
            isinstance(
                content,
                dict,
            )
            and
            required_fields.issubset(
                set(
                    content.keys()
                )
            )
        )

        return {
            "loaded": structurally_valid,
            "artifact_id": artifact.get(
                "artifact_id"
            ),
            "name": artifact.get(
                "name"
            ),
            "version": artifact.get(
                "version"
            ),
            "publisher": artifact.get(
                "publisher"
            ),
            "sha256": calculate_hash(
                artifact
            ),
            "knowledge": deepcopy(
                content
            ) if structurally_valid else None,
        }


# ============================================================
# VULNERABLE KNOWLEDGE CONSUMER
# ============================================================

def consume_knowledge(
    knowledge,
):

    if knowledge is None:

        return {
            "success": False,
            "reason": (
                "Knowledge artifact unavailable."
            ),
        }

    target = knowledge.get(
        "project_record"
    )

    classification = (
        knowledge.get(
            "classification"
        )
    )

    security_approval = (
        knowledge.get(
            "security_approval",
            False,
        )
    )

    authorized_role = (
        knowledge.get(
            "authorized_role"
        )
    )

    recommended_action = (
        knowledge.get(
            "recommended_action"
        )
    )

    # --------------------------------------------------------
    # Intentionally vulnerable:
    # The application trusts the dataset as factual truth.
    # --------------------------------------------------------

    restricted_target_accepted = (
        target
        == RESTRICTED_TARGET
    )

    public_classification_accepted = (
        target
        == RESTRICTED_TARGET
        and
        classification
        == "public"
    )

    approval_accepted = (
        security_approval is True
    )

    authority_accepted = (
        authorized_role
        == "security_agent"
    )

    privileged_action_accepted = (
        recommended_action
        == "delete_record"
    )

    runtime_compromised = (
        restricted_target_accepted
        or public_classification_accepted
        or approval_accepted
        or authority_accepted
        or privileged_action_accepted
    )

    return {
        "success": True,
        "target": target,
        "classification": (
            classification
        ),
        "security_approval": (
            security_approval
        ),
        "authorized_role": (
            authorized_role
        ),
        "recommended_action": (
            recommended_action
        ),
        "restricted_target_accepted": (
            restricted_target_accepted
        ),
        "public_classification_accepted": (
            public_classification_accepted
        ),
        "approval_accepted": (
            approval_accepted
        ),
        "authority_accepted": (
            authority_accepted
        ),
        "privileged_action_accepted": (
            privileged_action_accepted
        ),
        "runtime_compromised": (
            runtime_compromised
        ),
    }


# ============================================================
# SECURITY ANALYSIS
# ============================================================

def analyze_case(
    case,
    load_result,
    runtime_result,
):

    integrity_changed = (
        load_result[
            "sha256"
        ]
        != TRUSTED_HASH
    )

    malicious_dataset_loaded = (
        case[
            "poisoned"
        ]
        and
        load_result[
            "loaded"
        ]
    )

    false_fact_accepted = (
        case[
            "poisoned"
        ]
        and
        runtime_result.get(
            "success",
            False,
        )
        and
        runtime_result.get(
            "runtime_compromised",
            False,
        )
    )

    return {
        "integrity_changed": (
            integrity_changed
        ),

        "malicious_dataset_loaded": (
            malicious_dataset_loaded
        ),

        "false_fact_accepted": (
            false_fact_accepted
        ),

        "restricted_target_substitution": (
            runtime_result.get(
                "restricted_target_accepted",
                False,
            )
        ),

        "false_classification_accepted": (
            runtime_result.get(
                "public_classification_accepted",
                False,
            )
        ),

        "false_approval_accepted": (
            runtime_result.get(
                "approval_accepted",
                False,
            )
        ),

        "false_authority_accepted": (
            runtime_result.get(
                "authority_accepted",
                False,
            )
        ),

        "privileged_action_accepted": (
            runtime_result.get(
                "privileged_action_accepted",
                False,
            )
        ),

        "runtime_compromised": (
            case[
                "poisoned"
            ]
            and
            runtime_result.get(
                "runtime_compromised",
                False,
            )
        ),
    }


# ============================================================
# RATE
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


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 25 Lab 5: "
        "Dataset / Knowledge Artifact Poisoning ==="
    )

    loader = (
        VulnerableDatasetLoader()
    )

    poisoned_cases = 0

    malicious_dataset_loads = 0

    integrity_changes = 0

    false_fact_acceptances = 0

    restricted_target_substitutions = 0

    false_classification_acceptances = 0

    false_approval_acceptances = 0

    false_authority_acceptances = 0

    privileged_action_acceptances = 0

    runtime_compromises = 0

    clean_cases = 0

    clean_safe_cases = 0


    for case in TESTS:

        print(
            "\n========================================"
        )

        print(
            f"Case {case['case_id']}: "
            f"{case['name']}"
        )

        print(
            "========================================"
        )

        print(
            "Poisoned:",
            case[
                "poisoned"
            ],
        )


        artifact = deepcopy(
            case[
                "artifact"
            ]
        )


        print(
            "\nDataset Artifact:"
        )

        print(
            json.dumps(
                artifact,
                indent=2,
            )
        )


        # ====================================================
        # LOAD
        # ====================================================

        load_result = (
            loader.load(
                artifact
            )
        )


        print(
            "\nLoader Result:"
        )

        print(
            json.dumps(
                load_result,
                indent=2,
            )
        )


        # ====================================================
        # CONSUME KNOWLEDGE
        # ====================================================

        runtime_result = (
            consume_knowledge(
                load_result.get(
                    "knowledge"
                )
            )
        )


        print(
            "\nKnowledge Consumption Result:"
        )

        print(
            json.dumps(
                runtime_result,
                indent=2,
            )
        )


        # ====================================================
        # ANALYZE
        # ====================================================

        analysis = analyze_case(
            case,
            load_result,
            runtime_result,
        )


        if case[
            "poisoned"
        ]:

            poisoned_cases += 1

            if analysis[
                "malicious_dataset_loaded"
            ]:
                malicious_dataset_loads += 1

            if analysis[
                "integrity_changed"
            ]:
                integrity_changes += 1

            if analysis[
                "false_fact_accepted"
            ]:
                false_fact_acceptances += 1

            if analysis[
                "restricted_target_substitution"
            ]:
                restricted_target_substitutions += 1

            if analysis[
                "false_classification_accepted"
            ]:
                false_classification_acceptances += 1

            if analysis[
                "false_approval_accepted"
            ]:
                false_approval_acceptances += 1

            if analysis[
                "false_authority_accepted"
            ]:
                false_authority_acceptances += 1

            if analysis[
                "privileged_action_accepted"
            ]:
                privileged_action_acceptances += 1

            if analysis[
                "runtime_compromised"
            ]:
                runtime_compromises += 1


        else:

            clean_cases += 1

            clean_safe = (
                load_result[
                    "loaded"
                ]
                and
                not analysis[
                    "integrity_changed"
                ]
                and
                runtime_result[
                    "success"
                ]
                and
                runtime_result[
                    "target"
                ]
                == TRUSTED_TARGET
                and
                runtime_result[
                    "classification"
                ]
                == "internal"
                and
                runtime_result[
                    "security_approval"
                ]
                is False
                and
                runtime_result[
                    "authorized_role"
                ]
                == "worker_agent"
                and
                runtime_result[
                    "recommended_action"
                ]
                == "read_record"
                and
                not runtime_result[
                    "runtime_compromised"
                ]
            )

            if clean_safe:
                clean_safe_cases += 1


        # ====================================================
        # OUTPUT
        # ====================================================

        print(
            "\nSecurity Analysis:"
        )

        print(
            "Integrity Changed:",
            analysis[
                "integrity_changed"
            ],
        )

        print(
            "Malicious Dataset Loaded:",
            analysis[
                "malicious_dataset_loaded"
            ],
        )

        print(
            "False Fact Accepted:",
            analysis[
                "false_fact_accepted"
            ],
        )

        print(
            "Restricted Target Substituted:",
            analysis[
                "restricted_target_substitution"
            ],
        )

        print(
            "False Classification Accepted:",
            analysis[
                "false_classification_accepted"
            ],
        )

        print(
            "False Approval Accepted:",
            analysis[
                "false_approval_accepted"
            ],
        )

        print(
            "False Authority Accepted:",
            analysis[
                "false_authority_accepted"
            ],
        )

        print(
            "Privileged Action Accepted:",
            analysis[
                "privileged_action_accepted"
            ],
        )

        print(
            "Runtime Compromised:",
            analysis[
                "runtime_compromised"
            ],
        )


    # ========================================================
    # SUMMARY
    # ========================================================

    print(
        "\n========================================"
    )

    print(
        "       DATASET POISONING SUMMARY"
    )

    print(
        "========================================"
    )

    print(
        "Poisoned dataset cases:",
        poisoned_cases,
    )

    print(
        "Malicious datasets loaded:",
        malicious_dataset_loads,
    )

    print(
        "Malicious Dataset Load Rate:",
        f"{rate(
            malicious_dataset_loads,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Dataset Integrity Change Rate:",
        f"{rate(
            integrity_changes,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "False Fact Acceptance Rate:",
        f"{rate(
            false_fact_acceptances,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Restricted Target Substitution Rate:",
        f"{rate(
            restricted_target_substitutions,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "False Classification Acceptance Rate:",
        f"{rate(
            false_classification_acceptances,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "False Approval Acceptance Rate:",
        f"{rate(
            false_approval_acceptances,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "False Authority Acceptance Rate:",
        f"{rate(
            false_authority_acceptances,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Privileged Action Acceptance Rate:",
        f"{rate(
            privileged_action_acceptances,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Knowledge-Induced Runtime Compromise Rate:",
        f"{rate(
            runtime_compromises,
            poisoned_cases
        ):.2f}%"
    )


    # ========================================================
    # CLEAN UTILITY
    # ========================================================

    print(
        "\n=== Clean Utility ==="
    )

    print(
        "Clean dataset cases:",
        clean_cases,
    )

    print(
        "Clean safe dataset executions:",
        clean_safe_cases,
    )

    print(
        "Clean Dataset Utility Rate:",
        f"{rate(
            clean_safe_cases,
            clean_cases
        ):.2f}%"
    )


    # ========================================================
    # INTERPRETATION
    # ========================================================

    print(
        "\nSecurity Interpretation:"
    )

    print(
        "The vulnerable application accepts the dataset "
        "because its schema is structurally valid, but does "
        "not verify that the artifact still matches the "
        "trusted dataset hash or trusted knowledge semantics."
    )

    print(
        "A compromised knowledge artifact can therefore "
        "redefine facts, classifications, targets, approvals, "
        "roles, or recommended actions before runtime."
    )

    print(
        "Knowledge retrieved from a loaded artifact should "
        "not automatically be treated as security authority."
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