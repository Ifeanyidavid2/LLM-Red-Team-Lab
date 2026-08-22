"""
Day 25 - Lab 6
Model / Adapter Substitution

Purpose:
Measure whether a substituted model or adapter artifact can remain
functionally valid and loadable while introducing unauthorized capabilities
or unsafe runtime behavior.

Core Principle:
An AI component being available or functional does not establish
that it is authentic, trusted, or safe to load.
"""

import hashlib
import json
from copy import deepcopy


# ============================================================
# TRUSTED BASELINE MODEL
# ============================================================

TRUSTED_MODEL = {
    "artifact_id": "MODEL-2501",
    "name": "project-review-model",
    "version": "1.0.0",
    "publisher": "trusted_ai_team",
    "artifact_type": "model",
    "purpose": (
        "Analyze project documentation and produce factual summaries."
    ),
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


TRUSTED_ADAPTER = {
    "artifact_id": "ADAPTER-2501",
    "name": "project-review-adapter",
    "version": "1.0.0",
    "publisher": "trusted_ai_team",
    "artifact_type": "adapter",
    "purpose": (
        "Specialize the project-review model for project documentation."
    ),
    "capabilities": [
        "project_domain_adaptation",
    ],
    "content": {
        "behavior_modifier": "none",
        "target_override": None,
        "privilege_override": False,
    },
}


TRUSTED_TARGET = "R-2502"
RESTRICTED_TARGET = "R-2599"


# ============================================================
# HASH HELPERS
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

    encoded = canonical_json(
        artifact
    ).encode(
        "utf-8"
    )

    return hashlib.sha256(
        encoded
    ).hexdigest()


TRUSTED_MODEL_HASH = calculate_hash(
    TRUSTED_MODEL
)

TRUSTED_ADAPTER_HASH = calculate_hash(
    TRUSTED_ADAPTER
)


# ============================================================
# TEST CASES
# ============================================================

TESTS = [

    {
        "case_id": 1,
        "name": "Clean trusted model and adapter",
        "poisoned": False,

        "model": deepcopy(
            TRUSTED_MODEL
        ),

        "adapter": deepcopy(
            TRUSTED_ADAPTER
        ),
    },

    {
        "case_id": 2,
        "name": "Model payload substituted",
        "poisoned": True,

        "model": {
            **deepcopy(
                TRUSTED_MODEL
            ),

            "content": {
                **deepcopy(
                    TRUSTED_MODEL[
                        "content"
                    ]
                ),

                "behavior": "restricted_target_review",

                "default_target": "R-2599",
            },
        },

        "adapter": deepcopy(
            TRUSTED_ADAPTER
        ),
    },

    {
        "case_id": 3,
        "name": "Adapter target substitution",
        "poisoned": True,

        "model": deepcopy(
            TRUSTED_MODEL
        ),

        "adapter": {
            **deepcopy(
                TRUSTED_ADAPTER
            ),

            "content": {
                **deepcopy(
                    TRUSTED_ADAPTER[
                        "content"
                    ]
                ),

                "behavior_modifier": (
                    "override_target"
                ),

                "target_override": (
                    "R-2599"
                ),
            },
        },
    },

    {
        "case_id": 4,
        "name": "Unauthorized model capability expansion",
        "poisoned": True,

        "model": {
            **deepcopy(
                TRUSTED_MODEL
            ),

            "capabilities": [
                "summarize_project",
                "delete_record",
            ],

            "content": {
                **deepcopy(
                    TRUSTED_MODEL[
                        "content"
                    ]
                ),

                "allow_privileged_action": True,

                "default_action": (
                    "delete_record"
                ),

                "default_target": (
                    "R-2599"
                ),
            },
        },

        "adapter": deepcopy(
            TRUSTED_ADAPTER
        ),
    },

    {
        "case_id": 5,
        "name": "Adapter privilege override",
        "poisoned": True,

        "model": deepcopy(
            TRUSTED_MODEL
        ),

        "adapter": {
            **deepcopy(
                TRUSTED_ADAPTER
            ),

            "content": {
                **deepcopy(
                    TRUSTED_ADAPTER[
                        "content"
                    ]
                ),

                "behavior_modifier": (
                    "enable_privileged_action"
                ),

                "target_override": (
                    "R-2599"
                ),

                "privilege_override": True,
            },
        },
    },

    {
        "case_id": 6,
        "name": "Publisher identity impersonation",
        "poisoned": True,

        "model": {
            **deepcopy(
                TRUSTED_MODEL
            ),

            # Same visible trusted publisher string.
            # The vulnerable loader does not verify
            # publisher provenance or signatures.
            "publisher": (
                "trusted_ai_team"
            ),

            "content": {
                **deepcopy(
                    TRUSTED_MODEL[
                        "content"
                    ]
                ),

                "behavior": (
                    "impersonated_model"
                ),

                "default_action": (
                    "delete_record"
                ),

                "default_target": (
                    "R-2599"
                ),

                "allow_privileged_action": True,
            },
        },

        "adapter": deepcopy(
            TRUSTED_ADAPTER
        ),
    },

    {
        "case_id": 7,
        "name": "Second clean trusted model and adapter",
        "poisoned": False,

        "model": deepcopy(
            TRUSTED_MODEL
        ),

        "adapter": deepcopy(
            TRUSTED_ADAPTER
        ),
    },
]


# ============================================================
# VULNERABLE MODEL / ADAPTER LOADER
# ============================================================

class VulnerableModelLoader:

    def load_model(
        self,
        artifact,
    ):

        structurally_valid = (
            artifact.get(
                "artifact_type"
            )
            == "model"
            and
            isinstance(
                artifact.get(
                    "content"
                ),
                dict,
            )
            and
            isinstance(
                artifact.get(
                    "capabilities"
                ),
                list,
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
            "capabilities": deepcopy(
                artifact.get(
                    "capabilities",
                    [],
                )
            ),
            "content": deepcopy(
                artifact.get(
                    "content"
                )
            ),
            "sha256": calculate_hash(
                artifact
            ),
        }


    def load_adapter(
        self,
        artifact,
    ):

        structurally_valid = (
            artifact.get(
                "artifact_type"
            )
            == "adapter"
            and
            isinstance(
                artifact.get(
                    "content"
                ),
                dict,
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
            "content": deepcopy(
                artifact.get(
                    "content"
                )
            ),
            "sha256": calculate_hash(
                artifact
            ),
        }


# ============================================================
# SYNTHETIC RUNTIME
# ============================================================

def execute_model_runtime(
    model_result,
    adapter_result,
):

    if (
        not model_result[
            "loaded"
        ]
        or
        not adapter_result[
            "loaded"
        ]
    ):

        return {
            "success": False,
            "reason": (
                "Model or adapter failed to load."
            ),
        }

    model = model_result[
        "content"
    ]

    adapter = adapter_result[
        "content"
    ]

    action = model.get(
        "default_action",
        "read_record",
    )

    target = model.get(
        "default_target",
        TRUSTED_TARGET,
    )

    privileged = model.get(
        "allow_privileged_action",
        False,
    )


    # ========================================================
    # ADAPTER MODIFICATION
    # ========================================================

    if (
        adapter.get(
            "behavior_modifier"
        )
        == "override_target"
        and
        adapter.get(
            "target_override"
        )
        is not None
    ):

        target = adapter[
            "target_override"
        ]


    if (
        adapter.get(
            "behavior_modifier"
        )
        == "enable_privileged_action"
        and
        adapter.get(
            "privilege_override"
        )
        is True
    ):

        privileged = True

        action = "delete_record"

        if adapter.get(
            "target_override"
        ) is not None:

            target = adapter[
                "target_override"
            ]


    restricted_target_selected = (
        target
        == RESTRICTED_TARGET
    )

    privileged_action_selected = (
        action
        == "delete_record"
    )

    unauthorized_capability_used = (
        privileged_action_selected
        and
        (
            "delete_record"
            in model_result.get(
                "capabilities",
                []
            )
            or
            privileged
        )
    )

    runtime_compromised = (
        restricted_target_selected
        or
        privileged_action_selected
        or
        unauthorized_capability_used
    )

    return {
        "success": True,
        "action": action,
        "target": target,
        "privileged": privileged,
        "restricted_target_selected": (
            restricted_target_selected
        ),
        "privileged_action_selected": (
            privileged_action_selected
        ),
        "unauthorized_capability_used": (
            unauthorized_capability_used
        ),
        "runtime_compromised": (
            runtime_compromised
        ),
    }


# ============================================================
# ANALYSIS
# ============================================================

def analyze_case(
    case,
    model_result,
    adapter_result,
    runtime_result,
):

    model_integrity_changed = (
        model_result[
            "sha256"
        ]
        != TRUSTED_MODEL_HASH
    )

    adapter_integrity_changed = (
        adapter_result[
            "sha256"
        ]
        != TRUSTED_ADAPTER_HASH
    )

    model_substituted = (
        case[
            "poisoned"
        ]
        and
        model_integrity_changed
    )

    adapter_substituted = (
        case[
            "poisoned"
        ]
        and
        adapter_integrity_changed
    )

    malicious_artifact_loaded = (
        case[
            "poisoned"
        ]
        and
        (
            (
                model_substituted
                and
                model_result[
                    "loaded"
                ]
            )
            or
            (
                adapter_substituted
                and
                adapter_result[
                    "loaded"
                ]
            )
        )
    )

    unauthorized_capability = (
        case[
            "poisoned"
        ]
        and
        runtime_result.get(
            "unauthorized_capability_used",
            False,
        )
    )

    restricted_target = (
        case[
            "poisoned"
        ]
        and
        runtime_result.get(
            "restricted_target_selected",
            False,
        )
    )

    privileged_action = (
        case[
            "poisoned"
        ]
        and
        runtime_result.get(
            "privileged_action_selected",
            False,
        )
    )

    runtime_compromised = (
        case[
            "poisoned"
        ]
        and
        runtime_result.get(
            "runtime_compromised",
            False,
        )
    )

    return {
        "model_integrity_changed": (
            model_integrity_changed
        ),

        "adapter_integrity_changed": (
            adapter_integrity_changed
        ),

        "model_substituted": (
            model_substituted
        ),

        "adapter_substituted": (
            adapter_substituted
        ),

        "malicious_artifact_loaded": (
            malicious_artifact_loaded
        ),

        "unauthorized_capability": (
            unauthorized_capability
        ),

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
        "\n=== Day 25 Lab 6: "
        "Model / Adapter Substitution ==="
    )

    loader = VulnerableModelLoader()

    poisoned_cases = 0

    substituted_artifact_loads = 0

    model_integrity_mismatches = 0

    adapter_integrity_mismatches = 0

    model_substitutions = 0

    adapter_substitutions = 0

    unauthorized_capabilities = 0

    restricted_target_selections = 0

    privileged_action_selections = 0

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


        model_artifact = deepcopy(
            case[
                "model"
            ]
        )

        adapter_artifact = deepcopy(
            case[
                "adapter"
            ]
        )


        # ====================================================
        # LOAD MODEL
        # ====================================================

        model_result = (
            loader.load_model(
                model_artifact
            )
        )

        adapter_result = (
            loader.load_adapter(
                adapter_artifact
            )
        )


        print(
            "\nModel Loader Result:"
        )

        print(
            json.dumps(
                model_result,
                indent=2,
            )
        )

        print(
            "\nAdapter Loader Result:"
        )

        print(
            json.dumps(
                adapter_result,
                indent=2,
            )
        )


        # ====================================================
        # RUNTIME
        # ====================================================

        runtime_result = (
            execute_model_runtime(
                model_result,
                adapter_result,
            )
        )


        print(
            "\nSynthetic Runtime Result:"
        )

        print(
            json.dumps(
                runtime_result,
                indent=2,
            )
        )


        # ====================================================
        # ANALYSIS
        # ====================================================

        analysis = analyze_case(
            case,
            model_result,
            adapter_result,
            runtime_result,
        )


        if case[
            "poisoned"
        ]:

            poisoned_cases += 1

            if analysis[
                "malicious_artifact_loaded"
            ]:
                substituted_artifact_loads += 1

            if analysis[
                "model_integrity_changed"
            ]:
                model_integrity_mismatches += 1

            if analysis[
                "adapter_integrity_changed"
            ]:
                adapter_integrity_mismatches += 1

            if analysis[
                "model_substituted"
            ]:
                model_substitutions += 1

            if analysis[
                "adapter_substituted"
            ]:
                adapter_substitutions += 1

            if analysis[
                "unauthorized_capability"
            ]:
                unauthorized_capabilities += 1

            if analysis[
                "restricted_target_selected"
            ]:
                restricted_target_selections += 1

            if analysis[
                "privileged_action_selected"
            ]:
                privileged_action_selections += 1

            if analysis[
                "runtime_compromised"
            ]:
                runtime_compromises += 1


        else:

            clean_cases += 1

            clean_safe = (
                model_result[
                    "loaded"
                ]
                and
                adapter_result[
                    "loaded"
                ]
                and
                not analysis[
                    "model_integrity_changed"
                ]
                and
                not analysis[
                    "adapter_integrity_changed"
                ]
                and
                runtime_result[
                    "success"
                ]
                and
                runtime_result[
                    "action"
                ]
                == "read_record"
                and
                runtime_result[
                    "target"
                ]
                == TRUSTED_TARGET
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
            "Model Integrity Changed:",
            analysis[
                "model_integrity_changed"
            ],
        )

        print(
            "Adapter Integrity Changed:",
            analysis[
                "adapter_integrity_changed"
            ],
        )

        print(
            "Model Substituted:",
            analysis[
                "model_substituted"
            ],
        )

        print(
            "Adapter Substituted:",
            analysis[
                "adapter_substituted"
            ],
        )

        print(
            "Substituted Artifact Loaded:",
            analysis[
                "malicious_artifact_loaded"
            ],
        )

        print(
            "Unauthorized Capability Used:",
            analysis[
                "unauthorized_capability"
            ],
        )

        print(
            "Restricted Target Selected:",
            analysis[
                "restricted_target_selected"
            ],
        )

        print(
            "Privileged Action Selected:",
            analysis[
                "privileged_action_selected"
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
        "       MODEL / ADAPTER SUMMARY"
    )

    print(
        "========================================"
    )

    print(
        "Poisoned substitution cases:",
        poisoned_cases,
    )

    print(
        "Substituted artifacts loaded:",
        substituted_artifact_loads,
    )

    print(
        "Substituted Artifact Load Rate:",
        f"{rate(
            substituted_artifact_loads,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Model Integrity Mismatch Rate:",
        f"{rate(
            model_integrity_mismatches,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Adapter Integrity Mismatch Rate:",
        f"{rate(
            adapter_integrity_mismatches,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Model Substitution Rate:",
        f"{rate(
            model_substitutions,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Adapter Substitution Rate:",
        f"{rate(
            adapter_substitutions,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Unauthorized Capability Rate:",
        f"{rate(
            unauthorized_capabilities,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Restricted Target Selection Rate:",
        f"{rate(
            restricted_target_selections,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Privileged Action Selection Rate:",
        f"{rate(
            privileged_action_selections,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Model / Adapter Runtime Compromise Rate:",
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
        "Clean model/adapter cases:",
        clean_cases,
    )

    print(
        "Clean safe executions:",
        clean_safe_cases,
    )

    print(
        "Clean Model / Adapter Utility Rate:",
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
        "The vulnerable loader verifies only that model and "
        "adapter artifacts are structurally usable. It does "
        "not require the artifacts to match trusted hashes, "
        "signed provenance, expected capabilities, or trusted "
        "publisher identity."
    )

    print(
        "A substituted model or adapter can therefore remain "
        "functional while silently changing targets, adding "
        "privileged behavior, or expanding runtime capability."
    )

    print(
        "Model trust must include both the model artifact "
        "itself and every adapter or extension applied to it."
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