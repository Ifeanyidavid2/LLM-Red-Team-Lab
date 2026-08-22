"""
Day 25 Lab 11
Transitive Dependency Compromise

Purpose:
Measure whether a trusted top-level AI artifact can become effectively
compromised because one of its indirect dependencies is malicious.

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


# ============================================================
# TRUSTED DEPENDENCY GRAPH
# ============================================================

TRUSTED_APP = finalize_artifact(
    {
        "artifact_id": "APP-2511",
        "name": "ai-review-application",
        "version": "1.0.0",
        "publisher": "trusted_ai_team",
        "artifact_type": "application",
        "dependencies": [
            "model-runtime",
        ],
        "content": {
            "requested_action": "read_record",
            "target": "R-2502",
        },
    }
)


TRUSTED_MODEL_RUNTIME = finalize_artifact(
    {
        "artifact_id": "DEP-2511-A",
        "name": "model-runtime",
        "version": "3.2.0",
        "publisher": "trusted_ai_team",
        "artifact_type": "dependency",
        "dependencies": [
            "record-client",
        ],
        "capabilities": [
            "model_execution",
        ],
        "content": {
            "behavior": "normal",
        },
    }
)


TRUSTED_RECORD_CLIENT = finalize_artifact(
    {
        "artifact_id": "DEP-2511-B",
        "name": "record-client",
        "version": "2.1.0",
        "publisher": "trusted_security_team",
        "artifact_type": "dependency",
        "dependencies": [
            "transport-helper",
        ],
        "capabilities": [
            "record_lookup",
        ],
        "content": {
            "target_override": None,
            "privileged_mode": False,
        },
    }
)


TRUSTED_TRANSPORT_HELPER = finalize_artifact(
    {
        "artifact_id": "DEP-2511-C",
        "name": "transport-helper",
        "version": "1.4.0",
        "publisher": "trusted_security_team",
        "artifact_type": "dependency",
        "dependencies": [],
        "capabilities": [
            "transport",
        ],
        "content": {
            "target_rewrite": None,
            "privileged_mode": False,
            "security_status_override": None,
        },
    }
)


TRUSTED_HASHES = {
    artifact["name"]: artifact["sha256"]
    for artifact in [
        TRUSTED_APP,
        TRUSTED_MODEL_RUNTIME,
        TRUSTED_RECORD_CLIENT,
        TRUSTED_TRANSPORT_HELPER,
    ]
}


# ============================================================
# MALICIOUS TRANSITIVE DEPENDENCIES
# ============================================================

MALICIOUS_TRANSPORT_TARGET = finalize_artifact(
    {
        **{
            key: copy.deepcopy(value)
            for key, value
            in TRUSTED_TRANSPORT_HELPER.items()
            if key != "sha256"
        },
        "content": {
            "target_rewrite": "R-2599",
            "privileged_mode": False,
            "security_status_override": None,
        },
    }
)


MALICIOUS_TRANSPORT_PRIVILEGED = finalize_artifact(
    {
        **{
            key: copy.deepcopy(value)
            for key, value
            in TRUSTED_TRANSPORT_HELPER.items()
            if key != "sha256"
        },
        "capabilities": [
            "transport",
            "delete_record",
            "admin_override",
        ],
        "content": {
            "target_rewrite": "R-2599",
            "privileged_mode": True,
            "security_status_override": "allowed",
        },
    }
)


MALICIOUS_RECORD_CLIENT = finalize_artifact(
    {
        **{
            key: copy.deepcopy(value)
            for key, value
            in TRUSTED_RECORD_CLIENT.items()
            if key != "sha256"
        },
        "content": {
            "target_override": "R-2599",
            "privileged_mode": True,
        },
    }
)


# ============================================================
# TEST CASES
# ============================================================

TEST_CASES = [

    {
        "name": (
            "Case 1: Clean trusted dependency graph"
        ),
        "poisoned": False,
        "graph": {
            "application": copy.deepcopy(
                TRUSTED_APP
            ),
            "model-runtime": copy.deepcopy(
                TRUSTED_MODEL_RUNTIME
            ),
            "record-client": copy.deepcopy(
                TRUSTED_RECORD_CLIENT
            ),
            "transport-helper": copy.deepcopy(
                TRUSTED_TRANSPORT_HELPER
            ),
        },
    },

    {
        "name": (
            "Case 2: Transitive target rewrite"
        ),
        "poisoned": True,
        "graph": {
            "application": copy.deepcopy(
                TRUSTED_APP
            ),
            "model-runtime": copy.deepcopy(
                TRUSTED_MODEL_RUNTIME
            ),
            "record-client": copy.deepcopy(
                TRUSTED_RECORD_CLIENT
            ),
            "transport-helper": copy.deepcopy(
                MALICIOUS_TRANSPORT_TARGET
            ),
        },
    },

    {
        "name": (
            "Case 3: Transitive privilege expansion"
        ),
        "poisoned": True,
        "graph": {
            "application": copy.deepcopy(
                TRUSTED_APP
            ),
            "model-runtime": copy.deepcopy(
                TRUSTED_MODEL_RUNTIME
            ),
            "record-client": copy.deepcopy(
                TRUSTED_RECORD_CLIENT
            ),
            "transport-helper": copy.deepcopy(
                MALICIOUS_TRANSPORT_PRIVILEGED
            ),
        },
    },

    {
        "name": (
            "Case 4: Direct dependency compromised"
        ),
        "poisoned": True,
        "graph": {
            "application": copy.deepcopy(
                TRUSTED_APP
            ),
            "model-runtime": copy.deepcopy(
                TRUSTED_MODEL_RUNTIME
            ),
            "record-client": copy.deepcopy(
                MALICIOUS_RECORD_CLIENT
            ),
            "transport-helper": copy.deepcopy(
                TRUSTED_TRANSPORT_HELPER
            ),
        },
    },

    {
        "name": (
            "Case 5: Direct and transitive compromise"
        ),
        "poisoned": True,
        "graph": {
            "application": copy.deepcopy(
                TRUSTED_APP
            ),
            "model-runtime": copy.deepcopy(
                TRUSTED_MODEL_RUNTIME
            ),
            "record-client": copy.deepcopy(
                MALICIOUS_RECORD_CLIENT
            ),
            "transport-helper": copy.deepcopy(
                MALICIOUS_TRANSPORT_PRIVILEGED
            ),
        },
    },

    {
        "name": (
            "Case 6: Top-level artifact remains authentic"
        ),
        "poisoned": True,
        "graph": {
            "application": copy.deepcopy(
                TRUSTED_APP
            ),
            "model-runtime": copy.deepcopy(
                TRUSTED_MODEL_RUNTIME
            ),
            "record-client": copy.deepcopy(
                TRUSTED_RECORD_CLIENT
            ),
            "transport-helper": copy.deepcopy(
                MALICIOUS_TRANSPORT_TARGET
            ),
        },
    },

    {
        "name": (
            "Case 7: Second clean dependency graph"
        ),
        "poisoned": False,
        "graph": {
            "application": copy.deepcopy(
                TRUSTED_APP
            ),
            "model-runtime": copy.deepcopy(
                TRUSTED_MODEL_RUNTIME
            ),
            "record-client": copy.deepcopy(
                TRUSTED_RECORD_CLIENT
            ),
            "transport-helper": copy.deepcopy(
                TRUSTED_TRANSPORT_HELPER
            ),
        },
    },
]


# ============================================================
# VULNERABLE DEPENDENCY LOADER
# ============================================================

def vulnerable_load_graph(graph):
    """
    Intentionally vulnerable.

    The loader checks only that every dependency exists and
    that the graph is structurally resolvable.

    It does NOT recursively validate:
    - trusted hashes
    - publisher provenance
    - capability changes
    - transitive dependency integrity
    """

    required = {
        "application",
        "model-runtime",
        "record-client",
        "transport-helper",
    }

    graph_complete = (
        required.issubset(
            graph.keys()
        )
    )

    if not graph_complete:
        return {
            "loaded": False,
            "reason": (
                "Dependency graph incomplete."
            ),
        }

    return {
        "loaded": True,
        "graph_complete": True,
        "resolved_components": list(
            graph.keys()
        ),
    }


# ============================================================
# SYNTHETIC RUNTIME
# ============================================================

def execute_graph(graph):

    app = graph[
        "application"
    ]

    record_client = graph[
        "record-client"
    ]

    transport = graph[
        "transport-helper"
    ]

    action = app[
        "content"
    ][
        "requested_action"
    ]

    trusted_target = app[
        "content"
    ][
        "target"
    ]

    actual_target = trusted_target

    privileged = False

    security_status = "allowed"


    # ========================================================
    # DIRECT DEPENDENCY EFFECT
    # ========================================================

    record_content = record_client[
        "content"
    ]

    if record_content.get(
        "target_override"
    ):

        actual_target = (
            record_content[
                "target_override"
            ]
        )

    if record_content.get(
        "privileged_mode",
        False,
    ):

        privileged = True
        action = "delete_record"


    # ========================================================
    # TRANSITIVE DEPENDENCY EFFECT
    # ========================================================

    transport_content = transport[
        "content"
    ]

    if transport_content.get(
        "target_rewrite"
    ):

        actual_target = (
            transport_content[
                "target_rewrite"
            ]
        )

    if transport_content.get(
        "privileged_mode",
        False,
    ):

        privileged = True
        action = "delete_record"

    if transport_content.get(
        "security_status_override"
    ):

        security_status = (
            transport_content[
                "security_status_override"
            ]
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
        or privileged
        or privileged_action
    )


    return {
        "success": True,
        "requested_action": (
            app[
                "content"
            ][
                "requested_action"
            ]
        ),
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
        "security_status": (
            security_status
        ),
        "runtime_compromised": (
            runtime_compromised
        ),
    }


# ============================================================
# GRAPH ANALYSIS
# ============================================================

def analyze_integrity(graph):

    integrity = {}

    for key, artifact in graph.items():

        trusted_hash = (
            TRUSTED_HASHES.get(
                artifact[
                    "name"
                ]
            )
        )

        integrity[
            key
        ] = {
            "hash_match": (
                artifact[
                    "sha256"
                ]
                == trusted_hash
            ),
            "artifact_name": (
                artifact[
                    "name"
                ]
            ),
        }

    return integrity


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 25 Lab 11: "
        "Transitive Dependency Compromise ==="
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


        graph = copy.deepcopy(
            case[
                "graph"
            ]
        )


        # ====================================================
        # LOAD GRAPH
        # ====================================================

        load_result = (
            vulnerable_load_graph(
                graph
            )
        )


        print(
            "\nDependency Graph Load Result:"
        )

        print_json(
            load_result
        )


        # ====================================================
        # INTEGRITY
        # ====================================================

        integrity = (
            analyze_integrity(
                graph
            )
        )


        print(
            "\nDependency Integrity:"
        )

        print_json(
            integrity
        )


        # ====================================================
        # RUNTIME
        # ====================================================

        runtime = (
            execute_graph(
                graph
            )
        )


        print(
            "\nSynthetic Runtime Result:"
        )

        print_json(
            runtime
        )


        # ====================================================
        # SECURITY ANALYSIS
        # ====================================================

        app_authentic = (
            integrity[
                "application"
            ][
                "hash_match"
            ]
        )

        model_runtime_authentic = (
            integrity[
                "model-runtime"
            ][
                "hash_match"
            ]
        )

        record_client_authentic = (
            integrity[
                "record-client"
            ][
                "hash_match"
            ]
        )

        transport_authentic = (
            integrity[
                "transport-helper"
            ][
                "hash_match"
            ]
        )


        transitive_dependency_compromised = (
            case[
                "poisoned"
            ]
            and
            not transport_authentic
        )


        direct_dependency_compromised = (
            case[
                "poisoned"
            ]
            and
            not record_client_authentic
        )


        top_level_still_authentic = (
            app_authentic
            and
            model_runtime_authentic
        )


        graph_compromise_propagated = (
            case[
                "poisoned"
            ]
            and
            runtime[
                "runtime_compromised"
            ]
        )


        capability_escalation = (
            case[
                "poisoned"
            ]
            and
            runtime[
                "privileged_action_selected"
            ]
        )


        malicious_graph_loaded = (
            case[
                "poisoned"
            ]
            and
            load_result[
                "loaded"
            ]
            and
            (
                transitive_dependency_compromised
                or direct_dependency_compromised
            )
        )


        print(
            "\nSecurity Analysis:"
        )

        print(
            "Top-Level Application Authentic:",
            app_authentic,
        )

        print(
            "Model Runtime Authentic:",
            model_runtime_authentic,
        )

        print(
            "Direct Dependency Authentic:",
            record_client_authentic,
        )

        print(
            "Transitive Dependency Authentic:",
            transport_authentic,
        )

        print(
            "Top-Level Still Authentic:",
            top_level_still_authentic,
        )

        print(
            "Direct Dependency Compromised:",
            direct_dependency_compromised,
        )

        print(
            "Transitive Dependency Compromised:",
            transitive_dependency_compromised,
        )

        print(
            "Malicious Dependency Graph Loaded:",
            malicious_graph_loaded,
        )

        print(
            "Dependency-Graph Propagation:",
            graph_compromise_propagated,
        )

        print(
            "Capability Escalation:",
            capability_escalation,
        )

        print(
            "Runtime Compromised:",
            runtime[
                "runtime_compromised"
            ],
        )


        clean_safe = (
            not case[
                "poisoned"
            ]
            and
            load_result[
                "loaded"
            ]
            and
            all(
                item[
                    "hash_match"
                ]
                for item
                in integrity.values()
            )
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

                "transitive_dependency_compromised": (
                    transitive_dependency_compromised
                ),

                "direct_dependency_compromised": (
                    direct_dependency_compromised
                ),

                "malicious_graph_loaded": (
                    malicious_graph_loaded
                ),

                "graph_compromise_propagated": (
                    graph_compromise_propagated
                ),

                "capability_escalation": (
                    capability_escalation
                ),

                "runtime_compromised": (
                    case[
                        "poisoned"
                    ]
                    and
                    runtime[
                        "runtime_compromised"
                    ]
                ),

                "top_level_still_authentic": (
                    case[
                        "poisoned"
                    ]
                    and
                    top_level_still_authentic
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


    transitive_compromises = sum(
        result[
            "transitive_dependency_compromised"
        ]
        for result
        in poisoned_results
    )


    direct_compromises = sum(
        result[
            "direct_dependency_compromised"
        ]
        for result
        in poisoned_results
    )


    malicious_graph_loads = sum(
        result[
            "malicious_graph_loaded"
        ]
        for result
        in poisoned_results
    )


    propagation_cases = sum(
        result[
            "graph_compromise_propagated"
        ]
        for result
        in poisoned_results
    )


    capability_escalations = sum(
        result[
            "capability_escalation"
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


    authentic_top_levels = sum(
        result[
            "top_level_still_authentic"
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
        "    TRANSITIVE DEPENDENCY SUMMARY"
    )

    print(
        "=" * 48
    )


    print(
        "Poisoned dependency-graph cases:",
        poisoned_count,
    )


    print(
        "Transitive dependency compromises:",
        transitive_compromises,
    )


    print(
        "Transitive Dependency Compromise Rate:",
        f"{rate(
            transitive_compromises,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Direct Dependency Compromise Rate:",
        f"{rate(
            direct_compromises,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Malicious Dependency-Graph Load Rate:",
        f"{rate(
            malicious_graph_loads,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Dependency-Graph Propagation Rate:",
        f"{rate(
            propagation_cases,
            poisoned_count
        ):.2f}%"
    )


    print(
        "Capability Escalation Rate:",
        f"{rate(
            capability_escalations,
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
        "Authentic Top-Level / Compromised Tree Rate:",
        f"{rate(
            authentic_top_levels,
            poisoned_count
        ):.2f}%"
    )


    print(
        "\n=== Clean Utility ==="
    )


    print(
        "Clean dependency-graph cases:",
        len(
            clean_results
        ),
    )


    print(
        "Clean safe dependency graphs:",
        clean_safe,
    )


    print(
        "Clean Dependency-Graph Utility Rate:",
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
        "A trusted top-level application and model runtime "
        "do not establish the trustworthiness of the full "
        "dependency tree."
    )


    print(
        "Compromise in a direct or transitive dependency "
        "can propagate into target selection, privilege, "
        "and runtime behavior even when the top-level "
        "artifact remains authentic."
    )


    print(
        "Supply-chain trust must therefore be evaluated "
        "recursively across the complete dependency graph."
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