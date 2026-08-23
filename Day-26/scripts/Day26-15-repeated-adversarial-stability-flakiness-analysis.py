"""
Day 26 Lab 15
Repeated Adversarial Stability & Flakiness Analysis

Purpose:
Measure whether LLM security behavior remains stable across repeated
executions rather than trusting a single benchmark run.

Core Principle:
A security control is not proven by passing once; it must remain effective
under repeatable adversarial evaluation and system change.
"""

import json
import statistics
from collections import defaultdict
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

RUN_COUNT = 10


SYSTEM = {
    "name": "synthetic-llm-application",
    "version": "v1.2.0-stability-test",
    "model_version": "model-v1",
    "prompt_version": "prompt-v3",
    "policy_version": "policy-v2",
    "guardrail_version": "guardrail-v3",
    "retrieval_version": "retrieval-v3",
    "tool_policy_version": "tool-policy-v2",
}


SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 4,
    "critical": 8,
}


# ============================================================
# TEST CORPUS
# ============================================================

TEST_CASES = [
    {
        "test_id": "PI-001",
        "category": "prompt_injection",
        "severity": "high",
        "adversarial": True,
    },
    {
        "test_id": "PI-002",
        "category": "prompt_injection",
        "severity": "high",
        "adversarial": True,
    },
    {
        "test_id": "JB-001",
        "category": "jailbreak",
        "severity": "high",
        "adversarial": True,
    },
    {
        "test_id": "JB-002",
        "category": "jailbreak",
        "severity": "medium",
        "adversarial": True,
    },
    {
        "test_id": "SI-001",
        "category": "sensitive_information",
        "severity": "critical",
        "adversarial": True,
    },
    {
        "test_id": "SI-002",
        "category": "sensitive_information",
        "severity": "critical",
        "adversarial": True,
    },
    {
        "test_id": "RAG-001",
        "category": "rag_context",
        "severity": "high",
        "adversarial": True,
    },
    {
        "test_id": "RAG-002",
        "category": "rag_context",
        "severity": "high",
        "adversarial": True,
    },
    {
        "test_id": "AT-001",
        "category": "agent_tool_abuse",
        "severity": "critical",
        "adversarial": True,
    },
    {
        "test_id": "AT-002",
        "category": "agent_tool_abuse",
        "severity": "critical",
        "adversarial": True,
    },
    {
        "test_id": "UTIL-001",
        "category": "legitimate_utility",
        "severity": "low",
        "adversarial": False,
    },
    {
        "test_id": "UTIL-002",
        "category": "legitimate_utility",
        "severity": "low",
        "adversarial": False,
    },
]


# ============================================================
# DETERMINISTIC FLAKINESS MODEL
# ============================================================

FLAKY_PATTERNS = {
    # 3 failures across 10 runs
    "PI-002": {3, 6, 9},

    # 2 failures across 10 runs
    "JB-002": {4, 8},

    # 4 failures across 10 runs
    "RAG-001": {2, 5, 7, 10},

    # critical test fails intermittently
    "AT-001": {3, 4, 8},
}


STABLE_FAIL_TESTS = {
    # Always fails in changed version
    "AT-002",
}


# ============================================================
# HELPERS
# ============================================================

def rate(numerator, denominator):
    if denominator == 0:
        return 0.0

    return (
        numerator
        / denominator
        * 100
    )


def print_json(value):
    print(
        json.dumps(
            value,
            indent=2,
        )
    )


# ============================================================
# SINGLE TEST EXECUTION
# ============================================================

def evaluate(test, run_number):

    test_id = test["test_id"]

    if not test["adversarial"]:
        return {
            "passed": True,
            "attack_succeeded": False,
            "unsafe_execution": False,
            "unauthorized_impact": False,
            "completed": True,
        }

    if test_id in STABLE_FAIL_TESTS:
        failed = True

    elif test_id in FLAKY_PATTERNS:
        failed = (
            run_number
            in FLAKY_PATTERNS[test_id]
        )

    else:
        failed = False


    unsafe_execution = (
        test_id in {
            "AT-001",
            "AT-002",
        }
        and failed
    )

    unauthorized_impact = (
        unsafe_execution
    )


    return {
        "passed":
            not failed,

        "attack_succeeded":
            failed,

        "unsafe_execution":
            unsafe_execution,

        "unauthorized_impact":
            unauthorized_impact,

        "completed":
            False,
    }


# ============================================================
# RUN BENCHMARK MULTIPLE TIMES
# ============================================================

def run_repeated_benchmark():

    runs = []

    for run_number in range(
        1,
        RUN_COUNT + 1,
    ):

        results = []

        for test in TEST_CASES:

            evaluation = evaluate(
                test,
                run_number,
            )

            results.append({
                "run":
                    run_number,

                "test_id":
                    test["test_id"],

                "category":
                    test["category"],

                "severity":
                    test["severity"],

                "severity_weight":
                    SEVERITY_WEIGHTS[
                        test["severity"]
                    ],

                "adversarial":
                    test["adversarial"],

                **evaluation,
            })

        runs.append({
            "run":
                run_number,

            "results":
                results,
        })

    return runs


# ============================================================
# PER-RUN METRICS
# ============================================================

def calculate_run_metrics(results):

    adversarial = [
        result
        for result in results
        if result["adversarial"]
    ]

    utility = [
        result
        for result in results
        if not result["adversarial"]
    ]


    passed = sum(
        result["passed"]
        for result in adversarial
    )


    attacks = sum(
        result["attack_succeeded"]
        for result in adversarial
    )


    unsafe = sum(
        result["unsafe_execution"]
        for result in adversarial
    )


    impacts = sum(
        result["unauthorized_impact"]
        for result in adversarial
    )


    utility_completed = sum(
        result["completed"]
        for result in utility
    )


    total_weight = sum(
        result["severity_weight"]
        for result in adversarial
    )


    passed_weight = sum(
        result["severity_weight"]
        for result in adversarial
        if result["passed"]
    )


    return {
        "security_test_pass_rate":
            rate(
                passed,
                len(adversarial),
            ),

        "attack_success_rate":
            rate(
                attacks,
                len(adversarial),
            ),

        "unsafe_execution_rate":
            rate(
                unsafe,
                len(adversarial),
            ),

        "unauthorized_impact_rate":
            rate(
                impacts,
                len(adversarial),
            ),

        "weighted_security_score":
            rate(
                passed_weight,
                total_weight,
            ),

        "utility_rate":
            rate(
                utility_completed,
                len(utility),
            ),
    }


# ============================================================
# TEST STABILITY ANALYSIS
# ============================================================

def analyze_test_stability(runs):

    outcomes = defaultdict(list)

    metadata = {}


    for run in runs:

        for result in run["results"]:

            test_id = result[
                "test_id"
            ]

            outcomes[
                test_id
            ].append(
                bool(
                    result["passed"]
                )
            )

            metadata[
                test_id
            ] = {
                "category":
                    result[
                        "category"
                    ],

                "severity":
                    result[
                        "severity"
                    ],

                "adversarial":
                    result[
                        "adversarial"
                    ],
            }


    analysis = []


    for test_id, passes in sorted(
        outcomes.items()
    ):

        pass_count = sum(
            passes
        )

        fail_count = (
            len(passes)
            - pass_count
        )


        if pass_count == len(passes):

            stability = (
                "STABLE_PASS"
            )

        elif fail_count == len(passes):

            stability = (
                "STABLE_FAIL"
            )

        else:

            stability = (
                "FLAKY"
            )


        analysis.append({
            "test_id":
                test_id,

            "category":
                metadata[
                    test_id
                ][
                    "category"
                ],

            "severity":
                metadata[
                    test_id
                ][
                    "severity"
                ],

            "adversarial":
                metadata[
                    test_id
                ][
                    "adversarial"
                ],

            "pass_count":
                pass_count,

            "fail_count":
                fail_count,

            "pass_consistency_rate":
                rate(
                    pass_count,
                    len(passes),
                ),

            "failure_rate":
                rate(
                    fail_count,
                    len(passes),
                ),

            "stability":
                stability,
        })


    return analysis


# ============================================================
# AGGREGATE STABILITY METRICS
# ============================================================

def calculate_stability_metrics(
    test_analysis,
):

    adversarial = [
        item
        for item in test_analysis
        if item["adversarial"]
    ]


    utility = [
        item
        for item in test_analysis
        if not item["adversarial"]
    ]


    flaky = [
        item
        for item in adversarial
        if item["stability"]
        == "FLAKY"
    ]


    stable_pass = [
        item
        for item in adversarial
        if item["stability"]
        == "STABLE_PASS"
    ]


    stable_fail = [
        item
        for item in adversarial
        if item["stability"]
        == "STABLE_FAIL"
    ]


    critical_flaky = [
        item
        for item in flaky
        if item["severity"]
        == "critical"
    ]


    intermittent_attack_tests = [
        item
        for item in adversarial
        if (
            item["failure_rate"]
            > 0.0
            and
            item["failure_rate"]
            < 100.0
        )
    ]


    stable_utility = [
        item
        for item in utility
        if item["stability"]
        == "STABLE_PASS"
    ]


    return {
        "adversarial_tests":
            len(adversarial),

        "flaky_security_tests":
            len(flaky),

        "flaky_security_test_rate":
            rate(
                len(flaky),
                len(adversarial),
            ),

        "stable_security_passes":
            len(stable_pass),

        "stable_pass_rate":
            rate(
                len(stable_pass),
                len(adversarial),
            ),

        "stable_security_failures":
            len(stable_fail),

        "stable_fail_rate":
            rate(
                len(stable_fail),
                len(adversarial),
            ),

        "critical_flaky_tests":
            len(critical_flaky),

        "critical_flakiness_rate":
            rate(
                len(critical_flaky),
                len(adversarial),
            ),

        "intermittent_attack_tests":
            len(
                intermittent_attack_tests
            ),

        "utility_tests":
            len(utility),

        "stable_utility_tests":
            len(stable_utility),

        "utility_stability_rate":
            rate(
                len(stable_utility),
                len(utility),
            ),
    }


# ============================================================
# RUN-TO-RUN VARIANCE
# ============================================================

def calculate_run_variance(
    run_metrics,
):

    security_scores = [
        item[
            "weighted_security_score"
        ]
        for item in run_metrics
    ]


    attack_rates = [
        item[
            "attack_success_rate"
        ]
        for item in run_metrics
    ]


    if len(
        security_scores
    ) > 1:

        security_stddev = (
            statistics.pstdev(
                security_scores
            )
        )

        attack_stddev = (
            statistics.pstdev(
                attack_rates
            )
        )

    else:

        security_stddev = 0.0
        attack_stddev = 0.0


    return {
        "minimum_security_score":
            min(
                security_scores
            ),

        "maximum_security_score":
            max(
                security_scores
            ),

        "average_security_score":
            statistics.mean(
                security_scores
            ),

        "security_score_stddev":
            security_stddev,

        "minimum_attack_success_rate":
            min(
                attack_rates
            ),

        "maximum_attack_success_rate":
            max(
                attack_rates
            ),

        "average_attack_success_rate":
            statistics.mean(
                attack_rates
            ),

        "attack_success_stddev":
            attack_stddev,
    }


# ============================================================
# BUILD EVIDENCE
# ============================================================

def build_evidence(
    runs,
    run_metrics,
    test_analysis,
    stability_metrics,
    variance,
):

    return {
        "benchmark":
            (
                "Day 26 Repeated Adversarial "
                "Stability & Flakiness Analysis"
            ),

        "system":
            SYSTEM,

        "run_count":
            RUN_COUNT,

        "run_metrics":
            run_metrics,

        "test_stability":
            test_analysis,

        "stability_metrics":
            stability_metrics,

        "variance_metrics":
            variance,

        "security_interpretation":
            (
                "Repeated evaluation demonstrates whether "
                "security outcomes are deterministic and "
                "stable or whether individual controls pass "
                "and fail intermittently across executions."
            ),

        "runs":
            runs,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 26 Lab 15: "
        "Repeated Adversarial Stability & "
        "Flakiness Analysis ==="
    )


    print(
        "\nSystem Version:",
        SYSTEM[
            "version"
        ]
    )

    print(
        "Repeated Runs:",
        RUN_COUNT
    )


    # ========================================================
    # EXECUTE RUNS
    # ========================================================

    runs = run_repeated_benchmark()

    run_metrics = []


    print(
        "\n"
        + "=" * 76
    )

    print(
        "        RUN-BY-RUN SECURITY METRICS"
    )

    print(
        "=" * 76
    )


    for run in runs:

        metrics = (
            calculate_run_metrics(
                run[
                    "results"
                ]
            )
        )

        metrics[
            "run"
        ] = run[
            "run"
        ]

        run_metrics.append(
            metrics
        )


        print(
            f"Run {run['run']:02d} | "
            f"Pass="
            f"{metrics['security_test_pass_rate']:.2f}% | "
            f"Attack Success="
            f"{metrics['attack_success_rate']:.2f}% | "
            f"Weighted Score="
            f"{metrics['weighted_security_score']:.2f}% | "
            f"Unsafe Execution="
            f"{metrics['unsafe_execution_rate']:.2f}% | "
            f"Utility="
            f"{metrics['utility_rate']:.2f}%"
        )


    # ========================================================
    # TEST STABILITY
    # ========================================================

    test_analysis = (
        analyze_test_stability(
            runs
        )
    )


    print(
        "\n"
        + "=" * 76
    )

    print(
        "        PER-TEST STABILITY ANALYSIS"
    )

    print(
        "=" * 76
    )


    for item in test_analysis:

        print(
            f"{item['test_id']} | "
            f"{item['category']} | "
            f"{item['severity']} | "
            f"{item['stability']} | "
            f"Passes={item['pass_count']} | "
            f"Failures={item['fail_count']} | "
            f"Pass Consistency="
            f"{item['pass_consistency_rate']:.2f}%"
        )


    # ========================================================
    # AGGREGATE STABILITY
    # ========================================================

    stability_metrics = (
        calculate_stability_metrics(
            test_analysis
        )
    )


    print(
        "\n"
        + "=" * 76
    )

    print(
        "        SECURITY STABILITY METRICS"
    )

    print(
        "=" * 76
    )


    print(
        "Adversarial Tests:",
        stability_metrics[
            "adversarial_tests"
        ]
    )

    print(
        "Flaky Security Tests:",
        stability_metrics[
            "flaky_security_tests"
        ]
    )

    print(
        "Flaky Security Test Rate:",
        f"{stability_metrics['flaky_security_test_rate']:.2f}%"
    )

    print(
        "Stable Security Passes:",
        stability_metrics[
            "stable_security_passes"
        ]
    )

    print(
        "Stable Pass Rate:",
        f"{stability_metrics['stable_pass_rate']:.2f}%"
    )

    print(
        "Stable Security Failures:",
        stability_metrics[
            "stable_security_failures"
        ]
    )

    print(
        "Stable Fail Rate:",
        f"{stability_metrics['stable_fail_rate']:.2f}%"
    )

    print(
        "Critical Flaky Tests:",
        stability_metrics[
            "critical_flaky_tests"
        ]
    )

    print(
        "Critical Flakiness Rate:",
        f"{stability_metrics['critical_flakiness_rate']:.2f}%"
    )

    print(
        "Intermittent Attack Tests:",
        stability_metrics[
            "intermittent_attack_tests"
        ]
    )

    print(
        "Utility Stability Rate:",
        f"{stability_metrics['utility_stability_rate']:.2f}%"
    )


    # ========================================================
    # VARIANCE
    # ========================================================

    variance = (
        calculate_run_variance(
            run_metrics
        )
    )


    print(
        "\n"
        + "=" * 76
    )

    print(
        "        RUN-TO-RUN VARIANCE"
    )

    print(
        "=" * 76
    )


    print(
        "Minimum Security Score:",
        f"{variance['minimum_security_score']:.2f}%"
    )

    print(
        "Maximum Security Score:",
        f"{variance['maximum_security_score']:.2f}%"
    )

    print(
        "Average Security Score:",
        f"{variance['average_security_score']:.2f}%"
    )

    print(
        "Security Score Standard Deviation:",
        f"{variance['security_score_stddev']:.2f}"
    )

    print(
        "Minimum Attack Success Rate:",
        f"{variance['minimum_attack_success_rate']:.2f}%"
    )

    print(
        "Maximum Attack Success Rate:",
        f"{variance['maximum_attack_success_rate']:.2f}%"
    )

    print(
        "Average Attack Success Rate:",
        f"{variance['average_attack_success_rate']:.2f}%"
    )

    print(
        "Attack Success Standard Deviation:",
        f"{variance['attack_success_stddev']:.2f}"
    )


    # ========================================================
    # SECURITY CHECKS
    # ========================================================

    flakiness_detected = (
        stability_metrics[
            "flaky_security_tests"
        ]
        > 0
    )


    critical_flakiness_detected = (
        stability_metrics[
            "critical_flaky_tests"
        ]
        > 0
    )


    stable_failure_detected = (
        stability_metrics[
            "stable_security_failures"
        ]
        > 0
    )


    utility_stable = (
        stability_metrics[
            "utility_stability_rate"
        ]
        == 100.0
    )


    print(
        "\n"
        + "=" * 76
    )

    print(
        "        STABILITY SECURITY CHECKS"
    )

    print(
        "=" * 76
    )


    print(
        "Security Flakiness Detected:",
        flakiness_detected
    )

    print(
        "Critical Security Flakiness Detected:",
        critical_flakiness_detected
    )

    print(
        "Stable Security Failure Detected:",
        stable_failure_detected
    )

    print(
        "Legitimate Utility Stable:",
        utility_stable
    )

    print(
        "Single Successful Run Sufficient:",
        False
    )

    print(
        "Repeated Evaluation Required:",
        True
    )


    # ========================================================
    # WRITE EVIDENCE
    # ========================================================

    evidence = build_evidence(
        runs,
        run_metrics,
        test_analysis,
        stability_metrics,
        variance,
    )


    output_path = (
        Path.cwd()
        / "day26-stability-flakiness-evidence.json"
    )


    output_path.write_text(
        json.dumps(
            evidence,
            indent=2,
        ),
        encoding="utf-8",
    )


    print(
        "\nEvidence written to:"
    )

    print(
        output_path
    )


    print(
        "\nSecurity Interpretation:"
    )

    print(
        "A single passing benchmark execution does not "
        "establish stable security."
    )

    print(
        "Repeated evaluation reveals intermittent control "
        "failure, stable failure, critical flakiness, and "
        "run-to-run security-score variance that would be "
        "hidden by one-shot testing."
    )

    print(
        "Security regression programs should therefore "
        "measure both correctness and consistency."
    )


    print(
        "\nCore Principle:"
    )

    print(
        "A security control is not proven by passing once; "
        "it must remain effective under repeatable "
        "adversarial evaluation and system change."
    )


if __name__ == "__main__":
    main()