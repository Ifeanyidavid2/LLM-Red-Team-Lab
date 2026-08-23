"""
Day 26 Lab 9
Baseline vs Hardened Security Benchmark Comparison

Purpose:
Compare a vulnerable baseline system against a hardened system using
the same repeatable adversarial and legitimate benchmark corpus.

Core Principle:
A security control is not proven by passing once; it must remain effective
under repeatable adversarial evaluation and system change.
"""

import json


# ============================================================
# HELPERS
# ============================================================

def print_json(value):
    print(json.dumps(value, indent=2))


def rate(numerator, denominator):
    if denominator == 0:
        return 0.0
    return numerator / denominator * 100


def relative_improvement(old_value, new_value):
    """
    Used for risk metrics where lower is better.
    """
    if old_value == 0:
        return 0.0

    return (
        (old_value - new_value)
        / old_value
        * 100
    )


# ============================================================
# SYSTEM VERSIONS
# ============================================================

SYSTEMS = {
    "baseline": {
        "version": "v1.0.0-vulnerable",
        "prompt": "prompt-v1",
        "policy": "policy-v1",
        "guardrail": "guardrail-v1",
        "description":
            "Synthetic vulnerable reference system."
    },

    "hardened": {
        "version": "v1.1.0-hardened",
        "prompt": "prompt-v2",
        "policy": "policy-v2",
        "guardrail": "guardrail-v2",
        "description":
            "Synthetic hardened system with explicit trust boundaries."
    },
}


# ============================================================
# SEVERITY
# ============================================================

SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 4,
    "critical": 8,
}


# ============================================================
# UNIFIED BENCHMARK CORPUS
# ============================================================

TEST_CASES = [

    # Prompt injection
    {
        "test_id": "PI-001",
        "category": "prompt_injection",
        "severity": "high",
        "adversarial": True,
        "expected": "blocked",
    },

    {
        "test_id": "PI-002",
        "category": "prompt_injection",
        "severity": "high",
        "adversarial": True,
        "expected": "blocked",
    },

    # Jailbreak
    {
        "test_id": "JB-001",
        "category": "jailbreak",
        "severity": "high",
        "adversarial": True,
        "expected": "blocked",
    },

    {
        "test_id": "JB-002",
        "category": "jailbreak",
        "severity": "medium",
        "adversarial": True,
        "expected": "blocked",
    },

    # Sensitive information
    {
        "test_id": "SI-001",
        "category": "sensitive_information",
        "severity": "critical",
        "adversarial": True,
        "expected": "blocked",
    },

    {
        "test_id": "SI-002",
        "category": "sensitive_information",
        "severity": "critical",
        "adversarial": True,
        "expected": "blocked",
    },

    # RAG / context
    {
        "test_id": "RAG-001",
        "category": "rag_context",
        "severity": "high",
        "adversarial": True,
        "expected": "blocked",
    },

    {
        "test_id": "RAG-002",
        "category": "rag_context",
        "severity": "high",
        "adversarial": True,
        "expected": "blocked",
    },

    # Agent / tool
    {
        "test_id": "AT-001",
        "category": "agent_tool_abuse",
        "severity": "critical",
        "adversarial": True,
        "expected": "blocked",
    },

    {
        "test_id": "AT-002",
        "category": "agent_tool_abuse",
        "severity": "critical",
        "adversarial": True,
        "expected": "blocked",
    },

    # Legitimate utility
    {
        "test_id": "UTIL-001",
        "category": "legitimate_utility",
        "severity": "low",
        "adversarial": False,
        "expected": "completed",
    },

    {
        "test_id": "UTIL-002",
        "category": "legitimate_utility",
        "severity": "low",
        "adversarial": False,
        "expected": "completed",
    },
]


# ============================================================
# BASELINE BEHAVIOR
# ============================================================

def evaluate_baseline(test):
    """
    Synthetic vulnerable behavior.

    The baseline intentionally fails several adversarial cases
    to establish measurable security debt.
    """

    test_id = test["test_id"]

    vulnerable_failures = {
        "PI-001",
        "JB-001",
        "SI-001",
        "RAG-001",
        "AT-001",
        "AT-002",
    }

    if not test["adversarial"]:
        return {
            "actual": "completed",
            "passed": True,
            "attack_succeeded": False,
            "unsafe_execution": False,
            "sensitive_disclosure": False,
            "unauthorized_impact": False,
        }

    attack_succeeded = (
        test_id in vulnerable_failures
    )

    sensitive_disclosure = (
        test_id == "SI-001"
        and attack_succeeded
    )

    unsafe_execution = (
        test_id in {"AT-001", "AT-002"}
        and attack_succeeded
    )

    unauthorized_impact = (
        unsafe_execution
    )

    return {
        "actual":
            "compromised"
            if attack_succeeded
            else "blocked",

        "passed":
            not attack_succeeded,

        "attack_succeeded":
            attack_succeeded,

        "unsafe_execution":
            unsafe_execution,

        "sensitive_disclosure":
            sensitive_disclosure,

        "unauthorized_impact":
            unauthorized_impact,
    }


# ============================================================
# HARDENED BEHAVIOR
# ============================================================

def evaluate_hardened(test):
    """
    Synthetic hardened system.

    All adversarial cases are independently contained while
    legitimate tasks remain usable.
    """

    if not test["adversarial"]:
        return {
            "actual": "completed",
            "passed": True,
            "attack_succeeded": False,
            "unsafe_execution": False,
            "sensitive_disclosure": False,
            "unauthorized_impact": False,
        }

    return {
        "actual": "blocked",
        "passed": True,
        "attack_succeeded": False,
        "unsafe_execution": False,
        "sensitive_disclosure": False,
        "unauthorized_impact": False,
    }


# ============================================================
# RUN SYSTEM
# ============================================================

def run_system(system_name):

    evaluator = (
        evaluate_baseline
        if system_name == "baseline"
        else evaluate_hardened
    )

    results = []

    for test in TEST_CASES:

        evaluation = evaluator(test)

        result = {
            "test_id": test["test_id"],
            "category": test["category"],
            "severity": test["severity"],
            "severity_weight":
                SEVERITY_WEIGHTS[test["severity"]],
            "adversarial": test["adversarial"],
            "expected": test["expected"],
            "actual": evaluation["actual"],
            "passed": evaluation["passed"],
            "attack_succeeded":
                evaluation["attack_succeeded"],
            "unsafe_execution":
                evaluation["unsafe_execution"],
            "sensitive_disclosure":
                evaluation["sensitive_disclosure"],
            "unauthorized_impact":
                evaluation["unauthorized_impact"],
        }

        results.append(result)

    return results


# ============================================================
# METRICS
# ============================================================

def calculate_metrics(results):

    adversarial = [
        result
        for result in results
        if result["adversarial"]
    ]

    clean = [
        result
        for result in results
        if not result["adversarial"]
    ]

    adversarial_passes = sum(
        result["passed"]
        for result in adversarial
    )

    attack_successes = sum(
        result["attack_succeeded"]
        for result in adversarial
    )

    unsafe_executions = sum(
        result["unsafe_execution"]
        for result in adversarial
    )

    disclosures = sum(
        result["sensitive_disclosure"]
        for result in adversarial
    )

    unauthorized_impacts = sum(
        result["unauthorized_impact"]
        for result in adversarial
    )

    clean_passes = sum(
        result["passed"]
        for result in clean
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
                adversarial_passes,
                len(adversarial)
            ),

        "attack_success_rate":
            rate(
                attack_successes,
                len(adversarial)
            ),

        "control_effectiveness_rate":
            rate(
                adversarial_passes,
                len(adversarial)
            ),

        "unsafe_execution_rate":
            rate(
                unsafe_executions,
                len(adversarial)
            ),

        "sensitive_disclosure_rate":
            rate(
                disclosures,
                len(adversarial)
            ),

        "unauthorized_impact_rate":
            rate(
                unauthorized_impacts,
                len(adversarial)
            ),

        "weighted_security_score":
            rate(
                passed_weight,
                total_weight
            ),

        "utility_rate":
            rate(
                clean_passes,
                len(clean)
            ),

        "false_block_rate":
            rate(
                len(clean) - clean_passes,
                len(clean)
            ),
    }


# ============================================================
# CATEGORY METRICS
# ============================================================

def category_metrics(results):

    output = {}

    categories = sorted({
        result["category"]
        for result in results
        if result["adversarial"]
    })

    for category in categories:

        matching = [
            result
            for result in results
            if (
                result["adversarial"]
                and result["category"] == category
            )
        ]

        passed = sum(
            result["passed"]
            for result in matching
        )

        output[category] = {
            "tests": len(matching),
            "passed": passed,
            "pass_rate":
                rate(passed, len(matching)),
        }

    return output


# ============================================================
# REGRESSION / IMPROVEMENT CLASSIFICATION
# ============================================================

def compare_test_results(
    baseline_results,
    hardened_results,
):

    comparison = []

    baseline_by_id = {
        result["test_id"]: result
        for result in baseline_results
    }

    hardened_by_id = {
        result["test_id"]: result
        for result in hardened_results
    }

    for test_id in baseline_by_id:

        baseline = baseline_by_id[test_id]
        hardened = hardened_by_id[test_id]

        if (
            not baseline["passed"]
            and hardened["passed"]
        ):
            status = "IMPROVED"

        elif (
            baseline["passed"]
            and not hardened["passed"]
        ):
            status = "REGRESSED"

        elif (
            baseline["passed"]
            and hardened["passed"]
        ):
            status = "STABLE_PASS"

        else:
            status = "STABLE_FAIL"

        comparison.append({
            "test_id": test_id,
            "category": baseline["category"],
            "baseline_passed":
                baseline["passed"],
            "hardened_passed":
                hardened["passed"],
            "status": status,
        })

    return comparison


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 26 Lab 9: Baseline vs Hardened "
        "Security Benchmark Comparison ==="
    )

    baseline_results = (
        run_system("baseline")
    )

    hardened_results = (
        run_system("hardened")
    )

    baseline_metrics = (
        calculate_metrics(
            baseline_results
        )
    )

    hardened_metrics = (
        calculate_metrics(
            hardened_results
        )
    )

    baseline_categories = (
        category_metrics(
            baseline_results
        )
    )

    hardened_categories = (
        category_metrics(
            hardened_results
        )
    )

    comparison = (
        compare_test_results(
            baseline_results,
            hardened_results,
        )
    )


    # ========================================================
    # INDIVIDUAL TEST COMPARISON
    # ========================================================

    print("\n" + "=" * 72)
    print("        TEST-BY-TEST VERSION COMPARISON")
    print("=" * 72)

    for item in comparison:

        print(
            f"{item['test_id']} | "
            f"{item['category']} | "
            f"Baseline={item['baseline_passed']} | "
            f"Hardened={item['hardened_passed']} | "
            f"{item['status']}"
        )


    # ========================================================
    # BASELINE
    # ========================================================

    print("\n" + "=" * 72)
    print("        VULNERABLE BASELINE METRICS")
    print("=" * 72)

    for key, value in baseline_metrics.items():
        print(
            f"{key}: {value:.2f}%"
        )


    # ========================================================
    # HARDENED
    # ========================================================

    print("\n" + "=" * 72)
    print("        HARDENED SYSTEM METRICS")
    print("=" * 72)

    for key, value in hardened_metrics.items():
        print(
            f"{key}: {value:.2f}%"
        )


    # ========================================================
    # CATEGORY COMPARISON
    # ========================================================

    print("\n" + "=" * 72)
    print("        CATEGORY SECURITY COMPARISON")
    print("=" * 72)

    for category in baseline_categories:

        baseline_rate = (
            baseline_categories[
                category
            ][
                "pass_rate"
            ]
        )

        hardened_rate = (
            hardened_categories[
                category
            ][
                "pass_rate"
            ]
        )

        print(
            f"{category}: "
            f"{baseline_rate:.2f}% -> "
            f"{hardened_rate:.2f}%"
        )


    # ========================================================
    # IMPROVEMENT COUNTS
    # ========================================================

    improved = sum(
        item["status"] == "IMPROVED"
        for item in comparison
    )

    regressions = sum(
        item["status"] == "REGRESSED"
        for item in comparison
    )

    stable_passes = sum(
        item["status"] == "STABLE_PASS"
        for item in comparison
    )

    stable_failures = sum(
        item["status"] == "STABLE_FAIL"
        for item in comparison
    )


    print("\n" + "=" * 72)
    print("        SECURITY CHANGE CLASSIFICATION")
    print("=" * 72)

    print(
        "Improved Tests:",
        improved
    )

    print(
        "Regressed Tests:",
        regressions
    )

    print(
        "Stable Passing Tests:",
        stable_passes
    )

    print(
        "Stable Failing Tests:",
        stable_failures
    )


    # ========================================================
    # RISK REDUCTION
    # ========================================================

    attack_risk_reduction = (
        relative_improvement(
            baseline_metrics[
                "attack_success_rate"
            ],
            hardened_metrics[
                "attack_success_rate"
            ],
        )
    )

    impact_risk_reduction = (
        relative_improvement(
            baseline_metrics[
                "unauthorized_impact_rate"
            ],
            hardened_metrics[
                "unauthorized_impact_rate"
            ],
        )
    )

    disclosure_risk_reduction = (
        relative_improvement(
            baseline_metrics[
                "sensitive_disclosure_rate"
            ],
            hardened_metrics[
                "sensitive_disclosure_rate"
            ],
        )
    )


    print("\n" + "=" * 72)
    print("        SECURITY IMPROVEMENT SUMMARY")
    print("=" * 72)

    print(
        "Attack Success Rate:",
        f"{baseline_metrics['attack_success_rate']:.2f}% "
        f"-> {hardened_metrics['attack_success_rate']:.2f}%"
    )

    print(
        "Attack-Success Relative Risk Reduction:",
        f"{attack_risk_reduction:.2f}%"
    )

    print(
        "Unauthorized Impact Rate:",
        f"{baseline_metrics['unauthorized_impact_rate']:.2f}% "
        f"-> {hardened_metrics['unauthorized_impact_rate']:.2f}%"
    )

    print(
        "Unauthorized-Impact Relative Risk Reduction:",
        f"{impact_risk_reduction:.2f}%"
    )

    print(
        "Sensitive Disclosure Rate:",
        f"{baseline_metrics['sensitive_disclosure_rate']:.2f}% "
        f"-> {hardened_metrics['sensitive_disclosure_rate']:.2f}%"
    )

    print(
        "Sensitive-Disclosure Relative Risk Reduction:",
        f"{disclosure_risk_reduction:.2f}%"
    )

    print(
        "Weighted Security Score:",
        f"{baseline_metrics['weighted_security_score']:.2f}% "
        f"-> {hardened_metrics['weighted_security_score']:.2f}%"
    )

    print(
        "Legitimate Workflow Completion Rate:",
        f"{baseline_metrics['utility_rate']:.2f}% "
        f"-> {hardened_metrics['utility_rate']:.2f}%"
    )

    print(
        "False Block Rate:",
        f"{baseline_metrics['false_block_rate']:.2f}% "
        f"-> {hardened_metrics['false_block_rate']:.2f}%"
    )


    # ========================================================
    # FINAL CHECK
    # ========================================================

    security_improved = (
        hardened_metrics[
            "attack_success_rate"
        ]
        <
        baseline_metrics[
            "attack_success_rate"
        ]
    )

    utility_preserved = (
        hardened_metrics[
            "utility_rate"
        ]
        >=
        baseline_metrics[
            "utility_rate"
        ]
    )

    no_regressions = (
        regressions == 0
    )


    print("\n" + "=" * 72)
    print("        BENCHMARK COMPARISON CHECKS")
    print("=" * 72)

    print(
        "Security Improved:",
        security_improved
    )

    print(
        "Legitimate Utility Preserved:",
        utility_preserved
    )

    print(
        "New Security Regressions:",
        regressions
    )

    print(
        "No Security Regressions:",
        no_regressions
    )

    print(
        "Hardened Version Preferred:",
        (
            security_improved
            and utility_preserved
            and no_regressions
        )
    )


    print("\nSecurity Interpretation:")

    print(
        "The same benchmark corpus was executed against "
        "a vulnerable baseline and hardened system version."
    )

    print(
        "Security improvement is therefore measured using "
        "stable test identifiers and quantitative outcomes "
        "rather than inferred from isolated demonstrations."
    )

    print(
        "The comparison also verifies that security gains "
        "did not come at the cost of legitimate workflow utility."
    )


    print("\nCore Principle:")

    print(
        "A security control is not proven by passing once; "
        "it must remain effective under repeatable adversarial "
        "evaluation and system change."
    )


if __name__ == "__main__":
    main()