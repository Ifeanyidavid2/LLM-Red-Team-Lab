"""
Day 26 Lab 13
Automated Security Regression Detection

Purpose:
Load the hardened and changed-system evidence snapshots, compare stable
test IDs, automatically detect PASS -> FAIL security regressions,
classify severity, calculate regression metrics, and write a reusable
regression report.

Core Principle:
A security control is not proven by passing once; it must remain effective
under repeatable adversarial evaluation and system change.
"""

import json
from pathlib import Path


# ============================================================
# HELPERS
# ============================================================

def rate(numerator, denominator):
    if denominator == 0:
        return 0.0
    return numerator / denominator * 100


def load_json(path):
    return json.loads(
        Path(path).read_text(
            encoding="utf-8"
        )
    )


# ============================================================
# INPUT EVIDENCE FILES
# ============================================================

BASE_DIR = Path.cwd()

HARDENED_PATH = (
    BASE_DIR
    / "day26-hardened-evaluation-evidence.json"
)

CHANGED_PATH = (
    BASE_DIR
    / "day26-regressed-system-evidence.json"
)


# ============================================================
# LOAD EVIDENCE
# ============================================================

def load_evidence():

    if not HARDENED_PATH.exists():
        raise FileNotFoundError(
            f"Missing hardened evidence: {HARDENED_PATH}"
        )

    if not CHANGED_PATH.exists():
        raise FileNotFoundError(
            f"Missing changed-system evidence: {CHANGED_PATH}"
        )

    hardened = load_json(
        HARDENED_PATH
    )

    changed = load_json(
        CHANGED_PATH
    )

    return hardened, changed


# ============================================================
# RESULT INDEX
# ============================================================

def index_results(evidence):

    return {
        result["test_id"]: result
        for result in evidence["results"]
    }


# ============================================================
# CHANGE CLASSIFICATION
# ============================================================

def classify_change(
    old_result,
    new_result,
):

    old_pass = bool(
        old_result["passed"]
    )

    new_pass = bool(
        new_result["passed"]
    )

    if old_pass and not new_pass:
        return "REGRESSED"

    if not old_pass and new_pass:
        return "IMPROVED"

    if old_pass and new_pass:
        return "STABLE_PASS"

    return "STABLE_FAIL"


# ============================================================
# COMPARE RESULTS
# ============================================================

def compare_results(
    hardened,
    changed,
):

    old_index = index_results(
        hardened
    )

    new_index = index_results(
        changed
    )

    all_test_ids = sorted(
        set(old_index)
        | set(new_index)
    )

    comparison = []

    for test_id in all_test_ids:

        old_result = old_index.get(
            test_id
        )

        new_result = new_index.get(
            test_id
        )

        # Detect corpus drift
        if old_result is None:
            comparison.append({
                "test_id": test_id,
                "status": "NEW_TEST",
                "category":
                    new_result["category"],
                "severity":
                    new_result["severity"],
            })
            continue

        if new_result is None:
            comparison.append({
                "test_id": test_id,
                "status": "MISSING_TEST",
                "category":
                    old_result["category"],
                "severity":
                    old_result["severity"],
            })
            continue

        status = classify_change(
            old_result,
            new_result,
        )

        comparison.append({
            "test_id": test_id,
            "category":
                old_result["category"],
            "severity":
                old_result["severity"],
            "adversarial":
                old_result["adversarial"],
            "old_passed":
                old_result["passed"],
            "new_passed":
                new_result["passed"],
            "old_attack_succeeded":
                old_result.get(
                    "attack_succeeded",
                    False,
                ),
            "new_attack_succeeded":
                new_result.get(
                    "attack_succeeded",
                    False,
                ),
            "old_unsafe_execution":
                old_result.get(
                    "unsafe_execution",
                    False,
                ),
            "new_unsafe_execution":
                new_result.get(
                    "unsafe_execution",
                    False,
                ),
            "old_unauthorized_impact":
                old_result.get(
                    "unauthorized_impact",
                    False,
                ),
            "new_unauthorized_impact":
                new_result.get(
                    "unauthorized_impact",
                    False,
                ),
            "status":
                status,
        })

    return comparison


# ============================================================
# REGRESSION METRICS
# ============================================================

def calculate_regression_metrics(
    comparison,
):

    comparable = [
        item
        for item in comparison
        if item["status"]
        not in {
            "NEW_TEST",
            "MISSING_TEST",
        }
    ]

    adversarial = [
        item
        for item in comparable
        if item.get(
            "adversarial",
            False,
        )
    ]

    regressions = [
        item
        for item in adversarial
        if item["status"]
        == "REGRESSED"
    ]

    improvements = [
        item
        for item in adversarial
        if item["status"]
        == "IMPROVED"
    ]

    stable_passes = [
        item
        for item in adversarial
        if item["status"]
        == "STABLE_PASS"
    ]

    stable_failures = [
        item
        for item in adversarial
        if item["status"]
        == "STABLE_FAIL"
    ]

    critical_regressions = [
        item
        for item in regressions
        if item["severity"]
        == "critical"
    ]

    high_or_critical_regressions = [
        item
        for item in regressions
        if item["severity"]
        in {
            "high",
            "critical",
        }
    ]

    unsafe_execution_regressions = [
        item
        for item in regressions
        if item[
            "new_unsafe_execution"
        ]
    ]

    impact_regressions = [
        item
        for item in regressions
        if item[
            "new_unauthorized_impact"
        ]
    ]

    new_tests = [
        item
        for item in comparison
        if item["status"]
        == "NEW_TEST"
    ]

    missing_tests = [
        item
        for item in comparison
        if item["status"]
        == "MISSING_TEST"
    ]

    return {
        "comparable_adversarial_tests":
            len(adversarial),

        "regression_count":
            len(regressions),

        "regression_rate":
            rate(
                len(regressions),
                len(adversarial),
            ),

        "improvement_count":
            len(improvements),

        "stable_pass_count":
            len(stable_passes),

        "stable_fail_count":
            len(stable_failures),

        "critical_regression_count":
            len(critical_regressions),

        "critical_regression_rate":
            rate(
                len(critical_regressions),
                len(adversarial),
            ),

        "high_or_critical_regression_count":
            len(
                high_or_critical_regressions
            ),

        "unsafe_execution_regression_count":
            len(
                unsafe_execution_regressions
            ),

        "unauthorized_impact_regression_count":
            len(
                impact_regressions
            ),

        "new_test_count":
            len(new_tests),

        "missing_test_count":
            len(missing_tests),
    }


# ============================================================
# CATEGORY REGRESSION SUMMARY
# ============================================================

def category_regression_summary(
    comparison,
):

    categories = sorted({
        item["category"]
        for item in comparison
        if item.get(
            "adversarial",
            False,
        )
    })

    output = {}

    for category in categories:

        matching = [
            item
            for item in comparison
            if (
                item.get(
                    "adversarial",
                    False,
                )
                and
                item["category"]
                == category
            )
        ]

        regressions = sum(
            item["status"]
            == "REGRESSED"
            for item in matching
        )

        output[category] = {
            "tests":
                len(matching),

            "regressions":
                regressions,

            "regression_rate":
                rate(
                    regressions,
                    len(matching),
                ),
        }

    return output


# ============================================================
# SECURITY SCORE DELTA
# ============================================================

def metric_deltas(
    hardened,
    changed,
):

    old_metrics = hardened[
        "metrics"
    ]

    new_metrics = changed[
        "metrics"
    ]

    keys = [
        "security_test_pass_rate",
        "attack_success_rate",
        "control_effectiveness_rate",
        "sensitive_disclosure_rate",
        "unsafe_execution_rate",
        "unauthorized_impact_rate",
        "weighted_security_score",
        "legitimate_workflow_completion_rate",
        "false_block_rate",
    ]

    output = {}

    for key in keys:

        old_value = float(
            old_metrics[key]
        )

        new_value = float(
            new_metrics[key]
        )

        output[key] = {
            "hardened":
                old_value,

            "changed":
                new_value,

            "delta":
                new_value
                - old_value,
        }

    return output


# ============================================================
# RELEASE-RISK CLASSIFICATION
# ============================================================

def classify_release_risk(
    metrics,
):

    if (
        metrics[
            "critical_regression_count"
        ]
        > 0
    ):
        return "CRITICAL"

    if (
        metrics[
            "high_or_critical_regression_count"
        ]
        > 0
    ):
        return "HIGH"

    if (
        metrics[
            "regression_count"
        ]
        > 0
    ):
        return "MEDIUM"

    return "LOW"


# ============================================================
# BUILD REPORT
# ============================================================

def build_report(
    hardened,
    changed,
    comparison,
    metrics,
    categories,
    deltas,
):

    release_risk = (
        classify_release_risk(
            metrics
        )
    )

    regressions = [
        item
        for item in comparison
        if item["status"]
        == "REGRESSED"
    ]

    return {
        "benchmark":
            "Day 26 Automated Security Regression Detection",

        "reference_system":
            hardened[
                "system"
            ],

        "changed_system":
            changed[
                "system"
            ],

        "regression_metrics":
            metrics,

        "category_regressions":
            categories,

        "metric_deltas":
            deltas,

        "release_risk":
            release_risk,

        "regressions":
            regressions,

        "comparison":
            comparison,

        "regression_detected":
            metrics[
                "regression_count"
            ]
            > 0,

        "critical_regression_detected":
            metrics[
                "critical_regression_count"
            ]
            > 0,

        "security_interpretation":
            (
                "Stable benchmark identifiers allow previously "
                "passing security tests to be automatically "
                "compared across system versions. PASS -> FAIL "
                "transitions are treated as security regressions "
                "and severity is used to determine release risk."
            ),
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 26 Lab 13: "
        "Automated Security Regression Detection ==="
    )

    hardened, changed = (
        load_evidence()
    )

    print(
        "\nReference Version:",
        hardened[
            "system"
        ][
            "version"
        ],
    )

    print(
        "Changed Version:",
        changed[
            "system"
        ][
            "version"
        ],
    )

    comparison = compare_results(
        hardened,
        changed,
    )

    metrics = (
        calculate_regression_metrics(
            comparison
        )
    )

    categories = (
        category_regression_summary(
            comparison
        )
    )

    deltas = metric_deltas(
        hardened,
        changed,
    )


    # ========================================================
    # TEST-BY-TEST RESULTS
    # ========================================================

    print(
        "\n"
        + "=" * 76
    )

    print(
        "        AUTOMATED TEST CHANGE CLASSIFICATION"
    )

    print(
        "=" * 76
    )

    for item in comparison:

        print(
            f"{item['test_id']} | "
            f"{item['category']} | "
            f"{item['severity']} | "
            f"{item['status']}"
        )


    # ========================================================
    # REGRESSIONS
    # ========================================================

    print(
        "\n"
        + "=" * 76
    )

    print(
        "        DETECTED PASS -> FAIL REGRESSIONS"
    )

    print(
        "=" * 76
    )

    regressions = [
        item
        for item in comparison
        if item["status"]
        == "REGRESSED"
    ]

    for item in regressions:

        print(
            f"- {item['test_id']} | "
            f"{item['category']} | "
            f"{item['severity']}"
        )

        print(
            "  Attack Succeeded:",
            item[
                "new_attack_succeeded"
            ]
        )

        print(
            "  Unsafe Execution:",
            item[
                "new_unsafe_execution"
            ]
        )

        print(
            "  Unauthorized Impact:",
            item[
                "new_unauthorized_impact"
            ]
        )


    # ========================================================
    # METRICS
    # ========================================================

    print(
        "\n"
        + "=" * 76
    )

    print(
        "        REGRESSION METRICS"
    )

    print(
        "=" * 76
    )

    print(
        "Comparable Adversarial Tests:",
        metrics[
            "comparable_adversarial_tests"
        ]
    )

    print(
        "Regression Count:",
        metrics[
            "regression_count"
        ]
    )

    print(
        "Regression Rate:",
        f"{metrics['regression_rate']:.2f}%"
    )

    print(
        "Critical Regression Count:",
        metrics[
            "critical_regression_count"
        ]
    )

    print(
        "Critical Regression Rate:",
        f"{metrics['critical_regression_rate']:.2f}%"
    )

    print(
        "High/Critical Regression Count:",
        metrics[
            "high_or_critical_regression_count"
        ]
    )

    print(
        "Unsafe-Execution Regressions:",
        metrics[
            "unsafe_execution_regression_count"
        ]
    )

    print(
        "Unauthorized-Impact Regressions:",
        metrics[
            "unauthorized_impact_regression_count"
        ]
    )

    print(
        "Improved Tests:",
        metrics[
            "improvement_count"
        ]
    )

    print(
        "Stable Passing Tests:",
        metrics[
            "stable_pass_count"
        ]
    )

    print(
        "Stable Failing Tests:",
        metrics[
            "stable_fail_count"
        ]
    )

    print(
        "New Tests:",
        metrics[
            "new_test_count"
        ]
    )

    print(
        "Missing Tests:",
        metrics[
            "missing_test_count"
        ]
    )


    # ========================================================
    # CATEGORY REGRESSIONS
    # ========================================================

    print(
        "\n"
        + "=" * 76
    )

    print(
        "        CATEGORY REGRESSION SUMMARY"
    )

    print(
        "=" * 76
    )

    for category, values in (
        categories.items()
    ):

        print(
            f"{category}: "
            f"{values['regressions']} / "
            f"{values['tests']} regressed "
            f"({values['regression_rate']:.2f}%)"
        )


    # ========================================================
    # METRIC DELTAS
    # ========================================================

    print(
        "\n"
        + "=" * 76
    )

    print(
        "        SECURITY METRIC DELTAS"
    )

    print(
        "=" * 76
    )

    for metric, values in (
        deltas.items()
    ):

        print(
            f"{metric}: "
            f"{values['hardened']:.2f}% -> "
            f"{values['changed']:.2f}% | "
            f"Delta={values['delta']:+.2f} pp"
        )


    # ========================================================
    # RELEASE RISK
    # ========================================================

    release_risk = (
        classify_release_risk(
            metrics
        )
    )

    print(
        "\n"
        + "=" * 76
    )

    print(
        "        REGRESSION RISK CLASSIFICATION"
    )

    print(
        "=" * 76
    )

    print(
        "Security Regression Detected:",
        metrics[
            "regression_count"
        ]
        > 0
    )

    print(
        "Critical Regression Detected:",
        metrics[
            "critical_regression_count"
        ]
        > 0
    )

    print(
        "Release Risk:",
        release_risk
    )

    print(
        "Regression Evidence Sufficient:",
        (
            metrics[
                "regression_count"
            ]
            > 0
            and
            metrics[
                "new_test_count"
            ]
            == 0
            and
            metrics[
                "missing_test_count"
            ]
            == 0
        )
    )


    # ========================================================
    # WRITE REPORT
    # ========================================================

    report = build_report(
        hardened,
        changed,
        comparison,
        metrics,
        categories,
        deltas,
    )

    output_path = (
        BASE_DIR
        / "day26-automated-regression-report.json"
    )

    output_path.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        "\nRegression report written to:"
    )

    print(
        output_path
    )


    print(
        "\nSecurity Interpretation:"
    )

    print(
        "The regression engine compares stable test IDs "
        "across the hardened reference and changed version."
    )

    print(
        "Previously passing tests that now fail are "
        "automatically identified as security regressions "
        "and classified by severity and impact."
    )

    print(
        "This converts adversarial evaluation into an "
        "automatable release-security signal."
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