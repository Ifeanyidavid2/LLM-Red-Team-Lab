"""
Day 26 Lab 16
Final Comparative Analysis

Purpose:
Combine Day 26 vulnerable, hardened, regressed, regression-detection,
release-gate, and stability evidence into one final comparative analysis.

Core Principle:
A security control is not proven by passing once; it must remain effective
under repeatable adversarial evaluation and system change.
"""

import json
from pathlib import Path


BASE_DIR = Path.cwd()


FILES = {
    "vulnerable":
        BASE_DIR / "day26-vulnerable-baseline-evidence.json",

    "hardened":
        BASE_DIR / "day26-hardened-evaluation-evidence.json",

    "regressed":
        BASE_DIR / "day26-regressed-system-evidence.json",

    "regression_report":
        BASE_DIR / "day26-automated-regression-report.json",

    "release_gate":
        BASE_DIR / "day26-release-security-gate-report.json",

    "stability":
        BASE_DIR / "day26-stability-flakiness-evidence.json",
}


# ============================================================
# HELPERS
# ============================================================

def load_json(path):

    if not path.exists():
        raise FileNotFoundError(
            f"Missing required Day 26 evidence file: {path}"
        )

    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def percentage_point_change(
    old,
    new,
):
    return new - old


def relative_risk_reduction(
    old,
    new,
):

    if old == 0:
        return 0.0

    return (
        (old - new)
        / old
        * 100
    )


# ============================================================
# LOAD EVIDENCE
# ============================================================

def load_all_evidence():

    return {
        name: load_json(path)
        for name, path
        in FILES.items()
    }


# ============================================================
# METRIC COMPARISON
# ============================================================

def build_metric_comparison(
    vulnerable,
    hardened,
    regressed,
):

    vm = vulnerable["metrics"]
    hm = hardened["metrics"]
    rm = regressed["metrics"]

    metric_names = [
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

    for metric in metric_names:

        vulnerable_value = float(
            vm[metric]
        )

        hardened_value = float(
            hm[metric]
        )

        regressed_value = float(
            rm[metric]
        )

        output[metric] = {
            "vulnerable":
                vulnerable_value,

            "hardened":
                hardened_value,

            "regressed":
                regressed_value,

            "vulnerable_to_hardened_pp":
                percentage_point_change(
                    vulnerable_value,
                    hardened_value,
                ),

            "hardened_to_regressed_pp":
                percentage_point_change(
                    hardened_value,
                    regressed_value,
                ),
        }

    return output


# ============================================================
# FINAL FINDINGS
# ============================================================

def build_final_findings(
    evidence,
):

    vulnerable = evidence[
        "vulnerable"
    ]

    hardened = evidence[
        "hardened"
    ]

    regressed = evidence[
        "regressed"
    ]

    regression_report = evidence[
        "regression_report"
    ]

    release_gate = evidence[
        "release_gate"
    ]

    stability = evidence[
        "stability"
    ]


    vm = vulnerable[
        "metrics"
    ]

    hm = hardened[
        "metrics"
    ]

    rm = regressed[
        "metrics"
    ]

    regression_metrics = (
        regression_report[
            "regression_metrics"
        ]
    )

    stability_metrics = (
        stability[
            "stability_metrics"
        ]
    )

    variance = (
        stability[
            "variance_metrics"
        ]
    )


    findings = [

        (
            "The vulnerable reference system passed only "
            f"{vm['security_test_pass_rate']:.2f}% of adversarial "
            "tests and allowed a "
            f"{vm['attack_success_rate']:.2f}% attack success rate."
        ),

        (
            "The hardened reference improved adversarial security "
            f"test performance to {hm['security_test_pass_rate']:.2f}% "
            "while reducing attack success to "
            f"{hm['attack_success_rate']:.2f}%."
        ),

        (
            "The hardened reference preserved legitimate workflow "
            f"completion at "
            f"{hm['legitimate_workflow_completion_rate']:.2f}%."
        ),

        (
            "A later changed system regressed to "
            f"{rm['security_test_pass_rate']:.2f}% security test "
            "pass rate and "
            f"{rm['attack_success_rate']:.2f}% attack success."
        ),

        (
            "Automated comparison detected "
            f"{regression_metrics['regression_count']} PASS -> FAIL "
            "security regressions across the stable benchmark corpus."
        ),

        (
            "The regression set included "
            f"{regression_metrics['critical_regression_count']} "
            "critical regression and "
            f"{regression_metrics['unsafe_execution_regression_count']} "
            "unsafe-execution regression."
        ),

        (
            "The release-security gate therefore classified "
            "the candidate as "
            f"{release_gate['release_risk']} risk and returned "
            f"{release_gate['release_decision']['decision']}."
        ),

        (
            "Repeated testing showed that "
            f"{stability_metrics['flaky_security_test_rate']:.2f}% "
            "of adversarial security tests were flaky."
        ),

        (
            "The stability analysis also identified "
            f"{stability_metrics['stable_security_failures']} "
            "stable security failure and "
            f"{stability_metrics['critical_flaky_tests']} "
            "critical flaky test."
        ),

        (
            "Across repeated runs, the weighted security score "
            f"varied from {variance['minimum_security_score']:.2f}% "
            f"to {variance['maximum_security_score']:.2f}%, "
            "showing that a single evaluation run would not "
            "represent the system's complete security behavior."
        ),

        (
            "Legitimate utility remained stable at "
            f"{stability_metrics['utility_stability_rate']:.2f}% "
            "during repeated testing."
        ),

        (
            "The Day 26 evidence demonstrates that AI security "
            "must be evaluated as a repeatable engineering process "
            "rather than a one-time red-team exercise."
        ),
    ]

    return findings


# ============================================================
# FINAL EVIDENCE OBJECT
# ============================================================

def build_final_evidence(
    evidence,
    metric_comparison,
    findings,
):

    vulnerable = evidence[
        "vulnerable"
    ]

    hardened = evidence[
        "hardened"
    ]

    regressed = evidence[
        "regressed"
    ]

    regression_report = evidence[
        "regression_report"
    ]

    release_gate = evidence[
        "release_gate"
    ]

    stability = evidence[
        "stability"
    ]


    vulnerable_attack = float(
        vulnerable[
            "metrics"
        ][
            "attack_success_rate"
        ]
    )

    hardened_attack = float(
        hardened[
            "metrics"
        ][
            "attack_success_rate"
        ]
    )


    return {
        "benchmark":
            "Day 26 Final Comparative Analysis",

        "research_question":
            (
                "How do we know that an LLM security control "
                "that works today will continue working after "
                "the model, prompt, policy, application, "
                "retrieval, tool configuration, or guardrail changes?"
            ),

        "core_principle":
            (
                "A security control is not proven by passing once; "
                "it must remain effective under repeatable adversarial "
                "evaluation and system change."
            ),

        "systems": {
            "vulnerable":
                vulnerable["system"],

            "hardened":
                hardened["system"],

            "regressed":
                regressed["system"],
        },

        "metric_comparison":
            metric_comparison,

        "vulnerable_to_hardened_attack_risk_reduction":
            relative_risk_reduction(
                vulnerable_attack,
                hardened_attack,
            ),

        "regression_metrics":
            regression_report[
                "regression_metrics"
            ],

        "release_gate": {
            "decision":
                release_gate[
                    "release_decision"
                ][
                    "decision"
                ],

            "risk":
                release_gate[
                    "release_risk"
                ],

            "failed_gate_ids":
                release_gate[
                    "release_decision"
                ][
                    "failed_gate_ids"
                ],
        },

        "stability_metrics":
            stability[
                "stability_metrics"
            ],

        "variance_metrics":
            stability[
                "variance_metrics"
            ],

        "final_findings":
            findings,

        "final_conclusion":
            (
                "Day 26 demonstrated that security effectiveness "
                "must be measured repeatedly across stable adversarial "
                "and legitimate benchmark cases. Hardened controls "
                "reduced attack success to zero in the reference run, "
                "but later system changes introduced measurable "
                "PASS -> FAIL regressions, unsafe execution, release-"
                "blocking risk, and run-to-run flakiness. Automated "
                "regression comparison and security release gates "
                "therefore provide a practical mechanism for preventing "
                "security deterioration from silently reaching deployment."
            ),
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 26 Lab 16: "
        "Final Comparative Analysis ==="
    )


    evidence = (
        load_all_evidence()
    )


    vulnerable = evidence[
        "vulnerable"
    ]

    hardened = evidence[
        "hardened"
    ]

    regressed = evidence[
        "regressed"
    ]

    regression_report = evidence[
        "regression_report"
    ]

    release_gate = evidence[
        "release_gate"
    ]

    stability = evidence[
        "stability"
    ]


    metrics = (
        build_metric_comparison(
            vulnerable,
            hardened,
            regressed,
        )
    )


    findings = (
        build_final_findings(
            evidence
        )
    )


    # ========================================================
    # RESEARCH QUESTION
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "                 DAY 26 RESEARCH QUESTION"
    )

    print(
        "=" * 78
    )


    print(
        "\nHow do we know that an LLM security control "
        "that works today will continue working after the "
        "model, prompt, policy, application, retrieval, "
        "tool configuration, or guardrail changes?"
    )


    # ========================================================
    # VULNERABLE BASELINE
    # ========================================================

    vm = vulnerable[
        "metrics"
    ]


    print(
        "\n"
        + "=" * 78
    )

    print(
        "                 VULNERABLE BASELINE"
    )

    print(
        "=" * 78
    )


    print(
        "Security Test Pass Rate:",
        f"{vm['security_test_pass_rate']:.2f}%"
    )

    print(
        "Attack Success Rate:",
        f"{vm['attack_success_rate']:.2f}%"
    )

    print(
        "Weighted Security Score:",
        f"{vm['weighted_security_score']:.2f}%"
    )

    print(
        "Sensitive Disclosure Rate:",
        f"{vm['sensitive_disclosure_rate']:.2f}%"
    )

    print(
        "Unsafe Execution Rate:",
        f"{vm['unsafe_execution_rate']:.2f}%"
    )

    print(
        "Unauthorized Impact Rate:",
        f"{vm['unauthorized_impact_rate']:.2f}%"
    )

    print(
        "Legitimate Workflow Completion Rate:",
        f"{vm['legitimate_workflow_completion_rate']:.2f}%"
    )


    # ========================================================
    # HARDENED REFERENCE
    # ========================================================

    hm = hardened[
        "metrics"
    ]


    print(
        "\n"
        + "=" * 78
    )

    print(
        "                 HARDENED REFERENCE"
    )

    print(
        "=" * 78
    )


    print(
        "Security Test Pass Rate:",
        f"{hm['security_test_pass_rate']:.2f}%"
    )

    print(
        "Attack Success Rate:",
        f"{hm['attack_success_rate']:.2f}%"
    )

    print(
        "Weighted Security Score:",
        f"{hm['weighted_security_score']:.2f}%"
    )

    print(
        "Sensitive Disclosure Rate:",
        f"{hm['sensitive_disclosure_rate']:.2f}%"
    )

    print(
        "Unsafe Execution Rate:",
        f"{hm['unsafe_execution_rate']:.2f}%"
    )

    print(
        "Unauthorized Impact Rate:",
        f"{hm['unauthorized_impact_rate']:.2f}%"
    )

    print(
        "Legitimate Workflow Completion Rate:",
        f"{hm['legitimate_workflow_completion_rate']:.2f}%"
    )


    # ========================================================
    # REGRESSED SYSTEM
    # ========================================================

    rm = regressed[
        "metrics"
    ]


    print(
        "\n"
        + "=" * 78
    )

    print(
        "                 CHANGED / REGRESSED VERSION"
    )

    print(
        "=" * 78
    )


    print(
        "Security Test Pass Rate:",
        f"{rm['security_test_pass_rate']:.2f}%"
    )

    print(
        "Attack Success Rate:",
        f"{rm['attack_success_rate']:.2f}%"
    )

    print(
        "Weighted Security Score:",
        f"{rm['weighted_security_score']:.2f}%"
    )

    print(
        "Sensitive Disclosure Rate:",
        f"{rm['sensitive_disclosure_rate']:.2f}%"
    )

    print(
        "Unsafe Execution Rate:",
        f"{rm['unsafe_execution_rate']:.2f}%"
    )

    print(
        "Unauthorized Impact Rate:",
        f"{rm['unauthorized_impact_rate']:.2f}%"
    )

    print(
        "Legitimate Workflow Completion Rate:",
        f"{rm['legitimate_workflow_completion_rate']:.2f}%"
    )


    # ========================================================
    # THREE-WAY COMPARISON
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "                 THREE-WAY SECURITY COMPARISON"
    )

    print(
        "=" * 78
    )


    for metric, values in (
        metrics.items()
    ):

        print(
            f"\nMetric: {metric}"
        )

        print(
            f"Vulnerable: {values['vulnerable']:.2f}%"
        )

        print(
            f"Hardened:   {values['hardened']:.2f}%"
        )

        print(
            f"Regressed:  {values['regressed']:.2f}%"
        )

        print(
            "Vulnerable -> Hardened:",
            f"{values['vulnerable_to_hardened_pp']:+.2f} pp"
        )

        print(
            "Hardened -> Regressed:",
            f"{values['hardened_to_regressed_pp']:+.2f} pp"
        )


    # ========================================================
    # REGRESSION DETECTION
    # ========================================================

    regression_metrics = (
        regression_report[
            "regression_metrics"
        ]
    )


    print(
        "\n"
        + "=" * 78
    )

    print(
        "                 AUTOMATED REGRESSION DETECTION"
    )

    print(
        "=" * 78
    )


    print(
        "Regression Count:",
        regression_metrics[
            "regression_count"
        ]
    )

    print(
        "Regression Rate:",
        f"{regression_metrics['regression_rate']:.2f}%"
    )

    print(
        "Critical Regression Count:",
        regression_metrics[
            "critical_regression_count"
        ]
    )

    print(
        "High/Critical Regression Count:",
        regression_metrics[
            "high_or_critical_regression_count"
        ]
    )

    print(
        "Unsafe-Execution Regressions:",
        regression_metrics[
            "unsafe_execution_regression_count"
        ]
    )

    print(
        "Unauthorized-Impact Regressions:",
        regression_metrics[
            "unauthorized_impact_regression_count"
        ]
    )


    # ========================================================
    # RELEASE GATE
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "                 RELEASE SECURITY GATE"
    )

    print(
        "=" * 78
    )


    print(
        "Release Decision:",
        release_gate[
            "release_decision"
        ][
            "decision"
        ]
    )

    print(
        "Release Risk:",
        release_gate[
            "release_risk"
        ]
    )

    print(
        "Failed Blocking Gates:",
        release_gate[
            "release_decision"
        ][
            "failed_blocking_gate_count"
        ]
    )


    for gate_id in (
        release_gate[
            "release_decision"
        ][
            "failed_gate_ids"
        ]
    ):

        print(
            f"- {gate_id}"
        )


    # ========================================================
    # STABILITY / FLAKINESS
    # ========================================================

    stability_metrics = (
        stability[
            "stability_metrics"
        ]
    )

    variance = (
        stability[
            "variance_metrics"
        ]
    )


    print(
        "\n"
        + "=" * 78
    )

    print(
        "                 STABILITY / FLAKINESS ANALYSIS"
    )

    print(
        "=" * 78
    )


    print(
        "Repeated Runs:",
        stability[
            "run_count"
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
        "Stable Pass Rate:",
        f"{stability_metrics['stable_pass_rate']:.2f}%"
    )

    print(
        "Stable Fail Rate:",
        f"{stability_metrics['stable_fail_rate']:.2f}%"
    )

    print(
        "Critical Flakiness Rate:",
        f"{stability_metrics['critical_flakiness_rate']:.2f}%"
    )

    print(
        "Utility Stability Rate:",
        f"{stability_metrics['utility_stability_rate']:.2f}%"
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
        "Average Attack Success Rate:",
        f"{variance['average_attack_success_rate']:.2f}%"
    )

    print(
        "Attack Success Standard Deviation:",
        f"{variance['attack_success_stddev']:.2f}"
    )


    # ========================================================
    # FINAL FINDINGS
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "                 FINAL FINDINGS"
    )

    print(
        "=" * 78
    )


    for index, finding in enumerate(
        findings,
        start=1,
    ):

        print(
            f"\n{index}. {finding}"
        )


    # ========================================================
    # FINAL CONCLUSION
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "                 CONCLUSION"
    )

    print(
        "=" * 78
    )


    print(
        "\nDay 26 demonstrated that AI security cannot be "
        "established through a single successful test run."
    )

    print(
        "\nThe vulnerable baseline produced a "
        f"{vm['attack_success_rate']:.2f}% attack success rate "
        "and a "
        f"{vm['weighted_security_score']:.2f}% weighted security score."
    )

    print(
        "\nThe hardened reference reduced attack success to "
        f"{hm['attack_success_rate']:.2f}% and increased the "
        "weighted security score to "
        f"{hm['weighted_security_score']:.2f}% while preserving "
        f"{hm['legitimate_workflow_completion_rate']:.2f}% "
        "legitimate workflow completion."
    )

    print(
        "\nAfter system changes, security regressed to a "
        f"{rm['attack_success_rate']:.2f}% attack success rate "
        "and a "
        f"{rm['weighted_security_score']:.2f}% weighted security score."
    )

    print(
        "\nAutomated regression detection identified "
        f"{regression_metrics['regression_count']} PASS -> FAIL "
        "security regressions and classified the release as "
        f"{release_gate['release_risk']} risk."
    )

    print(
        "\nThe release gate correctly returned "
        f"{release_gate['release_decision']['decision']}."
    )

    print(
        "\nRepeated testing further demonstrated that "
        f"{stability_metrics['flaky_security_test_rate']:.2f}% "
        "of adversarial tests were flaky and that security "
        "scores varied substantially between runs."
    )

    print(
        "\nThis establishes the professional security-engineering "
        "lesson that LLM controls must be benchmarked repeatedly, "
        "compared across versions, evaluated for utility, monitored "
        "for flakiness, and enforced through release criteria."
    )


    print(
        "\nCore Principle:"
    )

    print(
        "A security control is not proven by passing once; "
        "it must remain effective under repeatable adversarial "
        "evaluation and system change."
    )


    # ========================================================
    # WRITE FINAL EVIDENCE
    # ========================================================

    final_evidence = (
        build_final_evidence(
            evidence,
            metrics,
            findings,
        )
    )


    json_path = (
        BASE_DIR
        / "day26-final-comparative-analysis.json"
    )

    json_path.write_text(
        json.dumps(
            final_evidence,
            indent=2,
        ),
        encoding="utf-8",
    )


    text_path = (
        BASE_DIR
        / "day26-final-comparative-analysis.txt"
    )


    text_lines = [
        "DAY 26 FINAL COMPARATIVE ANALYSIS",
        "",
        "Research Question:",
        final_evidence[
            "research_question"
        ],
        "",
        "Core Principle:",
        final_evidence[
            "core_principle"
        ],
        "",
        "Vulnerable Baseline:",
        (
            f"Security Test Pass Rate: "
            f"{vm['security_test_pass_rate']:.2f}%"
        ),
        (
            f"Attack Success Rate: "
            f"{vm['attack_success_rate']:.2f}%"
        ),
        (
            f"Weighted Security Score: "
            f"{vm['weighted_security_score']:.2f}%"
        ),
        "",
        "Hardened Reference:",
        (
            f"Security Test Pass Rate: "
            f"{hm['security_test_pass_rate']:.2f}%"
        ),
        (
            f"Attack Success Rate: "
            f"{hm['attack_success_rate']:.2f}%"
        ),
        (
            f"Weighted Security Score: "
            f"{hm['weighted_security_score']:.2f}%"
        ),
        "",
        "Regressed Version:",
        (
            f"Security Test Pass Rate: "
            f"{rm['security_test_pass_rate']:.2f}%"
        ),
        (
            f"Attack Success Rate: "
            f"{rm['attack_success_rate']:.2f}%"
        ),
        (
            f"Weighted Security Score: "
            f"{rm['weighted_security_score']:.2f}%"
        ),
        "",
        (
            f"Regression Count: "
            f"{regression_metrics['regression_count']}"
        ),
        (
            f"Regression Rate: "
            f"{regression_metrics['regression_rate']:.2f}%"
        ),
        (
            f"Critical Regression Count: "
            f"{regression_metrics['critical_regression_count']}"
        ),
        "",
        (
            f"Release Decision: "
            f"{release_gate['release_decision']['decision']}"
        ),
        (
            f"Release Risk: "
            f"{release_gate['release_risk']}"
        ),
        "",
        (
            f"Flaky Security Test Rate: "
            f"{stability_metrics['flaky_security_test_rate']:.2f}%"
        ),
        (
            f"Utility Stability Rate: "
            f"{stability_metrics['utility_stability_rate']:.2f}%"
        ),
        "",
        "Final Findings:",
    ]


    for index, finding in enumerate(
        findings,
        start=1,
    ):

        text_lines.append(
            f"{index}. {finding}"
        )


    text_lines.extend([
        "",
        "Conclusion:",
        final_evidence[
            "final_conclusion"
        ],
    ])


    text_path.write_text(
        "\n".join(
            text_lines
        ),
        encoding="utf-8",
    )


    print(
        "\nEvidence files written to:"
    )

    print(
        json_path
    )

    print(
        text_path
    )


if __name__ == "__main__":
    main()