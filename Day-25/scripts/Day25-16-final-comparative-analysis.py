"""
Day 25 Lab 16
Final Comparative Analysis

Purpose:
Consolidate the Day 25 AI supply-chain assessment results and compare
the vulnerable end-to-end architecture against hardened containment and
defense-in-depth retest results.

Core Principle:
An AI component being available or functional does not establish
that it is authentic, trusted, or safe to load.
"""

from pathlib import Path


# ============================================================
# HELPERS
# ============================================================

def pct(value):
    return f"{value:.2f}%"


def percentage_point_change(
    vulnerable,
    hardened,
):
    return (
        vulnerable
        - hardened
    )


def relative_risk_reduction(
    vulnerable,
    hardened,
):
    if vulnerable == 0:
        return 0.0

    return (
        (
            vulnerable
            - hardened
        )
        / vulnerable
        * 100
    )


def section(title):
    return (
        "\n"
        + "=" * 76
        + "\n"
        + title.center(76)
        + "\n"
        + "=" * 76
        + "\n"
    )


# ============================================================
# DAY 25 RESEARCH QUESTION
# ============================================================

RESEARCH_QUESTION = (
    "Can compromised models, prompts, policies, datasets, dependencies, "
    "tools, configurations, or AI artifacts cross the supply-chain trust "
    "boundary and cause runtime compromise, and can independently enforced "
    "provenance, integrity, capability, and runtime controls prevent "
    "unauthorized impact?"
)


CORE_PRINCIPLE = (
    "An AI component being available or functional does not establish "
    "that it is authentic, trusted, or safe to load."
)


# ============================================================
# LAB RESULTS
# ============================================================

LAB_RESULTS = [

    {
        "lab": "Lab 3 - Prompt-Template Supply-Chain Poisoning",
        "metric": "Runtime Compromise Rate",
        "value": 100.00,
        "utility": 100.00,
        "finding": (
            "Structurally valid prompt artifacts were accepted even when "
            "their trusted integrity changed, allowing malicious "
            "instructions to enter runtime context."
        ),
    },

    {
        "lab": "Lab 4 - Configuration / Policy Artifact Tampering",
        "metric": "Runtime Authorization Compromise Rate",
        "value": 100.00,
        "utility": 100.00,
        "finding": (
            "Tampered policy artifacts redefined targets, capabilities, "
            "approval handling, and authorization semantics."
        ),
    },

    {
        "lab": "Lab 5 - Dataset / Knowledge Artifact Poisoning",
        "metric": "Knowledge-Induced Runtime Compromise Rate",
        "value": 100.00,
        "utility": 100.00,
        "finding": (
            "Poisoned knowledge artifacts introduced false facts, "
            "restricted targets, false approvals, false authorities, "
            "and privileged-action recommendations."
        ),
    },

    {
        "lab": "Lab 6 - Model / Adapter Substitution",
        "metric": "Model / Adapter Runtime Compromise Rate",
        "value": 100.00,
        "utility": 100.00,
        "finding": (
            "Substituted models and adapters remained functional while "
            "changing targets, privileges, and effective capabilities."
        ),
    },

    {
        "lab": "Lab 7 - Tool Package / Dependency Compromise",
        "metric": "Tool / Dependency Runtime Compromise Rate",
        "value": 100.00,
        "utility": 100.00,
        "finding": (
            "API-compatible tool and dependency artifacts silently "
            "rewrote targets, expanded capabilities, or falsified "
            "security results."
        ),
    },

    {
        "lab": "Lab 8 - Dependency Confusion & Artifact Substitution",
        "metric": "Dependency-Confusion Runtime Compromise Rate",
        "value": 100.00,
        "utility": 100.00,
        "finding": (
            "Weak package resolution allowed public, higher-version, "
            "same-version, impersonated, or typosquatted artifacts to "
            "replace trusted dependencies."
        ),
    },

    {
        "lab": "Lab 9 - Artifact Metadata & Provenance Spoofing",
        "metric": "Metadata-Induced Runtime Compromise Rate",
        "value": 100.00,
        "utility": 100.00,
        "finding": (
            "Self-asserted publisher, signature, provenance, build, commit, "
            "and SBOM metadata created false trust decisions."
        ),
    },

    {
        "lab": "Lab 10 - Hash / Integrity Verification Bypass",
        "metric": "Integrity-Bypass Runtime Compromise Rate",
        "value": 100.00,
        "utility": 100.00,
        "finding": (
            "Weak integrity architecture failed despite use of SHA-256 "
            "because verification used partial coverage, stale state, "
            "attacker-controlled digests, or excluded fields."
        ),
    },

    {
        "lab": "Lab 11 - Transitive Dependency Compromise",
        "metric": "Runtime Compromise Rate",
        "value": 100.00,
        "utility": 100.00,
        "finding": (
            "An authentic top-level application and model remained "
            "compromised in effect when direct or transitive dependencies "
            "were malicious."
        ),
    },

    {
        "lab": "Lab 12 - Compromised Artifact -> Runtime Propagation",
        "metric": "Pre-Runtime -> Runtime Propagation Rate",
        "value": 83.33,
        "utility": 100.00,
        "finding": (
            "Most compromised artifacts crossed the loading boundary and "
            "altered runtime behavior, while independent downstream policy "
            "still blocked some individual compromise paths."
        ),
    },
]


# ============================================================
# VULNERABLE BASELINE - LAB 13
# ============================================================

VULNERABLE = {
    "Artifact Trust Bypass Rate": 100.00,
    "Malicious Artifact Load Rate": 100.00,
    "Supply-Chain Propagation Rate": 100.00,
    "Runtime Compromise Rate": 100.00,
    "Unauthorized System Impact Rate": 100.00,
    "Attack Chain Completion Rate": 100.00,
    "Legitimate Workflow Completion Rate": 100.00,
}


# ============================================================
# HARDENED CONTAINMENT - LAB 14
# ============================================================

HARDENED_CONTAINMENT = {
    "Containment Rate": 100.00,
    "Malicious Artifact Load Rate": 0.00,
    "Unauthorized System Impact Rate": 0.00,
    "Attack Chain Completion Rate": 0.00,
    "Legitimate Workflow Completion Rate": 100.00,
}


# ============================================================
# HARDENED ADVERSARIAL RETEST - LAB 15
# ============================================================

HARDENED_RETEST = {
    "Defense-in-Depth Containment Rate": 100.00,
    "Malicious Load Survival Rate": 33.33,
    "Unsafe Runtime Execution Rate": 0.00,
    "Unauthorized System Impact Rate": 0.00,
    "Attack Chain Completion Rate": 0.00,
    "Average Trust Boundaries Crossed": 4.67,
    "Maximum Trust Boundaries Crossed": 7.00,
    "Legitimate Workflow Completion Rate": 100.00,
}


# ============================================================
# DEFENSE-IN-DEPTH BOUNDARIES
# ============================================================

DEFENSE_BOUNDARIES = [
    "SOURCE_TRUST",
    "ARTIFACT_IDENTITY",
    "VERSION_BINDING",
    "PUBLISHER_IDENTITY",
    "PROVENANCE",
    "FULL_INTEGRITY",
    "CAPABILITY_POLICY",
    "RUNTIME_ACTION_BINDING",
    "RUNTIME_TARGET_BINDING",
    "RUNTIME_PRIVILEGE",
    "RUNTIME_APPROVAL",
]


# ============================================================
# FINAL FINDINGS
# ============================================================

FINAL_FINDINGS = [

    (
        "1. Artifact availability, successful loading, or functional output "
        "does not establish authenticity or trust."
    ),

    (
        "2. Prompt templates, policies, datasets, models, adapters, tool "
        "packages, dependencies, and metadata are all part of the AI "
        "supply-chain attack surface."
    ),

    (
        "3. Package names, versions, publisher strings, source labels, "
        "signature-status fields, provenance claims, and SBOM references "
        "are assertions until independently verified."
    ),

    (
        "4. Cryptographic integrity is only effective when the complete "
        "security-relevant artifact is hashed and the expected digest is "
        "obtained from a trusted external source."
    ),

    (
        "5. Dependency resolution must be treated as a security boundary; "
        "higher versions, public repositories, same-version packages, and "
        "typosquatted artifacts must not automatically win resolution."
    ),

    (
        "6. Trust validation must recurse across the full dependency graph. "
        "Authenticity of the top-level model or application does not imply "
        "authenticity of direct or transitive dependencies."
    ),

    (
        "7. Artifact-generated capabilities must not automatically become "
        "execution capabilities. Capability sets require independent policy "
        "binding."
    ),

    (
        "8. Supply-chain trust and runtime authorization must be connected. "
        "Even a loaded artifact must not redefine action, target, privilege, "
        "approval, or execution authority."
    ),

    (
        "9. Defense-in-depth remains effective when earlier supply-chain "
        "controls are assumed bypassed, provided independent downstream "
        "controls continue to fail closed."
    ),

    (
        "10. The hardened architecture reduced end-to-end attack-chain "
        "completion and unauthorized system impact from 100.00% to 0.00% "
        "while preserving 100.00% legitimate workflow completion."
    ),
]


# ============================================================
# LIMITATIONS
# ============================================================

LIMITATIONS = [

    (
        "The benchmark uses synthetic AI artifacts, package registries, "
        "metadata, signatures, provenance records, dependency graphs, "
        "runtime actions, and protected records."
    ),

    (
        "The tests demonstrate architectural trust and containment "
        "properties rather than exploitation of a production package "
        "repository, model registry, signing infrastructure, or deployment "
        "pipeline."
    ),

    (
        "Signature and provenance checks are represented as synthetic "
        "validation logic rather than real public-key cryptography, "
        "certificate-chain validation, transparency logs, or external "
        "attestation services."
    ),

    (
        "Several vulnerable labs intentionally isolate one trust failure at "
        "a time. Real-world attacks may combine these weaknesses in more "
        "complex ways."
    ),
]


# ============================================================
# BUILD REPORT
# ============================================================

def build_report():

    lines = []


    lines.append(
        "=== Day 25 Lab 16: Final Comparative Analysis ===\n"
    )


    # ========================================================
    # RESEARCH QUESTION
    # ========================================================

    lines.append(
        section(
            "DAY 25 RESEARCH QUESTION"
        )
    )

    lines.append(
        RESEARCH_QUESTION
        + "\n"
    )


    # ========================================================
    # VULNERABLE PROGRESSION
    # ========================================================

    lines.append(
        section(
            "VULNERABLE SUPPLY-CHAIN PROGRESSION"
        )
    )


    for result in LAB_RESULTS:

        lines.append(
            f"{result['lab']}\n"
        )

        lines.append(
            f"{result['metric']}: "
            f"{pct(result['value'])}\n"
        )

        lines.append(
            "Clean Utility Rate: "
            f"{pct(result['utility'])}\n"
        )

        lines.append(
            result[
                "finding"
            ]
            + "\n\n"
        )


    # ========================================================
    # LAB 13
    # ========================================================

    lines.append(
        section(
            "LAB 13 VULNERABLE END-TO-END BASELINE"
        )
    )


    for metric, value in (
        VULNERABLE.items()
    ):

        lines.append(
            f"{metric}: "
            f"{pct(value)}\n"
        )


    # ========================================================
    # LAB 14
    # ========================================================

    lines.append(
        section(
            "LAB 14 HARDENED CONTAINMENT ARCHITECTURE"
        )
    )


    for metric, value in (
        HARDENED_CONTAINMENT.items()
    ):

        lines.append(
            f"{metric}: "
            f"{pct(value)}\n"
        )


    # ========================================================
    # LAB 15
    # ========================================================

    lines.append(
        section(
            "LAB 15 HARDENED ADVERSARIAL RETEST"
        )
    )


    lines.append(
        "Defense-in-Depth Containment Rate: "
        f"{pct(
            HARDENED_RETEST[
                'Defense-in-Depth Containment Rate'
            ]
        )}\n"
    )

    lines.append(
        "Malicious Load Survival Rate: "
        f"{pct(
            HARDENED_RETEST[
                'Malicious Load Survival Rate'
            ]
        )}\n"
    )

    lines.append(
        "Unsafe Runtime Execution Rate: "
        f"{pct(
            HARDENED_RETEST[
                'Unsafe Runtime Execution Rate'
            ]
        )}\n"
    )

    lines.append(
        "Unauthorized System Impact Rate: "
        f"{pct(
            HARDENED_RETEST[
                'Unauthorized System Impact Rate'
            ]
        )}\n"
    )

    lines.append(
        "Attack Chain Completion Rate: "
        f"{pct(
            HARDENED_RETEST[
                'Attack Chain Completion Rate'
            ]
        )}\n"
    )

    lines.append(
        "Average Trust Boundaries Crossed: "
        f"{HARDENED_RETEST[
            'Average Trust Boundaries Crossed'
        ]:.2f} / 7\n"
    )

    lines.append(
        "Maximum Trust Boundaries Crossed: "
        f"{HARDENED_RETEST[
            'Maximum Trust Boundaries Crossed'
        ]:.0f} / 7\n"
    )

    lines.append(
        "Legitimate Workflow Completion Rate: "
        f"{pct(
            HARDENED_RETEST[
                'Legitimate Workflow Completion Rate'
            ]
        )}\n"
    )


    # ========================================================
    # VULNERABLE VS HARDENED
    # ========================================================

    lines.append(
        section(
            "VULNERABLE VS HARDENED"
        )
    )


    comparison_metrics = [

        (
            "Malicious Artifact Load Rate",
            VULNERABLE[
                "Malicious Artifact Load Rate"
            ],
            HARDENED_CONTAINMENT[
                "Malicious Artifact Load Rate"
            ],
        ),

        (
            "Unauthorized System Impact Rate",
            VULNERABLE[
                "Unauthorized System Impact Rate"
            ],
            HARDENED_RETEST[
                "Unauthorized System Impact Rate"
            ],
        ),

        (
            "Attack Chain Completion Rate",
            VULNERABLE[
                "Attack Chain Completion Rate"
            ],
            HARDENED_RETEST[
                "Attack Chain Completion Rate"
            ],
        ),

        (
            "Legitimate Workflow Completion Rate",
            VULNERABLE[
                "Legitimate Workflow Completion Rate"
            ],
            HARDENED_RETEST[
                "Legitimate Workflow Completion Rate"
            ],
        ),
    ]


    for (
        metric,
        vulnerable_value,
        hardened_value,
    ) in comparison_metrics:

        lines.append(
            f"Metric: {metric}\n"
        )

        lines.append(
            "Vulnerable: "
            f"{pct(
                vulnerable_value
            )}\n"
        )

        lines.append(
            "Hardened: "
            f"{pct(
                hardened_value
            )}\n"
        )

        change = (
            percentage_point_change(
                vulnerable_value,
                hardened_value,
            )
        )

        lines.append(
            "Change: "
            f"{change:.2f} percentage points\n"
        )


        if (
            metric
            !=
            "Legitimate Workflow Completion Rate"
        ):

            reduction = (
                relative_risk_reduction(
                    vulnerable_value,
                    hardened_value,
                )
            )

            lines.append(
                "Relative Risk Reduction: "
                f"{pct(reduction)}\n"
            )


        lines.append(
            "\n"
        )


    # ========================================================
    # TRUST CHAIN
    # ========================================================

    lines.append(
        section(
            "TRUST-CHAIN SECURITY MODEL"
        )
    )


    trust_chain = [
        "Trusted Artifact Source",
        "Artifact Identity",
        "Pinned Version",
        "Authenticated Publisher",
        "Verified Provenance",
        "Full Artifact Integrity",
        "Dependency-Graph Trust",
        "Capability Policy",
        "Load Authorization",
        "Runtime Action Binding",
        "Runtime Target Binding",
        "Privilege / Approval Enforcement",
    ]


    for index, control in enumerate(
        trust_chain,
        start=1,
    ):

        lines.append(
            f"{index}. {control}\n"
        )


    # ========================================================
    # DEFENSE IN DEPTH
    # ========================================================

    lines.append(
        section(
            "DEFENSE-IN-DEPTH VALIDATION"
        )
    )


    for boundary in (
        DEFENSE_BOUNDARIES
    ):

        lines.append(
            f"- {boundary}\n"
        )


    lines.append(
        "\n"
        "The hardened adversarial retest demonstrated "
        "that compromise can cross earlier boundaries "
        "without automatically becoming execution authority. "
        "Independent downstream controls continued to "
        "contain malicious artifacts before unauthorized "
        "system impact occurred.\n"
    )


    # ========================================================
    # FINAL FINDINGS
    # ========================================================

    lines.append(
        section(
            "FINAL FINDINGS"
        )
    )


    for finding in (
        FINAL_FINDINGS
    ):

        lines.append(
            finding
            + "\n"
        )


    # ========================================================
    # LIMITATIONS
    # ========================================================

    lines.append(
        section(
            "LIMITATIONS"
        )
    )


    for limitation in (
        LIMITATIONS
    ):

        lines.append(
            limitation
            + "\n\n"
        )


    # ========================================================
    # CONCLUSION
    # ========================================================

    lines.append(
        section(
            "CONCLUSION"
        )
    )


    lines.append(
        "Day 25 demonstrated that AI supply-chain compromise "
        "can occur before application startup through poisoned "
        "prompt templates, altered security policies, malicious "
        "datasets, substituted models or adapters, compromised "
        "tool packages, dependency confusion, spoofed provenance, "
        "weak integrity verification, and malicious transitive "
        "dependencies.\n\n"
    )


    lines.append(
        "The vulnerable end-to-end architecture produced a "
        "100.00% artifact trust bypass rate, 100.00% malicious "
        "artifact load rate, 100.00% supply-chain propagation "
        "rate, 100.00% runtime compromise rate, 100.00% "
        "unauthorized system impact rate, and 100.00% "
        "end-to-end attack-chain completion rate.\n\n"
    )


    lines.append(
        "The hardened supply-chain architecture achieved a "
        "100.00% containment rate with 0.00% malicious artifact "
        "loading, 0.00% unauthorized system impact, and 0.00% "
        "attack-chain completion while preserving 100.00% "
        "legitimate workflow completion.\n\n"
    )


    lines.append(
        "During the hardened adversarial retest, 33.33% of "
        "malicious artifacts were intentionally allowed to "
        "survive into later trust stages because earlier "
        "controls were assumed bypassed. Despite this, unsafe "
        "runtime execution, unauthorized system impact, and "
        "attack-chain completion all remained at 0.00%, "
        "demonstrating effective defense in depth.\n\n"
    )


    lines.append(
        "The assessment therefore shows that AI artifact trust "
        "must be established continuously across artifact "
        "source, identity, version, publisher, provenance, "
        "integrity, dependency graphs, capabilities, loading, "
        "and runtime execution authority.\n\n"
    )


    lines.append(
        "Core Principle:\n"
    )

    lines.append(
        CORE_PRINCIPLE
        + "\n"
    )


    return "".join(
        lines
    )


# ============================================================
# MAIN
# ============================================================

def main():

    report = build_report()

    print(
        report
    )


    evidence_path = (
        Path.cwd()
        / "day25-final-comparative-analysis.txt"
    )


    evidence_path.write_text(
        report,
        encoding="utf-8",
    )


    print(
        "\nEvidence file written to:"
    )

    print(
        evidence_path
    )


if __name__ == "__main__":
    main()