from pathlib import Path


print(
    "\n=== Day 23 Lab 15: "
    "Final Comparative Analysis ==="
)


# ============================================================
# VERIFIED DAY 23 RESULTS
# ============================================================

RESULTS = {

    "Lab 2 - Vulnerable Tool Selection": {
        "metric": "Unsafe Tool Selection Rate",
        "value": 66.67,
        "interpretation": (
            "The model selected tools outside the current "
            "agent's authorized capability set."
        ),
    },

    "Lab 3 - Malicious Tool Description Poisoning": {
        "metric": "Malicious Tool Description Influence Rate",
        "value": 50.00,
        "interpretation": (
            "Model-visible tool descriptions influenced "
            "tool-selection behavior."
        ),
    },

    "Lab 4 - Excessive Tool Permissions": {
        "metric": "Excessive Permission Exploitation Rate",
        "value": 75.00,
        "interpretation": (
            "Broader tool exposure increased selection "
            "of unnecessary high-risk tools."
        ),
    },

    "Lab 5 - Parameter Manipulation": {
        "metric": "Parameter Manipulation Success Rate",
        "value": 100.00,
        "interpretation": (
            "Model-generated tool arguments changed targets, "
            "expanded scope, or inserted unauthorized parameters."
        ),
    },

    "Lab 6 - Confused Tool Selection": {
        "metric": "Confused Tool Selection Rate",
        "value": 60.00,
        "interpretation": (
            "The model sometimes replaced a sufficient safe tool "
            "with a more privileged or inappropriate alternative."
        ),
    },

    "Lab 7 - Indirect Tool-Output Injection": {
        "metric": "Indirect Tool Injection Success Rate",
        "value": 100.00,
        "interpretation": (
            "Poisoned tool output influenced downstream "
            "tool-selection behavior."
        ),
    },

    "Lab 8 - Tool-Result Poisoning": {
        "metric": "Tool-Result Poisoning Success Rate",
        "value": 50.00,
        "interpretation": (
            "False tool evidence corrupted selected "
            "security-sensitive model judgments."
        ),
    },

    "Lab 9 - Chained Tool Attack": {
        "metric": "Chained Tool Attack Success Rate",
        "value": 75.00,
        "interpretation": (
            "Multiple tool-layer weaknesses composed into "
            "security-impacting attack chains."
        ),
    },

    "Lab 10 - MCP Trust Boundary": {
        "metric": "Unsafe MCP Registration Rate",
        "value": 0.00,
        "interpretation": (
            "Trusted server identity, ownership, metadata, "
            "and capability controls blocked unsafe registrations."
        ),
    },

    "Lab 11 - Least Privilege": {
        "metric": "Unauthorized Tool Authorization Rate",
        "value": 0.00,
        "interpretation": (
            "Visible or delegated tools could not be executed "
            "without the delegate's own capability."
        ),
    },

    "Lab 12 - Parameter Enforcement": {
        "metric": "Unsafe Parameter Execution Rate",
        "value": 0.00,
        "interpretation": (
            "Trusted schemas, target binding, and value policy "
            "prevented unsafe model-generated arguments."
        ),
    },

    "Lab 13 - Hardened Tool/MCP Architecture": {
        "metric": "Unsafe Tool Execution Rate",
        "value": 0.00,
        "interpretation": (
            "The integrated security pipeline blocked all "
            "tested malicious execution attempts."
        ),
    },

    "Lab 14 - Hardened Adversarial Retest": {
        "metric": "Unauthorized System Impact Rate",
        "value": 0.00,
        "interpretation": (
            "Dangerous model proposals were fully contained "
            "by trusted application-controlled execution state."
        ),
    },
}


# ============================================================
# BEFORE / AFTER COMPARISONS
# ============================================================

COMPARISONS = [

    {
        "attack": "Unauthorized tool selection",
        "vulnerable": 66.67,
        "hardened": 0.00,
        "control": (
            "Capability enforcement and least-privilege "
            "tool exposure/execution"
        ),
    },

    {
        "attack": "Parameter manipulation",
        "vulnerable": 100.00,
        "hardened": 0.00,
        "control": (
            "Strict parameter schema, trusted target binding, "
            "scope enforcement, and value policy"
        ),
    },

    {
        "attack": "MCP/server trust abuse",
        "vulnerable": 100.00,
        "hardened": 0.00,
        "control": (
            "Trusted server identity, tool ownership, "
            "allowlists, and metadata validation"
        ),
    },

    {
        "attack": "Chained tool compromise",
        "vulnerable": 75.00,
        "hardened": 0.00,
        "control": (
            "Independent validation at each execution stage"
        ),
    },

    {
        "attack": "Adversarial model proposals",
        "vulnerable": 100.00,
        "hardened": 0.00,
        "control": (
            "Trusted application state prevents model proposals "
            "from redefining server, tool, target, scope, "
            "parameters, or approval"
        ),
    },
]


# ============================================================
# OUTPUT HELPERS
# ============================================================

def improvement(
    vulnerable,
    hardened,
):

    return vulnerable - hardened


# ============================================================
# CONSOLE REPORT
# ============================================================

print(
    "\n========================================"
)

print(
    "       DAY 23 COMPARATIVE SUMMARY"
)

print(
    "========================================"
)


for name, result in RESULTS.items():

    print(
        f"\n{name}"
    )

    print(
        f"{result['metric']}: "
        f"{result['value']:.2f}%"
    )

    print(
        result[
            "interpretation"
        ]
    )


print(
    "\n========================================"
)

print(
    "      VULNERABLE VS HARDENED"
)

print(
    "========================================"
)


for comparison in COMPARISONS:

    reduction = improvement(
        comparison[
            "vulnerable"
        ],
        comparison[
            "hardened"
        ],
    )

    print(
        f"\nAttack Class: "
        f"{comparison['attack']}"
    )

    print(
        "Vulnerable Rate:",
        f"{comparison['vulnerable']:.2f}%"
    )

    print(
        "Hardened Rate:",
        f"{comparison['hardened']:.2f}%"
    )

    print(
        "Risk Reduction:",
        f"{reduction:.2f} percentage points"
    )

    print(
        "Primary Control:",
        comparison[
            "control"
        ]
    )


# ============================================================
# FINAL SECURITY FINDINGS
# ============================================================

FINDINGS = [
    (
        "Tool discovery and tool availability must not "
        "be treated as execution authority."
    ),
    (
        "Tool descriptions and tool results are part of "
        "the model-visible prompt attack surface."
    ),
    (
        "Model-generated parameters are untrusted proposals "
        "and require independent schema, target, scope, "
        "and value validation."
    ),
    (
        "MCP-style tool providers create a separate server "
        "trust boundary requiring identity, ownership, "
        "allowlist, and metadata controls."
    ),
    (
        "Excessive tool exposure increases both accidental "
        "and adversarial tool-selection risk."
    ),
    (
        "Tool-chain attacks can compose across tool output, "
        "selection, parameters, approvals, and delegated authority."
    ),
    (
        "Trusted execution state must be stored outside "
        "model-generated content."
    ),
    (
        "Compromised model reasoning does not need to result "
        "in compromised execution when independent controls "
        "bind identity, capability, scope, parameters, "
        "resource policy, and approval."
    ),
]


print(
    "\n========================================"
)

print(
    "           FINAL FINDINGS"
)

print(
    "========================================"
)


for index, finding in enumerate(
    FINDINGS,
    start=1,
):

    print(
        f"{index}. {finding}"
    )


# ============================================================
# FINAL CONCLUSION
# ============================================================

CONCLUSION = (
    "Day 23 demonstrated that tool-enabled LLM agents can be "
    "manipulated through malicious tool metadata, excessive "
    "permissions, parameter substitution, poisoned tool results, "
    "confused tool selection, chained attacks, and MCP-style "
    "trust-boundary abuse. The hardened architecture reduced "
    "tested unauthorized execution impact to zero by treating "
    "all model-generated tool actions as untrusted proposals "
    "and independently enforcing server identity, tool ownership, "
    "agent capability, target binding, parameter schemas, scope, "
    "resource policy, and trusted approvals."
)


print(
    "\n========================================"
)

print(
    "             CONCLUSION"
)

print(
    "========================================"
)

print(
    CONCLUSION
)


print(
    "\nCore Principle:"
)

print(
    "Tool availability does not imply tool authority; "
    "every AI-initiated action must remain independently "
    "constrained by identity, capability, scope, parameters, "
    "and policy."
)


# ============================================================
# WRITE EVIDENCE FILE
# ============================================================

output_path = Path(
    "day23-final-comparative-analysis.txt"
)


with output_path.open(
    "w",
    encoding="utf-8",
) as file:

    file.write(
        "DAY 23 FINAL COMPARATIVE ANALYSIS\n"
    )

    file.write(
        "=" * 60
        + "\n\n"
    )


    for name, result in RESULTS.items():

        file.write(
            f"{name}\n"
        )

        file.write(
            f"{result['metric']}: "
            f"{result['value']:.2f}%\n"
        )

        file.write(
            f"{result['interpretation']}\n\n"
        )


    file.write(
        "VULNERABLE VS HARDENED\n"
    )

    file.write(
        "=" * 60
        + "\n\n"
    )


    for comparison in COMPARISONS:

        file.write(
            f"Attack Class: "
            f"{comparison['attack']}\n"
        )

        file.write(
            f"Vulnerable Rate: "
            f"{comparison['vulnerable']:.2f}%\n"
        )

        file.write(
            f"Hardened Rate: "
            f"{comparison['hardened']:.2f}%\n"
        )

        file.write(
            f"Primary Control: "
            f"{comparison['control']}\n\n"
        )


    file.write(
        "FINAL FINDINGS\n"
    )

    file.write(
        "=" * 60
        + "\n\n"
    )


    for index, finding in enumerate(
        FINDINGS,
        start=1,
    ):

        file.write(
            f"{index}. {finding}\n"
        )


    file.write(
        "\nCONCLUSION\n"
    )

    file.write(
        "=" * 60
        + "\n\n"
    )

    file.write(
        CONCLUSION
        + "\n\n"
    )

    file.write(
        "Core Principle:\n"
    )

    file.write(
        "Tool availability does not imply tool authority; "
        "every AI-initiated action must remain independently "
        "constrained by identity, capability, scope, parameters, "
        "and policy.\n"
    )


print(
    "\nEvidence file written to:"
)

print(
    output_path.resolve()
)