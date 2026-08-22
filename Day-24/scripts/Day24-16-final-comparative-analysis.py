"""
Day 24 - Lab 16
Final Vulnerable vs Hardened Comparative Analysis

Purpose:
Consolidate measured Day 24 results into a final comparative
security assessment.

Portfolio theme:
Autonomous Agent Attack Chains & Blast-Radius Containment

Core Principle:
A compromised component must not automatically compromise
the whole autonomous system.
"""

from pathlib import Path


# ============================================================
# LAB RESULTS
# ============================================================

LAB_RESULTS = [

    {
        "lab": 3,
        "name": "Indirect Injection Entry Point",
        "primary_metric": "Indirect Injection Compromise Rate",
        "rate": 100.00,
        "utility": 100.00,
        "finding": (
            "External attacker-controlled content compromised "
            "Agent A observations in all poisoned cases."
        ),
    },

    {
        "lab": 4,
        "name": "Agent A Compromise & Malicious Memory Write",
        "primary_metric": "Malicious Memory Write Rate",
        "rate": 100.00,
        "utility": 100.00,
        "finding": (
            "Compromised observations were persisted into "
            "shared memory without independent validation."
        ),
    },

    {
        "lab": 5,
        "name": "Cross-Agent Context Propagation",
        "primary_metric": "Cross-Component Propagation Rate",
        "rate": 100.00,
        "utility": 100.00,
        "finding": (
            "Poisoned shared memory propagated into Agent B "
            "planning across every poisoned test."
        ),
    },

    {
        "lab": 6,
        "name": "Persistent Memory Poisoning",
        "primary_metric": "Persistence Survival Rate",
        "rate": 100.00,
        "utility": 100.00,
        "finding": (
            "Attacker-influenced memory survived beyond the "
            "original malicious workflow and affected later "
            "clean workflow executions."
        ),
    },

    {
        "lab": 7,
        "name": "Agent B Planning Manipulation",
        "primary_metric": "Planning Manipulation Rate",
        "rate": 100.00,
        "utility": 0.00,
        "finding": (
            "Poisoned persistent memory produced dangerous "
            "Agent B plans, although clean planning also "
            "showed substantial model/schema instability."
        ),
    },

    {
        "lab": 8,
        "name": "MCP / Tool-Selection Escalation",
        "primary_metric": "MCP Cross-Boundary Propagation Rate",
        "rate": 100.00,
        "utility": 100.00,
        "finding": (
            "Compromised plans propagated into MCP/tool "
            "selection when server, tool and target proposals "
            "were not independently bound to trusted task state."
        ),
    },

    {
        "lab": 9,
        "name": "Parameter & Target Manipulation",
        "primary_metric": "Parameter Manipulation Rate",
        "rate": 100.00,
        "utility": 100.00,
        "finding": (
            "Every poisoned case produced a manipulated "
            "execution request."
        ),
    },

    {
        "lab": 10,
        "name": "Privilege Escalation Chain",
        "primary_metric": "Privilege Escalation Rate",
        "rate": 75.00,
        "utility": 100.00,
        "finding": (
            "Model-generated authority and approval state "
            "allowed worker-level requests to acquire "
            "restricted execution authority."
        ),
    },

    {
        "lab": 11,
        "name": "Persistent State Manipulation",
        "primary_metric": "Persistent State Manipulation Rate",
        "rate": 75.00,
        "utility": 100.00,
        "finding": (
            "Successful privilege escalation produced durable "
            "changes to restricted synthetic state."
        ),
    },

    {
        "lab": 12,
        "name": "Agent C Downstream Propagation",
        "primary_metric": "Downstream Compromise Rate",
        "rate": 100.00,
        "utility": 100.00,
        "finding": (
            "Agent C trusted compromised persistent state "
            "without independently validating provenance."
        ),
    },
]


# ============================================================
# VULNERABLE END-TO-END RESULTS - LAB 13
# ============================================================

VULNERABLE = {

    "Attack Chain Completion Rate": 80.00,

    "Cross-Component Propagation Rate": 100.00,

    "Privilege Escalation Rate": 80.00,

    "Persistent Impact Rate": 80.00,

    "Downstream Compromise Rate": 80.00,

    "Dangerous Proposal Rate": 100.00,

    "Unauthorized System Impact Rate": 80.00,

    "Average Compromised Components": 7.40,

    "Maximum Components": 8.00,

    "Blast Radius": 92.50,

    "Legitimate Workflow Completion Rate": 100.00,
}


# ============================================================
# HARDENED CONTAINMENT RESULTS - LAB 14
# ============================================================

HARDENED_CONTAINMENT = {

    "Containment Rate": 100.00,

    "Attack Chain Completion Rate": 0.00,

    "Unauthorized System Impact Rate": 0.00,

    "Average Compromised Components": 1.00,

    "Maximum Components": 8.00,

    "Blast Radius": 12.50,

    "Blast-Radius Reduction": 86.49,

    "Legitimate Workflow Completion Rate": 100.00,
}


# ============================================================
# HARDENED ADVERSARIAL RETEST - LAB 15
# ============================================================

HARDENED_RETEST = {

    "Defense-in-Depth Containment Rate": 100.00,

    "Unsafe Execution Rate": 0.00,

    "Unauthorized System Impact Rate": 0.00,

    "Attack Chain Completion Rate": 0.00,

    "Average Compromised Components": 1.17,

    "Maximum Compromised Components": 2.00,

    "Maximum Components": 8.00,

    "Blast Radius": 14.58,

    "Blast-Radius Reduction": 84.23,

    "Legitimate Workflow Completion Rate": 100.00,
}


# ============================================================
# CONTROL STAGES PROVEN IN LAB 15
# ============================================================

CONTAINMENT_STAGES = {

    "Memory Boundary": (
        "MEMORY_AUTHORITY"
    ),

    "Agent B Planning Boundary": (
        "AGENT_B_TOOL_BINDING"
    ),

    "MCP / Tool Boundary": (
        "MCP_TOOL_BINDING"
    ),

    "Parameter Boundary": (
        "PARAMETER_SCHEMA"
    ),

    "Authorization Boundary": (
        "AUTH_CAPABILITY"
    ),

    "Persistent-State Boundary": (
        "STATE_PROVENANCE"
    ),
}


# ============================================================
# HELPERS
# ============================================================

def percentage_point_reduction(
    vulnerable,
    hardened,
):

    return (
        vulnerable
        - hardened
    )


def relative_reduction(
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


def line():

    return (
        "="
        * 72
    )


# ============================================================
# REPORT BUILDING
# ============================================================

def build_report():

    output = []

    output.append(
        "=== Day 24 Lab 16: Final Comparative Analysis ==="
    )

    output.append(
        ""
    )

    output.append(
        line()
    )

    output.append(
        "               DAY 24 RESEARCH QUESTION"
    )

    output.append(
        line()
    )

    output.append(
        ""
    )

    output.append(
        "Can an attacker turn one compromised input or agent "
        "into a multi-stage autonomous attack chain, and can "
        "architectural controls contain the blast radius "
        "before unauthorized system impact occurs?"
    )

    output.append(
        ""
    )

    # ========================================================
    # VULNERABILITY PROGRESSION
    # ========================================================

    output.append(
        line()
    )

    output.append(
        "             VULNERABLE ATTACK PROGRESSION"
    )

    output.append(
        line()
    )

    output.append(
        ""
    )

    for result in LAB_RESULTS:

        output.append(
            (
                f"Lab {result['lab']} - "
                f"{result['name']}"
            )
        )

        output.append(
            (
                f"{result['primary_metric']}: "
                f"{result['rate']:.2f}%"
            )
        )

        output.append(
            (
                "Clean Utility Rate: "
                f"{result['utility']:.2f}%"
            )
        )

        output.append(
            result[
                "finding"
            ]
        )

        output.append(
            ""
        )

    # ========================================================
    # END-TO-END VULNERABLE BASELINE
    # ========================================================

    output.append(
        line()
    )

    output.append(
        "            LAB 13 VULNERABLE BASELINE"
    )

    output.append(
        line()
    )

    output.append(
        ""
    )

    for metric, value in VULNERABLE.items():

        if metric in {
            "Average Compromised Components",
            "Maximum Components",
        }:

            continue

        output.append(
            f"{metric}: {value:.2f}%"
        )

    output.append(
        (
            "Average Compromised Components: "
            f"{VULNERABLE['Average Compromised Components']:.2f} "
            f"/ {VULNERABLE['Maximum Components']:.0f}"
        )
    )

    output.append(
        ""
    )

    # ========================================================
    # HARDENED CONTAINMENT
    # ========================================================

    output.append(
        line()
    )

    output.append(
        "           LAB 14 CONTAINMENT ARCHITECTURE"
    )

    output.append(
        line()
    )

    output.append(
        ""
    )

    for metric, value in HARDENED_CONTAINMENT.items():

        if metric in {
            "Average Compromised Components",
            "Maximum Components",
        }:

            continue

        output.append(
            f"{metric}: {value:.2f}%"
        )

    output.append(
        (
            "Average Compromised Components: "
            f"{HARDENED_CONTAINMENT['Average Compromised Components']:.2f} "
            f"/ {HARDENED_CONTAINMENT['Maximum Components']:.0f}"
        )
    )

    output.append(
        ""
    )

    # ========================================================
    # HARDENED RETEST
    # ========================================================

    output.append(
        line()
    )

    output.append(
        "       LAB 15 HARDENED ADVERSARIAL RETEST"
    )

    output.append(
        line()
    )

    output.append(
        ""
    )

    for metric, value in HARDENED_RETEST.items():

        if metric in {
            "Average Compromised Components",
            "Maximum Compromised Components",
            "Maximum Components",
        }:

            continue

        output.append(
            f"{metric}: {value:.2f}%"
        )

    output.append(
        (
            "Average Compromised Components: "
            f"{HARDENED_RETEST['Average Compromised Components']:.2f} "
            f"/ {HARDENED_RETEST['Maximum Components']:.0f}"
        )
    )

    output.append(
        (
            "Maximum Compromised Components: "
            f"{HARDENED_RETEST['Maximum Compromised Components']:.0f} "
            f"/ {HARDENED_RETEST['Maximum Components']:.0f}"
        )
    )

    output.append(
        ""
    )

    # ========================================================
    # VULNERABLE VS HARDENED
    # ========================================================

    output.append(
        line()
    )

    output.append(
        "              VULNERABLE VS HARDENED"
    )

    output.append(
        line()
    )

    comparison_metrics = [

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
            "Unauthorized System Impact Rate",
            VULNERABLE[
                "Unauthorized System Impact Rate"
            ],
            HARDENED_RETEST[
                "Unauthorized System Impact Rate"
            ],
        ),

        (
            "Blast Radius",
            VULNERABLE[
                "Blast Radius"
            ],
            HARDENED_RETEST[
                "Blast Radius"
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

    output.append(
        ""
    )

    for (
        metric,
        vulnerable_value,
        hardened_value,
    ) in comparison_metrics:

        pp_change = (
            percentage_point_reduction(
                vulnerable_value,
                hardened_value,
            )
        )

        output.append(
            f"Metric: {metric}"
        )

        output.append(
            (
                "Vulnerable: "
                f"{vulnerable_value:.2f}%"
            )
        )

        output.append(
            (
                "Hardened: "
                f"{hardened_value:.2f}%"
            )
        )

        output.append(
            (
                "Change: "
                f"{pp_change:.2f} percentage points"
            )
        )

        if (
            vulnerable_value > 0
            and
            metric
            != "Legitimate Workflow Completion Rate"
        ):

            relative = relative_reduction(
                vulnerable_value,
                hardened_value,
            )

            output.append(
                (
                    "Relative Risk Reduction: "
                    f"{relative:.2f}%"
                )
            )

        output.append(
            ""
        )

    # ========================================================
    # BLAST-RADIUS ANALYSIS
    # ========================================================

    output.append(
        line()
    )

    output.append(
        "              BLAST-RADIUS ANALYSIS"
    )

    output.append(
        line()
    )

    vulnerable_blast = VULNERABLE[
        "Blast Radius"
    ]

    hardened_blast = HARDENED_RETEST[
        "Blast Radius"
    ]

    blast_reduction = relative_reduction(
        vulnerable_blast,
        hardened_blast,
    )

    output.append(
        ""
    )

    output.append(
        (
            "Vulnerable Blast Radius: "
            f"{vulnerable_blast:.2f}%"
        )
    )

    output.append(
        (
            "Hardened Blast Radius: "
            f"{hardened_blast:.2f}%"
        )
    )

    output.append(
        (
            "Blast-Radius Reduction: "
            f"{blast_reduction:.2f}%"
        )
    )

    output.append(
        ""
    )

    output.append(
        (
            "Vulnerable Average Compromised Components: "
            f"{VULNERABLE['Average Compromised Components']:.2f} / 8"
        )
    )

    output.append(
        (
            "Hardened Average Compromised Components: "
            f"{HARDENED_RETEST['Average Compromised Components']:.2f} / 8"
        )
    )

    output.append(
        (
            "Hardened Maximum Compromised Components: "
            f"{HARDENED_RETEST['Maximum Compromised Components']:.0f} / 8"
        )
    )

    output.append(
        ""
    )

    # ========================================================
    # DEFENSE IN DEPTH
    # ========================================================

    output.append(
        line()
    )

    output.append(
        "          DEFENSE-IN-DEPTH VALIDATION"
    )

    output.append(
        line()
    )

    output.append(
        ""
    )

    for boundary, control in (
        CONTAINMENT_STAGES.items()
    ):

        output.append(
            f"{boundary}: {control}"
        )

    output.append(
        ""
    )

    output.append(
        (
            "Each tested compromise entry stage was stopped "
            "by an independently enforced downstream boundary."
        )
    )

    output.append(
        ""
    )

    # ========================================================
    # FINAL FINDINGS
    # ========================================================

    output.append(
        line()
    )

    output.append(
        "                 FINAL FINDINGS"
    )

    output.append(
        line()
    )

    output.append(
        ""
    )

    findings = [

        (
            "1. Indirect prompt injection can become a "
            "system-level threat when model output is passed "
            "across autonomous trust boundaries."
        ),

        (
            "2. Shared and persistent memory can transform "
            "temporary attacker influence into durable "
            "cross-workflow compromise."
        ),

        (
            "3. Agent-generated context must not be treated "
            "as identity, authorization, approval, scope, or "
            "security-policy state."
        ),

        (
            "4. Tool and MCP availability must remain separate "
            "from tool execution authority."
        ),

        (
            "5. Model-generated parameters require strict "
            "schema validation, trusted target binding, scope "
            "enforcement, and resource-policy checks."
        ),

        (
            "6. Model-generated authority and approval claims "
            "must never directly satisfy execution authorization."
        ),

        (
            "7. Persistent application state is itself a trust "
            "boundary and requires provenance and authorization "
            "integrity."
        ),

        (
            "8. Downstream agents must validate state provenance "
            "instead of blindly accepting current persistent "
            "state as authoritative."
        ),

        (
            "9. Defense-in-depth contained compromise even when "
            "attacks were injected after earlier controls were "
            "assumed to have failed."
        ),

        (
            "10. The hardened architecture reduced unauthorized "
            "system impact from 80.00% to 0.00% while preserving "
            "100.00% legitimate workflow completion."
        ),
    ]

    for finding in findings:

        output.append(
            finding
        )

    output.append(
        ""
    )

    # ========================================================
    # LIMITATIONS
    # ========================================================

    output.append(
        line()
    )

    output.append(
        "                   LIMITATIONS"
    )

    output.append(
        line()
    )

    output.append(
        ""
    )

    output.append(
        (
            "Lab 7 showed significant baseline planning/schema "
            "instability on clean model inputs. Its poisoned-case "
            "results therefore demonstrate unsafe planning "
            "susceptibility but do not isolate poisoned memory "
            "as the sole cause of every unsafe proposal."
        )
    )

    output.append(
        ""
    )

    output.append(
        (
            "The benchmark uses synthetic records, agents, "
            "authorization state, MCP-style servers, and tool "
            "executions. Results demonstrate architectural "
            "security properties rather than exploitation of "
            "a production environment."
        )
    )

    output.append(
        ""
    )

    # ========================================================
    # CONCLUSION
    # ========================================================

    output.append(
        line()
    )

    output.append(
        "                    CONCLUSION"
    )

    output.append(
        line()
    )

    output.append(
        ""
    )

    output.append(
        (
            "Day 24 demonstrated that a single compromised "
            "input can propagate through autonomous agents, "
            "persistent memory, MCP/tool selection, execution "
            "parameters, authorization boundaries, persistent "
            "system state, and downstream agents when upstream "
            "outputs are implicitly trusted."
        )
    )

    output.append(
        ""
    )

    output.append(
        (
            "The vulnerable end-to-end architecture produced "
            "an 80.00% attack-chain completion rate, an 80.00% "
            "unauthorized system impact rate, and a 92.50% "
            "normalized blast radius."
        )
    )

    output.append(
        ""
    )

    output.append(
        (
            "The hardened adversarial retest achieved a "
            "100.00% defense-in-depth containment rate, "
            "0.00% unsafe execution rate, 0.00% unauthorized "
            "system impact rate, and 0.00% attack-chain "
            "completion rate."
        )
    )

    output.append(
        ""
    )

    output.append(
        (
            "The hardened blast radius was reduced to 14.58%, "
            "representing an 84.23% reduction relative to the "
            "vulnerable end-to-end architecture, while legitimate "
            "workflow completion remained at 100.00%."
        )
    )

    output.append(
        ""
    )

    output.append(
        "Core Principle:"
    )

    output.append(
        (
            "A compromised component must not automatically "
            "compromise the whole autonomous system."
        )
    )

    return "\n".join(
        output
    )


# ============================================================
# MAIN
# ============================================================

def main():

    report = build_report()

    print(
        report
    )

    evidence_path = Path(
        "day24-final-comparative-analysis.txt"
    )

    evidence_path.write_text(
        report,
        encoding="utf-8",
    )

    print(
        "\nEvidence file written to:"
    )

    print(
        evidence_path.resolve()
    )


if __name__ == "__main__":
    main()