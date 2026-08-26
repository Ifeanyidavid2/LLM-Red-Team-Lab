"""
Day 29 Lab 13
Consolidated Findings Register & Root-Cause Analysis

Purpose:
Consolidate overlapping Day 29 red-team test failures into a smaller,
professional consulting-style findings register.

The lab maps technical evidence into:
- material security findings;
- root causes;
- affected controls;
- business assets;
- risk scenarios;
- remediation owners;
- required corrective actions;
- retest criteria.

Core Principle:
A professional assessment should consolidate symptoms into root-cause
findings so remediation addresses the security architecture rather than
patching individual prompts or test cases.
"""

from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
import hashlib
import json


ENGAGEMENT_ID = "ENG-2901"
SYSTEM_ID = "ENT-AI-2901"
TRACE_ID = "TRACE-2913"


# =============================================================================
# CONSOLIDATED FINDINGS
# =============================================================================

FINDINGS = [
    {
        "finding_id": "CF-2901",
        "title": "Untrusted Instructions Can Alter Trusted AI Tasks and Targets",
        "severity": "CRITICAL",
        "domain": "INSTRUCTION_TRUST",

        "source_findings": [
            "FIND-2902",
            "FIND-2904",
            "FIND-2906",
            "FIND-2908",
            "FIND-2919",
            "FIND-2920",
        ],

        "affected_assets": [
            "System Instruction Integrity",
            "Trusted Task",
            "Trusted Target",
            "Agent Goal",
        ],

        "root_cause":
            "Natural-language input and retrieved content are not sufficiently separated from trusted task, goal, target, or authority state.",

        "business_impact":
            "Attackers can redirect approved workflows toward restricted targets or privileged actions.",

        "control_failures": [
            "Instruction Trust Separation",
            "Trusted Task Binding",
            "Trusted Target Binding",
            "Independent Authority Validation",
        ],

        "risk_ids": [
            "RISK-2912-03",
            "RISK-2912-05",
        ],

        "owner": "AI Security Engineering",

        "remediation_priority": "IMMEDIATE",

        "remediation": [
            "Enforce explicit instruction hierarchy.",
            "Treat user and retrieved content as untrusted data.",
            "Cryptographically or structurally bind trusted tasks and targets outside the model.",
            "Reject model or user claims of authorization.",
        ],

        "retest_criteria": [
            "Prompt injection cannot alter trusted task.",
            "Retrieved instructions cannot alter trusted target.",
            "User-supplied approval claims are rejected.",
            "Model-generated authority cannot satisfy authorization.",
        ],
    },

    {
        "finding_id": "CF-2902",
        "title": "RAG Trust Boundary Permits Poisoned Context and Indirect Prompt Injection",
        "severity": "CRITICAL",
        "domain": "RAG_SECURITY",

        "source_findings": [
            "FIND-2918",
            "FIND-2919",
            "FIND-2920",
            "FIND-2921",
            "FIND-2922",
            "FIND-2923",
            "FIND-2924",
        ],

        "affected_assets": [
            "RAG Knowledge System",
            "Retrieved Context",
            "Persistent Memory",
            "Agent Planner",
        ],

        "root_cause":
            "Retrieved documents are admitted without sufficient source provenance, context classification, instruction isolation, or fail-closed admission controls.",

        "business_impact":
            "Malicious retrieval content can manipulate model behavior, persist into memory, influence agents, expose sensitive information, and support privileged execution.",

        "control_failures": [
            "RAG Source Validation",
            "Document Provenance",
            "Indirect Prompt Injection Detection",
            "Fail-Closed Context Admission",
            "Retrieved Data Minimization",
        ],

        "risk_ids": [
            "RISK-2912-02",
            "RISK-2912-08",
        ],

        "owner": "RAG Platform Team",

        "remediation_priority": "IMMEDIATE",

        "remediation": [
            "Require trusted provenance for retrieved sources.",
            "Classify retrieved documents as untrusted by default.",
            "Scan for indirect instruction behavior.",
            "Fail closed when provenance or context trust cannot be established.",
            "Minimize sensitive retrieved content exposed to the model.",
        ],

        "retest_criteria": [
            "Poisoned documents are quarantined.",
            "Indirect prompt injection is rejected.",
            "Retrieved target substitution fails.",
            "RAG content cannot directly create persistent state.",
        ],
    },

    {
        "finding_id": "CF-2903",
        "title": "Persistent AI Memory Enables Cross-Session and Cross-Agent Compromise",
        "severity": "CRITICAL",
        "domain": "MEMORY_SECURITY",

        "source_findings": [
            "FIND-2921",
            "FIND-2927",
            "FIND-2928",
            "FIND-2929",
            "FIND-2930",
            "FIND-2931",
            "FIND-2932",
            "FIND-2933",
            "FIND-2934",
        ],

        "affected_assets": [
            "Persistent Memory",
            "Session State",
            "Agent State",
            "Trusted Goal",
            "Trusted Target",
            "Authorization Context",
        ],

        "root_cause":
            "Persistent memory lacks sufficient write authorization, provenance, session binding, agent binding, expiry enforcement, and trust-level isolation.",

        "business_impact":
            "Attacker-controlled state survives the originating interaction and can compromise future sessions, agents, targets, and privileged workflows.",

        "control_failures": [
            "Memory Write Authorization",
            "Memory Provenance",
            "Cross-Session Isolation",
            "Cross-Agent Isolation",
            "Memory Expiry",
            "Memory Trust Classification",
        ],

        "risk_ids": [
            "RISK-2912-02",
        ],

        "owner": "AI Platform Team",

        "remediation_priority": "IMMEDIATE",

        "remediation": [
            "Authorize memory writes outside model-generated state.",
            "Bind memory records to provenance, user, session, agent, trust level, and expiry.",
            "Treat persistent memory as non-authoritative input.",
            "Require validation before memory influences goals, targets, or authorization.",
        ],

        "retest_criteria": [
            "Unauthorized memory writes fail.",
            "Malicious memory cannot cross sessions.",
            "Malicious memory cannot cross agents.",
            "Expired or provenance-invalid memory is rejected.",
            "Memory cannot supply execution authority.",
        ],
    },

    {
        "finding_id": "CF-2904",
        "title": "Agent and Tool Boundaries Permit Privileged Execution Manipulation",
        "severity": "CRITICAL",
        "domain": "AGENT_TOOL_SECURITY",

        "source_findings": [
            "FIND-2937",
            "FIND-2938",
            "FIND-2939",
            "FIND-2940",
            "FIND-2945",
            "FIND-2946",
        ],

        "affected_assets": [
            "Agent Planner",
            "Privileged Tool",
            "Tool Parameters",
            "Restricted Business Data",
        ],

        "root_cause":
            "Agent-generated plans are not sufficiently constrained by trusted goal binding, tool allowlisting, target binding, parameter validation, or resource-level authorization.",

        "business_impact":
            "Compromised model state can reach destructive enterprise capabilities and create direct business impact.",

        "control_failures": [
            "Agent Goal Binding",
            "Tool Allowlisting",
            "Trusted Target Binding",
            "Strict Parameter Validation",
            "Resource-Level Authorization",
        ],

        "risk_ids": [
            "RISK-2912-03",
            "RISK-2912-04",
        ],

        "owner": "Agent Security Team",

        "remediation_priority": "IMMEDIATE",

        "remediation": [
            "Bind agents to approved goals.",
            "Allow only tools explicitly authorized for the task.",
            "Bind tool targets outside model control.",
            "Validate parameters against signed or trusted task context.",
            "Require resource-level authorization at execution time.",
        ],

        "retest_criteria": [
            "Agent cannot change read task into delete task.",
            "Unauthorized privileged tools are unavailable.",
            "Target substitution fails.",
            "Unsafe parameters are rejected.",
            "Restricted business data cannot be modified without independent authorization.",
        ],
    },

    {
        "finding_id": "CF-2905",
        "title": "Authorization Enforcement Fails Closed Inconsistently",
        "severity": "CRITICAL",
        "domain": "AUTHORIZATION",

        "source_findings": [
            "FIND-2906",
            "FIND-2923",
            "FIND-2932",
            "FIND-2941",
            "FIND-2943",
        ],

        "affected_assets": [
            "Authorization Service",
            "Authorization Decision",
            "Privileged Tool",
            "Restricted Business Data",
        ],

        "root_cause":
            "Authorization claims can originate from model-controlled state and explicit authorization denial does not reliably terminate the execution path.",

        "business_impact":
            "Privileged actions may execute without valid independent approval or even after explicit denial.",

        "control_failures": [
            "Independent Authorization",
            "Fail-Closed Enforcement",
            "External Approval Verification",
            "Authorization-to-Execution Binding",
        ],

        "risk_ids": [
            "RISK-2912-05",
            "RISK-2912-03",
        ],

        "owner": "Identity Security",

        "remediation_priority": "IMMEDIATE",

        "remediation": [
            "Require authorization from an independent policy decision point.",
            "Never accept model-generated approval as authority.",
            "Terminate execution immediately after denial.",
            "Bind authorization decisions to tool, target, parameters, identity, and time.",
        ],

        "retest_criteria": [
            "Model-generated approval is rejected.",
            "User-supplied approval is rejected.",
            "Authorization denial blocks downstream execution.",
            "Authorization cannot be reused for another tool or target.",
        ],
    },

    {
        "finding_id": "CF-2906",
        "title": "Task Credentials Are Not Sufficiently Scoped to Authorized Operations",
        "severity": "HIGH",
        "domain": "CREDENTIAL_SECURITY",

        "source_findings": [
            "FIND-2944",
        ],

        "affected_assets": [
            "Credential Broker",
            "Task Credential",
            "Privileged Tool",
        ],

        "root_cause":
            "Credentials are not tightly bound to approved tool, target, task, scope, and lifetime.",

        "business_impact":
            "Valid credentials can be reused to amplify unauthorized privileged operations.",

        "control_failures": [
            "Least Privilege",
            "Task-Bound Credentials",
            "Short-Lived Credentials",
            "Credential-to-Tool Binding",
        ],

        "risk_ids": [
            "RISK-2912-06",
        ],

        "owner": "Platform Identity Team",

        "remediation_priority": "HIGH",

        "remediation": [
            "Issue short-lived credentials per approved task.",
            "Bind credentials to tool, target, scope, and transaction.",
            "Prevent credential reuse across privileged operations.",
        ],

        "retest_criteria": [
            "read_record credentials cannot invoke delete_record.",
            "Expired task credentials fail.",
            "Credentials cannot be reused against a different target.",
        ],
    },

    {
        "finding_id": "CF-2907",
        "title": "Sensitive Model-Visible Data Can Be Exposed or Aggregated",
        "severity": "CRITICAL",
        "domain": "DATA_PROTECTION",

        "source_findings": [
            "FIND-2910",
            "FIND-2911",
            "FIND-2913",
            "FIND-2914",
            "FIND-2916",
        ],

        "affected_assets": [
            "Retrieved Context",
            "Persistent Memory",
            "Authorization Metadata",
            "Restricted Business Data",
        ],

        "root_cause":
            "Sensitive information is exposed to model context without sufficient authorization, isolation, minimization, or independent output DLP enforcement.",

        "business_impact":
            "Restricted and sensitive enterprise information can be disclosed or aggregated beyond intended need-to-know scope.",

        "control_failures": [
            "RAG Data Minimization",
            "Memory Access Isolation",
            "Authorization Metadata Protection",
            "Restricted Data DLP",
            "Output DLP",
        ],

        "risk_ids": [
            "RISK-2912-01",
            "RISK-2912-08",
        ],

        "owner": "Data Security",

        "remediation_priority": "IMMEDIATE",

        "remediation": [
            "Minimize sensitive information before model context.",
            "Enforce source-level authorization before retrieval.",
            "Isolate memory per identity/session.",
            "Protect authorization metadata.",
            "Apply independent output DLP and classification-aware filtering.",
        ],

        "retest_criteria": [
            "Restricted records cannot be disclosed.",
            "Cross-user memory disclosure fails.",
            "Authorization metadata is protected.",
            "Sensitive multi-source aggregation is blocked.",
        ],
    },

    {
        "finding_id": "CF-2908",
        "title": "AI Detection Engineering Misses Early Attack Stages",
        "severity": "HIGH",
        "domain": "DETECTION_ENGINEERING",

        "source_findings": [],

        "affected_assets": [
            "Security Telemetry",
            "Detection Engine",
            "Incident Response",
        ],

        "root_cause":
            "Security telemetry exists, but detection rules do not adequately correlate prompt, retrieval, memory, cross-session, agent, and model-authority anomalies.",

        "business_impact":
            "Attackers can progress through multiple AI-specific stages before defensive action begins.",

        "control_failures": [
            "Prompt Detection",
            "RAG Correlation",
            "Memory Persistence Detection",
            "Cross-Session Detection",
            "Agent Goal Anomaly Detection",
            "Authority Spoofing Detection",
        ],

        "risk_ids": [
            "RISK-2912-07",
        ],

        "owner": "AI SOC",

        "remediation_priority": "HIGH",

        "remediation": [
            "Correlate prompt injection with later RAG and memory events.",
            "Alert on unauthorized persistent memory writes.",
            "Detect cross-session and cross-agent malicious-state activation.",
            "Detect trusted-goal or target changes.",
            "Alert on model-generated authority and authorization anomalies.",
        ],

        "retest_criteria": [
            "Prompt/RAG attack chain generates an early alert.",
            "Unauthorized memory write generates a high-severity alert.",
            "Cross-session malicious memory activation is detected.",
            "Detection occurs before privileged execution.",
        ],
    },
]


# =============================================================================
# ROOT CAUSE THEMES
# =============================================================================

ROOT_CAUSE_THEMES = [
    {
        "theme_id": "ROOT-2901",
        "theme": "Trust Boundary Failure",
        "findings": [
            "CF-2901",
            "CF-2902",
            "CF-2903",
        ],
    },
    {
        "theme_id": "ROOT-2902",
        "theme": "Model-Controlled State Reaches Privilege",
        "findings": [
            "CF-2904",
            "CF-2905",
            "CF-2906",
        ],
    },
    {
        "theme_id": "ROOT-2903",
        "theme": "Insufficient Sensitive-Data Isolation",
        "findings": [
            "CF-2907",
        ],
    },
    {
        "theme_id": "ROOT-2904",
        "theme": "Detection Lag Across AI-Specific Attack Stages",
        "findings": [
            "CF-2908",
        ],
    },
]


# =============================================================================
# HELPERS
# =============================================================================

def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def hash_data(value):
    return hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def header(title):
    print("\n" + "=" * 102)
    print(f"        {title}")
    print("=" * 102)


# =============================================================================
# MAIN
# =============================================================================

def main():

    print(
        "\n=== Day 29 Lab 13: Consolidated Findings Register "
        "& Root-Cause Analysis ==="
    )

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    # ---------------------------------------------------------------------
    # FINDINGS REGISTER
    # ---------------------------------------------------------------------

    header("CONSOLIDATED ENTERPRISE SECURITY FINDINGS")

    for finding in FINDINGS:

        print(
            f"{finding['finding_id']} | "
            f"{finding['severity']} | "
            f"{finding['domain']} | "
            f"{finding['title']}"
        )

        print(
            "  Source Findings: "
            + (
                ", ".join(
                    finding[
                        "source_findings"
                    ]
                )
                if finding[
                    "source_findings"
                ]
                else "Detection-derived"
            )
        )

        print(
            f"  Owner: "
            f"{finding['owner']}"
        )

        print(
            f"  Remediation Priority: "
            f"{finding['remediation_priority']}"
        )

        print(
            f"  Root Cause: "
            f"{finding['root_cause']}"
        )

        print(
            f"  Business Impact: "
            f"{finding['business_impact']}"
        )

    # ---------------------------------------------------------------------
    # SEVERITY
    # ---------------------------------------------------------------------

    severity_distribution = Counter(
        finding["severity"]
        for finding in FINDINGS
    )

    header("CONSOLIDATED FINDING SEVERITY")

    for severity in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]:

        print(
            f"{severity}: "
            f"{severity_distribution.get(severity, 0)}"
        )

    # ---------------------------------------------------------------------
    # SOURCE FINDING COVERAGE
    # ---------------------------------------------------------------------

    all_source_findings = sorted({
        source_id
        for finding in FINDINGS
        for source_id
        in finding["source_findings"]
    })

    header("TECHNICAL FINDING CONSOLIDATION")

    print(
        f"Material Consolidated Findings: "
        f"{len(FINDINGS)}"
    )

    print(
        f"Technical Findings Consolidated: "
        f"{len(all_source_findings)}"
    )

    consolidation_ratio = (
        len(all_source_findings)
        / len(FINDINGS)
        if FINDINGS
        else 0
    )

    print(
        f"Average Technical Findings per "
        f"Material Finding: "
        f"{consolidation_ratio:.2f}"
    )

    # ---------------------------------------------------------------------
    # ROOT CAUSE THEMES
    # ---------------------------------------------------------------------

    header("ROOT-CAUSE THEMES")

    for theme in ROOT_CAUSE_THEMES:

        print(
            f"{theme['theme_id']} | "
            f"{theme['theme']}"
        )

        print(
            "  Findings: "
            + ", ".join(
                theme["findings"]
            )
        )

    # ---------------------------------------------------------------------
    # REMEDIATION OWNERSHIP
    # ---------------------------------------------------------------------

    owner_distribution = Counter(
        finding["owner"]
        for finding in FINDINGS
    )

    header("REMEDIATION OWNERSHIP")

    for owner, count in sorted(
        owner_distribution.items()
    ):

        print(
            f"{owner}: "
            f"{count} finding(s)"
        )

    # ---------------------------------------------------------------------
    # CONTROL GAP REGISTER
    # ---------------------------------------------------------------------

    control_gap_frequency = Counter(
        control
        for finding in FINDINGS
        for control
        in finding["control_failures"]
    )

    header("CONTROL GAP FREQUENCY")

    for control, count in (
        control_gap_frequency
        .most_common()
    ):

        print(
            f"{control}: "
            f"{count} finding(s)"
        )

    # ---------------------------------------------------------------------
    # RISK COVERAGE
    # ---------------------------------------------------------------------

    risk_ids = sorted({
        risk_id
        for finding in FINDINGS
        for risk_id
        in finding["risk_ids"]
    })

    header("RISK REGISTER COVERAGE")

    print(
        f"Risk Scenarios Referenced: "
        f"{len(risk_ids)}"
    )

    for risk_id in risk_ids:

        mapped_findings = [
            finding["finding_id"]
            for finding in FINDINGS
            if risk_id
            in finding["risk_ids"]
        ]

        print(
            f"{risk_id} -> "
            + ", ".join(
                mapped_findings
            )
        )

    # ---------------------------------------------------------------------
    # RETEST REGISTER
    # ---------------------------------------------------------------------

    retest_requirements = []

    for finding in FINDINGS:

        for index, criterion in enumerate(
            finding["retest_criteria"],
            start=1,
        ):

            retest_requirements.append({
                "retest_id":
                    f"RETEST-{finding['finding_id']}-{index:02d}",

                "finding_id":
                    finding["finding_id"],

                "severity":
                    finding["severity"],

                "criterion":
                    criterion,

                "status":
                    "PENDING",
            })

    header("ADVERSARIAL RETEST REQUIREMENTS")

    for retest in retest_requirements:

        print(
            f"{retest['retest_id']} | "
            f"{retest['severity']} | "
            f"{retest['finding_id']} | "
            f"{retest['status']}"
        )

        print(
            f"  {retest['criterion']}"
        )

    # ---------------------------------------------------------------------
    # REMEDIATION PRIORITY
    # ---------------------------------------------------------------------

    immediate_findings = [
        finding
        for finding in FINDINGS
        if finding[
            "remediation_priority"
        ]
        == "IMMEDIATE"
    ]

    high_findings = [
        finding
        for finding in FINDINGS
        if finding[
            "remediation_priority"
        ]
        == "HIGH"
    ]

    header("REMEDIATION PRIORITY SUMMARY")

    print(
        f"Immediate Remediation Findings: "
        f"{len(immediate_findings)}"
    )

    print(
        f"High Priority Remediation Findings: "
        f"{len(high_findings)}"
    )

    for finding in immediate_findings:

        print(
            f"- {finding['finding_id']} | "
            f"{finding['title']}"
        )

    # ---------------------------------------------------------------------
    # VALIDATION
    # ---------------------------------------------------------------------

    finding_ids = [
        finding["finding_id"]
        for finding in FINDINGS
    ]

    theme_ids = [
        theme["theme_id"]
        for theme in ROOT_CAUSE_THEMES
    ]

    finding_id_set = set(
        finding_ids
    )

    checks = {
        "Unique Consolidated Finding IDs":
            len(finding_ids)
            == len(set(finding_ids)),

        "Unique Root Cause Theme IDs":
            len(theme_ids)
            == len(set(theme_ids)),

        "All Root Cause Theme Findings Valid":
            all(
                finding_id
                in finding_id_set
                for theme
                in ROOT_CAUSE_THEMES
                for finding_id
                in theme["findings"]
            ),

        "Critical Findings Present":
            severity_distribution.get(
                "CRITICAL",
                0
            ) > 0,

        "Instruction Trust Finding Present":
            any(
                finding["domain"]
                == "INSTRUCTION_TRUST"
                for finding in FINDINGS
            ),

        "RAG Finding Present":
            any(
                finding["domain"]
                == "RAG_SECURITY"
                for finding in FINDINGS
            ),

        "Memory Finding Present":
            any(
                finding["domain"]
                == "MEMORY_SECURITY"
                for finding in FINDINGS
            ),

        "Agent / Tool Finding Present":
            any(
                finding["domain"]
                == "AGENT_TOOL_SECURITY"
                for finding in FINDINGS
            ),

        "Authorization Finding Present":
            any(
                finding["domain"]
                == "AUTHORIZATION"
                for finding in FINDINGS
            ),

        "Credential Finding Present":
            any(
                finding["domain"]
                == "CREDENTIAL_SECURITY"
                for finding in FINDINGS
            ),

        "Data Protection Finding Present":
            any(
                finding["domain"]
                == "DATA_PROTECTION"
                for finding in FINDINGS
            ),

        "Detection Finding Present":
            any(
                finding["domain"]
                == "DETECTION_ENGINEERING"
                for finding in FINDINGS
            ),

        "All Findings Have Owners":
            all(
                finding["owner"]
                for finding in FINDINGS
            ),

        "All Findings Have Root Causes":
            all(
                finding["root_cause"]
                for finding in FINDINGS
            ),

        "All Findings Have Remediation":
            all(
                len(
                    finding["remediation"]
                ) > 0
                for finding in FINDINGS
            ),

        "All Findings Have Retest Criteria":
            all(
                len(
                    finding["retest_criteria"]
                ) > 0
                for finding in FINDINGS
            ),

        "Risk Register Coverage Present":
            len(risk_ids) > 0,

        "Retest Register Generated":
            len(
                retest_requirements
            ) > 0,
    }

    checks[
        "Consolidated Findings Assessment Valid"
    ] = all(
        checks.values()
    )

    header("CONSOLIDATED FINDINGS SECURITY CHECKS")

    for check, result in checks.items():

        print(
            f"{check}: {result}"
        )

    # ---------------------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------------------

    header("CONSOLIDATED FINDINGS SUMMARY")

    print(
        f"Material Findings: "
        f"{len(FINDINGS)}"
    )

    print(
        f"Critical Findings: "
        f"{severity_distribution.get('CRITICAL', 0)}"
    )

    print(
        f"High Findings: "
        f"{severity_distribution.get('HIGH', 0)}"
    )

    print(
        f"Technical Findings Consolidated: "
        f"{len(all_source_findings)}"
    )

    print(
        f"Root-Cause Themes: "
        f"{len(ROOT_CAUSE_THEMES)}"
    )

    print(
        f"Remediation Owners: "
        f"{len(owner_distribution)}"
    )

    print(
        f"Risk Scenarios Covered: "
        f"{len(risk_ids)}"
    )

    print(
        f"Adversarial Retest Requirements: "
        f"{len(retest_requirements)}"
    )

    print(
        f"Immediate Remediation Findings: "
        f"{len(immediate_findings)}"
    )

    # ---------------------------------------------------------------------
    # EXPORT
    # ---------------------------------------------------------------------

    evidence = {
        "engagement_id":
            ENGAGEMENT_ID,

        "system_id":
            SYSTEM_ID,

        "trace_id":
            TRACE_ID,

        "timestamp_utc":
            timestamp,

        "consolidated_findings":
            FINDINGS,

        "root_cause_themes":
            ROOT_CAUSE_THEMES,

        "owner_distribution":
            dict(
                owner_distribution
            ),

        "control_gap_frequency":
            dict(
                control_gap_frequency
            ),

        "risk_ids":
            risk_ids,

        "retest_requirements":
            retest_requirements,

        "metrics": {
            "material_findings":
                len(FINDINGS),

            "critical_findings":
                severity_distribution.get(
                    "CRITICAL",
                    0
                ),

            "high_findings":
                severity_distribution.get(
                    "HIGH",
                    0
                ),

            "technical_findings_consolidated":
                len(
                    all_source_findings
                ),

            "root_cause_themes":
                len(
                    ROOT_CAUSE_THEMES
                ),

            "remediation_owners":
                len(
                    owner_distribution
                ),

            "risk_scenarios_covered":
                len(risk_ids),

            "retest_requirements":
                len(
                    retest_requirements
                ),

            "immediate_remediation_findings":
                len(
                    immediate_findings
                ),
        },

        "security_checks":
            checks,
    }

    evidence["evidence_hash"] = hash_data(
        evidence
    )

    output = Path(
        "day29-consolidated-findings-root-cause-evidence.json"
    )

    output.write_text(
        json.dumps(
            evidence,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print("\nEvidence written to:")
    print(output)

    print("\nSecurity Interpretation:")

    print(
        "The consolidated findings register transforms individual "
        "red-team test failures into material security findings that "
        "represent systemic control weaknesses."
    )

    print(
        "This prevents remediation from becoming a collection of "
        "prompt-specific patches and instead directs engineering teams "
        "toward instruction trust, retrieval, memory, agent execution, "
        "authorization, credential, data-protection and detection controls."
    )

    print(
        "Each material finding now has business impact, ownership, "
        "corrective actions and explicit adversarial retest criteria."
    )

    print("\nCore Principle:")

    print(
        "A professional assessment should consolidate symptoms into "
        "root-cause findings so remediation addresses the security "
        "architecture rather than patching individual prompts or "
        "test cases."
    )


if __name__ == "__main__":
    main()