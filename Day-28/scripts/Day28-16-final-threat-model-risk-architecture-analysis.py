"""
Day 28 Lab 16
Final Threat Model, Risk & Architecture Comparative Analysis

Purpose:
Synthesize the complete Day 28 threat-modeling program into one
comparative analysis covering assets, trust boundaries, attack surfaces,
STRIDE threats, prompt/RAG/memory/agent threats, attack trees,
framework mapping, risk prioritization, control value, residual risk,
and hardened security architecture.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json


print(
    "\n=== Day 28 Lab 16: "
    "Final Threat Model, Risk & Architecture Comparative Analysis ===\n"
)


# ============================================================
# DAY 28 RESEARCH QUESTION
# ============================================================

RESEARCH_QUESTION = (
    "Can we systematically identify LLM assets, trust boundaries, "
    "attack surfaces, threats, abuse paths and business impacts before "
    "deployment, then translate those risks into security architecture "
    "and prioritized controls?"
)


# ============================================================
# LAB SUMMARY DATA
# ============================================================

LABS = [
    {
        "lab": "Lab 1",
        "name": "AI System & Security Asset Inventory",
        "primary_metric": "14 assets",
        "valid": True,
    },

    {
        "lab": "Lab 2",
        "name": "Data Flow & Trust Boundary Mapping",
        "primary_metric": "Trust boundaries mapped",
        "valid": True,
    },

    {
        "lab": "Lab 3",
        "name": "AI Attack Surface Mapping",
        "primary_metric": "17 attack surfaces",
        "valid": True,
    },

    {
        "lab": "Lab 4",
        "name": "STRIDE-Style LLM Threat Modeling",
        "primary_metric": "32 threat scenarios",
        "valid": True,
    },

    {
        "lab": "Lab 5",
        "name": "Prompt & Instruction Threat Modeling",
        "primary_metric": "20 prompt threats",
        "valid": True,
    },

    {
        "lab": "Lab 6",
        "name": "RAG & Knowledge-System Threat Modeling",
        "primary_metric": "23 RAG threats",
        "valid": True,
    },

    {
        "lab": "Lab 7",
        "name": "Memory & Persistent-State Threat Modeling",
        "primary_metric": "26 memory threats",
        "valid": True,
    },

    {
        "lab": "Lab 8",
        "name": "Agent & Tool-Execution Threat Modeling",
        "primary_metric": "32 agent/tool threats",
        "valid": True,
    },

    {
        "lab": "Lab 9",
        "name": "Attack Trees & Multi-Stage Abuse Paths",
        "primary_metric": "8 attack paths",
        "valid": True,
    },

    {
        "lab": "Lab 10",
        "name": "OWASP-Aligned AI Risk Mapping",
        "primary_metric": "14 risk areas",
        "valid": True,
    },

    {
        "lab": "Lab 11",
        "name": "MITRE ATLAS-Aligned Adversary Mapping",
        "primary_metric": "22 techniques",
        "valid": True,
    },

    {
        "lab": "Lab 12",
        "name": "Likelihood x Impact Risk Prioritization",
        "primary_metric": "21 prioritized risks",
        "valid": True,
    },

    {
        "lab": "Lab 13",
        "name": "Formal AI Security Risk Register",
        "primary_metric": "21 risk records",
        "valid": True,
    },

    {
        "lab": "Lab 14",
        "name": "Security Control & Residual Risk Analysis",
        "primary_metric": "83.31% overall risk reduction",
        "valid": True,
    },

    {
        "lab": "Lab 15",
        "name": "Hardened Reference AI Security Architecture",
        "primary_metric": "11 zones / 10 trust boundaries",
        "valid": True,
    },
]


# ============================================================
# ASSET / SURFACE SUMMARY
# ============================================================

ASSET_SUMMARY = {
    "total_assets": 14,
    "critical_assets": 8,
    "trust_sensitive_assets": 7,
    "security_objectives": [
        "confidentiality",
        "integrity",
        "availability",
    ],
}


ATTACK_SURFACE_SUMMARY = {
    "attack_surfaces": 17,
    "entry_points": 2,
    "persistent_surfaces": 5,
    "privileged_surfaces": 6,
    "business_impact_surfaces": 7,
    "high_critical_surfaces": 6,
}


# ============================================================
# THREAT SUMMARY
# ============================================================

THREAT_SUMMARY = {
    "stride_threats": 32,
    "prompt_instruction_threats": 20,
    "rag_threats": 23,
    "memory_threats": 26,
    "agent_tool_threats": 32,

    "total_specialized_threat_scenarios":
        20 + 23 + 26 + 32,
}


# ============================================================
# ATTACK TREE SUMMARY
# ============================================================

ATTACK_TREE_SUMMARY = {
    "attack_objectives": 5,
    "attack_nodes": 20,
    "attack_paths": 8,
    "attack_trees": 3,
    "high_critical_paths": 4,
    "attack_domains": 9,
    "multi_path_choke_points": 10,
}


# ============================================================
# FRAMEWORK MAPPING SUMMARY
# ============================================================

FRAMEWORK_SUMMARY = {
    "owasp_aligned_risk_areas": 14,
    "owasp_mapped_threats": 26,
    "owasp_attack_paths": 8,

    "atlas_aligned_tactics": 9,
    "atlas_aligned_techniques": 22,
    "atlas_mapped_threats": 26,
    "atlas_attack_paths": 8,
    "atlas_detection_opportunities": 9,
}


# ============================================================
# RISK SUMMARY
# ============================================================

RISK_SUMMARY = {
    "risk_scenarios": 21,
    "risk_domains": 10,

    "top_residual_risks": [
        {
            "risk_id": "RISK-2805",
            "name": "Persistent Memory Poisoning",
            "residual_score": 36,
        },
        {
            "risk_id": "RISK-2807",
            "name": "Cross-Agent Memory Propagation",
            "residual_score": 32,
        },
        {
            "risk_id": "RISK-2802",
            "name": "Indirect RAG Prompt Injection",
            "residual_score": 31,
        },
        {
            "risk_id": "RISK-2806",
            "name": "Cross-Session Memory Activation",
            "residual_score": 31,
        },
        {
            "risk_id": "RISK-2816",
            "name": "Credential Scope Abuse",
            "residual_score": 31,
        },
    ],

    "high_persistence_risks": 4,
    "high_privilege_risks": 10,
    "wide_blast_radius_risks": 12,
}


# ============================================================
# FORMAL RISK REGISTER SUMMARY
# ============================================================

RISK_REGISTER_SUMMARY = {
    "risk_records": 21,
    "risk_owners": 12,
    "non_acceptable_by_default": 10,
    "target_low_risks": 14,
    "target_medium_risks": 7,
    "target_high_risks": 0,
    "target_critical_risks": 0,
    "target_architecture_deployment_ready": True,
}


# ============================================================
# CONTROL REDUCTION SUMMARY
# ============================================================

CONTROL_SUMMARY = {
    "security_controls": 21,

    "total_inherent_risk": 683,
    "total_target_residual_risk": 114,
    "total_risk_reduction": 569,
    "overall_risk_reduction_percent": 83.31,

    "high_value_controls": 15,
    "architectural_choke_points": 9,

    "highest_value_controls": [
        {
            "control_id": "CTRL-2819",
            "name": "Tamper-Evident AI Security Telemetry",
            "risks_addressed": 20,
            "addressable_reduction": 555,
        },
        {
            "control_id": "CTRL-2812",
            "name": "Fail-Closed Independent Authorization",
            "risks_addressed": 7,
            "addressable_reduction": 196,
        },
        {
            "control_id": "CTRL-2811",
            "name": "Trusted Target Binding",
            "risks_addressed": 4,
            "addressable_reduction": 107,
        },
        {
            "control_id": "CTRL-2805",
            "name": "Authorized Memory Writes",
            "risks_addressed": 3,
            "addressable_reduction": 102,
        },
        {
            "control_id": "CTRL-2806",
            "name": "Memory Provenance & Integrity",
            "risks_addressed": 3,
            "addressable_reduction": 102,
        },
    ],
}


# ============================================================
# HARDENED ARCHITECTURE SUMMARY
# ============================================================

ARCHITECTURE_SUMMARY = {
    "security_zones": 11,
    "trust_boundaries": 10,
    "architectural_controls": 18,
    "security_data_flows": 12,
    "deployment_gates": 9,
    "preventive_controls": 16,
    "detective_controls": 1,
    "corrective_controls": 1,
    "required_gates_passed": 9,
    "required_gates_total": 9,
    "deployment_approved": True,
}


# ============================================================
# BEFORE / AFTER SECURITY COMPARISON
# ============================================================

BEFORE_AFTER = [
    {
        "area": "Prompt / Instruction Trust",
        "before":
            "Untrusted natural-language content may influence trusted instructions.",
        "after":
            "Instruction trust is explicitly separated and mediated.",
    },

    {
        "area": "RAG Security",
        "before":
            "Retrieved content may enter runtime without provenance or trust validation.",
        "after":
            "RAG provenance, document authorization and fail-closed context admission are enforced.",
    },

    {
        "area": "Persistent Memory",
        "before":
            "Untrusted model or retrieved state may persist across sessions and agents.",
        "after":
            "Memory writes require authorization, provenance, isolation, expiry and integrity validation.",
    },

    {
        "area": "Agent Planning",
        "before":
            "Model-generated plans may drift or select privileged capabilities.",
        "after":
            "Agent goals and actions are bound to trusted task state.",
    },

    {
        "area": "Tool Execution",
        "before":
            "Tool choice, target and parameters may be influenced by model-generated state.",
        "after":
            "Tool allowlisting, target binding and strict parameter validation are enforced.",
    },

    {
        "area": "Authorization",
        "before":
            "Model-generated approval or fail-open behavior may enable privileged execution.",
        "after":
            "Authorization is independent, non-model, and fail-closed.",
    },

    {
        "area": "Secrets",
        "before":
            "Credentials may enter model context or be reused beyond intended scope.",
        "after":
            "Secrets are isolated and credentials are short-lived and task-bound.",
    },

    {
        "area": "Business Data",
        "before":
            "Privileged AI actions may reach restricted business resources.",
        "after":
            "Resource-level authorization and destructive-action controls protect business data.",
    },

    {
        "area": "Observability",
        "before":
            "Security activity may be incomplete or difficult to reconstruct.",
        "after":
            "Independent tamper-evident AI security telemetry is required.",
    },
]


# ============================================================
# FINAL FINDINGS
# ============================================================

FINAL_FINDINGS = [
    (
        "The threat model identified the AI system as a collection of "
        "interacting trust domains rather than treating the LLM as the "
        "only security-relevant component."
    ),

    (
        "Prompt injection risk becomes materially more dangerous when "
        "combined with RAG, persistent memory, agents, tools and authorization."
    ),

    (
        "Persistent memory creates unique AI persistence and cross-session "
        "attack paths that require explicit authorization and provenance."
    ),

    (
        "Agentic AI increases risk because model-generated plans can "
        "approach privileged business execution."
    ),

    (
        "Authorization must remain independent from model-generated "
        "language, context, memory and approval claims."
    ),

    (
        "Attack trees revealed repeated architectural choke points, "
        "particularly privileged tool selection, authorization, memory, "
        "target binding and telemetry."
    ),

    (
        "Likelihood x impact scoring alone was insufficient; persistence, "
        "privilege, blast radius and detection difficulty materially "
        "changed AI risk priority."
    ),

    (
        "The formal risk register converted technical threats into "
        "accountable business risk ownership and treatment decisions."
    ),

    (
        "The target control architecture reduced modeled aggregate risk "
        "from 683 to 114, representing an 83.31% reduction."
    ),

    (
        "The hardened architecture uses explicit trust zones, enforcement "
        "points and deployment gates rather than relying on a single LLM guardrail."
    ),

    (
        "All nine required deployment security gates passed in the "
        "synthetic target architecture."
    ),

    (
        "The Day 28 evidence demonstrates that threat modeling can drive "
        "AI security architecture before deployment rather than only "
        "documenting vulnerabilities after implementation."
    ),
]


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 100)
    print(f"                 {title}")
    print("=" * 100)


header("DAY 28 RESEARCH QUESTION")

print(RESEARCH_QUESTION)


header("ASSET & ATTACK-SURFACE BASELINE")

print(
    f"Total Assets: "
    f"{ASSET_SUMMARY['total_assets']}"
)

print(
    f"Critical Assets: "
    f"{ASSET_SUMMARY['critical_assets']}"
)

print(
    f"Attack Surfaces: "
    f"{ATTACK_SURFACE_SUMMARY['attack_surfaces']}"
)

print(
    f"Privileged Surfaces: "
    f"{ATTACK_SURFACE_SUMMARY['privileged_surfaces']}"
)

print(
    f"Business-Impact Surfaces: "
    f"{ATTACK_SURFACE_SUMMARY['business_impact_surfaces']}"
)


header("THREAT ENUMERATION")

print(
    f"STRIDE Threats: "
    f"{THREAT_SUMMARY['stride_threats']}"
)

print(
    f"Prompt / Instruction Threats: "
    f"{THREAT_SUMMARY['prompt_instruction_threats']}"
)

print(
    f"RAG Threats: "
    f"{THREAT_SUMMARY['rag_threats']}"
)

print(
    f"Memory Threats: "
    f"{THREAT_SUMMARY['memory_threats']}"
)

print(
    f"Agent / Tool Threats: "
    f"{THREAT_SUMMARY['agent_tool_threats']}"
)

print(
    f"Specialized Threat Scenarios: "
    f"{THREAT_SUMMARY['total_specialized_threat_scenarios']}"
)


header("ATTACK TREES & ABUSE PATHS")

for key, value in ATTACK_TREE_SUMMARY.items():

    print(
        f"{key}: {value}"
    )


header("FRAMEWORK CORRELATION")

print(
    f"OWASP-Aligned Risk Areas: "
    f"{FRAMEWORK_SUMMARY['owasp_aligned_risk_areas']}"
)

print(
    f"OWASP-Mapped Threats: "
    f"{FRAMEWORK_SUMMARY['owasp_mapped_threats']}"
)

print(
    f"ATLAS-Aligned Tactics: "
    f"{FRAMEWORK_SUMMARY['atlas_aligned_tactics']}"
)

print(
    f"ATLAS-Aligned Techniques: "
    f"{FRAMEWORK_SUMMARY['atlas_aligned_techniques']}"
)

print(
    f"ATLAS Detection Opportunities: "
    f"{FRAMEWORK_SUMMARY['atlas_detection_opportunities']}"
)


header("TOP PRIORITIZED AI RISKS")

for index, risk in enumerate(
    RISK_SUMMARY["top_residual_risks"],
    start=1,
):

    print(
        f"{index}. "
        f"{risk['risk_id']} | "
        f"Residual={risk['residual_score']} | "
        f"{risk['name']}"
    )


header("FORMAL RISK REGISTER")

print(
    f"Risk Records: "
    f"{RISK_REGISTER_SUMMARY['risk_records']}"
)

print(
    f"Risk Owners: "
    f"{RISK_REGISTER_SUMMARY['risk_owners']}"
)

print(
    f"Non-Acceptable-by-Default Risks: "
    f"{RISK_REGISTER_SUMMARY['non_acceptable_by_default']}"
)

print(
    f"Target Low Risks: "
    f"{RISK_REGISTER_SUMMARY['target_low_risks']}"
)

print(
    f"Target Medium Risks: "
    f"{RISK_REGISTER_SUMMARY['target_medium_risks']}"
)

print(
    f"Target High Risks: "
    f"{RISK_REGISTER_SUMMARY['target_high_risks']}"
)

print(
    f"Target Critical Risks: "
    f"{RISK_REGISTER_SUMMARY['target_critical_risks']}"
)


header("RISK REDUCTION")

print(
    f"Total Inherent Risk Score: "
    f"{CONTROL_SUMMARY['total_inherent_risk']}"
)

print(
    f"Total Target Residual Risk Score: "
    f"{CONTROL_SUMMARY['total_target_residual_risk']}"
)

print(
    f"Absolute Risk Reduction: "
    f"{CONTROL_SUMMARY['total_risk_reduction']}"
)

print(
    f"Overall Risk Reduction: "
    f"{CONTROL_SUMMARY['overall_risk_reduction_percent']:.2f}%"
)

print(
    f"High-Value Controls: "
    f"{CONTROL_SUMMARY['high_value_controls']}"
)

print(
    f"Architectural Choke Points: "
    f"{CONTROL_SUMMARY['architectural_choke_points']}"
)


header("HIGHEST-VALUE SECURITY CONTROLS")

for control in CONTROL_SUMMARY[
    "highest_value_controls"
]:

    print(
        f"{control['control_id']} | "
        f"Reduction={control['addressable_reduction']} | "
        f"Risks={control['risks_addressed']} | "
        f"{control['name']}"
    )


header("HARDENED REFERENCE ARCHITECTURE")

print(
    f"Security Zones: "
    f"{ARCHITECTURE_SUMMARY['security_zones']}"
)

print(
    f"Trust Boundaries: "
    f"{ARCHITECTURE_SUMMARY['trust_boundaries']}"
)

print(
    f"Architectural Controls: "
    f"{ARCHITECTURE_SUMMARY['architectural_controls']}"
)

print(
    f"Secure Data Flows: "
    f"{ARCHITECTURE_SUMMARY['security_data_flows']}"
)

print(
    f"Deployment Gates: "
    f"{ARCHITECTURE_SUMMARY['deployment_gates']}"
)

print(
    f"Required Gates Passed: "
    f"{ARCHITECTURE_SUMMARY['required_gates_passed']} / "
    f"{ARCHITECTURE_SUMMARY['required_gates_total']}"
)

print(
    f"Deployment Approved: "
    f"{ARCHITECTURE_SUMMARY['deployment_approved']}"
)


header("BEFORE / AFTER SECURITY ARCHITECTURE")

for comparison in BEFORE_AFTER:

    print(
        f"\nArea: {comparison['area']}"
    )

    print(
        f"Before: {comparison['before']}"
    )

    print(
        f"After:  {comparison['after']}"
    )


header("FINAL FINDINGS")

for index, finding in enumerate(
    FINAL_FINDINGS,
    start=1,
):

    print(
        f"{index}. {finding}"
    )


# ============================================================
# ANSWER THE RESEARCH QUESTION
# ============================================================

header("RESEARCH QUESTION ANSWER")

research_answer = (
    "Yes. Day 28 demonstrates a repeatable method for identifying "
    "AI assets, data flows, trust boundaries, attack surfaces, threats, "
    "multi-stage abuse paths and business impacts before deployment. "
    "Those findings were converted into risk scores, a formal risk register, "
    "prioritized controls, residual-risk targets, architectural trust zones, "
    "enforcement points and deployment security gates."
)

print(research_answer)


# ============================================================
# VALIDATION
# ============================================================

header("DAY 28 FINAL VALIDATION")

all_labs_valid = all(
    lab["valid"]
    for lab in LABS
)


checks = {
    "All Day 28 Labs Valid":
        all_labs_valid,

    "Assets Identified":
        ASSET_SUMMARY[
            "total_assets"
        ] > 0,

    "Attack Surfaces Identified":
        ATTACK_SURFACE_SUMMARY[
            "attack_surfaces"
        ] > 0,

    "Threats Enumerated":
        THREAT_SUMMARY[
            "total_specialized_threat_scenarios"
        ] > 0,

    "Attack Trees Created":
        ATTACK_TREE_SUMMARY[
            "attack_trees"
        ] > 0,

    "Framework Mapping Completed":
        (
            FRAMEWORK_SUMMARY[
                "owasp_mapped_threats"
            ] > 0
            and
            FRAMEWORK_SUMMARY[
                "atlas_mapped_threats"
            ] > 0
        ),

    "Risk Register Created":
        RISK_REGISTER_SUMMARY[
            "risk_records"
        ] > 0,

    "Residual Risk Reduced":
        (
            CONTROL_SUMMARY[
                "total_target_residual_risk"
            ]
            <
            CONTROL_SUMMARY[
                "total_inherent_risk"
            ]
        ),

    "No Target Critical Risks":
        RISK_REGISTER_SUMMARY[
            "target_critical_risks"
        ] == 0,

    "Hardened Architecture Defined":
        ARCHITECTURE_SUMMARY[
            "security_zones"
        ] > 0,

    "Deployment Gates Enforced":
        (
            ARCHITECTURE_SUMMARY[
                "required_gates_passed"
            ]
            ==
            ARCHITECTURE_SUMMARY[
                "required_gates_total"
            ]
        ),

    "Target Architecture Deployment Approved":
        ARCHITECTURE_SUMMARY[
            "deployment_approved"
        ],
}


for check, result in checks.items():

    print(
        f"{check}: {result}"
    )


day28_valid = all(
    checks.values()
)


print(
    f"\nDay 28 Threat Modeling & Security Architecture Assessment Valid: "
    f"{day28_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "day":
        28,

    "title":
        "LLM Threat Modeling, Risk Assessment & Security Architecture",

    "research_question":
        RESEARCH_QUESTION,

    "research_answer":
        research_answer,

    "labs":
        LABS,

    "asset_summary":
        ASSET_SUMMARY,

    "attack_surface_summary":
        ATTACK_SURFACE_SUMMARY,

    "threat_summary":
        THREAT_SUMMARY,

    "attack_tree_summary":
        ATTACK_TREE_SUMMARY,

    "framework_summary":
        FRAMEWORK_SUMMARY,

    "risk_summary":
        RISK_SUMMARY,

    "risk_register_summary":
        RISK_REGISTER_SUMMARY,

    "control_summary":
        CONTROL_SUMMARY,

    "architecture_summary":
        ARCHITECTURE_SUMMARY,

    "before_after":
        BEFORE_AFTER,

    "final_findings":
        FINAL_FINDINGS,

    "security_checks":
        checks,

    "assessment_valid":
        day28_valid,
}


JSON_OUTPUT = (
    "day28-final-threat-model-risk-architecture-analysis.json"
)

TXT_OUTPUT = (
    "day28-final-threat-model-risk-architecture-analysis.txt"
)


with open(
    JSON_OUTPUT,
    "w",
    encoding="utf-8",
) as file:

    json.dump(
        REPORT,
        file,
        indent=2,
    )


with open(
    TXT_OUTPUT,
    "w",
    encoding="utf-8",
) as file:

    file.write(
        "DAY 28 FINAL THREAT MODEL, RISK & ARCHITECTURE ANALYSIS\n"
    )

    file.write(
        "=" * 70
        + "\n\n"
    )

    file.write(
        f"Research Question:\n"
        f"{RESEARCH_QUESTION}\n\n"
    )

    file.write(
        f"Research Answer:\n"
        f"{research_answer}\n\n"
    )

    file.write(
        "Key Findings:\n"
    )

    for index, finding in enumerate(
        FINAL_FINDINGS,
        start=1,
    ):

        file.write(
            f"{index}. {finding}\n"
        )

    file.write(
        "\nCore Principle:\n"
    )

    file.write(
        "AI security should be designed from identified threats and "
        "trust boundaries, not added only after vulnerabilities are discovered.\n"
    )


print("\nEvidence files written to:")
print(JSON_OUTPUT)
print(TXT_OUTPUT)


# ============================================================
# CONCLUSION
# ============================================================

header("CONCLUSION")

print(
    "Day 28 demonstrates that effective AI security architecture can "
    "be derived systematically from threat modeling."
)

print(
    "The process began with assets, data flows and trust boundaries, "
    "then expanded into attack surfaces, STRIDE threats, prompt, RAG, "
    "memory and agent-specific abuse scenarios, attack trees, OWASP-aligned "
    "risk mapping and ATLAS-aligned adversary behavior."
)

print(
    "The resulting threats were prioritized using business risk, persistence, "
    "privilege, blast radius and detectability, then converted into a formal "
    "risk register with ownership and treatment requirements."
)

print(
    "The hardened target architecture reduced aggregate modeled risk from "
    "683 to 114, an 83.31% reduction, while defining explicit security zones, "
    "trust boundaries, controls, secure data flows and deployment gates."
)

print(
    "This establishes the professional security-engineering lesson that "
    "AI security should be intentionally designed from identified threats "
    "before deployment rather than added reactively after incidents occur."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)