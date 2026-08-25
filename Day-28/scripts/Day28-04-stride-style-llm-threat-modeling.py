"""
Day 28 Lab 4
STRIDE-Style LLM Threat Modeling

Purpose:
Apply a STRIDE-inspired threat-modeling method to LLM, RAG,
memory, agent, tool, authorization, secret, downstream, and
observability attack surfaces.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter, defaultdict


print(
    "\n=== Day 28 Lab 4: "
    "STRIDE-Style LLM Threat Modeling ===\n"
)


# ============================================================
# STRIDE DEFINITIONS ADAPTED TO AI
# ============================================================

STRIDE = {
    "S": {
        "name": "Spoofing",
        "description":
            "Impersonation of a user, authority, source, tool, "
            "document, model identity, or trusted execution context."
    },

    "T": {
        "name": "Tampering",
        "description":
            "Unauthorized modification of prompts, retrieved context, "
            "memory, policies, parameters, authorization decisions, "
            "telemetry, or business data."
    },

    "R": {
        "name": "Repudiation",
        "description":
            "Inability to reliably attribute, prove, or reconstruct "
            "AI actions, model-generated decisions, tool calls, or "
            "security-impacting events."
    },

    "I": {
        "name": "Information Disclosure",
        "description":
            "Exposure of system prompts, retrieved sensitive data, "
            "persistent memory, credentials, business records, "
            "or security telemetry."
    },

    "D": {
        "name": "Denial of Service",
        "description":
            "Degradation or exhaustion of model, retrieval, memory, "
            "agent, tool, authorization, or downstream resources."
    },

    "E": {
        "name": "Elevation of Privilege",
        "description":
            "Obtaining execution authority, tool capability, identity "
            "privilege, or access beyond the trusted task boundary."
    },
}


# ============================================================
# THREAT SURFACES
# ============================================================

SURFACES = [
    {
        "surface_id": "AS-2801",
        "name": "User Prompt Entry",
        "category": "INPUT",
        "criticality": "high",
    },
    {
        "surface_id": "AS-2802",
        "name": "System Prompt / Instruction Hierarchy",
        "category": "INSTRUCTION",
        "criticality": "critical",
    },
    {
        "surface_id": "AS-2804",
        "name": "RAG Knowledge Store",
        "category": "RAG",
        "criticality": "high",
    },
    {
        "surface_id": "AS-2805",
        "name": "Retrieved Context Admission",
        "category": "RAG",
        "criticality": "high",
    },
    {
        "surface_id": "AS-2806",
        "name": "Persistent Memory Write",
        "category": "MEMORY",
        "criticality": "critical",
    },
    {
        "surface_id": "AS-2807",
        "name": "Persistent Memory Read",
        "category": "MEMORY",
        "criticality": "critical",
    },
    {
        "surface_id": "AS-2808",
        "name": "LLM Runtime",
        "category": "MODEL",
        "criticality": "critical",
    },
    {
        "surface_id": "AS-2809",
        "name": "Agent Planning",
        "category": "AGENT",
        "criticality": "critical",
    },
    {
        "surface_id": "AS-2810",
        "name": "Tool Router",
        "category": "TOOL",
        "criticality": "critical",
    },
    {
        "surface_id": "AS-2811",
        "name": "Authorization Request",
        "category": "AUTHORIZATION",
        "criticality": "critical",
    },
    {
        "surface_id": "AS-2812",
        "name": "Authorization Decision",
        "category": "AUTHORIZATION",
        "criticality": "critical",
    },
    {
        "surface_id": "AS-2813",
        "name": "Secret Retrieval",
        "category": "SECRET",
        "criticality": "critical",
    },
    {
        "surface_id": "AS-2815",
        "name": "Delete Record Tool",
        "category": "TOOL",
        "criticality": "critical",
    },
    {
        "surface_id": "AS-2816",
        "name": "Restricted Record",
        "category": "DOWNSTREAM",
        "criticality": "critical",
    },
    {
        "surface_id": "AS-2817",
        "name": "Security Telemetry",
        "category": "OBSERVABILITY",
        "criticality": "high",
    },
]


# ============================================================
# THREAT LIBRARY
# ============================================================

THREATS = [
    {
        "threat_id": "THR-2801",
        "stride": "S",
        "surface_id": "AS-2801",
        "name": "User Identity / Authority Spoofing",
        "scenario":
            "An attacker submits instructions while claiming to act "
            "for a trusted user, administrator, or security authority.",
        "impact":
            "Untrusted instructions may be treated as authorized."
    },

    {
        "threat_id": "THR-2802",
        "stride": "T",
        "surface_id": "AS-2801",
        "name": "Prompt Instruction Tampering",
        "scenario":
            "User-controlled instructions attempt to modify or override "
            "the intended system task.",
        "impact":
            "Trusted instruction hierarchy may be subverted."
    },

    {
        "threat_id": "THR-2803",
        "stride": "I",
        "surface_id": "AS-2802",
        "name": "System Prompt Disclosure",
        "scenario":
            "An attacker attempts to extract confidential system "
            "instructions or hidden policy context.",
        "impact":
            "Security policy and implementation details may be exposed."
    },

    {
        "threat_id": "THR-2804",
        "stride": "T",
        "surface_id": "AS-2802",
        "name": "Instruction Hierarchy Manipulation",
        "scenario":
            "Untrusted content is interpreted as higher-priority "
            "instruction authority.",
        "impact":
            "Model behavior may deviate from intended policy."
    },

    {
        "threat_id": "THR-2805",
        "stride": "S",
        "surface_id": "AS-2804",
        "name": "RAG Source Impersonation",
        "scenario":
            "A malicious document falsely claims to originate from "
            "a trusted source.",
        "impact":
            "Poisoned retrieval data may inherit false trust."
    },

    {
        "threat_id": "THR-2806",
        "stride": "T",
        "surface_id": "AS-2804",
        "name": "RAG Document Poisoning",
        "scenario":
            "Knowledge-store content is modified or replaced with "
            "malicious instructions or false business information.",
        "impact":
            "Retrieved context may manipulate model behavior."
    },

    {
        "threat_id": "THR-2807",
        "stride": "I",
        "surface_id": "AS-2804",
        "name": "Sensitive Retrieval Disclosure",
        "scenario":
            "Retrieval queries return documents outside the authorized "
            "information scope.",
        "impact":
            "Sensitive knowledge may be exposed."
    },

    {
        "threat_id": "THR-2808",
        "stride": "T",
        "surface_id": "AS-2805",
        "name": "Retrieved Context Manipulation",
        "scenario":
            "Retrieved content injects instructions, false authority, "
            "or target substitutions into runtime context.",
        "impact":
            "Untrusted context can influence model decisions."
    },

    {
        "threat_id": "THR-2809",
        "stride": "E",
        "surface_id": "AS-2805",
        "name": "Context-to-Authority Escalation",
        "scenario":
            "Retrieved text claims approval, identity, or authorization "
            "and the system treats the claim as execution authority.",
        "impact":
            "Untrusted text may acquire privilege."
    },

    {
        "threat_id": "THR-2810",
        "stride": "T",
        "surface_id": "AS-2806",
        "name": "Persistent Memory Poisoning",
        "scenario":
            "Malicious or manipulated state is written into long-lived "
            "AI memory.",
        "impact":
            "Compromise may persist beyond the original session."
    },

    {
        "threat_id": "THR-2811",
        "stride": "E",
        "surface_id": "AS-2806",
        "name": "Unauthorized Memory Persistence",
        "scenario":
            "The model writes persistent state without independent "
            "authorization.",
        "impact":
            "Untrusted model output gains durable influence."
    },

    {
        "threat_id": "THR-2812",
        "stride": "I",
        "surface_id": "AS-2807",
        "name": "Cross-Session Memory Disclosure",
        "scenario":
            "A later session retrieves sensitive memory belonging to "
            "another user, task, or trust context.",
        "impact":
            "Confidential cross-session information may be exposed."
    },

    {
        "threat_id": "THR-2813",
        "stride": "T",
        "surface_id": "AS-2807",
        "name": "Cross-Session Poison Activation",
        "scenario":
            "Malicious stored instructions are retrieved during a "
            "future session.",
        "impact":
            "Persistent compromise may propagate across sessions."
    },

    {
        "threat_id": "THR-2814",
        "stride": "I",
        "surface_id": "AS-2808",
        "name": "Sensitive Context Exposure",
        "scenario":
            "The LLM reveals protected prompt, retrieved context, "
            "memory, or secret-bearing information.",
        "impact":
            "Confidential information may leave trusted boundaries."
    },

    {
        "threat_id": "THR-2815",
        "stride": "D",
        "surface_id": "AS-2808",
        "name": "Model Resource Exhaustion",
        "scenario":
            "Adversarial requests consume excessive model context, "
            "tokens, compute, or concurrency.",
        "impact":
            "Availability and cost controls may be affected."
    },

    {
        "threat_id": "THR-2816",
        "stride": "T",
        "surface_id": "AS-2809",
        "name": "Agent Goal Hijacking",
        "scenario":
            "Untrusted input modifies the agent's intended objective "
            "or planning state.",
        "impact":
            "Agent actions may diverge from the authorized task."
    },

    {
        "threat_id": "THR-2817",
        "stride": "E",
        "surface_id": "AS-2809",
        "name": "Privileged Action Proposal",
        "scenario":
            "The agent proposes a higher-privilege tool or target than "
            "the trusted task requires.",
        "impact":
            "Model planning can approach privileged execution."
    },

    {
        "threat_id": "THR-2818",
        "stride": "T",
        "surface_id": "AS-2810",
        "name": "Tool Parameter Manipulation",
        "scenario":
            "Tool names, targets, or parameters are altered before "
            "execution.",
        "impact":
            "A safe task may become unsafe at execution time."
    },

    {
        "threat_id": "THR-2819",
        "stride": "E",
        "surface_id": "AS-2810",
        "name": "Unsafe Tool Selection",
        "scenario":
            "The router selects a privileged tool based on model output "
            "without independent task binding.",
        "impact":
            "The model may obtain execution authority indirectly."
    },

    {
        "threat_id": "THR-2820",
        "stride": "S",
        "surface_id": "AS-2811",
        "name": "Approval / Authority Spoofing",
        "scenario":
            "Model-generated text claims that authorization has already "
            "been granted.",
        "impact":
            "Fake approval may influence security controls."
    },

    {
        "threat_id": "THR-2821",
        "stride": "E",
        "surface_id": "AS-2811",
        "name": "Model-Generated Authorization Escalation",
        "scenario":
            "Authorization requests inherit model-created role, approval, "
            "or privilege state.",
        "impact":
            "Untrusted model output may elevate execution privilege."
    },

    {
        "threat_id": "THR-2822",
        "stride": "T",
        "surface_id": "AS-2812",
        "name": "Authorization Decision Tampering",
        "scenario":
            "A denial is changed, ignored, or replaced with an approval.",
        "impact":
            "Unauthorized execution may proceed."
    },

    {
        "threat_id": "THR-2823",
        "stride": "E",
        "surface_id": "AS-2812",
        "name": "Fail-Open Authorization",
        "scenario":
            "Execution continues when authorization is missing, invalid, "
            "or denied.",
        "impact":
            "Privileged operations may execute without approval."
    },

    {
        "threat_id": "THR-2824",
        "stride": "I",
        "surface_id": "AS-2813",
        "name": "Credential Disclosure",
        "scenario":
            "API credentials or tokens are exposed to the model, prompt, "
            "logs, or unauthorized components.",
        "impact":
            "Secrets may enable downstream compromise."
    },

    {
        "threat_id": "THR-2825",
        "stride": "E",
        "surface_id": "AS-2813",
        "name": "Credential Scope Abuse",
        "scenario":
            "A credential is used for actions beyond the trusted task.",
        "impact":
            "Secret-bearing capability may expand attacker privilege."
    },

    {
        "threat_id": "THR-2826",
        "stride": "T",
        "surface_id": "AS-2815",
        "name": "Privileged Tool Target Tampering",
        "scenario":
            "A delete request substitutes a restricted target for the "
            "authorized target.",
        "impact":
            "Critical business data may be modified or destroyed."
    },

    {
        "threat_id": "THR-2827",
        "stride": "E",
        "surface_id": "AS-2815",
        "name": "Unauthorized Privileged Execution",
        "scenario":
            "The delete tool executes without valid independent "
            "authorization.",
        "impact":
            "High-impact destructive action may occur."
    },

    {
        "threat_id": "THR-2828",
        "stride": "T",
        "surface_id": "AS-2816",
        "name": "Restricted Record Modification",
        "scenario":
            "Restricted business data is altered or deleted.",
        "impact":
            "Business integrity and availability may be affected."
    },

    {
        "threat_id": "THR-2829",
        "stride": "I",
        "surface_id": "AS-2816",
        "name": "Restricted Record Disclosure",
        "scenario":
            "Restricted business information is read by an unauthorized "
            "user or agent.",
        "impact":
            "Business confidentiality may be compromised."
    },

    {
        "threat_id": "THR-2830",
        "stride": "R",
        "surface_id": "AS-2817",
        "name": "Insufficient AI Auditability",
        "scenario":
            "Prompt, retrieval, memory, agent, authorization, or execution "
            "events cannot be reliably attributed.",
        "impact":
            "Incident reconstruction and accountability may fail."
    },

    {
        "threat_id": "THR-2831",
        "stride": "T",
        "surface_id": "AS-2817",
        "name": "Security Telemetry Tampering",
        "scenario":
            "AI security events are removed, altered, or suppressed.",
        "impact":
            "Detection and forensic reconstruction may be impaired."
    },

    {
        "threat_id": "THR-2832",
        "stride": "D",
        "surface_id": "AS-2817",
        "name": "Detection Pipeline Exhaustion",
        "scenario":
            "Excessive events overwhelm logging or alert-processing "
            "capacity.",
        "impact":
            "Important attack signals may be delayed or dropped."
    },
]


# ============================================================
# SEVERITY MODEL
# ============================================================

STRIDE_BASE_WEIGHT = {
    "S": 2,
    "T": 3,
    "R": 2,
    "I": 3,
    "D": 2,
    "E": 4,
}

CRITICALITY_WEIGHT = {
    "high": 3,
    "critical": 5,
}


SURFACE_MAP = {
    surface["surface_id"]: surface
    for surface in SURFACES
}


for threat in THREATS:

    surface = SURFACE_MAP[
        threat["surface_id"]
    ]

    score = (
        STRIDE_BASE_WEIGHT[
            threat["stride"]
        ]
        +
        CRITICALITY_WEIGHT[
            surface["criticality"]
        ]
    )

    if threat["stride"] == "E":
        score += 2

    if threat["stride"] == "T":
        score += 1

    if score >= 10:
        priority = "CRITICAL"
    elif score >= 8:
        priority = "HIGH"
    elif score >= 6:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    threat["score"] = score
    threat["priority"] = priority
    threat["stride_name"] = STRIDE[
        threat["stride"]
    ]["name"]


# ============================================================
# ANALYSIS
# ============================================================

stride_counter = Counter(
    threat["stride"]
    for threat in THREATS
)

priority_counter = Counter(
    threat["priority"]
    for threat in THREATS
)

surface_threats = defaultdict(list)

for threat in THREATS:
    surface_threats[
        threat["surface_id"]
    ].append(
        threat["threat_id"]
    )

high_critical = [
    threat
    for threat in THREATS
    if threat["priority"]
    in {"HIGH", "CRITICAL"}
]

elevation_threats = [
    threat
    for threat in THREATS
    if threat["stride"] == "E"
]

tampering_threats = [
    threat
    for threat in THREATS
    if threat["stride"] == "T"
]


# ============================================================
# CONTROL THEMES
# ============================================================

CONTROL_THEMES = [
    {
        "control_id": "CTRL-2801",
        "name": "Instruction Trust Separation",
        "addresses": [
            "THR-2802",
            "THR-2804",
            "THR-2808",
        ],
    },

    {
        "control_id": "CTRL-2802",
        "name": "RAG Source & Provenance Validation",
        "addresses": [
            "THR-2805",
            "THR-2806",
            "THR-2807",
        ],
    },

    {
        "control_id": "CTRL-2803",
        "name": "Authorized Persistent Memory Writes",
        "addresses": [
            "THR-2810",
            "THR-2811",
            "THR-2813",
        ],
    },

    {
        "control_id": "CTRL-2804",
        "name": "Context / Memory Data Isolation",
        "addresses": [
            "THR-2812",
            "THR-2814",
        ],
    },

    {
        "control_id": "CTRL-2805",
        "name": "Agent Task Binding",
        "addresses": [
            "THR-2816",
            "THR-2817",
        ],
    },

    {
        "control_id": "CTRL-2806",
        "name": "Tool Parameter Validation",
        "addresses": [
            "THR-2818",
            "THR-2819",
            "THR-2826",
        ],
    },

    {
        "control_id": "CTRL-2807",
        "name": "Independent Fail-Closed Authorization",
        "addresses": [
            "THR-2820",
            "THR-2821",
            "THR-2822",
            "THR-2823",
            "THR-2827",
        ],
    },

    {
        "control_id": "CTRL-2808",
        "name": "Secret Isolation & Least Privilege",
        "addresses": [
            "THR-2824",
            "THR-2825",
        ],
    },

    {
        "control_id": "CTRL-2809",
        "name": "Business Data Authorization",
        "addresses": [
            "THR-2828",
            "THR-2829",
        ],
    },

    {
        "control_id": "CTRL-2810",
        "name": "Tamper-Evident AI Security Telemetry",
        "addresses": [
            "THR-2830",
            "THR-2831",
            "THR-2832",
        ],
    },
]


covered_threat_ids = {
    threat_id
    for control in CONTROL_THEMES
    for threat_id in control["addresses"]
}


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 84)
    print(f"        {title}")
    print("=" * 84)


header("STRIDE DEFINITIONS")

for stride_id, definition in STRIDE.items():

    print(
        f"{stride_id} | "
        f"{definition['name']}"
    )

    print(
        f"  {definition['description']}"
    )


header("LLM STRIDE THREAT REGISTER")

for threat in THREATS:

    print(
        f"{threat['threat_id']} | "
        f"{threat['stride']} - "
        f"{threat['stride_name']} | "
        f"{threat['priority']} | "
        f"Score={threat['score']} | "
        f"{threat['name']}"
    )

    print(
        f"  Surface: "
        f"{threat['surface_id']} "
        f"({SURFACE_MAP[threat['surface_id']]['name']})"
    )

    print(
        f"  Scenario: "
        f"{threat['scenario']}"
    )

    print(
        f"  Impact: "
        f"{threat['impact']}"
    )


header("STRIDE THREAT DISTRIBUTION")

for stride_id in [
    "S", "T", "R", "I", "D", "E"
]:

    print(
        f"{stride_id} - "
        f"{STRIDE[stride_id]['name']}: "
        f"{stride_counter.get(stride_id, 0)}"
    )


header("THREAT PRIORITY DISTRIBUTION")

for priority in [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
]:

    print(
        f"{priority}: "
        f"{priority_counter.get(priority, 0)}"
    )


header("HIGH / CRITICAL THREATS")

for threat in sorted(
    high_critical,
    key=lambda item: item["score"],
    reverse=True
):

    print(
        f"{threat['threat_id']} | "
        f"{threat['priority']} | "
        f"{threat['stride_name']} | "
        f"{threat['name']}"
    )


header("ELEVATION OF PRIVILEGE THREATS")

for threat in elevation_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['surface_id']} | "
        f"{threat['name']}"
    )


header("TAMPERING THREATS")

for threat in tampering_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['surface_id']} | "
        f"{threat['name']}"
    )


header("THREATS BY ATTACK SURFACE")

for surface in SURFACES:

    ids = surface_threats.get(
        surface["surface_id"],
        []
    )

    print(
        f"{surface['surface_id']} | "
        f"{surface['name']} | "
        f"Threats={len(ids)} | "
        f"{ids}"
    )


header("PRELIMINARY CONTROL THEMES")

for control in CONTROL_THEMES:

    print(
        f"{control['control_id']} | "
        f"{control['name']}"
    )

    print(
        "  Threats: "
        + ", ".join(
            control["addresses"]
        )
    )


# ============================================================
# SUMMARY
# ============================================================

header("STRIDE THREAT-MODEL SUMMARY")

print(
    f"Attack Surfaces Modeled: "
    f"{len(SURFACES)}"
)

print(
    f"Threat Scenarios: "
    f"{len(THREATS)}"
)

print(
    f"STRIDE Categories Represented: "
    f"{len(stride_counter)} / 6"
)

print(
    f"High/Critical Threats: "
    f"{len(high_critical)}"
)

print(
    f"Elevation-of-Privilege Threats: "
    f"{len(elevation_threats)}"
)

print(
    f"Tampering Threats: "
    f"{len(tampering_threats)}"
)

print(
    f"Preliminary Security Controls: "
    f"{len(CONTROL_THEMES)}"
)

print(
    f"Threats With Preliminary Control Coverage: "
    f"{len(covered_threat_ids)} / {len(THREATS)}"
)


# ============================================================
# VALIDATION
# ============================================================

header("STRIDE THREAT-MODEL SECURITY CHECKS")

threat_ids = [
    threat["threat_id"]
    for threat in THREATS
]

surface_ids = {
    surface["surface_id"]
    for surface in SURFACES
}

checks = {
    "Unique Threat IDs":
        len(threat_ids)
        == len(set(threat_ids)),

    "All Threat Surfaces Valid":
        all(
            threat["surface_id"]
            in surface_ids
            for threat in THREATS
        ),

    "Spoofing Threats Identified":
        stride_counter["S"] > 0,

    "Tampering Threats Identified":
        stride_counter["T"] > 0,

    "Repudiation Threats Identified":
        stride_counter["R"] > 0,

    "Information Disclosure Threats Identified":
        stride_counter["I"] > 0,

    "Denial of Service Threats Identified":
        stride_counter["D"] > 0,

    "Elevation of Privilege Threats Identified":
        stride_counter["E"] > 0,

    "Persistent-Memory Threats Identified":
        any(
            threat["surface_id"]
            in {"AS-2806", "AS-2807"}
            for threat in THREATS
        ),

    "RAG Threats Identified":
        any(
            threat["surface_id"]
            in {"AS-2804", "AS-2805"}
            for threat in THREATS
        ),

    "Agent Threats Identified":
        any(
            threat["surface_id"]
            == "AS-2809"
            for threat in THREATS
        ),

    "Authorization Threats Identified":
        any(
            threat["surface_id"]
            in {"AS-2811", "AS-2812"}
            for threat in THREATS
        ),

    "Privileged Tool Threats Identified":
        any(
            threat["surface_id"]
            == "AS-2815"
            for threat in THREATS
        ),

    "Observability Threats Identified":
        any(
            threat["surface_id"]
            == "AS-2817"
            for threat in THREATS
        ),

    "Control Coverage Present":
        len(covered_threat_ids) > 0,
}


for check, result in checks.items():
    print(
        f"{check}: {result}"
    )


stride_model_valid = all(
    checks.values()
)


print(
    f"\nSTRIDE-Style AI Threat Model Valid: "
    f"{stride_model_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 4",

    "title":
        "STRIDE-Style LLM Threat Modeling",

    "stride":
        STRIDE,

    "surfaces":
        SURFACES,

    "threats":
        THREATS,

    "control_themes":
        CONTROL_THEMES,

    "metrics": {
        "attack_surfaces_modeled":
            len(SURFACES),

        "threat_scenarios":
            len(THREATS),

        "stride_categories_represented":
            len(stride_counter),

        "high_critical_threats":
            len(high_critical),

        "elevation_of_privilege_threats":
            len(elevation_threats),

        "tampering_threats":
            len(tampering_threats),

        "preliminary_controls":
            len(CONTROL_THEMES),

        "threats_with_control_coverage":
            len(covered_threat_ids),
    },

    "security_checks":
        checks,

    "stride_model_valid":
        stride_model_valid,
}


OUTPUT_FILE = (
    "day28-stride-llm-threat-model-evidence.json"
)


with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8",
) as file:

    json.dump(
        REPORT,
        file,
        indent=2,
    )


print("\nEvidence written to:")
print(OUTPUT_FILE)


# ============================================================
# INTERPRETATION
# ============================================================

print("\nSecurity Interpretation:")

print(
    "The STRIDE-style assessment demonstrates that AI threat "
    "modeling must extend beyond conventional application inputs "
    "to include retrieved context, persistent memory, model-generated "
    "planning state, tool parameters, authorization decisions, secrets, "
    "privileged execution, business data, and security telemetry."
)

print(
    "Elevation of privilege is especially important in agentic AI "
    "systems because model-generated text or plans must never become "
    "execution authority without independent authorization."
)

print(
    "The threat register now provides structured scenarios that can "
    "be converted into attack trees, industry-framework mappings, "
    "likelihood-impact scores, risk-register entries, and security controls."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)