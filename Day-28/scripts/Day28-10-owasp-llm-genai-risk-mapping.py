"""
Day 28 Lab 10
OWASP LLM / GenAI Risk Mapping

Purpose:
Map Day 28 AI threat scenarios and attack paths to major OWASP
LLM / Generative AI security risk areas.

This is a synthetic educational mapping rather than an assertion
that every scenario corresponds one-to-one with an official OWASP
category.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter, defaultdict


print(
    "\n=== Day 28 Lab 10: "
    "OWASP LLM / GenAI Risk Mapping ===\n"
)


# ============================================================
# OWASP-STYLE AI RISK AREAS
# ============================================================

RISK_AREAS = [
    {
        "risk_id": "OWASP-AI-01",
        "name": "Prompt Injection",
        "description":
            "Untrusted instructions influence model behavior "
            "or downstream execution.",
    },
    {
        "risk_id": "OWASP-AI-02",
        "name": "Sensitive Information Disclosure",
        "description":
            "Sensitive prompts, secrets, memory, retrieved data "
            "or business information may be exposed.",
    },
    {
        "risk_id": "OWASP-AI-03",
        "name": "Supply Chain / External Dependency Risk",
        "description":
            "Models, datasets, retrieval sources, plugins or "
            "dependencies introduce untrusted behavior.",
    },
    {
        "risk_id": "OWASP-AI-04",
        "name": "Data and Model Poisoning",
        "description":
            "Untrusted or manipulated information corrupts "
            "model-visible context or persistent AI state.",
    },
    {
        "risk_id": "OWASP-AI-05",
        "name": "Improper Output Handling",
        "description":
            "Model-generated content is trusted as executable, "
            "authorized or security-relevant state.",
    },
    {
        "risk_id": "OWASP-AI-06",
        "name": "Excessive Agency",
        "description":
            "AI agents receive excessive capability, autonomy, "
            "scope or privilege.",
    },
    {
        "risk_id": "OWASP-AI-07",
        "name": "System Prompt / Instruction Exposure",
        "description":
            "Trusted instructions or security policy become "
            "exposed or attacker-influenced.",
    },
    {
        "risk_id": "OWASP-AI-08",
        "name": "Vector / Embedding / Retrieval Weakness",
        "description":
            "Retrieval integrity, provenance or authorization "
            "failures introduce unsafe context.",
    },
    {
        "risk_id": "OWASP-AI-09",
        "name": "Misinformation / Trust Failure",
        "description":
            "Model-generated assertions are treated as trusted "
            "facts, approvals or authority.",
    },
    {
        "risk_id": "OWASP-AI-10",
        "name": "Unbounded Consumption",
        "description":
            "AI or tool execution consumes excessive resources "
            "or enters uncontrolled execution loops.",
    },
    {
        "risk_id": "OWASP-AI-11",
        "name": "Persistent Memory Security",
        "description":
            "Long-lived AI memory creates persistence and "
            "cross-session influence risks.",
    },
    {
        "risk_id": "OWASP-AI-12",
        "name": "Tool and Privileged Execution Security",
        "description":
            "Model-driven tool calls reach sensitive or "
            "privileged business operations.",
    },
    {
        "risk_id": "OWASP-AI-13",
        "name": "Authorization and Identity Boundary Failure",
        "description":
            "AI-generated state improperly influences identity "
            "or authorization decisions.",
    },
    {
        "risk_id": "OWASP-AI-14",
        "name": "AI Observability and Forensic Weakness",
        "description":
            "Security-relevant AI activity cannot be reliably "
            "detected, correlated or reconstructed.",
    },
]


# ============================================================
# DAY 28 THREAT SCENARIOS
# ============================================================

THREATS = [
    {
        "threat_id": "THR-2801",
        "name": "Direct Prompt Injection",
        "severity": "HIGH",
        "risk_score": 20,
        "mappings": ["OWASP-AI-01"],
    },
    {
        "threat_id": "THR-2802",
        "name": "Indirect RAG Prompt Injection",
        "severity": "CRITICAL",
        "risk_score": 25,
        "mappings": [
            "OWASP-AI-01",
            "OWASP-AI-08",
        ],
    },
    {
        "threat_id": "THR-2803",
        "name": "RAG Source Poisoning",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-03",
            "OWASP-AI-04",
            "OWASP-AI-08",
        ],
    },
    {
        "threat_id": "THR-2804",
        "name": "Unsafe Retrieved Context Admission",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-04",
            "OWASP-AI-08",
        ],
    },
    {
        "threat_id": "THR-2805",
        "name": "Sensitive RAG Data Disclosure",
        "severity": "HIGH",
        "risk_score": 16,
        "mappings": [
            "OWASP-AI-02",
            "OWASP-AI-08",
        ],
    },
    {
        "threat_id": "THR-2806",
        "name": "Unauthorized Persistent Memory Write",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-04",
            "OWASP-AI-11",
        ],
    },
    {
        "threat_id": "THR-2807",
        "name": "Cross-Session Memory Poisoning",
        "severity": "CRITICAL",
        "risk_score": 25,
        "mappings": [
            "OWASP-AI-04",
            "OWASP-AI-11",
        ],
    },
    {
        "threat_id": "THR-2808",
        "name": "Memory-Based Sensitive Data Exposure",
        "severity": "HIGH",
        "risk_score": 16,
        "mappings": [
            "OWASP-AI-02",
            "OWASP-AI-11",
        ],
    },
    {
        "threat_id": "THR-2809",
        "name": "Agent Goal Hijacking",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-01",
            "OWASP-AI-06",
        ],
    },
    {
        "threat_id": "THR-2810",
        "name": "Agent Task Drift",
        "severity": "HIGH",
        "risk_score": 16,
        "mappings": ["OWASP-AI-06"],
    },
    {
        "threat_id": "THR-2811",
        "name": "Unsafe Privileged Tool Selection",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-06",
            "OWASP-AI-12",
        ],
    },
    {
        "threat_id": "THR-2812",
        "name": "Tool Parameter Injection",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-05",
            "OWASP-AI-12",
        ],
    },
    {
        "threat_id": "THR-2813",
        "name": "Trusted Target Substitution",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-06",
            "OWASP-AI-12",
        ],
    },
    {
        "threat_id": "THR-2814",
        "name": "Model-Generated Approval",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-05",
            "OWASP-AI-09",
            "OWASP-AI-13",
        ],
    },
    {
        "threat_id": "THR-2815",
        "name": "Fail-Open Authorization",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-12",
            "OWASP-AI-13",
        ],
    },
    {
        "threat_id": "THR-2816",
        "name": "Identity Confusion",
        "severity": "HIGH",
        "risk_score": 15,
        "mappings": ["OWASP-AI-13"],
    },
    {
        "threat_id": "THR-2817",
        "name": "Credential Exposure to Model Context",
        "severity": "HIGH",
        "risk_score": 15,
        "mappings": [
            "OWASP-AI-02",
            "OWASP-AI-12",
        ],
    },
    {
        "threat_id": "THR-2818",
        "name": "Credential Scope Abuse",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-06",
            "OWASP-AI-12",
            "OWASP-AI-13",
        ],
    },
    {
        "threat_id": "THR-2819",
        "name": "Restricted Business Record Disclosure",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-02",
            "OWASP-AI-12",
            "OWASP-AI-13",
        ],
    },
    {
        "threat_id": "THR-2820",
        "name": "Restricted Business Record Destruction",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-06",
            "OWASP-AI-12",
            "OWASP-AI-13",
        ],
    },
    {
        "threat_id": "THR-2821",
        "name": "Downstream Service Trust Abuse",
        "severity": "CRITICAL",
        "risk_score": 20,
        "mappings": [
            "OWASP-AI-05",
            "OWASP-AI-12",
        ],
    },
    {
        "threat_id": "THR-2822",
        "name": "Agent Execution Loop",
        "severity": "MEDIUM",
        "risk_score": 12,
        "mappings": [
            "OWASP-AI-06",
            "OWASP-AI-10",
        ],
    },
    {
        "threat_id": "THR-2823",
        "name": "Tool Invocation Flood",
        "severity": "MEDIUM",
        "risk_score": 12,
        "mappings": [
            "OWASP-AI-10",
            "OWASP-AI-12",
        ],
    },
    {
        "threat_id": "THR-2824",
        "name": "System Prompt Disclosure",
        "severity": "HIGH",
        "risk_score": 16,
        "mappings": [
            "OWASP-AI-02",
            "OWASP-AI-07",
        ],
    },
    {
        "threat_id": "THR-2825",
        "name": "Security Telemetry Suppression",
        "severity": "HIGH",
        "risk_score": 15,
        "mappings": ["OWASP-AI-14"],
    },
    {
        "threat_id": "THR-2826",
        "name": "Authorization Evidence Tampering",
        "severity": "HIGH",
        "risk_score": 15,
        "mappings": [
            "OWASP-AI-13",
            "OWASP-AI-14",
        ],
    },
]


RISK_MAP = {
    item["risk_id"]: item
    for item in RISK_AREAS
}


# ============================================================
# VALIDATE MAPPINGS
# ============================================================

valid_risk_ids = set(RISK_MAP)

for threat in THREATS:

    threat["mapping_valid"] = all(
        risk_id in valid_risk_ids
        for risk_id in threat["mappings"]
    )


# ============================================================
# RISK DISTRIBUTION
# ============================================================

risk_distribution = Counter()

for threat in THREATS:
    for risk_id in threat["mappings"]:
        risk_distribution[risk_id] += 1


severity_distribution = Counter(
    threat["severity"]
    for threat in THREATS
)


# ============================================================
# RISK-TO-THREAT INDEX
# ============================================================

risk_to_threats = defaultdict(list)

for threat in THREATS:

    for risk_id in threat["mappings"]:

        risk_to_threats[risk_id].append(
            threat["threat_id"]
        )


# ============================================================
# CONTROL LIBRARY
# ============================================================

CONTROLS = [
    {
        "control_id": "OWASP-CTRL-01",
        "name": "Instruction Trust Separation",
        "risks": [
            "OWASP-AI-01",
            "OWASP-AI-07",
        ],
    },
    {
        "control_id": "OWASP-CTRL-02",
        "name": "Sensitive Data Minimization & DLP",
        "risks": [
            "OWASP-AI-02",
        ],
    },
    {
        "control_id": "OWASP-CTRL-03",
        "name": "AI Supply-Chain Validation",
        "risks": [
            "OWASP-AI-03",
        ],
    },
    {
        "control_id": "OWASP-CTRL-04",
        "name": "RAG Provenance & Poisoning Controls",
        "risks": [
            "OWASP-AI-04",
            "OWASP-AI-08",
        ],
    },
    {
        "control_id": "OWASP-CTRL-05",
        "name": "Output Isolation & Validation",
        "risks": [
            "OWASP-AI-05",
            "OWASP-AI-09",
        ],
    },
    {
        "control_id": "OWASP-CTRL-06",
        "name": "Least-Privilege Agent Architecture",
        "risks": [
            "OWASP-AI-06",
        ],
    },
    {
        "control_id": "OWASP-CTRL-07",
        "name": "Execution Budgets & Rate Limits",
        "risks": [
            "OWASP-AI-10",
        ],
    },
    {
        "control_id": "OWASP-CTRL-08",
        "name": "Authorized Persistent Memory",
        "risks": [
            "OWASP-AI-11",
        ],
    },
    {
        "control_id": "OWASP-CTRL-09",
        "name": "Tool Allowlisting & Parameter Validation",
        "risks": [
            "OWASP-AI-12",
        ],
    },
    {
        "control_id": "OWASP-CTRL-10",
        "name": "Fail-Closed Independent Authorization",
        "risks": [
            "OWASP-AI-13",
        ],
    },
    {
        "control_id": "OWASP-CTRL-11",
        "name": "Tamper-Evident AI Security Telemetry",
        "risks": [
            "OWASP-AI-14",
        ],
    },
]


covered_risks = {
    risk_id
    for control in CONTROLS
    for risk_id in control["risks"]
}


# ============================================================
# ATTACK-PATH MAPPING
# ============================================================

ATTACK_PATHS = [
    {
        "path_id": "PATH-2801",
        "name": "Prompt Injection to Privileged Execution",
        "owasp_risks": [
            "OWASP-AI-01",
            "OWASP-AI-06",
            "OWASP-AI-12",
            "OWASP-AI-13",
        ],
    },
    {
        "path_id": "PATH-2802",
        "name": "RAG Poisoning to Persistent AI Compromise",
        "owasp_risks": [
            "OWASP-AI-01",
            "OWASP-AI-04",
            "OWASP-AI-08",
            "OWASP-AI-11",
        ],
    },
    {
        "path_id": "PATH-2803",
        "name": "Prompt Injection to Restricted Data Access",
        "owasp_risks": [
            "OWASP-AI-01",
            "OWASP-AI-02",
            "OWASP-AI-06",
            "OWASP-AI-12",
            "OWASP-AI-13",
        ],
    },
    {
        "path_id": "PATH-2804",
        "name": "Persistent Memory to Destructive Execution",
        "owasp_risks": [
            "OWASP-AI-06",
            "OWASP-AI-11",
            "OWASP-AI-12",
            "OWASP-AI-13",
        ],
    },
    {
        "path_id": "PATH-2805",
        "name": "Credential Abuse to Destructive Business Impact",
        "owasp_risks": [
            "OWASP-AI-02",
            "OWASP-AI-06",
            "OWASP-AI-12",
            "OWASP-AI-13",
        ],
    },
    {
        "path_id": "PATH-2806",
        "name": "Target Substitution to Restricted Record Destruction",
        "owasp_risks": [
            "OWASP-AI-06",
            "OWASP-AI-12",
            "OWASP-AI-13",
        ],
    },
    {
        "path_id": "PATH-2807",
        "name": "Fake Approval to Authorization Bypass",
        "owasp_risks": [
            "OWASP-AI-05",
            "OWASP-AI-09",
            "OWASP-AI-12",
            "OWASP-AI-13",
        ],
    },
    {
        "path_id": "PATH-2808",
        "name": "Telemetry Evasion During Privileged Abuse",
        "owasp_risks": [
            "OWASP-AI-12",
            "OWASP-AI-13",
            "OWASP-AI-14",
        ],
    },
]


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 88)
    print(f"        {title}")
    print("=" * 88)


header("OWASP-STYLE AI SECURITY RISK AREAS")

for risk in RISK_AREAS:

    print(
        f"{risk['risk_id']} | "
        f"{risk['name']}"
    )

    print(
        f"  {risk['description']}"
    )


header("DAY 28 THREAT-TO-RISK MAPPING")

for threat in THREATS:

    print(
        f"{threat['threat_id']} | "
        f"{threat['severity']} | "
        f"Risk={threat['risk_score']} | "
        f"{threat['name']}"
    )

    print(
        "  OWASP Mapping: "
        + ", ".join(
            threat["mappings"]
        )
    )


header("RISK CATEGORY COVERAGE")

for risk in RISK_AREAS:

    threat_ids = risk_to_threats.get(
        risk["risk_id"],
        []
    )

    print(
        f"{risk['risk_id']} | "
        f"{risk['name']} | "
        f"Mapped Threats={len(threat_ids)}"
    )

    if threat_ids:
        print(
            "  Threats: "
            + ", ".join(threat_ids)
        )


header("THREAT SEVERITY DISTRIBUTION")

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


header("OWASP RISK EXPOSURE DISTRIBUTION")

for risk_id, count in sorted(
    risk_distribution.items(),
    key=lambda item: (
        -item[1],
        item[0]
    )
):

    print(
        f"{risk_id} | "
        f"{RISK_MAP[risk_id]['name']} | "
        f"Threat Mappings={count}"
    )


header("ATTACK-PATH TO OWASP RISK CORRELATION")

for path in ATTACK_PATHS:

    print(
        f"{path['path_id']} | "
        f"{path['name']}"
    )

    print(
        "  Risk Areas: "
        + ", ".join(
            path["owasp_risks"]
        )
    )


header("OWASP-ALIGNED SECURITY CONTROLS")

for control in CONTROLS:

    print(
        f"{control['control_id']} | "
        f"{control['name']}"
    )

    print(
        "  Risk Coverage: "
        + ", ".join(
            control["risks"]
        )
    )


# ============================================================
# PRIORITY ANALYSIS
# ============================================================

priority_risks = sorted(
    [
        {
            "risk_id": risk_id,
            "name": RISK_MAP[risk_id]["name"],
            "threat_count": count,
        }
        for risk_id, count
        in risk_distribution.items()
    ],
    key=lambda item: (
        -item["threat_count"],
        item["risk_id"],
    )
)


header("PRIORITIZED AI RISK AREAS")

for item in priority_risks:

    print(
        f"{item['risk_id']} | "
        f"Threats={item['threat_count']} | "
        f"{item['name']}"
    )


# ============================================================
# SUMMARY
# ============================================================

header("OWASP LLM / GENAI MAPPING SUMMARY")

mapped_threats = [
    threat
    for threat in THREATS
    if threat["mappings"]
]

high_critical = [
    threat
    for threat in THREATS
    if threat["severity"]
    in {"HIGH", "CRITICAL"}
]

mapped_risk_categories = {
    risk_id
    for threat in THREATS
    for risk_id in threat["mappings"]
}


print(
    f"AI Risk Areas: "
    f"{len(RISK_AREAS)}"
)

print(
    f"Threat Scenarios: "
    f"{len(THREATS)}"
)

print(
    f"Mapped Threat Scenarios: "
    f"{len(mapped_threats)} / "
    f"{len(THREATS)}"
)

print(
    f"High/Critical Threats: "
    f"{len(high_critical)}"
)

print(
    f"Risk Categories Represented: "
    f"{len(mapped_risk_categories)} / "
    f"{len(RISK_AREAS)}"
)

print(
    f"Attack Paths Mapped: "
    f"{len(ATTACK_PATHS)}"
)

print(
    f"Security Controls: "
    f"{len(CONTROLS)}"
)

print(
    f"Risk Categories With Control Coverage: "
    f"{len(covered_risks)} / "
    f"{len(RISK_AREAS)}"
)


# ============================================================
# VALIDATION
# ============================================================

header("OWASP RISK-MAPPING SECURITY CHECKS")

checks = {
    "All Threat Mappings Valid":
        all(
            threat["mapping_valid"]
            for threat in THREATS
        ),

    "All Threats Mapped":
        len(mapped_threats)
        == len(THREATS),

    "Prompt Injection Risk Represented":
        "OWASP-AI-01"
        in mapped_risk_categories,

    "Sensitive Disclosure Risk Represented":
        "OWASP-AI-02"
        in mapped_risk_categories,

    "Supply Chain Risk Represented":
        "OWASP-AI-03"
        in mapped_risk_categories,

    "Poisoning Risk Represented":
        "OWASP-AI-04"
        in mapped_risk_categories,

    "Output Handling Risk Represented":
        "OWASP-AI-05"
        in mapped_risk_categories,

    "Excessive Agency Risk Represented":
        "OWASP-AI-06"
        in mapped_risk_categories,

    "System Prompt Risk Represented":
        "OWASP-AI-07"
        in mapped_risk_categories,

    "Retrieval Risk Represented":
        "OWASP-AI-08"
        in mapped_risk_categories,

    "Trust Failure Risk Represented":
        "OWASP-AI-09"
        in mapped_risk_categories,

    "Resource Consumption Risk Represented":
        "OWASP-AI-10"
        in mapped_risk_categories,

    "Persistent Memory Risk Represented":
        "OWASP-AI-11"
        in mapped_risk_categories,

    "Tool Execution Risk Represented":
        "OWASP-AI-12"
        in mapped_risk_categories,

    "Authorization Risk Represented":
        "OWASP-AI-13"
        in mapped_risk_categories,

    "Observability Risk Represented":
        "OWASP-AI-14"
        in mapped_risk_categories,

    "All Risk Areas Have Control Coverage":
        all(
            risk["risk_id"]
            in covered_risks
            for risk in RISK_AREAS
        ),

    "Attack Paths Mapped":
        all(
            path["owasp_risks"]
            for path in ATTACK_PATHS
        ),
}


for check, result in checks.items():

    print(
        f"{check}: {result}"
    )


mapping_valid = all(
    checks.values()
)


print(
    f"\nOWASP LLM / GenAI Risk Mapping Valid: "
    f"{mapping_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 10",

    "title":
        "OWASP LLM / GenAI Risk Mapping",

    "risk_areas":
        RISK_AREAS,

    "threats":
        THREATS,

    "attack_paths":
        ATTACK_PATHS,

    "controls":
        CONTROLS,

    "risk_distribution":
        dict(risk_distribution),

    "severity_distribution":
        dict(severity_distribution),

    "metrics": {
        "risk_areas":
            len(RISK_AREAS),

        "threat_scenarios":
            len(THREATS),

        "mapped_threats":
            len(mapped_threats),

        "high_critical_threats":
            len(high_critical),

        "risk_categories_represented":
            len(mapped_risk_categories),

        "attack_paths_mapped":
            len(ATTACK_PATHS),

        "security_controls":
            len(CONTROLS),

        "risk_categories_with_control_coverage":
            len(covered_risks),
    },

    "security_checks":
        checks,

    "mapping_valid":
        mapping_valid,
}


OUTPUT_FILE = (
    "day28-owasp-llm-genai-risk-mapping-evidence.json"
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
    "The OWASP-aligned mapping translates Day 28 technical "
    "threat scenarios into recognizable AI security risk areas."
)

print(
    "The model demonstrates that individual AI attack scenarios "
    "frequently span multiple risk categories, particularly when "
    "prompt manipulation reaches retrieval, memory, agents, "
    "authorization, tools and downstream business systems."
)

print(
    "The mapping also links each identified risk area to an "
    "architectural control so that threat modeling produces "
    "actionable security design requirements rather than only "
    "a list of vulnerabilities."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and "
    "trust boundaries, not added only after vulnerabilities are "
    "discovered."
)