"""
Day 28 Lab 11
MITRE ATLAS-Aligned Adversary Technique Mapping

Purpose:
Translate Day 28 LLM threat scenarios, attack paths, and AI-specific
security behaviors into a threat-informed adversary lifecycle.

Important:
This lab uses MITRE ATLAS-aligned concepts and synthetic identifiers
for portfolio threat-modeling purposes. Synthetic IDs in this file
should not be represented as official MITRE ATLAS technique IDs.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter, defaultdict


print(
    "\n=== Day 28 Lab 11: "
    "MITRE ATLAS-Aligned Adversary Technique Mapping ===\n"
)


# ============================================================
# ADVERSARY TACTICS
# ============================================================

TACTICS = [
    {
        "tactic_id": "ATLAS-TA-01",
        "name": "Reconnaissance",
        "description":
            "Adversary gathers information about prompts, models, "
            "retrieval sources, tools, privileges, identities, or controls."
    },

    {
        "tactic_id": "ATLAS-TA-02",
        "name": "Initial Access",
        "description":
            "Adversary introduces malicious or manipulative content "
            "into an AI workflow."
    },

    {
        "tactic_id": "ATLAS-TA-03",
        "name": "AI / ML Attack Staging",
        "description":
            "Adversary prepares poisoned data, prompts, retrieval "
            "content, memory state, or model-visible context."
    },

    {
        "tactic_id": "ATLAS-TA-04",
        "name": "Execution",
        "description":
            "Adversary causes AI-generated state to influence runtime "
            "behavior, agents, tools, or downstream actions."
    },

    {
        "tactic_id": "ATLAS-TA-05",
        "name": "Persistence",
        "description":
            "Adversary establishes long-lived malicious state through "
            "memory, RAG content, stored context, or reusable credentials."
    },

    {
        "tactic_id": "ATLAS-TA-06",
        "name": "Privilege / Authorization Abuse",
        "description":
            "Adversary attempts to obtain or misuse authority, approval, "
            "identity, privileged tools, or execution capability."
    },

    {
        "tactic_id": "ATLAS-TA-07",
        "name": "Collection",
        "description":
            "Adversary obtains sensitive prompt, memory, secret, "
            "retrieval, identity, or business information."
    },

    {
        "tactic_id": "ATLAS-TA-08",
        "name": "Defense Evasion",
        "description":
            "Adversary attempts to avoid prompt detection, policy controls, "
            "authorization enforcement, logging, or forensic reconstruction."
    },

    {
        "tactic_id": "ATLAS-TA-09",
        "name": "Impact",
        "description":
            "Adversary causes unauthorized data access, modification, "
            "destruction, service degradation, or business impact."
    },
]


TACTIC_MAP = {
    tactic["tactic_id"]: tactic
    for tactic in TACTICS
}


# ============================================================
# SYNTHETIC ATLAS-ALIGNED TECHNIQUE LIBRARY
# ============================================================

TECHNIQUES = [
    {
        "technique_id": "AI-TCH-2801",
        "name": "Prompt Injection",
        "tactic_id": "ATLAS-TA-02",
        "description":
            "Manipulate user-visible or hidden instructions to influence AI behavior."
    },

    {
        "technique_id": "AI-TCH-2802",
        "name": "Indirect Prompt Injection",
        "tactic_id": "ATLAS-TA-03",
        "description":
            "Embed malicious instructions inside retrieved or external content."
    },

    {
        "technique_id": "AI-TCH-2803",
        "name": "RAG Source Poisoning",
        "tactic_id": "ATLAS-TA-03",
        "description":
            "Introduce attacker-controlled or manipulated documents into retrieval sources."
    },

    {
        "technique_id": "AI-TCH-2804",
        "name": "Context Trust Manipulation",
        "tactic_id": "ATLAS-TA-04",
        "description":
            "Cause untrusted context to be interpreted as trusted instructions or authority."
    },

    {
        "technique_id": "AI-TCH-2805",
        "name": "Persistent Memory Poisoning",
        "tactic_id": "ATLAS-TA-05",
        "description":
            "Store malicious or manipulated AI state for later reuse."
    },

    {
        "technique_id": "AI-TCH-2806",
        "name": "Cross-Session State Activation",
        "tactic_id": "ATLAS-TA-05",
        "description":
            "Activate malicious persistent state in a later session or workflow."
    },

    {
        "technique_id": "AI-TCH-2807",
        "name": "Agent Goal Hijacking",
        "tactic_id": "ATLAS-TA-04",
        "description":
            "Modify an agent's intended objective or planning state."
    },

    {
        "technique_id": "AI-TCH-2808",
        "name": "Tool Selection Manipulation",
        "tactic_id": "ATLAS-TA-04",
        "description":
            "Influence the AI system to choose an unintended or privileged tool."
    },

    {
        "technique_id": "AI-TCH-2809",
        "name": "Target Substitution",
        "tactic_id": "ATLAS-TA-04",
        "description":
            "Replace the trusted execution target with a restricted or attacker-selected target."
    },

    {
        "technique_id": "AI-TCH-2810",
        "name": "Tool Parameter Manipulation",
        "tactic_id": "ATLAS-TA-04",
        "description":
            "Alter tool parameters so otherwise valid functionality performs an unsafe action."
    },

    {
        "technique_id": "AI-TCH-2811",
        "name": "Authority / Approval Spoofing",
        "tactic_id": "ATLAS-TA-06",
        "description":
            "Fabricate approval, administrator authority, policy exceptions, or trusted identity."
    },

    {
        "technique_id": "AI-TCH-2812",
        "name": "Authorization Bypass",
        "tactic_id": "ATLAS-TA-06",
        "description":
            "Cause execution to proceed despite missing, invalid, or denied authorization."
    },

    {
        "technique_id": "AI-TCH-2813",
        "name": "Credential Exposure",
        "tactic_id": "ATLAS-TA-07",
        "description":
            "Obtain API keys, tokens, secrets, or privileged credentials from AI-visible state."
    },

    {
        "technique_id": "AI-TCH-2814",
        "name": "Credential Scope Abuse",
        "tactic_id": "ATLAS-TA-06",
        "description":
            "Use valid credentials outside their intended task, tool, target, or scope."
    },

    {
        "technique_id": "AI-TCH-2815",
        "name": "Sensitive Context Extraction",
        "tactic_id": "ATLAS-TA-07",
        "description":
            "Extract system prompts, memory, RAG content, restricted records, or protected context."
    },

    {
        "technique_id": "AI-TCH-2816",
        "name": "Security Control Evasion",
        "tactic_id": "ATLAS-TA-08",
        "description":
            "Obfuscate, fragment, encode, or reframe adversarial instructions to evade controls."
    },

    {
        "technique_id": "AI-TCH-2817",
        "name": "Telemetry Suppression",
        "tactic_id": "ATLAS-TA-08",
        "description":
            "Suppress, remove, alter, or evade security telemetry and forensic evidence."
    },

    {
        "technique_id": "AI-TCH-2818",
        "name": "Restricted Data Access",
        "tactic_id": "ATLAS-TA-09",
        "description":
            "Access business information outside authorized scope."
    },

    {
        "technique_id": "AI-TCH-2819",
        "name": "Restricted Data Modification",
        "tactic_id": "ATLAS-TA-09",
        "description":
            "Alter protected or business-critical records."
    },

    {
        "technique_id": "AI-TCH-2820",
        "name": "Restricted Data Destruction",
        "tactic_id": "ATLAS-TA-09",
        "description":
            "Delete or destroy protected business resources."
    },

    {
        "technique_id": "AI-TCH-2821",
        "name": "Resource Exhaustion",
        "tactic_id": "ATLAS-TA-09",
        "description":
            "Consume excessive model, retrieval, memory, agent, or tool resources."
    },

    {
        "technique_id": "AI-TCH-2822",
        "name": "AI System Discovery",
        "tactic_id": "ATLAS-TA-01",
        "description":
            "Identify available tools, policies, model behavior, retrieval capabilities, or trust boundaries."
    },
]


TECHNIQUE_MAP = {
    technique["technique_id"]: technique
    for technique in TECHNIQUES
}


# ============================================================
# DAY 28 THREAT MAPPING
# ============================================================

THREATS = [
    {
        "threat_id": "THR-2801",
        "name": "Direct Prompt Injection",
        "severity": "HIGH",
        "techniques": ["AI-TCH-2801"],
    },

    {
        "threat_id": "THR-2802",
        "name": "Indirect RAG Prompt Injection",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2802",
            "AI-TCH-2804",
        ],
    },

    {
        "threat_id": "THR-2803",
        "name": "RAG Source Poisoning",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2803",
        ],
    },

    {
        "threat_id": "THR-2804",
        "name": "Unsafe Retrieved Context Admission",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2804",
        ],
    },

    {
        "threat_id": "THR-2805",
        "name": "Sensitive RAG Data Disclosure",
        "severity": "HIGH",
        "techniques": [
            "AI-TCH-2815",
        ],
    },

    {
        "threat_id": "THR-2806",
        "name": "Unauthorized Persistent Memory Write",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2805",
        ],
    },

    {
        "threat_id": "THR-2807",
        "name": "Cross-Session Memory Poisoning",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2805",
            "AI-TCH-2806",
        ],
    },

    {
        "threat_id": "THR-2808",
        "name": "Memory-Based Sensitive Data Exposure",
        "severity": "HIGH",
        "techniques": [
            "AI-TCH-2815",
        ],
    },

    {
        "threat_id": "THR-2809",
        "name": "Agent Goal Hijacking",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2807",
        ],
    },

    {
        "threat_id": "THR-2810",
        "name": "Agent Task Drift",
        "severity": "HIGH",
        "techniques": [
            "AI-TCH-2807",
        ],
    },

    {
        "threat_id": "THR-2811",
        "name": "Unsafe Privileged Tool Selection",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2808",
        ],
    },

    {
        "threat_id": "THR-2812",
        "name": "Tool Parameter Injection",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2810",
        ],
    },

    {
        "threat_id": "THR-2813",
        "name": "Trusted Target Substitution",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2809",
        ],
    },

    {
        "threat_id": "THR-2814",
        "name": "Model-Generated Approval",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2811",
        ],
    },

    {
        "threat_id": "THR-2815",
        "name": "Fail-Open Authorization",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2812",
        ],
    },

    {
        "threat_id": "THR-2816",
        "name": "Identity Confusion",
        "severity": "HIGH",
        "techniques": [
            "AI-TCH-2811",
        ],
    },

    {
        "threat_id": "THR-2817",
        "name": "Credential Exposure to Model Context",
        "severity": "HIGH",
        "techniques": [
            "AI-TCH-2813",
        ],
    },

    {
        "threat_id": "THR-2818",
        "name": "Credential Scope Abuse",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2814",
        ],
    },

    {
        "threat_id": "THR-2819",
        "name": "Restricted Business Record Disclosure",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2818",
        ],
    },

    {
        "threat_id": "THR-2820",
        "name": "Restricted Business Record Destruction",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2820",
        ],
    },

    {
        "threat_id": "THR-2821",
        "name": "Downstream Service Trust Abuse",
        "severity": "CRITICAL",
        "techniques": [
            "AI-TCH-2808",
            "AI-TCH-2812",
        ],
    },

    {
        "threat_id": "THR-2822",
        "name": "Agent Execution Loop",
        "severity": "MEDIUM",
        "techniques": [
            "AI-TCH-2821",
        ],
    },

    {
        "threat_id": "THR-2823",
        "name": "Tool Invocation Flood",
        "severity": "MEDIUM",
        "techniques": [
            "AI-TCH-2821",
        ],
    },

    {
        "threat_id": "THR-2824",
        "name": "System Prompt Disclosure",
        "severity": "HIGH",
        "techniques": [
            "AI-TCH-2815",
            "AI-TCH-2822",
        ],
    },

    {
        "threat_id": "THR-2825",
        "name": "Security Telemetry Suppression",
        "severity": "HIGH",
        "techniques": [
            "AI-TCH-2817",
        ],
    },

    {
        "threat_id": "THR-2826",
        "name": "Authorization Evidence Tampering",
        "severity": "HIGH",
        "techniques": [
            "AI-TCH-2817",
            "AI-TCH-2812",
        ],
    },
]


# ============================================================
# VALIDATE TECHNIQUE MAPPINGS
# ============================================================

valid_technique_ids = set(
    TECHNIQUE_MAP
)

for threat in THREATS:

    threat["mapping_valid"] = all(
        technique_id
        in valid_technique_ids
        for technique_id
        in threat["techniques"]
    )


# ============================================================
# DERIVE TACTICS FROM TECHNIQUES
# ============================================================

for threat in THREATS:

    tactics = sorted({
        TECHNIQUE_MAP[
            technique_id
        ]["tactic_id"]
        for technique_id
        in threat["techniques"]
    })

    threat["tactics"] = tactics


# ============================================================
# ATTACK PATHS
# ============================================================

ATTACK_PATHS = [
    {
        "path_id": "PATH-2801",
        "name":
            "Prompt Injection to Privileged Execution",
        "techniques": [
            "AI-TCH-2801",
            "AI-TCH-2807",
            "AI-TCH-2808",
            "AI-TCH-2811",
            "AI-TCH-2812",
        ],
    },

    {
        "path_id": "PATH-2802",
        "name":
            "RAG Poisoning to Persistent AI Compromise",
        "techniques": [
            "AI-TCH-2803",
            "AI-TCH-2802",
            "AI-TCH-2804",
            "AI-TCH-2805",
            "AI-TCH-2806",
        ],
    },

    {
        "path_id": "PATH-2803",
        "name":
            "Prompt Injection to Restricted Data Access",
        "techniques": [
            "AI-TCH-2801",
            "AI-TCH-2807",
            "AI-TCH-2809",
            "AI-TCH-2810",
            "AI-TCH-2818",
        ],
    },

    {
        "path_id": "PATH-2804",
        "name":
            "Persistent Memory to Destructive Execution",
        "techniques": [
            "AI-TCH-2805",
            "AI-TCH-2806",
            "AI-TCH-2807",
            "AI-TCH-2808",
            "AI-TCH-2812",
            "AI-TCH-2820",
        ],
    },

    {
        "path_id": "PATH-2805",
        "name":
            "Credential Abuse to Destructive Business Impact",
        "techniques": [
            "AI-TCH-2813",
            "AI-TCH-2814",
            "AI-TCH-2808",
            "AI-TCH-2820",
        ],
    },

    {
        "path_id": "PATH-2806",
        "name":
            "Target Substitution to Restricted Record Destruction",
        "techniques": [
            "AI-TCH-2807",
            "AI-TCH-2809",
            "AI-TCH-2810",
            "AI-TCH-2808",
            "AI-TCH-2820",
        ],
    },

    {
        "path_id": "PATH-2807",
        "name":
            "Fake Approval to Authorization Bypass",
        "techniques": [
            "AI-TCH-2811",
            "AI-TCH-2812",
            "AI-TCH-2808",
        ],
    },

    {
        "path_id": "PATH-2808",
        "name":
            "Telemetry Evasion During Privileged Abuse",
        "techniques": [
            "AI-TCH-2817",
            "AI-TCH-2812",
            "AI-TCH-2808",
            "AI-TCH-2820",
        ],
    },
]


for path in ATTACK_PATHS:

    path["tactics"] = []

    for technique_id in path[
        "techniques"
    ]:

        tactic_id = TECHNIQUE_MAP[
            technique_id
        ]["tactic_id"]

        if tactic_id not in path[
            "tactics"
        ]:
            path["tactics"].append(
                tactic_id
            )


# ============================================================
# TACTIC / TECHNIQUE DISTRIBUTION
# ============================================================

technique_distribution = Counter()

tactic_distribution = Counter()

for threat in THREATS:

    for technique_id in threat[
        "techniques"
    ]:

        technique_distribution[
            technique_id
        ] += 1

        tactic_id = TECHNIQUE_MAP[
            technique_id
        ]["tactic_id"]

        tactic_distribution[
            tactic_id
        ] += 1


# ============================================================
# TACTIC-TO-THREAT INDEX
# ============================================================

tactic_to_threats = defaultdict(list)

for threat in THREATS:

    for tactic_id in threat[
        "tactics"
    ]:

        tactic_to_threats[
            tactic_id
        ].append(
            threat["threat_id"]
        )


# ============================================================
# DEFENSIVE CONTROL MAPPING
# ============================================================

CONTROLS = [
    {
        "control_id": "ATLAS-CTRL-01",
        "name":
            "Instruction Trust Separation",
        "techniques": [
            "AI-TCH-2801",
            "AI-TCH-2802",
            "AI-TCH-2804",
        ],
    },

    {
        "control_id": "ATLAS-CTRL-02",
        "name":
            "RAG Source & Provenance Validation",
        "techniques": [
            "AI-TCH-2803",
            "AI-TCH-2804",
        ],
    },

    {
        "control_id": "ATLAS-CTRL-03",
        "name":
            "Authorized Persistent Memory",
        "techniques": [
            "AI-TCH-2805",
            "AI-TCH-2806",
        ],
    },

    {
        "control_id": "ATLAS-CTRL-04",
        "name":
            "Agent Goal / Task Binding",
        "techniques": [
            "AI-TCH-2807",
        ],
    },

    {
        "control_id": "ATLAS-CTRL-05",
        "name":
            "Tool / Target / Parameter Validation",
        "techniques": [
            "AI-TCH-2808",
            "AI-TCH-2809",
            "AI-TCH-2810",
        ],
    },

    {
        "control_id": "ATLAS-CTRL-06",
        "name":
            "Fail-Closed Independent Authorization",
        "techniques": [
            "AI-TCH-2811",
            "AI-TCH-2812",
        ],
    },

    {
        "control_id": "ATLAS-CTRL-07",
        "name":
            "Secret Isolation & Least Privilege",
        "techniques": [
            "AI-TCH-2813",
            "AI-TCH-2814",
        ],
    },

    {
        "control_id": "ATLAS-CTRL-08",
        "name":
            "Sensitive Data Access Control",
        "techniques": [
            "AI-TCH-2815",
            "AI-TCH-2818",
            "AI-TCH-2819",
            "AI-TCH-2820",
        ],
    },

    {
        "control_id": "ATLAS-CTRL-09",
        "name":
            "Adversarial Input Detection",
        "techniques": [
            "AI-TCH-2816",
        ],
    },

    {
        "control_id": "ATLAS-CTRL-10",
        "name":
            "Tamper-Evident AI Security Telemetry",
        "techniques": [
            "AI-TCH-2817",
        ],
    },

    {
        "control_id": "ATLAS-CTRL-11",
        "name":
            "Execution Budgets & Resource Limits",
        "techniques": [
            "AI-TCH-2821",
        ],
    },

    {
        "control_id": "ATLAS-CTRL-12",
        "name":
            "AI Capability Exposure Management",
        "techniques": [
            "AI-TCH-2822",
        ],
    },
]


covered_techniques = {
    technique_id
    for control in CONTROLS
    for technique_id in control[
        "techniques"
    ]
}


# ============================================================
# DETECTION OPPORTUNITIES
# ============================================================

DETECTION_OPPORTUNITIES = [
    {
        "detection_id": "DET-ATLAS-2801",
        "name":
            "Prompt Injection Detection",
        "techniques": [
            "AI-TCH-2801",
            "AI-TCH-2802",
            "AI-TCH-2816",
        ],
    },

    {
        "detection_id": "DET-ATLAS-2802",
        "name":
            "RAG Poisoning Detection",
        "techniques": [
            "AI-TCH-2803",
            "AI-TCH-2804",
        ],
    },

    {
        "detection_id": "DET-ATLAS-2803",
        "name":
            "Persistent Memory Abuse Detection",
        "techniques": [
            "AI-TCH-2805",
            "AI-TCH-2806",
        ],
    },

    {
        "detection_id": "DET-ATLAS-2804",
        "name":
            "Agent Goal / Tool Abuse Detection",
        "techniques": [
            "AI-TCH-2807",
            "AI-TCH-2808",
            "AI-TCH-2809",
            "AI-TCH-2810",
        ],
    },

    {
        "detection_id": "DET-ATLAS-2805",
        "name":
            "Authorization Abuse Detection",
        "techniques": [
            "AI-TCH-2811",
            "AI-TCH-2812",
        ],
    },

    {
        "detection_id": "DET-ATLAS-2806",
        "name":
            "Credential / Secret Abuse Detection",
        "techniques": [
            "AI-TCH-2813",
            "AI-TCH-2814",
        ],
    },

    {
        "detection_id": "DET-ATLAS-2807",
        "name":
            "Sensitive Data Access Detection",
        "techniques": [
            "AI-TCH-2815",
            "AI-TCH-2818",
            "AI-TCH-2819",
            "AI-TCH-2820",
        ],
    },

    {
        "detection_id": "DET-ATLAS-2808",
        "name":
            "Telemetry Evasion Detection",
        "techniques": [
            "AI-TCH-2817",
        ],
    },

    {
        "detection_id": "DET-ATLAS-2809",
        "name":
            "Resource Exhaustion Detection",
        "techniques": [
            "AI-TCH-2821",
        ],
    },
]


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 90)
    print(f"        {title}")
    print("=" * 90)


header(
    "ATLAS-ALIGNED ADVERSARY TACTICS"
)

for tactic in TACTICS:

    print(
        f"{tactic['tactic_id']} | "
        f"{tactic['name']}"
    )

    print(
        f"  {tactic['description']}"
    )


header(
    "ATLAS-ALIGNED TECHNIQUE LIBRARY"
)

for technique in TECHNIQUES:

    tactic = TACTIC_MAP[
        technique["tactic_id"]
    ]

    print(
        f"{technique['technique_id']} | "
        f"{tactic['name']} | "
        f"{technique['name']}"
    )

    print(
        f"  {technique['description']}"
    )


header(
    "DAY 28 THREAT-TO-ADVERSARY MAPPING"
)

for threat in THREATS:

    print(
        f"{threat['threat_id']} | "
        f"{threat['severity']} | "
        f"{threat['name']}"
    )

    print(
        "  Techniques: "
        + ", ".join(
            threat["techniques"]
        )
    )

    print(
        "  Tactics: "
        + ", ".join(
            threat["tactics"]
        )
    )


header(
    "TACTIC COVERAGE"
)

for tactic in TACTICS:

    threats = tactic_to_threats.get(
        tactic["tactic_id"],
        []
    )

    print(
        f"{tactic['tactic_id']} | "
        f"{tactic['name']} | "
        f"Mapped Threats={len(threats)}"
    )

    if threats:

        print(
            "  Threats: "
            + ", ".join(
                threats
            )
        )


header(
    "TECHNIQUE EXPOSURE DISTRIBUTION"
)

for technique_id, count in sorted(
    technique_distribution.items(),
    key=lambda item: (
        -item[1],
        item[0]
    )
):

    technique = TECHNIQUE_MAP[
        technique_id
    ]

    print(
        f"{technique_id} | "
        f"Threat Mappings={count} | "
        f"{technique['name']}"
    )


header(
    "TACTIC EXPOSURE DISTRIBUTION"
)

for tactic_id, count in sorted(
    tactic_distribution.items(),
    key=lambda item: (
        -item[1],
        item[0]
    )
):

    print(
        f"{tactic_id} | "
        f"Threat Mappings={count} | "
        f"{TACTIC_MAP[tactic_id]['name']}"
    )


header(
    "ATTACK-PATH ADVERSARY CORRELATION"
)

for path in ATTACK_PATHS:

    print(
        f"{path['path_id']} | "
        f"{path['name']}"
    )

    print(
        "  Techniques: "
        + " -> ".join(
            path["techniques"]
        )
    )

    print(
        "  Tactics: "
        + " -> ".join(
            path["tactics"]
        )
    )


header(
    "ATLAS-ALIGNED SECURITY CONTROLS"
)

for control in CONTROLS:

    print(
        f"{control['control_id']} | "
        f"{control['name']}"
    )

    print(
        "  Techniques: "
        + ", ".join(
            control["techniques"]
        )
    )


header(
    "DETECTION ENGINEERING OPPORTUNITIES"
)

for detection in DETECTION_OPPORTUNITIES:

    print(
        f"{detection['detection_id']} | "
        f"{detection['name']}"
    )

    print(
        "  Detects: "
        + ", ".join(
            detection["techniques"]
        )
    )


# ============================================================
# SUMMARY
# ============================================================

header(
    "MITRE ATLAS-ALIGNED MAPPING SUMMARY"
)

mapped_threats = [
    threat
    for threat in THREATS
    if threat["techniques"]
]

mapped_tactics = {
    tactic_id
    for threat in THREATS
    for tactic_id in threat["tactics"]
}

mapped_techniques = {
    technique_id
    for threat in THREATS
    for technique_id
    in threat["techniques"]
}

high_critical_threats = [
    threat
    for threat in THREATS
    if threat["severity"]
    in {
        "HIGH",
        "CRITICAL"
    }
]


print(
    f"Adversary Tactics: "
    f"{len(TACTICS)}"
)

print(
    f"Technique Definitions: "
    f"{len(TECHNIQUES)}"
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
    f"{len(high_critical_threats)}"
)

print(
    f"Tactics Represented: "
    f"{len(mapped_tactics)} / "
    f"{len(TACTICS)}"
)

print(
    f"Techniques Represented: "
    f"{len(mapped_techniques)} / "
    f"{len(TECHNIQUES)}"
)

print(
    f"Attack Paths Correlated: "
    f"{len(ATTACK_PATHS)}"
)

print(
    f"Security Controls: "
    f"{len(CONTROLS)}"
)

print(
    f"Techniques With Control Coverage: "
    f"{len(covered_techniques)} / "
    f"{len(TECHNIQUES)}"
)

print(
    f"Detection Opportunities: "
    f"{len(DETECTION_OPPORTUNITIES)}"
)


# ============================================================
# VALIDATION
# ============================================================

header(
    "MITRE ATLAS-ALIGNED SECURITY CHECKS"
)


def technique_present(
    technique_name
):

    return any(
        technique["name"]
        == technique_name
        for technique in TECHNIQUES
    )


checks = {
    "All Threat Mappings Valid":
        all(
            threat["mapping_valid"]
            for threat in THREATS
        ),

    "All Threats Have Adversary Mapping":
        len(mapped_threats)
        == len(THREATS),

    "Reconnaissance Represented":
        "ATLAS-TA-01"
        in {
            tactic["tactic_id"]
            for tactic in TACTICS
        },

    "Prompt Injection Mapped":
        technique_present(
            "Prompt Injection"
        ),

    "RAG Poisoning Mapped":
        technique_present(
            "RAG Source Poisoning"
        ),

    "Persistent Memory Attack Mapped":
        technique_present(
            "Persistent Memory Poisoning"
        ),

    "Agent Abuse Mapped":
        technique_present(
            "Agent Goal Hijacking"
        ),

    "Tool Abuse Mapped":
        technique_present(
            "Tool Selection Manipulation"
        ),

    "Authorization Abuse Mapped":
        technique_present(
            "Authorization Bypass"
        ),

    "Credential Abuse Mapped":
        technique_present(
            "Credential Scope Abuse"
        ),

    "Sensitive Collection Mapped":
        technique_present(
            "Sensitive Context Extraction"
        ),

    "Business Impact Mapped":
        technique_present(
            "Restricted Data Destruction"
        ),

    "Defense Evasion Mapped":
        technique_present(
            "Telemetry Suppression"
        ),

    "Resource Exhaustion Mapped":
        technique_present(
            "Resource Exhaustion"
        ),

    "Attack Paths Correlated":
        all(
            path["techniques"]
            and path["tactics"]
            for path in ATTACK_PATHS
        ),

    "All Techniques Have Control Coverage":
        all(
            technique[
                "technique_id"
            ]
            in covered_techniques
            for technique in TECHNIQUES
        ),

    "Detection Opportunities Present":
        len(
            DETECTION_OPPORTUNITIES
        ) > 0,
}


for check, result in checks.items():

    print(
        f"{check}: {result}"
    )


atlas_mapping_valid = all(
    checks.values()
)


print(
    f"\nMITRE ATLAS Adversary Mapping Valid: "
    f"{atlas_mapping_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 11",

    "title":
        "MITRE ATLAS-Aligned Adversary Technique Mapping",

    "methodology_note":
        (
            "Synthetic technique and tactic identifiers are used "
            "for educational threat-modeling purposes and should "
            "not be represented as official MITRE ATLAS IDs."
        ),

    "tactics":
        TACTICS,

    "techniques":
        TECHNIQUES,

    "threats":
        THREATS,

    "attack_paths":
        ATTACK_PATHS,

    "controls":
        CONTROLS,

    "detection_opportunities":
        DETECTION_OPPORTUNITIES,

    "metrics": {
        "tactics":
            len(TACTICS),

        "techniques":
            len(TECHNIQUES),

        "threat_scenarios":
            len(THREATS),

        "mapped_threat_scenarios":
            len(mapped_threats),

        "high_critical_threats":
            len(high_critical_threats),

        "tactics_represented":
            len(mapped_tactics),

        "techniques_represented":
            len(mapped_techniques),

        "attack_paths_correlated":
            len(ATTACK_PATHS),

        "security_controls":
            len(CONTROLS),

        "techniques_with_control_coverage":
            len(covered_techniques),

        "detection_opportunities":
            len(DETECTION_OPPORTUNITIES),
    },

    "security_checks":
        checks,

    "atlas_mapping_valid":
        atlas_mapping_valid,
}


OUTPUT_FILE = (
    "day28-mitre-atlas-adversary-mapping-evidence.json"
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


print(
    "\nEvidence written to:"
)

print(
    OUTPUT_FILE
)


# ============================================================
# INTERPRETATION
# ============================================================

print(
    "\nSecurity Interpretation:"
)

print(
    "The ATLAS-aligned adversary mapping translates Day 28 "
    "AI threat scenarios into a threat-informed lifecycle covering "
    "initial access, attack staging, execution, persistence, "
    "authorization abuse, collection, defense evasion and impact."
)

print(
    "The same AI attack path may span multiple adversary tactics. "
    "For example, poisoned retrieval can become persistent memory, "
    "later influence an agent, trigger privileged tool selection, "
    "bypass authorization and ultimately affect business data."
)

print(
    "Threat-informed architecture should therefore combine preventive "
    "controls with detection opportunities at each major adversary stage "
    "rather than relying on a single prompt filter or model guardrail."
)

print(
    "\nCore Principle:"
)

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)