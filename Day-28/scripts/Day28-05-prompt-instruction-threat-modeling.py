"""
Day 28 Lab 5
Prompt & Instruction Threat Modeling

Purpose:
Model prompt and instruction-specific threats across direct prompts,
system prompts, retrieved content, memory, agent planning and downstream
execution.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter, defaultdict


print(
    "\n=== Day 28 Lab 5: "
    "Prompt & Instruction Threat Modeling ===\n"
)


# ============================================================
# INSTRUCTION TRUST LEVELS
# ============================================================

TRUST_LEVELS = {
    "SYSTEM": 5,
    "DEVELOPER": 4,
    "APPLICATION_POLICY": 4,
    "AUTHORIZED_USER_TASK": 3,
    "RAG_CONTEXT": 1,
    "PERSISTENT_MEMORY": 1,
    "EXTERNAL_CONTENT": 0,
    "UNTRUSTED_USER_INPUT": 0,
}


# ============================================================
# INSTRUCTION SOURCES
# ============================================================

INSTRUCTION_SOURCES = [
    {
        "source_id": "SRC-2801",
        "name": "System Prompt",
        "type": "SYSTEM",
        "trusted": True,
        "persistent": True,
        "user_controlled": False,
    },
    {
        "source_id": "SRC-2802",
        "name": "Application Security Policy",
        "type": "APPLICATION_POLICY",
        "trusted": True,
        "persistent": True,
        "user_controlled": False,
    },
    {
        "source_id": "SRC-2803",
        "name": "Authorized User Task",
        "type": "AUTHORIZED_USER_TASK",
        "trusted": True,
        "persistent": False,
        "user_controlled": True,
    },
    {
        "source_id": "SRC-2804",
        "name": "Untrusted User Prompt Content",
        "type": "UNTRUSTED_USER_INPUT",
        "trusted": False,
        "persistent": False,
        "user_controlled": True,
    },
    {
        "source_id": "SRC-2805",
        "name": "Retrieved RAG Context",
        "type": "RAG_CONTEXT",
        "trusted": False,
        "persistent": False,
        "user_controlled": False,
    },
    {
        "source_id": "SRC-2806",
        "name": "Persistent AI Memory",
        "type": "PERSISTENT_MEMORY",
        "trusted": False,
        "persistent": True,
        "user_controlled": False,
    },
    {
        "source_id": "SRC-2807",
        "name": "External Tool / Web Content",
        "type": "EXTERNAL_CONTENT",
        "trusted": False,
        "persistent": False,
        "user_controlled": False,
    },
]


# ============================================================
# PROMPT / INSTRUCTION THREATS
# ============================================================

THREATS = [
    {
        "threat_id": "PTH-2801",
        "name": "Direct Prompt Injection",
        "category": "PROMPT_INJECTION",
        "source": "SRC-2804",
        "target": "System Prompt",
        "technique":
            "User input explicitly attempts to override trusted instructions.",
        "impact":
            "Trusted task or security policy may be replaced by attacker intent.",
        "likelihood": 5,
        "impact_score": 4,
    },

    {
        "threat_id": "PTH-2802",
        "name": "Indirect Prompt Injection",
        "category": "PROMPT_INJECTION",
        "source": "SRC-2805",
        "target": "LLM Runtime",
        "technique":
            "Retrieved content embeds instructions that are interpreted as executable guidance.",
        "impact":
            "Untrusted RAG content may steer model behavior.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2803",
        "name": "External Content Instruction Injection",
        "category": "PROMPT_INJECTION",
        "source": "SRC-2807",
        "target": "LLM Runtime",
        "technique":
            "Tool, webpage, document, or external content contains hidden or explicit instructions.",
        "impact":
            "External data may gain instruction authority.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2804",
        "name": "Instruction Hierarchy Confusion",
        "category": "TRUST_CONFUSION",
        "source": "SRC-2804",
        "target": "Instruction Resolver",
        "technique":
            "Lower-trust instructions are interpreted as having equal or greater priority than trusted instructions.",
        "impact":
            "Security boundaries encoded in higher-priority instructions may fail.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2805",
        "name": "Fake Administrator Authority",
        "category": "AUTHORITY_SPOOFING",
        "source": "SRC-2804",
        "target": "Application Policy",
        "technique":
            "Prompt claims that an administrator, security team, or trusted authority approved an exception.",
        "impact":
            "Untrusted language may be mistaken for authorization.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2806",
        "name": "Retrieved Authority Spoofing",
        "category": "AUTHORITY_SPOOFING",
        "source": "SRC-2805",
        "target": "Agent Planner",
        "technique":
            "RAG document claims approval, policy authority, or trusted identity.",
        "impact":
            "Retrieved text may influence privileged agent behavior.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2807",
        "name": "System Prompt Extraction",
        "category": "PROMPT_DISCLOSURE",
        "source": "SRC-2804",
        "target": "System Prompt",
        "technique":
            "Attacker requests hidden system instructions or uses transformation techniques to reveal them.",
        "impact":
            "Confidential security instructions and implementation details may be disclosed.",
        "likelihood": 4,
        "impact_score": 3,
    },

    {
        "threat_id": "PTH-2808",
        "name": "Policy Extraction",
        "category": "PROMPT_DISCLOSURE",
        "source": "SRC-2804",
        "target": "Application Security Policy",
        "technique":
            "Attacker attempts to reconstruct hidden policy or guardrail logic.",
        "impact":
            "Defensive logic may become easier to target.",
        "likelihood": 3,
        "impact_score": 3,
    },

    {
        "threat_id": "PTH-2809",
        "name": "Role-Play Policy Evasion",
        "category": "JAILBREAK",
        "source": "SRC-2804",
        "target": "LLM Runtime",
        "technique":
            "Attacker reframes restricted behavior as role-play, simulation, fiction, or alternate persona.",
        "impact":
            "Policy restrictions may be weakened or bypassed.",
        "likelihood": 4,
        "impact_score": 4,
    },

    {
        "threat_id": "PTH-2810",
        "name": "Instruction Encoding / Obfuscation",
        "category": "JAILBREAK",
        "source": "SRC-2804",
        "target": "Security Classifier",
        "technique":
            "Malicious instructions are encoded, fragmented, translated, or obfuscated to evade detection.",
        "impact":
            "Prompt security controls may fail to identify adversarial intent.",
        "likelihood": 4,
        "impact_score": 4,
    },

    {
        "threat_id": "PTH-2811",
        "name": "Persistent Instruction Poisoning",
        "category": "MEMORY_INSTRUCTION",
        "source": "SRC-2806",
        "target": "Future Session",
        "technique":
            "Malicious instructions stored in memory are retrieved during later interactions.",
        "impact":
            "Prompt compromise may persist beyond the originating session.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2812",
        "name": "Cross-Session Instruction Propagation",
        "category": "MEMORY_INSTRUCTION",
        "source": "SRC-2806",
        "target": "Different Agent / Session",
        "technique":
            "Stored state from one trust context influences another session or agent.",
        "impact":
            "Compromise may propagate across users, tasks, sessions, or agents.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2813",
        "name": "Prompt-to-Tool Target Substitution",
        "category": "EXECUTION_STEERING",
        "source": "SRC-2804",
        "target": "Tool Router",
        "technique":
            "Prompt manipulates the target or parameters of a legitimate tool action.",
        "impact":
            "Authorized functionality may be redirected toward restricted resources.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2814",
        "name": "Prompt-to-Privileged-Tool Escalation",
        "category": "EXECUTION_STEERING",
        "source": "SRC-2804",
        "target": "Privileged Tool",
        "technique":
            "Prompt influences the model or agent to request a tool with greater privilege than the trusted task requires.",
        "impact":
            "Natural-language manipulation may approach privileged execution.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2815",
        "name": "Prompt-Generated Approval",
        "category": "AUTHORIZATION_CONFUSION",
        "source": "SRC-2804",
        "target": "Authorization Service",
        "technique":
            "Model output fabricates an approval token, approval statement, or authorization state.",
        "impact":
            "Generated text may be incorrectly accepted as authorization evidence.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2816",
        "name": "Context-Generated Authorization",
        "category": "AUTHORIZATION_CONFUSION",
        "source": "SRC-2805",
        "target": "Authorization Service",
        "technique":
            "Retrieved context claims that a requested action is approved.",
        "impact":
            "External data may be incorrectly converted into execution authority.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2817",
        "name": "Prompt-Induced Secret Retrieval",
        "category": "SENSITIVE_INFORMATION",
        "source": "SRC-2804",
        "target": "Secret Store",
        "technique":
            "Prompt attempts to cause the application or agent to retrieve credentials unnecessarily.",
        "impact":
            "Secrets may enter model context or logs.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2818",
        "name": "Prompt-Induced Sensitive Record Access",
        "category": "SENSITIVE_INFORMATION",
        "source": "SRC-2804",
        "target": "Restricted Record",
        "technique":
            "Prompt manipulates retrieval or tool selection toward unauthorized business data.",
        "impact":
            "Confidential or restricted data may be exposed.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "PTH-2819",
        "name": "Prompt-Driven Resource Exhaustion",
        "category": "AVAILABILITY",
        "source": "SRC-2804",
        "target": "LLM Runtime",
        "technique":
            "Adversarial prompts generate excessive tokens, loops, tool calls, or retrieval cycles.",
        "impact":
            "Cost, availability, latency, or capacity may be affected.",
        "likelihood": 4,
        "impact_score": 3,
    },

    {
        "threat_id": "PTH-2820",
        "name": "Prompt-Based Logging Evasion",
        "category": "OBSERVABILITY",
        "source": "SRC-2804",
        "target": "Security Telemetry",
        "technique":
            "Prompt attempts to suppress, fragment, or obscure security-relevant actions.",
        "impact":
            "Detection and forensic reconstruction may be degraded.",
        "likelihood": 3,
        "impact_score": 4,
    },
]


# ============================================================
# RISK SCORING
# ============================================================

def classify(score):

    if score >= 20:
        return "CRITICAL"

    if score >= 15:
        return "HIGH"

    if score >= 8:
        return "MEDIUM"

    return "LOW"


for threat in THREATS:

    threat["risk_score"] = (
        threat["likelihood"]
        * threat["impact_score"]
    )

    threat["priority"] = classify(
        threat["risk_score"]
    )


# ============================================================
# CONTROL MODEL
# ============================================================

CONTROLS = [
    {
        "control_id": "PROMPT-CTRL-01",
        "name": "Explicit Instruction Hierarchy",
        "addresses": [
            "PTH-2801",
            "PTH-2804",
            "PTH-2809",
        ],
    },

    {
        "control_id": "PROMPT-CTRL-02",
        "name": "External Content Treated as Data",
        "addresses": [
            "PTH-2802",
            "PTH-2803",
            "PTH-2806",
        ],
    },

    {
        "control_id": "PROMPT-CTRL-03",
        "name": "Authority Claims Require Independent Verification",
        "addresses": [
            "PTH-2805",
            "PTH-2806",
            "PTH-2815",
            "PTH-2816",
        ],
    },

    {
        "control_id": "PROMPT-CTRL-04",
        "name": "Protected Prompt / Policy Isolation",
        "addresses": [
            "PTH-2807",
            "PTH-2808",
        ],
    },

    {
        "control_id": "PROMPT-CTRL-05",
        "name": "Prompt Injection Detection",
        "addresses": [
            "PTH-2801",
            "PTH-2802",
            "PTH-2803",
            "PTH-2810",
        ],
    },

    {
        "control_id": "PROMPT-CTRL-06",
        "name": "Authorized Memory Persistence",
        "addresses": [
            "PTH-2811",
            "PTH-2812",
        ],
    },

    {
        "control_id": "PROMPT-CTRL-07",
        "name": "Tool / Target Task Binding",
        "addresses": [
            "PTH-2813",
            "PTH-2814",
        ],
    },

    {
        "control_id": "PROMPT-CTRL-08",
        "name": "Independent Fail-Closed Authorization",
        "addresses": [
            "PTH-2814",
            "PTH-2815",
            "PTH-2816",
        ],
    },

    {
        "control_id": "PROMPT-CTRL-09",
        "name": "Secret & Data Least Privilege",
        "addresses": [
            "PTH-2817",
            "PTH-2818",
        ],
    },

    {
        "control_id": "PROMPT-CTRL-10",
        "name": "Resource & Tool Budgeting",
        "addresses": [
            "PTH-2819",
        ],
    },

    {
        "control_id": "PROMPT-CTRL-11",
        "name": "Tamper-Evident Security Telemetry",
        "addresses": [
            "PTH-2820",
        ],
    },
]


covered_threats = {
    threat_id
    for control in CONTROLS
    for threat_id in control["addresses"]
}


# ============================================================
# ATTACK CHAINS
# ============================================================

ABUSE_CHAINS = [
    {
        "chain_id": "PROMPT-CHAIN-01",
        "name": "Direct Prompt Injection to Privileged Execution",
        "steps": [
            "PTH-2801",
            "PTH-2804",
            "PTH-2814",
            "PTH-2815",
        ],
        "impact":
            "Untrusted prompt influences privileged execution.",
    },

    {
        "chain_id": "PROMPT-CHAIN-02",
        "name": "Indirect RAG Injection to Persistent Memory",
        "steps": [
            "PTH-2802",
            "PTH-2806",
            "PTH-2811",
            "PTH-2812",
        ],
        "impact":
            "Retrieved malicious instructions persist across sessions.",
    },

    {
        "chain_id": "PROMPT-CHAIN-03",
        "name": "Prompt Injection to Restricted Data",
        "steps": [
            "PTH-2801",
            "PTH-2813",
            "PTH-2818",
        ],
        "impact":
            "Prompt manipulation redirects authorized functionality toward restricted data.",
    },

    {
        "chain_id": "PROMPT-CHAIN-04",
        "name": "Prompt to Secret to Privileged Tool",
        "steps": [
            "PTH-2817",
            "PTH-2814",
            "PTH-2815",
        ],
        "impact":
            "Prompt manipulation obtains secret-bearing capability and approaches privileged execution.",
    },
]


# ============================================================
# ANALYSIS
# ============================================================

category_counter = Counter(
    threat["category"]
    for threat in THREATS
)

priority_counter = Counter(
    threat["priority"]
    for threat in THREATS
)

source_counter = Counter(
    threat["source"]
    for threat in THREATS
)

critical_high = [
    threat
    for threat in THREATS
    if threat["priority"]
    in {"CRITICAL", "HIGH"}
]

prompt_injection_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    == "PROMPT_INJECTION"
]

authorization_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    in {
        "AUTHORITY_SPOOFING",
        "AUTHORIZATION_CONFUSION",
    }
]

execution_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    == "EXECUTION_STEERING"
]


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 84)
    print(f"        {title}")
    print("=" * 84)


header("INSTRUCTION TRUST SOURCES")

for source in INSTRUCTION_SOURCES:

    trust = TRUST_LEVELS[
        source["type"]
    ]

    print(
        f"{source['source_id']} | "
        f"Trust={trust} | "
        f"{source['type']} | "
        f"{source['name']}"
    )

    print(
        f"  Trusted: {source['trusted']} | "
        f"Persistent: {source['persistent']} | "
        f"User Controlled: {source['user_controlled']}"
    )


header("PROMPT / INSTRUCTION THREAT REGISTER")

for threat in THREATS:

    print(
        f"{threat['threat_id']} | "
        f"{threat['category']} | "
        f"{threat['priority']} | "
        f"Risk={threat['risk_score']} | "
        f"{threat['name']}"
    )

    print(
        f"  Source: {threat['source']}"
    )

    print(
        f"  Target: {threat['target']}"
    )

    print(
        f"  Technique: {threat['technique']}"
    )

    print(
        f"  Impact: {threat['impact']}"
    )


header("PROMPT THREAT CATEGORY DISTRIBUTION")

for category, count in sorted(
    category_counter.items()
):

    print(
        f"{category}: {count}"
    )


header("PROMPT THREAT PRIORITY DISTRIBUTION")

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


header("HIGH / CRITICAL PROMPT THREATS")

for threat in sorted(
    critical_high,
    key=lambda item: item["risk_score"],
    reverse=True,
):

    print(
        f"{threat['threat_id']} | "
        f"{threat['priority']} | "
        f"Risk={threat['risk_score']} | "
        f"{threat['name']}"
    )


header("PROMPT INJECTION THREATS")

for threat in prompt_injection_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['name']}"
    )


header("AUTHORITY / AUTHORIZATION THREATS")

for threat in authorization_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['category']} | "
        f"{threat['name']}"
    )


header("EXECUTION-STEERING THREATS")

for threat in execution_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['name']}"
    )


header("CONTROL MAPPING")

for control in CONTROLS:

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


header("PROMPT ABUSE CHAINS")

for chain in ABUSE_CHAINS:

    print(
        f"{chain['chain_id']} | "
        f"{chain['name']}"
    )

    print(
        "  Path: "
        + " -> ".join(
            chain["steps"]
        )
    )

    print(
        f"  Impact: "
        f"{chain['impact']}"
    )


# ============================================================
# SUMMARY
# ============================================================

header("PROMPT / INSTRUCTION THREAT SUMMARY")

print(
    f"Instruction Sources: "
    f"{len(INSTRUCTION_SOURCES)}"
)

print(
    f"Prompt Threat Scenarios: "
    f"{len(THREATS)}"
)

print(
    f"Threat Categories: "
    f"{len(category_counter)}"
)

print(
    f"High/Critical Threats: "
    f"{len(critical_high)}"
)

print(
    f"Prompt Injection Threats: "
    f"{len(prompt_injection_threats)}"
)

print(
    f"Authority / Authorization Threats: "
    f"{len(authorization_threats)}"
)

print(
    f"Execution-Steering Threats: "
    f"{len(execution_threats)}"
)

print(
    f"Security Controls: "
    f"{len(CONTROLS)}"
)

print(
    f"Threats With Control Coverage: "
    f"{len(covered_threats)} / "
    f"{len(THREATS)}"
)

print(
    f"Multi-Stage Prompt Abuse Chains: "
    f"{len(ABUSE_CHAINS)}"
)


# ============================================================
# VALIDATION
# ============================================================

header("PROMPT THREAT-MODEL SECURITY CHECKS")

threat_ids = [
    threat["threat_id"]
    for threat in THREATS
]

source_ids = {
    source["source_id"]
    for source in INSTRUCTION_SOURCES
}

checks = {
    "Unique Threat IDs":
        len(threat_ids)
        == len(set(threat_ids)),

    "All Threat Sources Valid":
        all(
            threat["source"]
            in source_ids
            for threat in THREATS
        ),

    "Direct Prompt Injection Identified":
        any(
            threat["name"]
            == "Direct Prompt Injection"
            for threat in THREATS
        ),

    "Indirect Prompt Injection Identified":
        any(
            threat["name"]
            == "Indirect Prompt Injection"
            for threat in THREATS
        ),

    "Instruction Hierarchy Threat Identified":
        any(
            threat["category"]
            == "TRUST_CONFUSION"
            for threat in THREATS
        ),

    "System Prompt Disclosure Identified":
        any(
            threat["name"]
            == "System Prompt Extraction"
            for threat in THREATS
        ),

    "Jailbreak Threats Identified":
        any(
            threat["category"]
            == "JAILBREAK"
            for threat in THREATS
        ),

    "Persistent Instruction Threats Identified":
        any(
            threat["category"]
            == "MEMORY_INSTRUCTION"
            for threat in THREATS
        ),

    "Authority Spoofing Identified":
        len(authorization_threats) > 0,

    "Prompt-to-Tool Threats Identified":
        len(execution_threats) > 0,

    "Sensitive Information Threats Identified":
        any(
            threat["category"]
            == "SENSITIVE_INFORMATION"
            for threat in THREATS
        ),

    "Availability Threat Identified":
        any(
            threat["category"]
            == "AVAILABILITY"
            for threat in THREATS
        ),

    "Observability Threat Identified":
        any(
            threat["category"]
            == "OBSERVABILITY"
            for threat in THREATS
        ),

    "All Threats Have Control Coverage":
        all(
            threat["threat_id"]
            in covered_threats
            for threat in THREATS
        ),

    "Multi-Stage Abuse Chains Identified":
        len(ABUSE_CHAINS) > 0,
}


for check, result in checks.items():

    print(
        f"{check}: {result}"
    )


prompt_threat_model_valid = all(
    checks.values()
)


print(
    f"\nPrompt / Instruction Threat Model Valid: "
    f"{prompt_threat_model_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 5",

    "title":
        "Prompt & Instruction Threat Modeling",

    "trust_levels":
        TRUST_LEVELS,

    "instruction_sources":
        INSTRUCTION_SOURCES,

    "threats":
        THREATS,

    "controls":
        CONTROLS,

    "abuse_chains":
        ABUSE_CHAINS,

    "metrics": {
        "instruction_sources":
            len(INSTRUCTION_SOURCES),

        "threat_scenarios":
            len(THREATS),

        "threat_categories":
            len(category_counter),

        "high_critical_threats":
            len(critical_high),

        "prompt_injection_threats":
            len(prompt_injection_threats),

        "authority_authorization_threats":
            len(authorization_threats),

        "execution_steering_threats":
            len(execution_threats),

        "security_controls":
            len(CONTROLS),

        "threats_with_control_coverage":
            len(covered_threats),

        "abuse_chains":
            len(ABUSE_CHAINS),
    },

    "security_checks":
        checks,

    "prompt_threat_model_valid":
        prompt_threat_model_valid,
}


OUTPUT_FILE = (
    "day28-prompt-instruction-threat-model-evidence.json"
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
    "Prompt and instruction security is fundamentally a trust-boundary "
    "problem. User prompts, retrieved documents, persistent memory and "
    "external content may contain language that looks like instructions, "
    "but those sources do not automatically possess application authority."
)

print(
    "The most dangerous abuse paths arise when untrusted natural-language "
    "content can influence memory persistence, agent planning, tool targets, "
    "authorization state, secrets, or privileged execution."
)

print(
    "Secure architecture should therefore separate instruction authority "
    "from content, require independent authorization for security-sensitive "
    "actions, and bind tool execution to trusted task state rather than "
    "model-generated claims."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)