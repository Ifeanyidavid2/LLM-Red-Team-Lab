from collections import Counter, defaultdict
import json

print("\n=== Day 28 Lab 1: AI System & Security Asset Inventory ===\n")

SYSTEM = {
    "system_id": "AI-SYSTEM-2801",
    "name": "synthetic-enterprise-ai-assistant",
    "environment": "day28-threat-model-lab",
    "version": "v1.0.0",
    "business_function": "Enterprise knowledge retrieval and authorized workflow automation",
    "deployment_stage": "pre-deployment-threat-model",
}

ASSETS = [
    {
        "asset_id": "ASSET-2801",
        "name": "User Prompt",
        "type": "instruction",
        "component": "input_gateway",
        "classification": "untrusted",
        "criticality": "high",
        "security_objectives": ["integrity"],
    },
    {
        "asset_id": "ASSET-2802",
        "name": "System Prompt",
        "type": "instruction",
        "component": "llm_runtime",
        "classification": "confidential",
        "criticality": "critical",
        "security_objectives": ["confidentiality", "integrity"],
    },
    {
        "asset_id": "ASSET-2803",
        "name": "LLM",
        "type": "model",
        "component": "llm_runtime",
        "classification": "internal",
        "criticality": "critical",
        "security_objectives": ["integrity", "availability"],
    },
    {
        "asset_id": "ASSET-2804",
        "name": "RAG Knowledge Store",
        "type": "retrieval",
        "component": "retrieval_service",
        "classification": "internal",
        "criticality": "high",
        "security_objectives": [
            "confidentiality",
            "integrity",
            "availability"
        ],
    },
    {
        "asset_id": "ASSET-2805",
        "name": "Retrieved Documents",
        "type": "context",
        "component": "retrieval_service",
        "classification": "mixed_trust",
        "criticality": "high",
        "security_objectives": ["integrity"],
    },
    {
        "asset_id": "ASSET-2806",
        "name": "Persistent AI Memory",
        "type": "memory",
        "component": "memory_service",
        "classification": "sensitive",
        "criticality": "critical",
        "security_objectives": [
            "confidentiality",
            "integrity",
            "availability"
        ],
    },
    {
        "asset_id": "ASSET-2807",
        "name": "Agent Planner",
        "type": "agent",
        "component": "agent_runtime",
        "classification": "internal",
        "criticality": "critical",
        "security_objectives": ["integrity"],
    },
    {
        "asset_id": "ASSET-2808",
        "name": "Read Record Tool",
        "type": "tool",
        "component": "tool_runtime",
        "classification": "internal",
        "criticality": "medium",
        "security_objectives": ["integrity", "availability"],
    },
    {
        "asset_id": "ASSET-2809",
        "name": "Delete Record Tool",
        "type": "privileged_tool",
        "component": "tool_runtime",
        "classification": "restricted",
        "criticality": "critical",
        "security_objectives": ["integrity", "availability"],
    },
    {
        "asset_id": "ASSET-2810",
        "name": "Authorization Service",
        "type": "security_control",
        "component": "authorization_service",
        "classification": "restricted",
        "criticality": "critical",
        "security_objectives": ["integrity", "availability"],
    },
    {
        "asset_id": "ASSET-2811",
        "name": "User Identity",
        "type": "identity",
        "component": "identity_service",
        "classification": "sensitive",
        "criticality": "high",
        "security_objectives": [
            "confidentiality",
            "integrity"
        ],
    },
    {
        "asset_id": "ASSET-2812",
        "name": "API Credential",
        "type": "secret",
        "component": "secret_store",
        "classification": "restricted",
        "criticality": "critical",
        "security_objectives": ["confidentiality", "integrity"],
    },
    {
        "asset_id": "ASSET-2813",
        "name": "Restricted Record R-2899",
        "type": "business_data",
        "component": "record_service",
        "classification": "restricted",
        "criticality": "critical",
        "security_objectives": [
            "confidentiality",
            "integrity",
            "availability"
        ],
    },
    {
        "asset_id": "ASSET-2814",
        "name": "Security Telemetry",
        "type": "security_data",
        "component": "detection_engine",
        "classification": "sensitive",
        "criticality": "high",
        "security_objectives": [
            "confidentiality",
            "integrity",
            "availability"
        ],
    },
]

TRUST_LEVELS = {
    "untrusted": 0,
    "mixed_trust": 1,
    "internal": 2,
    "sensitive": 3,
    "confidential": 4,
    "restricted": 5,
}

CRITICALITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def print_header(title):
    print("\n" + "=" * 78)
    print(f"        {title}")
    print("=" * 78)


print_header("SYSTEM UNDER THREAT MODEL")

print(json.dumps(SYSTEM, indent=2))


print_header("AI SECURITY ASSET INVENTORY")

for asset in ASSETS:
    print(
        f"{asset['asset_id']} | "
        f"{asset['type']} | "
        f"{asset['criticality'].upper()} | "
        f"{asset['name']}"
    )

    print(f"  Component: {asset['component']}")
    print(f"  Classification: {asset['classification']}")
    print(
        "  Security Objectives: "
        + ", ".join(asset["security_objectives"])
    )


print_header("ASSET TYPE DISTRIBUTION")

type_counts = Counter(asset["type"] for asset in ASSETS)

for asset_type, count in sorted(type_counts.items()):
    print(f"{asset_type}: {count}")


print_header("CRITICALITY DISTRIBUTION")

criticality_counts = Counter(
    asset["criticality"] for asset in ASSETS
)

for criticality in ["critical", "high", "medium", "low"]:
    print(
        f"{criticality}: "
        f"{criticality_counts.get(criticality, 0)}"
    )


print_header("SECURITY OBJECTIVE COVERAGE")

objective_assets = defaultdict(list)

for asset in ASSETS:
    for objective in asset["security_objectives"]:
        objective_assets[objective].append(asset["asset_id"])

for objective in [
    "confidentiality",
    "integrity",
    "availability"
]:
    assets = objective_assets.get(objective, [])

    print(
        f"{objective}: "
        f"{len(assets)} assets | "
        f"{assets}"
    )


print_header("HIGH-VALUE AI ASSETS")

high_value_assets = [
    asset
    for asset in ASSETS
    if asset["criticality"] == "critical"
]

for asset in high_value_assets:
    print(
        f"{asset['asset_id']} | "
        f"{asset['name']} | "
        f"{asset['component']}"
    )

print(
    f"\nCritical Asset Count: "
    f"{len(high_value_assets)}"
)


print_header("TRUST-SENSITIVE ASSETS")

trust_sensitive = [
    asset
    for asset in ASSETS
    if asset["classification"]
    in {
        "untrusted",
        "mixed_trust",
        "confidential",
        "restricted"
    }
]

for asset in trust_sensitive:
    print(
        f"{asset['asset_id']} | "
        f"{asset['name']} | "
        f"Trust/Class={asset['classification']}"
    )


print_header("ASSET RISK EXPOSURE PRIORITY")

risk_priority = []

for asset in ASSETS:

    criticality_score = CRITICALITY_WEIGHTS[
        asset["criticality"]
    ]

    trust_score = TRUST_LEVELS[
        asset["classification"]
    ]

    objective_score = len(
        asset["security_objectives"]
    )

    exposure_score = (
        criticality_score * 3
        + objective_score
        + (
            2
            if asset["classification"]
            in {"untrusted", "mixed_trust"}
            else 0
        )
    )

    risk_priority.append({
        "asset_id": asset["asset_id"],
        "name": asset["name"],
        "score": exposure_score,
        "criticality": asset["criticality"],
        "classification": asset["classification"],
        "trust_reference": trust_score,
    })

risk_priority.sort(
    key=lambda item: item["score"],
    reverse=True
)

for item in risk_priority:
    print(
        f"{item['asset_id']} | "
        f"Score={item['score']} | "
        f"{item['criticality'].upper()} | "
        f"{item['name']}"
    )


print_header("PRELIMINARY SECURITY DEPENDENCIES")

DEPENDENCIES = [
    (
        "User Prompt",
        "LLM",
        "Untrusted instructions enter model processing"
    ),
    (
        "RAG Knowledge Store",
        "Retrieved Documents",
        "Retrieval integrity affects runtime context"
    ),
    (
        "Retrieved Documents",
        "LLM",
        "External context may influence model behavior"
    ),
    (
        "Persistent AI Memory",
        "Agent Planner",
        "Persistent state may influence future decisions"
    ),
    (
        "Agent Planner",
        "Delete Record Tool",
        "Model-generated plans may request privileged execution"
    ),
    (
        "Authorization Service",
        "Delete Record Tool",
        "Authorization must independently constrain execution"
    ),
    (
        "API Credential",
        "Tool Runtime",
        "Secrets may enable downstream service access"
    ),
    (
        "Delete Record Tool",
        "Restricted Record R-2899",
        "Privileged capability can create business impact"
    ),
]

for source, destination, reason in DEPENDENCIES:
    print(f"{source} -> {destination}")
    print(f"  Security Dependency: {reason}")


print_header("ASSET INVENTORY SECURITY CHECKS")

asset_ids = [
    asset["asset_id"]
    for asset in ASSETS
]

unique_ids = len(asset_ids) == len(set(asset_ids))

has_model = any(
    asset["type"] == "model"
    for asset in ASSETS
)

has_prompt = any(
    asset["type"] == "instruction"
    for asset in ASSETS
)

has_rag = any(
    asset["type"] == "retrieval"
    for asset in ASSETS
)

has_memory = any(
    asset["type"] == "memory"
    for asset in ASSETS
)

has_agent = any(
    asset["type"] == "agent"
    for asset in ASSETS
)

has_tool = any(
    asset["type"] in {"tool", "privileged_tool"}
    for asset in ASSETS
)

has_identity = any(
    asset["type"] == "identity"
    for asset in ASSETS
)

has_secret = any(
    asset["type"] == "secret"
    for asset in ASSETS
)

has_business_asset = any(
    asset["type"] == "business_data"
    for asset in ASSETS
)

checks = {
    "Unique Asset Identifiers": unique_ids,
    "Model Asset Identified": has_model,
    "Prompt / Instruction Assets Identified": has_prompt,
    "RAG Asset Identified": has_rag,
    "Persistent Memory Identified": has_memory,
    "Agent Asset Identified": has_agent,
    "Tool Assets Identified": has_tool,
    "Identity Asset Identified": has_identity,
    "Secret Asset Identified": has_secret,
    "Business-Critical Asset Identified": has_business_asset,
}

for name, result in checks.items():
    print(f"{name}: {result}")


inventory_valid = all(checks.values())

print(
    f"\nTotal Assets: {len(ASSETS)}"
)

print(
    f"Critical Assets: {len(high_value_assets)}"
)

print(
    f"Asset Inventory Valid: {inventory_valid}"
)


print("\nSecurity Interpretation:")
print(
    "The Day 28 threat model begins with an explicit inventory of "
    "AI and business assets rather than treating the LLM as the only "
    "security-relevant component."
)

print(
    "The inventory identifies prompts, model runtime, retrieved "
    "context, persistent memory, agents, tools, authorization, "
    "identities, credentials, business data, and security telemetry."
)

print(
    "Asset criticality, classification, security objectives, "
    "dependencies, and preliminary exposure priority provide the "
    "foundation for later trust-boundary mapping, attack-surface "
    "analysis, threat enumeration, risk scoring, and architecture."
)

print("\nCore Principle:")
print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)