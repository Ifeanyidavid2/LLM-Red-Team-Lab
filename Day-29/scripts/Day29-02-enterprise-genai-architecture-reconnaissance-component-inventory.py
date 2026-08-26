"""
Day 29 Lab 2
Enterprise GenAI Architecture Reconnaissance & Component Inventory

Purpose:
Perform authorized architecture reconnaissance against the synthetic
enterprise GenAI application and establish a security-focused inventory
of components, interfaces, assets, trust characteristics, dependencies,
and preliminary exposure priorities.
"""

from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
import hashlib
import json


ENGAGEMENT_ID = "ENG-2901"
SYSTEM_ID = "ENT-AI-2901"
TRACE_ID = "TRACE-2902"


COMPONENTS = [
    {
        "id": "COMP-2901",
        "name": "Enterprise User",
        "type": "identity",
        "trust": "external_authenticated",
        "criticality": "HIGH",
        "exposure": "external",
        "data": ["user_identity", "user_prompt"],
    },
    {
        "id": "COMP-2902",
        "name": "AI Assistant",
        "type": "application",
        "trust": "application_boundary",
        "criticality": "HIGH",
        "exposure": "external",
        "data": ["prompt", "response", "session_context"],
    },
    {
        "id": "COMP-2903",
        "name": "LLM Runtime",
        "type": "model",
        "trust": "trusted_runtime",
        "criticality": "CRITICAL",
        "exposure": "internal",
        "data": ["system_prompt", "runtime_context", "model_output"],
    },
    {
        "id": "COMP-2904",
        "name": "RAG Knowledge System",
        "type": "retrieval",
        "trust": "mixed_trust",
        "criticality": "HIGH",
        "exposure": "internal",
        "data": ["documents", "embeddings", "retrieved_context"],
    },
    {
        "id": "COMP-2905",
        "name": "Persistent Memory",
        "type": "memory",
        "trust": "sensitive_persistent_state",
        "criticality": "CRITICAL",
        "exposure": "internal",
        "data": ["memory_records", "preferences", "persistent_context"],
    },
    {
        "id": "COMP-2906",
        "name": "Agent Planner",
        "type": "agent",
        "trust": "model_influenced",
        "criticality": "CRITICAL",
        "exposure": "internal",
        "data": ["goals", "plans", "tool_requests"],
    },
    {
        "id": "COMP-2907",
        "name": "Tools / APIs",
        "type": "execution",
        "trust": "privileged_boundary",
        "criticality": "CRITICAL",
        "exposure": "privileged",
        "data": ["tool_parameters", "api_requests", "execution_results"],
    },
    {
        "id": "COMP-2908",
        "name": "Authorization Service",
        "type": "security_control",
        "trust": "independent_trusted_control",
        "criticality": "CRITICAL",
        "exposure": "restricted",
        "data": ["identity_context", "authorization_decision"],
    },
    {
        "id": "COMP-2909",
        "name": "Business Data",
        "type": "business_asset",
        "trust": "restricted",
        "criticality": "CRITICAL",
        "exposure": "restricted",
        "data": ["enterprise_records", "restricted_records"],
    },
    {
        "id": "COMP-2910",
        "name": "Security Telemetry",
        "type": "observability",
        "trust": "trusted_security_evidence",
        "criticality": "HIGH",
        "exposure": "restricted",
        "data": ["audit_events", "security_alerts", "forensic_logs"],
    },
    {
        "id": "COMP-2911",
        "name": "Credential Broker",
        "type": "secret_management",
        "trust": "restricted",
        "criticality": "CRITICAL",
        "exposure": "restricted",
        "data": ["api_credentials", "task_tokens"],
    },
]


INTERFACES = [
    {
        "id": "IFACE-2901",
        "source": "Enterprise User",
        "destination": "AI Assistant",
        "data": "User Prompt",
        "trust_crossing": True,
    },
    {
        "id": "IFACE-2902",
        "source": "AI Assistant",
        "destination": "LLM Runtime",
        "data": "Prompt + Session Context",
        "trust_crossing": True,
    },
    {
        "id": "IFACE-2903",
        "source": "LLM Runtime",
        "destination": "RAG Knowledge System",
        "data": "Retrieval Query",
        "trust_crossing": True,
    },
    {
        "id": "IFACE-2904",
        "source": "RAG Knowledge System",
        "destination": "LLM Runtime",
        "data": "Retrieved Documents",
        "trust_crossing": True,
    },
    {
        "id": "IFACE-2905",
        "source": "LLM Runtime",
        "destination": "Persistent Memory",
        "data": "Proposed Memory Write",
        "trust_crossing": True,
    },
    {
        "id": "IFACE-2906",
        "source": "Persistent Memory",
        "destination": "Agent Planner",
        "data": "Persistent Context",
        "trust_crossing": True,
    },
    {
        "id": "IFACE-2907",
        "source": "LLM Runtime",
        "destination": "Agent Planner",
        "data": "Proposed Goal / Plan",
        "trust_crossing": True,
    },
    {
        "id": "IFACE-2908",
        "source": "Agent Planner",
        "destination": "Authorization Service",
        "data": "Proposed Tool Action",
        "trust_crossing": True,
    },
    {
        "id": "IFACE-2909",
        "source": "Authorization Service",
        "destination": "Tools / APIs",
        "data": "Authorization Decision",
        "trust_crossing": True,
    },
    {
        "id": "IFACE-2910",
        "source": "Credential Broker",
        "destination": "Tools / APIs",
        "data": "Task Credential",
        "trust_crossing": True,
    },
    {
        "id": "IFACE-2911",
        "source": "Tools / APIs",
        "destination": "Business Data",
        "data": "Business Transaction",
        "trust_crossing": True,
    },
    {
        "id": "IFACE-2912",
        "source": "All Components",
        "destination": "Security Telemetry",
        "data": "Security Events",
        "trust_crossing": True,
    },
]


SECURITY_ASSETS = [
    ("ASSET-2901", "System Prompt", "CRITICAL"),
    ("ASSET-2902", "User Prompt", "HIGH"),
    ("ASSET-2903", "Retrieved Context", "HIGH"),
    ("ASSET-2904", "Persistent Memory", "CRITICAL"),
    ("ASSET-2905", "Agent Goal / Plan", "CRITICAL"),
    ("ASSET-2906", "Tool Parameters", "CRITICAL"),
    ("ASSET-2907", "Authorization Decision", "CRITICAL"),
    ("ASSET-2908", "API Credentials", "CRITICAL"),
    ("ASSET-2909", "Restricted Business Records", "CRITICAL"),
    ("ASSET-2910", "Security Telemetry", "HIGH"),
]


ATTACK_SURFACE_HINTS = [
    {
        "surface": "User Prompt Interface",
        "component": "AI Assistant",
        "risk": "prompt_injection",
    },
    {
        "surface": "System Instruction Boundary",
        "component": "LLM Runtime",
        "risk": "instruction_override",
    },
    {
        "surface": "Retrieved Document Admission",
        "component": "RAG Knowledge System",
        "risk": "rag_poisoning",
    },
    {
        "surface": "Persistent Memory Write",
        "component": "Persistent Memory",
        "risk": "memory_poisoning",
    },
    {
        "surface": "Persistent Memory Read",
        "component": "Persistent Memory",
        "risk": "cross_session_influence",
    },
    {
        "surface": "Agent Goal Generation",
        "component": "Agent Planner",
        "risk": "goal_hijacking",
    },
    {
        "surface": "Tool Selection",
        "component": "Tools / APIs",
        "risk": "privileged_tool_abuse",
    },
    {
        "surface": "Tool Parameters",
        "component": "Tools / APIs",
        "risk": "parameter_manipulation",
    },
    {
        "surface": "Authorization Decision",
        "component": "Authorization Service",
        "risk": "authorization_bypass",
    },
    {
        "surface": "Credential Delivery",
        "component": "Credential Broker",
        "risk": "credential_abuse",
    },
    {
        "surface": "Business Resource",
        "component": "Business Data",
        "risk": "unauthorized_business_impact",
    },
    {
        "surface": "Audit Pipeline",
        "component": "Security Telemetry",
        "risk": "telemetry_suppression",
    },
]


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
    print("\n" + "=" * 88)
    print(f"        {title}")
    print("=" * 88)


def exposure_score(component):
    criticality = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    exposure = {
        "internal": 1,
        "external": 3,
        "privileged": 4,
        "restricted": 2,
    }

    trust_bonus = 2 if component["trust"] in {
        "mixed_trust",
        "model_influenced",
        "privileged_boundary",
    } else 0

    return (
        criticality[component["criticality"]] * 3
        + exposure[component["exposure"]]
        + trust_bonus
    )


def main():
    print(
        "\n=== Day 29 Lab 2: Enterprise GenAI Architecture "
        "Reconnaissance & Component Inventory ==="
    )

    timestamp = datetime.now(timezone.utc).isoformat()

    header("RECONNAISSANCE CONTEXT")

    print(f"Engagement ID: {ENGAGEMENT_ID}")
    print(f"System ID: {SYSTEM_ID}")
    print(f"Trace ID: {TRACE_ID}")
    print(f"Timestamp UTC: {timestamp}")
    print("Assessment Mode: Authorized synthetic architecture reconnaissance")

    header("DISCOVERED ENTERPRISE GENAI COMPONENTS")

    for component in COMPONENTS:
        score = exposure_score(component)

        print(
            f"{component['id']} | "
            f"{component['name']} | "
            f"{component['type']} | "
            f"{component['criticality']} | "
            f"Exposure Score={score}"
        )
        print(
            f"  Trust: {component['trust']} | "
            f"Exposure: {component['exposure']}"
        )
        print(
            "  Data: "
            + ", ".join(component["data"])
        )

    header("ARCHITECTURE INTERFACES & TRUST CROSSINGS")

    for interface in INTERFACES:
        print(
            f"{interface['id']} | "
            f"{interface['source']} -> "
            f"{interface['destination']}"
        )
        print(
            f"  Data: {interface['data']} | "
            f"Trust Crossing={interface['trust_crossing']}"
        )

    header("SECURITY-RELEVANT ASSETS")

    for asset_id, name, criticality in SECURITY_ASSETS:
        print(
            f"{asset_id} | "
            f"{criticality} | "
            f"{name}"
        )

    header("PRELIMINARY ATTACK-SURFACE OBSERVATIONS")

    for index, surface in enumerate(
        ATTACK_SURFACE_HINTS,
        start=1,
    ):
        print(
            f"SURFACE-{index:04d} | "
            f"{surface['surface']} | "
            f"{surface['component']}"
        )
        print(f"  Preliminary Risk: {surface['risk']}")

    header("COMPONENT TYPE DISTRIBUTION")

    type_distribution = Counter(
        component["type"]
        for component in COMPONENTS
    )

    for key, value in sorted(type_distribution.items()):
        print(f"{key}: {value}")

    header("CRITICALITY DISTRIBUTION")

    criticality_distribution = Counter(
        component["criticality"]
        for component in COMPONENTS
    )

    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(
            f"{level.lower()}: "
            f"{criticality_distribution.get(level, 0)}"
        )

    header("HIGH-PRIORITY RECONNAISSANCE TARGETS")

    ranked = sorted(
        COMPONENTS,
        key=exposure_score,
        reverse=True,
    )

    for component in ranked:
        score = exposure_score(component)

        if score >= 12:
            print(
                f"{component['id']} | "
                f"Score={score} | "
                f"{component['criticality']} | "
                f"{component['name']}"
            )

    header("RECONNAISSANCE SECURITY CHECKS")

    component_ids = [x["id"] for x in COMPONENTS]
    interface_ids = [x["id"] for x in INTERFACES]

    component_names = {
        component["name"]
        for component in COMPONENTS
    }

    checks = {
        "Unique Component IDs":
            len(component_ids) == len(set(component_ids)),

        "Unique Interface IDs":
            len(interface_ids) == len(set(interface_ids)),

        "Enterprise User Identified":
            "Enterprise User" in component_names,

        "AI Assistant Identified":
            "AI Assistant" in component_names,

        "LLM Runtime Identified":
            "LLM Runtime" in component_names,

        "RAG System Identified":
            "RAG Knowledge System" in component_names,

        "Persistent Memory Identified":
            "Persistent Memory" in component_names,

        "Agent Planner Identified":
            "Agent Planner" in component_names,

        "Tool / API Boundary Identified":
            "Tools / APIs" in component_names,

        "Authorization Service Identified":
            "Authorization Service" in component_names,

        "Business Data Identified":
            "Business Data" in component_names,

        "Credential Broker Identified":
            "Credential Broker" in component_names,

        "Security Telemetry Identified":
            "Security Telemetry" in component_names,

        "Trust Crossings Identified":
            any(x["trust_crossing"] for x in INTERFACES),

        "Attack Surface Candidates Identified":
            len(ATTACK_SURFACE_HINTS) > 0,
    }

    checks["Architecture Reconnaissance Valid"] = all(
        checks.values()
    )

    for check, result in checks.items():
        print(f"{check}: {result}")

    header("RECONNAISSANCE SUMMARY")

    print(f"Components Discovered: {len(COMPONENTS)}")
    print(f"Architecture Interfaces: {len(INTERFACES)}")
    print(f"Security Assets: {len(SECURITY_ASSETS)}")
    print(
        "Trust Crossings: "
        f"{sum(x['trust_crossing'] for x in INTERFACES)}"
    )
    print(
        "Preliminary Attack Surfaces: "
        f"{len(ATTACK_SURFACE_HINTS)}"
    )
    print(
        "Critical Components: "
        f"{criticality_distribution.get('CRITICAL', 0)}"
    )

    evidence = {
        "engagement_id": ENGAGEMENT_ID,
        "system_id": SYSTEM_ID,
        "trace_id": TRACE_ID,
        "timestamp_utc": timestamp,
        "components": COMPONENTS,
        "interfaces": INTERFACES,
        "security_assets": [
            {
                "asset_id": asset_id,
                "name": name,
                "criticality": criticality,
            }
            for asset_id, name, criticality
            in SECURITY_ASSETS
        ],
        "attack_surface_hints": ATTACK_SURFACE_HINTS,
        "security_checks": checks,
    }

    evidence["evidence_hash"] = hash_data(evidence)

    evidence_path = Path(
        "day29-enterprise-genai-architecture-recon-evidence.json"
    )

    evidence_path.write_text(
        json.dumps(
            evidence,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print("\nEvidence written to:")
    print(evidence_path)

    print("\nSecurity Interpretation:")
    print(
        "Architecture reconnaissance identifies the complete GenAI "
        "execution path rather than treating the LLM as an isolated "
        "security target."
    )
    print(
        "The assessment exposes security-relevant interfaces between "
        "user input, model runtime, retrieval, persistent memory, "
        "agent planning, authorization, credentials, tools, business "
        "data and observability."
    )
    print(
        "These interfaces provide the foundation for systematic attack "
        "surface mapping and later adversarial testing."
    )

    print("\nCore Principle:")
    print(
        "An LLM red team cannot reliably attack, defend or assess "
        "business risk in a system it has not first mapped."
    )


if __name__ == "__main__":
    main()