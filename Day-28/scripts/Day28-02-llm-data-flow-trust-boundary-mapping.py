"""
Day 28 Lab 2
LLM Data-Flow Diagram & Trust-Boundary Mapping

Purpose:
Model AI data flows, components, trust zones, trust-boundary crossings,
and security-relevant dependencies before deployment.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter, defaultdict


print(
    "\n=== Day 28 Lab 2: "
    "LLM Data-Flow Diagram & Trust-Boundary Mapping ===\n"
)


# ============================================================
# SYSTEM
# ============================================================

SYSTEM = {
    "system_id": "AI-SYSTEM-2801",
    "name": "synthetic-enterprise-ai-assistant",
    "environment": "day28-threat-model-lab",
    "version": "v1.0.0",
}


# ============================================================
# TRUST ZONES
# ============================================================

TRUST_ZONES = {
    "ZONE-01": {
        "name": "External / Untrusted",
        "trust_level": 0,
        "description":
            "User-controlled or externally supplied input."
    },

    "ZONE-02": {
        "name": "Application Edge",
        "trust_level": 1,
        "description":
            "Input validation, API gateway and session boundary."
    },

    "ZONE-03": {
        "name": "AI Runtime",
        "trust_level": 2,
        "description":
            "LLM, context construction and agent planning."
    },

    "ZONE-04": {
        "name": "Data & Memory",
        "trust_level": 3,
        "description":
            "RAG stores, retrieved context and persistent memory."
    },

    "ZONE-05": {
        "name": "Security Control Plane",
        "trust_level": 4,
        "description":
            "Identity, authorization, secret and policy controls."
    },

    "ZONE-06": {
        "name": "Privileged Execution",
        "trust_level": 5,
        "description":
            "Privileged tools and downstream business operations."
    },

    "ZONE-07": {
        "name": "Security Monitoring",
        "trust_level": 4,
        "description":
            "Detection, logging and security telemetry."
    },
}


# ============================================================
# COMPONENTS
# ============================================================

COMPONENTS = [
    {
        "component_id": "COMP-2801",
        "name": "User",
        "type": "external_entity",
        "zone": "ZONE-01",
    },

    {
        "component_id": "COMP-2802",
        "name": "Input Gateway",
        "type": "process",
        "zone": "ZONE-02",
    },

    {
        "component_id": "COMP-2803",
        "name": "Identity Service",
        "type": "security_service",
        "zone": "ZONE-05",
    },

    {
        "component_id": "COMP-2804",
        "name": "LLM Runtime",
        "type": "ai_process",
        "zone": "ZONE-03",
    },

    {
        "component_id": "COMP-2805",
        "name": "RAG Knowledge Store",
        "type": "data_store",
        "zone": "ZONE-04",
    },

    {
        "component_id": "COMP-2806",
        "name": "Retrieval Service",
        "type": "process",
        "zone": "ZONE-04",
    },

    {
        "component_id": "COMP-2807",
        "name": "Persistent Memory",
        "type": "data_store",
        "zone": "ZONE-04",
    },

    {
        "component_id": "COMP-2808",
        "name": "Agent Planner",
        "type": "ai_process",
        "zone": "ZONE-03",
    },

    {
        "component_id": "COMP-2809",
        "name": "Authorization Service",
        "type": "security_service",
        "zone": "ZONE-05",
    },

    {
        "component_id": "COMP-2810",
        "name": "Secret Store",
        "type": "security_data_store",
        "zone": "ZONE-05",
    },

    {
        "component_id": "COMP-2811",
        "name": "Tool Router",
        "type": "process",
        "zone": "ZONE-03",
    },

    {
        "component_id": "COMP-2812",
        "name": "Read Record Tool",
        "type": "tool",
        "zone": "ZONE-06",
    },

    {
        "component_id": "COMP-2813",
        "name": "Delete Record Tool",
        "type": "privileged_tool",
        "zone": "ZONE-06",
    },

    {
        "component_id": "COMP-2814",
        "name": "Record Service",
        "type": "downstream_service",
        "zone": "ZONE-06",
    },

    {
        "component_id": "COMP-2815",
        "name": "Detection Engine",
        "type": "security_monitor",
        "zone": "ZONE-07",
    },
]


COMPONENT_MAP = {
    component["component_id"]: component
    for component in COMPONENTS
}


# ============================================================
# DATA FLOWS
# ============================================================

DATA_FLOWS = [
    {
        "flow_id": "FLOW-2801",
        "name": "User Prompt Submission",
        "source": "COMP-2801",
        "destination": "COMP-2802",
        "data": "user_prompt",
        "classification": "untrusted",
        "authenticated": True,
        "authorized": False,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2802",
        "name": "Identity Validation",
        "source": "COMP-2802",
        "destination": "COMP-2803",
        "data": "identity_claims",
        "classification": "sensitive",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2803",
        "name": "Prompt to LLM",
        "source": "COMP-2802",
        "destination": "COMP-2804",
        "data": "validated_prompt",
        "classification": "mixed_trust",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2804",
        "name": "Retrieval Query",
        "source": "COMP-2804",
        "destination": "COMP-2806",
        "data": "retrieval_query",
        "classification": "internal",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2805",
        "name": "Knowledge Store Lookup",
        "source": "COMP-2806",
        "destination": "COMP-2805",
        "data": "document_query",
        "classification": "internal",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2806",
        "name": "Retrieved Documents",
        "source": "COMP-2805",
        "destination": "COMP-2806",
        "data": "retrieved_documents",
        "classification": "mixed_trust",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2807",
        "name": "Retrieved Context to LLM",
        "source": "COMP-2806",
        "destination": "COMP-2804",
        "data": "retrieved_context",
        "classification": "mixed_trust",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2808",
        "name": "Memory Read",
        "source": "COMP-2807",
        "destination": "COMP-2804",
        "data": "persistent_memory",
        "classification": "sensitive",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2809",
        "name": "Memory Write",
        "source": "COMP-2804",
        "destination": "COMP-2807",
        "data": "new_memory_state",
        "classification": "sensitive",
        "authenticated": True,
        "authorized": False,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2810",
        "name": "LLM to Agent Planner",
        "source": "COMP-2804",
        "destination": "COMP-2808",
        "data": "model_plan_context",
        "classification": "internal",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2811",
        "name": "Agent Tool Proposal",
        "source": "COMP-2808",
        "destination": "COMP-2811",
        "data": "tool_and_target_proposal",
        "classification": "internal",
        "authenticated": True,
        "authorized": False,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2812",
        "name": "Authorization Request",
        "source": "COMP-2811",
        "destination": "COMP-2809",
        "data": "execution_request",
        "classification": "sensitive",
        "authenticated": True,
        "authorized": False,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2813",
        "name": "Authorization Decision",
        "source": "COMP-2809",
        "destination": "COMP-2811",
        "data": "authorization_decision",
        "classification": "restricted",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2814",
        "name": "Credential Retrieval",
        "source": "COMP-2810",
        "destination": "COMP-2811",
        "data": "api_credential",
        "classification": "restricted",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2815",
        "name": "Normal Tool Invocation",
        "source": "COMP-2811",
        "destination": "COMP-2812",
        "data": "read_record_request",
        "classification": "internal",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2816",
        "name": "Privileged Tool Invocation",
        "source": "COMP-2811",
        "destination": "COMP-2813",
        "data": "delete_record_request",
        "classification": "restricted",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2817",
        "name": "Privileged Business Operation",
        "source": "COMP-2813",
        "destination": "COMP-2814",
        "data": "delete_operation",
        "classification": "restricted",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },

    {
        "flow_id": "FLOW-2818",
        "name": "Security Telemetry",
        "source": "COMP-2804",
        "destination": "COMP-2815",
        "data": "ai_security_events",
        "classification": "sensitive",
        "authenticated": True,
        "authorized": True,
        "encrypted": True,
    },
]


# ============================================================
# TRUST BOUNDARY ANALYSIS
# ============================================================

def analyze_flow(flow):

    source = COMPONENT_MAP[flow["source"]]
    destination = COMPONENT_MAP[flow["destination"]]

    source_zone = TRUST_ZONES[source["zone"]]
    destination_zone = TRUST_ZONES[destination["zone"]]

    crosses_boundary = (
        source["zone"] != destination["zone"]
    )

    trust_delta = (
        destination_zone["trust_level"]
        - source_zone["trust_level"]
    )

    trust_increase = trust_delta > 0
    trust_decrease = trust_delta < 0

    security_flags = []

    if crosses_boundary:
        security_flags.append(
            "TRUST_BOUNDARY_CROSSING"
        )

    if trust_increase:
        security_flags.append(
            "TRUST_ELEVATION"
        )

    if (
        flow["classification"]
        in {"untrusted", "mixed_trust"}
        and trust_increase
    ):
        security_flags.append(
            "UNTRUSTED_DATA_ENTERING_HIGHER_TRUST"
        )

    if not flow["authorized"]:
        security_flags.append(
            "AUTHORIZATION_REQUIRED"
        )

    if (
        destination["type"]
        in {"privileged_tool", "downstream_service"}
    ):
        security_flags.append(
            "PRIVILEGED_EXECUTION_PATH"
        )

    if flow["data"] == "api_credential":
        security_flags.append(
            "SECRET_FLOW"
        )

    return {
        **flow,
        "source_name": source["name"],
        "destination_name": destination["name"],
        "source_zone": source["zone"],
        "destination_zone": destination["zone"],
        "source_trust_level": source_zone["trust_level"],
        "destination_trust_level":
            destination_zone["trust_level"],
        "trust_delta": trust_delta,
        "crosses_trust_boundary": crosses_boundary,
        "security_flags": security_flags,
    }


ANALYZED_FLOWS = [
    analyze_flow(flow)
    for flow in DATA_FLOWS
]


# ============================================================
# OUTPUT HELPERS
# ============================================================

def header(title):

    print("\n" + "=" * 82)
    print(f"        {title}")
    print("=" * 82)


# ============================================================
# OUTPUT
# ============================================================

header("TRUST ZONES")

for zone_id, zone in TRUST_ZONES.items():

    print(
        f"{zone_id} | "
        f"Trust={zone['trust_level']} | "
        f"{zone['name']}"
    )

    print(
        f"  {zone['description']}"
    )


header("SYSTEM COMPONENTS")

for component in COMPONENTS:

    zone = TRUST_ZONES[
        component["zone"]
    ]

    print(
        f"{component['component_id']} | "
        f"{component['type']} | "
        f"{component['name']} | "
        f"{component['zone']} "
        f"({zone['name']})"
    )


header("DATA FLOW DIAGRAM")

for flow in ANALYZED_FLOWS:

    print(
        f"{flow['flow_id']} | "
        f"{flow['source_name']} "
        f"-> "
        f"{flow['destination_name']}"
    )

    print(
        f"  Data: "
        f"{flow['data']}"
    )

    print(
        f"  Classification: "
        f"{flow['classification']}"
    )

    print(
        f"  Zones: "
        f"{flow['source_zone']} "
        f"-> "
        f"{flow['destination_zone']}"
    )

    print(
        f"  Trust Delta: "
        f"{flow['trust_delta']}"
    )

    print(
        f"  Boundary Crossing: "
        f"{flow['crosses_trust_boundary']}"
    )

    print(
        f"  Security Flags: "
        f"{flow['security_flags']}"
    )


header("TRUST-BOUNDARY CROSSINGS")

boundary_flows = [
    flow
    for flow in ANALYZED_FLOWS
    if flow["crosses_trust_boundary"]
]

for flow in boundary_flows:

    print(
        f"{flow['flow_id']} | "
        f"{flow['source_name']} "
        f"-> "
        f"{flow['destination_name']} | "
        f"{flow['source_zone']} "
        f"-> "
        f"{flow['destination_zone']}"
    )


header("TRUST-ELEVATION FLOWS")

trust_elevation_flows = [
    flow
    for flow in ANALYZED_FLOWS
    if flow["trust_delta"] > 0
]

for flow in trust_elevation_flows:

    print(
        f"{flow['flow_id']} | "
        f"{flow['source_name']} "
        f"-> "
        f"{flow['destination_name']} | "
        f"Delta=+{flow['trust_delta']}"
    )

    print(
        f"  Flags: "
        f"{flow['security_flags']}"
    )


header("UNTRUSTED DATA ENTERING HIGHER TRUST")

untrusted_elevation = [
    flow
    for flow in ANALYZED_FLOWS
    if (
        flow["classification"]
        in {"untrusted", "mixed_trust"}
        and
        flow["trust_delta"] > 0
    )
]

for flow in untrusted_elevation:

    print(
        f"{flow['flow_id']} | "
        f"{flow['name']} | "
        f"{flow['source_name']} "
        f"-> "
        f"{flow['destination_name']}"
    )


header("AUTHORIZATION-SENSITIVE FLOWS")

authorization_sensitive = [
    flow
    for flow in ANALYZED_FLOWS
    if "AUTHORIZATION_REQUIRED"
    in flow["security_flags"]
]

for flow in authorization_sensitive:

    print(
        f"{flow['flow_id']} | "
        f"{flow['name']} | "
        f"{flow['source_name']} "
        f"-> "
        f"{flow['destination_name']}"
    )


header("PRIVILEGED EXECUTION FLOWS")

privileged_flows = [
    flow
    for flow in ANALYZED_FLOWS
    if "PRIVILEGED_EXECUTION_PATH"
    in flow["security_flags"]
]

for flow in privileged_flows:

    print(
        f"{flow['flow_id']} | "
        f"{flow['name']} | "
        f"{flow['source_name']} "
        f"-> "
        f"{flow['destination_name']}"
    )


header("SECURITY FLAG DISTRIBUTION")

flag_counter = Counter()

for flow in ANALYZED_FLOWS:
    for flag in flow["security_flags"]:
        flag_counter[flag] += 1

for flag, count in sorted(
    flag_counter.items()
):
    print(f"{flag}: {count}")


# ============================================================
# ATTACK-SURFACE CANDIDATES
# ============================================================

header("PRELIMINARY ATTACK-SURFACE CANDIDATES")

ATTACK_SURFACE_CANDIDATES = [
    {
        "surface_id": "SURFACE-2801",
        "name": "Prompt Entry Boundary",
        "related_flow": "FLOW-2801",
        "risk":
            "Untrusted user instructions enter application processing."
    },

    {
        "surface_id": "SURFACE-2802",
        "name": "Prompt-to-LLM Trust Transition",
        "related_flow": "FLOW-2803",
        "risk":
            "Mixed-trust instructions enter the AI runtime."
    },

    {
        "surface_id": "SURFACE-2803",
        "name": "RAG Context Admission",
        "related_flow": "FLOW-2807",
        "risk":
            "Retrieved content may influence model behavior."
    },

    {
        "surface_id": "SURFACE-2804",
        "name": "Persistent Memory Write",
        "related_flow": "FLOW-2809",
        "risk":
            "Model-generated or untrusted state may become persistent."
    },

    {
        "surface_id": "SURFACE-2805",
        "name": "Agent Tool Proposal",
        "related_flow": "FLOW-2811",
        "risk":
            "Model-generated planning state may propose privileged action."
    },

    {
        "surface_id": "SURFACE-2806",
        "name": "Authorization Boundary",
        "related_flow": "FLOW-2812",
        "risk":
            "Tool execution must not inherit authority from the model."
    },

    {
        "surface_id": "SURFACE-2807",
        "name": "Secret Retrieval",
        "related_flow": "FLOW-2814",
        "risk":
            "Credential exposure may expand downstream capability."
    },

    {
        "surface_id": "SURFACE-2808",
        "name": "Privileged Tool Invocation",
        "related_flow": "FLOW-2816",
        "risk":
            "Privileged execution can produce high business impact."
    },

    {
        "surface_id": "SURFACE-2809",
        "name": "Downstream Business Operation",
        "related_flow": "FLOW-2817",
        "risk":
            "Unsafe execution can affect restricted business data."
    },
]

for surface in ATTACK_SURFACE_CANDIDATES:

    print(
        f"{surface['surface_id']} | "
        f"{surface['name']} | "
        f"{surface['related_flow']}"
    )

    print(
        f"  Risk: "
        f"{surface['risk']}"
    )


# ============================================================
# TRUST BOUNDARY SUMMARY
# ============================================================

header("TRUST-BOUNDARY SUMMARY")

print(
    f"Trust Zones: "
    f"{len(TRUST_ZONES)}"
)

print(
    f"System Components: "
    f"{len(COMPONENTS)}"
)

print(
    f"Data Flows: "
    f"{len(DATA_FLOWS)}"
)

print(
    f"Boundary-Crossing Flows: "
    f"{len(boundary_flows)}"
)

print(
    f"Trust-Elevation Flows: "
    f"{len(trust_elevation_flows)}"
)

print(
    f"Untrusted/Mixed-Trust Elevation Flows: "
    f"{len(untrusted_elevation)}"
)

print(
    f"Authorization-Sensitive Flows: "
    f"{len(authorization_sensitive)}"
)

print(
    f"Privileged Execution Flows: "
    f"{len(privileged_flows)}"
)

print(
    f"Preliminary Attack Surfaces: "
    f"{len(ATTACK_SURFACE_CANDIDATES)}"
)


# ============================================================
# SECURITY CHECKS
# ============================================================

header("DATA-FLOW / TRUST-BOUNDARY SECURITY CHECKS")

component_ids = [
    component["component_id"]
    for component in COMPONENTS
]

flow_ids = [
    flow["flow_id"]
    for flow in DATA_FLOWS
]

all_flow_components_valid = all(
    flow["source"] in COMPONENT_MAP
    and
    flow["destination"] in COMPONENT_MAP
    for flow in DATA_FLOWS
)

checks = {
    "Unique Component IDs":
        len(component_ids)
        == len(set(component_ids)),

    "Unique Flow IDs":
        len(flow_ids)
        == len(set(flow_ids)),

    "All Flow Components Valid":
        all_flow_components_valid,

    "External Trust Boundary Present":
        any(
            component["zone"] == "ZONE-01"
            for component in COMPONENTS
        ),

    "AI Runtime Boundary Present":
        any(
            component["zone"] == "ZONE-03"
            for component in COMPONENTS
        ),

    "Data / Memory Boundary Present":
        any(
            component["zone"] == "ZONE-04"
            for component in COMPONENTS
        ),

    "Security Control Boundary Present":
        any(
            component["zone"] == "ZONE-05"
            for component in COMPONENTS
        ),

    "Privileged Execution Boundary Present":
        any(
            component["zone"] == "ZONE-06"
            for component in COMPONENTS
        ),

    "Trust Boundary Crossings Identified":
        len(boundary_flows) > 0,

    "Trust Elevation Identified":
        len(trust_elevation_flows) > 0,

    "Untrusted Elevation Identified":
        len(untrusted_elevation) > 0,

    "Authorization-Sensitive Flows Identified":
        len(authorization_sensitive) > 0,

    "Privileged Execution Flows Identified":
        len(privileged_flows) > 0,

    "Attack Surfaces Identified":
        len(ATTACK_SURFACE_CANDIDATES) > 0,
}

for check, result in checks.items():
    print(f"{check}: {result}")


model_valid = all(
    checks.values()
)

print(
    f"\nThreat-Model Data Flow Valid: "
    f"{model_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 2",

    "title":
        "LLM Data-Flow Diagram & Trust-Boundary Mapping",

    "system":
        SYSTEM,

    "trust_zones":
        TRUST_ZONES,

    "components":
        COMPONENTS,

    "data_flows":
        ANALYZED_FLOWS,

    "attack_surface_candidates":
        ATTACK_SURFACE_CANDIDATES,

    "metrics": {
        "trust_zones":
            len(TRUST_ZONES),

        "components":
            len(COMPONENTS),

        "data_flows":
            len(DATA_FLOWS),

        "boundary_crossings":
            len(boundary_flows),

        "trust_elevations":
            len(trust_elevation_flows),

        "untrusted_elevations":
            len(untrusted_elevation),

        "authorization_sensitive_flows":
            len(authorization_sensitive),

        "privileged_execution_flows":
            len(privileged_flows),

        "attack_surface_candidates":
            len(ATTACK_SURFACE_CANDIDATES),
    },

    "security_checks":
        checks,

    "data_flow_model_valid":
        model_valid,
}


OUTPUT_FILE = (
    "day28-data-flow-trust-boundary-evidence.json"
)

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        REPORT,
        file,
        indent=2
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

print("\nSecurity Interpretation:")

print(
    "The data-flow model identifies where information moves "
    "between external users, application controls, AI runtime, "
    "retrieval and memory services, security controls, privileged "
    "execution, downstream services, and monitoring."
)

print(
    "Trust-boundary analysis highlights flows where lower-trust "
    "or mixed-trust data enters higher-trust components and where "
    "model-generated state approaches persistent memory, secrets, "
    "authorization, privileged tools, or business-critical data."
)

print(
    "These boundary crossings become the primary inputs for "
    "attack-surface enumeration and structured threat modeling "
    "in the next labs."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and "
    "trust boundaries, not added only after vulnerabilities are discovered."
)