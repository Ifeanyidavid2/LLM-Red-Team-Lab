"""
Day 29 Lab 3
Enterprise Attack-Surface & Trust-Boundary Mapping

Purpose:
Convert the authorized architecture reconnaissance baseline into a
formal attack-surface register covering entry points, trust boundaries,
persistence surfaces, privilege boundaries, business-impact surfaces,
and observability dependencies.
"""

from datetime import datetime, timezone
from pathlib import Path
from collections import Counter, defaultdict
import hashlib
import json


ENGAGEMENT_ID = "ENG-2901"
SYSTEM_ID = "ENT-AI-2901"
TRACE_ID = "TRACE-2903"


# =============================================================================
# TRUST BOUNDARIES
# =============================================================================

TRUST_BOUNDARIES = [
    {
        "boundary_id": "TB-2901",
        "name": "Enterprise User to AI Assistant",
        "source": "Enterprise User",
        "destination": "AI Assistant",
        "trust_type": "external_input",
        "security_dependency": "User-controlled natural language enters application processing.",
        "priority": "HIGH",
    },
    {
        "boundary_id": "TB-2902",
        "name": "AI Assistant to LLM Runtime",
        "source": "AI Assistant",
        "destination": "LLM Runtime",
        "trust_type": "instruction_boundary",
        "security_dependency": "Application context must not alter trusted system instruction hierarchy.",
        "priority": "CRITICAL",
    },
    {
        "boundary_id": "TB-2903",
        "name": "RAG to LLM Runtime",
        "source": "RAG Knowledge System",
        "destination": "LLM Runtime",
        "trust_type": "mixed_trust_context",
        "security_dependency": "Retrieved content must remain untrusted data rather than instruction authority.",
        "priority": "CRITICAL",
    },
    {
        "boundary_id": "TB-2904",
        "name": "LLM Runtime to Persistent Memory",
        "source": "LLM Runtime",
        "destination": "Persistent Memory",
        "trust_type": "persistent_state_write",
        "security_dependency": "Model output must not become persistent trusted state without authorization.",
        "priority": "CRITICAL",
    },
    {
        "boundary_id": "TB-2905",
        "name": "Persistent Memory to Agent Planner",
        "source": "Persistent Memory",
        "destination": "Agent Planner",
        "trust_type": "persistent_state_read",
        "security_dependency": "Stored state must not become authoritative planning input across sessions or agents.",
        "priority": "CRITICAL",
    },
    {
        "boundary_id": "TB-2906",
        "name": "LLM Runtime to Agent Planner",
        "source": "LLM Runtime",
        "destination": "Agent Planner",
        "trust_type": "model_to_agent",
        "security_dependency": "Model-generated plans must remain proposals rather than trusted goals.",
        "priority": "CRITICAL",
    },
    {
        "boundary_id": "TB-2907",
        "name": "Agent Planner to Authorization Service",
        "source": "Agent Planner",
        "destination": "Authorization Service",
        "trust_type": "privilege_request",
        "security_dependency": "Agent-generated authority or approval claims must not satisfy authorization.",
        "priority": "CRITICAL",
    },
    {
        "boundary_id": "TB-2908",
        "name": "Authorization Service to Tools / APIs",
        "source": "Authorization Service",
        "destination": "Tools / APIs",
        "trust_type": "execution_authorization",
        "security_dependency": "Denied, absent, or malformed authorization must fail closed.",
        "priority": "CRITICAL",
    },
    {
        "boundary_id": "TB-2909",
        "name": "Credential Broker to Tools / APIs",
        "source": "Credential Broker",
        "destination": "Tools / APIs",
        "trust_type": "secret_delivery",
        "security_dependency": "Credentials must remain scoped to the task, tool, target, and transaction.",
        "priority": "CRITICAL",
    },
    {
        "boundary_id": "TB-2910",
        "name": "Tools / APIs to Business Data",
        "source": "Tools / APIs",
        "destination": "Business Data",
        "trust_type": "business_impact",
        "security_dependency": "Tool authorization must independently constrain access to business resources.",
        "priority": "CRITICAL",
    },
    {
        "boundary_id": "TB-2911",
        "name": "All Components to Security Telemetry",
        "source": "All Components",
        "destination": "Security Telemetry",
        "trust_type": "observability",
        "security_dependency": "Security events must be complete, correlated, and tamper evident.",
        "priority": "HIGH",
    },
]


# =============================================================================
# ATTACK SURFACE REGISTER
# =============================================================================

ATTACK_SURFACES = [
    {
        "surface_id": "AS-2901",
        "name": "Enterprise Prompt Input",
        "component": "AI Assistant",
        "surface_type": "ENTRY_POINT",
        "trust_boundary": "TB-2901",
        "attack_category": "prompt_injection",
        "persistence": False,
        "privileged": False,
        "business_impact": False,
        "observability_required": True,
        "likelihood": 5,
        "impact": 4,
    },
    {
        "surface_id": "AS-2902",
        "name": "Instruction Hierarchy",
        "component": "LLM Runtime",
        "surface_type": "INSTRUCTION",
        "trust_boundary": "TB-2902",
        "attack_category": "instruction_override",
        "persistence": False,
        "privileged": False,
        "business_impact": False,
        "observability_required": True,
        "likelihood": 4,
        "impact": 5,
    },
    {
        "surface_id": "AS-2903",
        "name": "Retrieved Document Admission",
        "component": "RAG Knowledge System",
        "surface_type": "RAG",
        "trust_boundary": "TB-2903",
        "attack_category": "rag_poisoning",
        "persistence": True,
        "privileged": False,
        "business_impact": False,
        "observability_required": True,
        "likelihood": 4,
        "impact": 5,
    },
    {
        "surface_id": "AS-2904",
        "name": "Indirect Prompt Injection",
        "component": "RAG Knowledge System",
        "surface_type": "RAG",
        "trust_boundary": "TB-2903",
        "attack_category": "indirect_prompt_injection",
        "persistence": True,
        "privileged": False,
        "business_impact": False,
        "observability_required": True,
        "likelihood": 5,
        "impact": 5,
    },
    {
        "surface_id": "AS-2905",
        "name": "Persistent Memory Write",
        "component": "Persistent Memory",
        "surface_type": "MEMORY",
        "trust_boundary": "TB-2904",
        "attack_category": "memory_poisoning",
        "persistence": True,
        "privileged": False,
        "business_impact": False,
        "observability_required": True,
        "likelihood": 4,
        "impact": 5,
    },
    {
        "surface_id": "AS-2906",
        "name": "Cross-Session Memory Read",
        "component": "Persistent Memory",
        "surface_type": "MEMORY",
        "trust_boundary": "TB-2905",
        "attack_category": "cross_session_influence",
        "persistence": True,
        "privileged": False,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 4,
        "impact": 5,
    },
    {
        "surface_id": "AS-2907",
        "name": "Agent Goal Generation",
        "component": "Agent Planner",
        "surface_type": "AGENT",
        "trust_boundary": "TB-2906",
        "attack_category": "goal_hijacking",
        "persistence": False,
        "privileged": True,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 4,
        "impact": 5,
    },
    {
        "surface_id": "AS-2908",
        "name": "Agent Task Binding",
        "component": "Agent Planner",
        "surface_type": "AGENT",
        "trust_boundary": "TB-2906",
        "attack_category": "task_binding_bypass",
        "persistence": False,
        "privileged": True,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 4,
        "impact": 5,
    },
    {
        "surface_id": "AS-2909",
        "name": "Authorization Request",
        "component": "Authorization Service",
        "surface_type": "AUTHORIZATION",
        "trust_boundary": "TB-2907",
        "attack_category": "authority_spoofing",
        "persistence": False,
        "privileged": True,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 4,
        "impact": 5,
    },
    {
        "surface_id": "AS-2910",
        "name": "Authorization Enforcement",
        "component": "Authorization Service",
        "surface_type": "AUTHORIZATION",
        "trust_boundary": "TB-2908",
        "attack_category": "authorization_bypass",
        "persistence": False,
        "privileged": True,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 3,
        "impact": 5,
    },
    {
        "surface_id": "AS-2911",
        "name": "Privileged Tool Selection",
        "component": "Tools / APIs",
        "surface_type": "TOOL",
        "trust_boundary": "TB-2908",
        "attack_category": "privileged_tool_abuse",
        "persistence": False,
        "privileged": True,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 4,
        "impact": 5,
    },
    {
        "surface_id": "AS-2912",
        "name": "Tool Target Selection",
        "component": "Tools / APIs",
        "surface_type": "TOOL",
        "trust_boundary": "TB-2908",
        "attack_category": "target_substitution",
        "persistence": False,
        "privileged": True,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 4,
        "impact": 5,
    },
    {
        "surface_id": "AS-2913",
        "name": "Tool Parameters",
        "component": "Tools / APIs",
        "surface_type": "TOOL",
        "trust_boundary": "TB-2908",
        "attack_category": "parameter_manipulation",
        "persistence": False,
        "privileged": True,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 4,
        "impact": 5,
    },
    {
        "surface_id": "AS-2914",
        "name": "Task Credential",
        "component": "Credential Broker",
        "surface_type": "SECRET",
        "trust_boundary": "TB-2909",
        "attack_category": "credential_scope_abuse",
        "persistence": True,
        "privileged": True,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 3,
        "impact": 5,
    },
    {
        "surface_id": "AS-2915",
        "name": "Restricted Business Record Read",
        "component": "Business Data",
        "surface_type": "BUSINESS_DATA",
        "trust_boundary": "TB-2910",
        "attack_category": "unauthorized_data_access",
        "persistence": False,
        "privileged": True,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 3,
        "impact": 5,
    },
    {
        "surface_id": "AS-2916",
        "name": "Restricted Business Record Modification",
        "component": "Business Data",
        "surface_type": "BUSINESS_DATA",
        "trust_boundary": "TB-2910",
        "attack_category": "unauthorized_modification",
        "persistence": True,
        "privileged": True,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 3,
        "impact": 5,
    },
    {
        "surface_id": "AS-2917",
        "name": "Restricted Business Record Deletion",
        "component": "Business Data",
        "surface_type": "BUSINESS_DATA",
        "trust_boundary": "TB-2910",
        "attack_category": "destructive_impact",
        "persistence": True,
        "privileged": True,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 3,
        "impact": 5,
    },
    {
        "surface_id": "AS-2918",
        "name": "Security Event Collection",
        "component": "Security Telemetry",
        "surface_type": "OBSERVABILITY",
        "trust_boundary": "TB-2911",
        "attack_category": "telemetry_suppression",
        "persistence": False,
        "privileged": False,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 3,
        "impact": 4,
    },
    {
        "surface_id": "AS-2919",
        "name": "Forensic Evidence Integrity",
        "component": "Security Telemetry",
        "surface_type": "OBSERVABILITY",
        "trust_boundary": "TB-2911",
        "attack_category": "evidence_tampering",
        "persistence": True,
        "privileged": False,
        "business_impact": True,
        "observability_required": True,
        "likelihood": 3,
        "impact": 5,
    },
]


# =============================================================================
# ATTACK PATH HYPOTHESES
# =============================================================================

ATTACK_PATH_HYPOTHESES = [
    {
        "path_id": "HYP-2901",
        "name": "Prompt Injection to Privileged Execution",
        "surfaces": [
            "AS-2901",
            "AS-2902",
            "AS-2907",
            "AS-2908",
            "AS-2909",
            "AS-2911",
        ],
        "business_objective": "Unauthorized privileged tool execution",
    },
    {
        "path_id": "HYP-2902",
        "name": "RAG Poisoning to Persistent Memory",
        "surfaces": [
            "AS-2903",
            "AS-2904",
            "AS-2905",
            "AS-2906",
        ],
        "business_objective": "Persistent cross-session compromise",
    },
    {
        "path_id": "HYP-2903",
        "name": "Persistent Memory to Business Impact",
        "surfaces": [
            "AS-2905",
            "AS-2906",
            "AS-2907",
            "AS-2911",
            "AS-2912",
            "AS-2917",
        ],
        "business_objective": "Restricted business record destruction",
    },
    {
        "path_id": "HYP-2904",
        "name": "Authorization Failure to Destructive Execution",
        "surfaces": [
            "AS-2909",
            "AS-2910",
            "AS-2911",
            "AS-2912",
            "AS-2917",
        ],
        "business_objective": "Unauthorized destructive action",
    },
    {
        "path_id": "HYP-2905",
        "name": "Credential Abuse to Restricted Data",
        "surfaces": [
            "AS-2914",
            "AS-2911",
            "AS-2915",
        ],
        "business_objective": "Unauthorized restricted-data access",
    },
    {
        "path_id": "HYP-2906",
        "name": "Telemetry Evasion During Business Impact",
        "surfaces": [
            "AS-2918",
            "AS-2919",
            "AS-2911",
            "AS-2917",
        ],
        "business_objective": "Business impact with reduced forensic visibility",
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
    print("\n" + "=" * 92)
    print(f"        {title}")
    print("=" * 92)


def risk_score(surface):
    return surface["likelihood"] * surface["impact"]


def classify(score):
    if score >= 20:
        return "CRITICAL"
    if score >= 15:
        return "HIGH"
    if score >= 8:
        return "MEDIUM"
    return "LOW"


# =============================================================================
# MAIN
# =============================================================================

def main():
    print(
        "\n=== Day 29 Lab 3: Enterprise Attack-Surface "
        "& Trust-Boundary Mapping ==="
    )

    timestamp = datetime.now(timezone.utc).isoformat()

    boundary_ids = {
        boundary["boundary_id"]
        for boundary in TRUST_BOUNDARIES
    }

    surface_ids = {
        surface["surface_id"]
        for surface in ATTACK_SURFACES
    }

    for surface in ATTACK_SURFACES:
        surface["risk_score"] = risk_score(surface)
        surface["severity"] = classify(surface["risk_score"])

    header("TRUST BOUNDARY REGISTER")

    for boundary in TRUST_BOUNDARIES:
        print(
            f"{boundary['boundary_id']} | "
            f"{boundary['priority']} | "
            f"{boundary['source']} -> "
            f"{boundary['destination']} | "
            f"{boundary['name']}"
        )
        print(
            f"  Type: {boundary['trust_type']}"
        )
        print(
            f"  Dependency: "
            f"{boundary['security_dependency']}"
        )

    header("ENTERPRISE ATTACK-SURFACE REGISTER")

    for surface in ATTACK_SURFACES:
        print(
            f"{surface['surface_id']} | "
            f"{surface['surface_type']} | "
            f"{surface['severity']} | "
            f"Risk={surface['risk_score']} | "
            f"{surface['name']}"
        )
        print(
            f"  Component: {surface['component']}"
        )
        print(
            f"  Boundary: {surface['trust_boundary']}"
        )
        print(
            f"  Attack Category: "
            f"{surface['attack_category']}"
        )
        print(
            f"  Persistent={surface['persistence']} | "
            f"Privileged={surface['privileged']} | "
            f"Business Impact={surface['business_impact']}"
        )

    header("ATTACK-SURFACE TYPE DISTRIBUTION")

    type_distribution = Counter(
        surface["surface_type"]
        for surface in ATTACK_SURFACES
    )

    for surface_type, count in sorted(
        type_distribution.items()
    ):
        print(f"{surface_type}: {count}")

    header("SEVERITY DISTRIBUTION")

    severity_distribution = Counter(
        surface["severity"]
        for surface in ATTACK_SURFACES
    )

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

    persistent_surfaces = [
        surface
        for surface in ATTACK_SURFACES
        if surface["persistence"]
    ]

    privileged_surfaces = [
        surface
        for surface in ATTACK_SURFACES
        if surface["privileged"]
    ]

    business_impact_surfaces = [
        surface
        for surface in ATTACK_SURFACES
        if surface["business_impact"]
    ]

    high_critical = [
        surface
        for surface in ATTACK_SURFACES
        if surface["severity"]
        in {"HIGH", "CRITICAL"}
    ]

    header("PERSISTENCE ATTACK SURFACES")

    for surface in persistent_surfaces:
        print(
            f"{surface['surface_id']} | "
            f"{surface['severity']} | "
            f"{surface['name']}"
        )

    header("PRIVILEGED ATTACK SURFACES")

    for surface in privileged_surfaces:
        print(
            f"{surface['surface_id']} | "
            f"{surface['severity']} | "
            f"{surface['name']}"
        )

    header("BUSINESS-IMPACT ATTACK SURFACES")

    for surface in business_impact_surfaces:
        print(
            f"{surface['surface_id']} | "
            f"{surface['severity']} | "
            f"{surface['name']}"
        )

    header("PRELIMINARY MULTI-STAGE ATTACK HYPOTHESES")

    for path in ATTACK_PATH_HYPOTHESES:
        print(
            f"{path['path_id']} | "
            f"{path['name']}"
        )
        print(
            "  Path: "
            + " -> ".join(path["surfaces"])
        )
        print(
            f"  Business Objective: "
            f"{path['business_objective']}"
        )

    # =====================================================================
    # CHOKE-POINT ANALYSIS
    # =====================================================================

    surface_usage = Counter()

    for path in ATTACK_PATH_HYPOTHESES:
        for surface_id in path["surfaces"]:
            surface_usage[surface_id] += 1

    choke_points = [
        {
            "surface_id": surface_id,
            "name": next(
                surface["name"]
                for surface in ATTACK_SURFACES
                if surface["surface_id"] == surface_id
            ),
            "path_count": count,
        }
        for surface_id, count
        in surface_usage.items()
        if count >= 2
    ]

    choke_points.sort(
        key=lambda item: (
            -item["path_count"],
            item["surface_id"],
        )
    )

    header("MULTI-PATH ARCHITECTURAL CHOKE POINTS")

    for choke in choke_points:
        print(
            f"{choke['surface_id']} | "
            f"Paths={choke['path_count']} | "
            f"{choke['name']}"
        )

    # =====================================================================
    # VALIDATION
    # =====================================================================

    header("ATTACK-SURFACE SECURITY CHECKS")

    checks = {
        "Unique Trust Boundary IDs":
            len(TRUST_BOUNDARIES)
            == len(boundary_ids),

        "Unique Attack Surface IDs":
            len(ATTACK_SURFACES)
            == len(surface_ids),

        "All Surface Boundaries Valid":
            all(
                surface["trust_boundary"]
                in boundary_ids
                for surface in ATTACK_SURFACES
            ),

        "Prompt Entry Point Identified":
            any(
                surface["attack_category"]
                == "prompt_injection"
                for surface in ATTACK_SURFACES
            ),

        "RAG Attack Surface Identified":
            any(
                surface["surface_type"]
                == "RAG"
                for surface in ATTACK_SURFACES
            ),

        "Memory Attack Surface Identified":
            any(
                surface["surface_type"]
                == "MEMORY"
                for surface in ATTACK_SURFACES
            ),

        "Agent Attack Surface Identified":
            any(
                surface["surface_type"]
                == "AGENT"
                for surface in ATTACK_SURFACES
            ),

        "Authorization Surface Identified":
            any(
                surface["surface_type"]
                == "AUTHORIZATION"
                for surface in ATTACK_SURFACES
            ),

        "Tool Attack Surface Identified":
            any(
                surface["surface_type"]
                == "TOOL"
                for surface in ATTACK_SURFACES
            ),

        "Credential Surface Identified":
            any(
                surface["surface_type"]
                == "SECRET"
                for surface in ATTACK_SURFACES
            ),

        "Business Impact Surface Identified":
            len(business_impact_surfaces) > 0,

        "Observability Surface Identified":
            any(
                surface["surface_type"]
                == "OBSERVABILITY"
                for surface in ATTACK_SURFACES
            ),

        "Persistence Surfaces Identified":
            len(persistent_surfaces) > 0,

        "Privileged Surfaces Identified":
            len(privileged_surfaces) > 0,

        "High / Critical Surfaces Identified":
            len(high_critical) > 0,

        "Attack Hypotheses Defined":
            len(ATTACK_PATH_HYPOTHESES) > 0,

        "All Hypothesis Surfaces Valid":
            all(
                surface_id in surface_ids
                for path in ATTACK_PATH_HYPOTHESES
                for surface_id in path["surfaces"]
            ),

        "Architectural Choke Points Identified":
            len(choke_points) > 0,
    }

    checks["Attack Surface Model Valid"] = all(
        checks.values()
    )

    for check, result in checks.items():
        print(f"{check}: {result}")

    header("ATTACK-SURFACE SUMMARY")

    print(
        f"Trust Boundaries: "
        f"{len(TRUST_BOUNDARIES)}"
    )
    print(
        f"Attack Surfaces: "
        f"{len(ATTACK_SURFACES)}"
    )
    print(
        f"High / Critical Surfaces: "
        f"{len(high_critical)}"
    )
    print(
        f"Persistence Surfaces: "
        f"{len(persistent_surfaces)}"
    )
    print(
        f"Privileged Surfaces: "
        f"{len(privileged_surfaces)}"
    )
    print(
        f"Business-Impact Surfaces: "
        f"{len(business_impact_surfaces)}"
    )
    print(
        f"Attack Hypotheses: "
        f"{len(ATTACK_PATH_HYPOTHESES)}"
    )
    print(
        f"Architectural Choke Points: "
        f"{len(choke_points)}"
    )

    # =====================================================================
    # EXPORT
    # =====================================================================

    evidence = {
        "engagement_id": ENGAGEMENT_ID,
        "system_id": SYSTEM_ID,
        "trace_id": TRACE_ID,
        "timestamp_utc": timestamp,
        "trust_boundaries": TRUST_BOUNDARIES,
        "attack_surfaces": ATTACK_SURFACES,
        "attack_path_hypotheses": ATTACK_PATH_HYPOTHESES,
        "choke_points": choke_points,
        "metrics": {
            "trust_boundaries":
                len(TRUST_BOUNDARIES),
            "attack_surfaces":
                len(ATTACK_SURFACES),
            "high_critical_surfaces":
                len(high_critical),
            "persistence_surfaces":
                len(persistent_surfaces),
            "privileged_surfaces":
                len(privileged_surfaces),
            "business_impact_surfaces":
                len(business_impact_surfaces),
            "attack_hypotheses":
                len(ATTACK_PATH_HYPOTHESES),
            "architectural_choke_points":
                len(choke_points),
        },
        "security_checks": checks,
    }

    evidence["evidence_hash"] = hash_data(
        evidence
    )

    output = Path(
        "day29-enterprise-attack-surface-trust-boundary-evidence.json"
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
        "The attack-surface model converts architectural reconnaissance "
        "into concrete adversarial entry points, persistence mechanisms, "
        "privilege boundaries, business-impact surfaces, and observability "
        "dependencies."
    )
    print(
        "The model shows that enterprise GenAI risk is concentrated not "
        "only at the prompt interface, but at the transitions between "
        "retrieval, persistent memory, agents, authorization, tools, "
        "credentials and restricted business resources."
    )
    print(
        "Multi-stage attack hypotheses identify the paths that should be "
        "prioritized during the red-team execution phase."
    )

    print("\nCore Principle:")
    print(
        "Attack surfaces matter most when they can be chained across "
        "trust boundaries into persistence, privilege, or business impact."
    )


if __name__ == "__main__":
    main()