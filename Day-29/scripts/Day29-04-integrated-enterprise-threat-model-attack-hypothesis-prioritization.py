"""
Day 29 Lab 4
Integrated Enterprise Threat Model & Attack Hypothesis Prioritization

Purpose:
Translate the Day 29 architecture and attack-surface model into a
prioritized enterprise LLM red-team test plan.

The lab combines threat hypotheses, affected assets, trust boundaries,
attack surfaces, business consequences, likelihood, impact, persistence,
privilege, blast radius, detection difficulty, and chain feasibility.

Core Principle:
A professional red-team engagement should prioritize attack hypotheses
according to realistic business consequence and attack-chain feasibility,
not simply test every weakness in arbitrary order.
"""

from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
import hashlib
import json


ENGAGEMENT_ID = "ENG-2901"
SYSTEM_ID = "ENT-AI-2901"
TRACE_ID = "TRACE-2904"


# =============================================================================
# CRITICAL ASSETS
# =============================================================================

ASSETS = [
    {
        "asset_id": "ASSET-2901",
        "name": "System Prompt",
        "criticality": "CRITICAL",
    },
    {
        "asset_id": "ASSET-2902",
        "name": "Retrieved Context",
        "criticality": "HIGH",
    },
    {
        "asset_id": "ASSET-2903",
        "name": "Persistent Memory",
        "criticality": "CRITICAL",
    },
    {
        "asset_id": "ASSET-2904",
        "name": "Agent Goal / Plan",
        "criticality": "CRITICAL",
    },
    {
        "asset_id": "ASSET-2905",
        "name": "Authorization Decision",
        "criticality": "CRITICAL",
    },
    {
        "asset_id": "ASSET-2906",
        "name": "Task Credential",
        "criticality": "CRITICAL",
    },
    {
        "asset_id": "ASSET-2907",
        "name": "Privileged Tool",
        "criticality": "CRITICAL",
    },
    {
        "asset_id": "ASSET-2908",
        "name": "Restricted Business Data",
        "criticality": "CRITICAL",
    },
    {
        "asset_id": "ASSET-2909",
        "name": "Security Telemetry",
        "criticality": "HIGH",
    },
]


# =============================================================================
# THREAT HYPOTHESES
# =============================================================================

THREATS = [
    {
        "threat_id": "THREAT-2901",
        "name": "Direct Prompt Injection",
        "category": "PROMPT",
        "attack_surface": "AS-2901",
        "trust_boundary": "TB-2901",
        "affected_assets": [
            "ASSET-2901",
            "ASSET-2904",
        ],
        "likelihood": 5,
        "impact": 4,
        "persistence": 1,
        "privilege": 2,
        "blast_radius": 2,
        "detectability": 2,
        "chain_feasibility": 5,
        "business_consequence":
            "Untrusted user instructions may alter intended AI behavior.",
    },
    {
        "threat_id": "THREAT-2902",
        "name": "Instruction Hierarchy Override",
        "category": "PROMPT",
        "attack_surface": "AS-2902",
        "trust_boundary": "TB-2902",
        "affected_assets": [
            "ASSET-2901",
            "ASSET-2904",
        ],
        "likelihood": 4,
        "impact": 5,
        "persistence": 1,
        "privilege": 3,
        "blast_radius": 3,
        "detectability": 3,
        "chain_feasibility": 4,
        "business_consequence":
            "Trusted instruction integrity may be compromised.",
    },
    {
        "threat_id": "THREAT-2903",
        "name": "RAG Source Poisoning",
        "category": "RAG",
        "attack_surface": "AS-2903",
        "trust_boundary": "TB-2903",
        "affected_assets": [
            "ASSET-2902",
            "ASSET-2903",
        ],
        "likelihood": 4,
        "impact": 5,
        "persistence": 4,
        "privilege": 2,
        "blast_radius": 4,
        "detectability": 3,
        "chain_feasibility": 4,
        "business_consequence":
            "Malicious retrieved content may influence multiple AI sessions.",
    },
    {
        "threat_id": "THREAT-2904",
        "name": "Indirect Prompt Injection",
        "category": "RAG",
        "attack_surface": "AS-2904",
        "trust_boundary": "TB-2903",
        "affected_assets": [
            "ASSET-2902",
            "ASSET-2904",
        ],
        "likelihood": 5,
        "impact": 5,
        "persistence": 3,
        "privilege": 3,
        "blast_radius": 4,
        "detectability": 4,
        "chain_feasibility": 5,
        "business_consequence":
            "Retrieved instructions may manipulate model or agent behavior.",
    },
    {
        "threat_id": "THREAT-2905",
        "name": "Persistent Memory Poisoning",
        "category": "MEMORY",
        "attack_surface": "AS-2905",
        "trust_boundary": "TB-2904",
        "affected_assets": [
            "ASSET-2903",
            "ASSET-2904",
        ],
        "likelihood": 4,
        "impact": 5,
        "persistence": 5,
        "privilege": 3,
        "blast_radius": 5,
        "detectability": 4,
        "chain_feasibility": 4,
        "business_consequence":
            "Malicious AI state may persist beyond the originating session.",
    },
    {
        "threat_id": "THREAT-2906",
        "name": "Cross-Session Memory Influence",
        "category": "MEMORY",
        "attack_surface": "AS-2906",
        "trust_boundary": "TB-2905",
        "affected_assets": [
            "ASSET-2903",
            "ASSET-2904",
        ],
        "likelihood": 4,
        "impact": 5,
        "persistence": 5,
        "privilege": 3,
        "blast_radius": 5,
        "detectability": 4,
        "chain_feasibility": 4,
        "business_consequence":
            "Compromised state may influence later sessions and users.",
    },
    {
        "threat_id": "THREAT-2907",
        "name": "Agent Goal Hijacking",
        "category": "AGENT",
        "attack_surface": "AS-2907",
        "trust_boundary": "TB-2906",
        "affected_assets": [
            "ASSET-2904",
            "ASSET-2907",
        ],
        "likelihood": 4,
        "impact": 5,
        "persistence": 2,
        "privilege": 5,
        "blast_radius": 4,
        "detectability": 3,
        "chain_feasibility": 4,
        "business_consequence":
            "Agent may pursue attacker-influenced goals.",
    },
    {
        "threat_id": "THREAT-2908",
        "name": "Task Binding Bypass",
        "category": "AGENT",
        "attack_surface": "AS-2908",
        "trust_boundary": "TB-2906",
        "affected_assets": [
            "ASSET-2904",
            "ASSET-2907",
        ],
        "likelihood": 4,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 4,
        "detectability": 3,
        "chain_feasibility": 4,
        "business_consequence":
            "Agent-generated actions may exceed approved task scope.",
    },
    {
        "threat_id": "THREAT-2909",
        "name": "Model-Generated Approval Spoofing",
        "category": "AUTHORIZATION",
        "attack_surface": "AS-2909",
        "trust_boundary": "TB-2907",
        "affected_assets": [
            "ASSET-2905",
            "ASSET-2907",
        ],
        "likelihood": 4,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 4,
        "chain_feasibility": 4,
        "business_consequence":
            "Generated language may be mistaken for real approval.",
    },
    {
        "threat_id": "THREAT-2910",
        "name": "Authorization Bypass",
        "category": "AUTHORIZATION",
        "attack_surface": "AS-2910",
        "trust_boundary": "TB-2908",
        "affected_assets": [
            "ASSET-2905",
            "ASSET-2907",
            "ASSET-2908",
        ],
        "likelihood": 3,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 4,
        "chain_feasibility": 4,
        "business_consequence":
            "Privileged actions may execute despite denied authorization.",
    },
    {
        "threat_id": "THREAT-2911",
        "name": "Privileged Tool Abuse",
        "category": "TOOL",
        "attack_surface": "AS-2911",
        "trust_boundary": "TB-2908",
        "affected_assets": [
            "ASSET-2907",
            "ASSET-2908",
        ],
        "likelihood": 4,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 3,
        "chain_feasibility": 5,
        "business_consequence":
            "Compromised AI decisions may trigger privileged business operations.",
    },
    {
        "threat_id": "THREAT-2912",
        "name": "Target Substitution",
        "category": "TOOL",
        "attack_surface": "AS-2912",
        "trust_boundary": "TB-2908",
        "affected_assets": [
            "ASSET-2907",
            "ASSET-2908",
        ],
        "likelihood": 4,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 3,
        "chain_feasibility": 5,
        "business_consequence":
            "A valid action may be redirected to a restricted target.",
    },
    {
        "threat_id": "THREAT-2913",
        "name": "Tool Parameter Manipulation",
        "category": "TOOL",
        "attack_surface": "AS-2913",
        "trust_boundary": "TB-2908",
        "affected_assets": [
            "ASSET-2907",
            "ASSET-2908",
        ],
        "likelihood": 4,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 3,
        "chain_feasibility": 5,
        "business_consequence":
            "Tool parameters may transform legitimate functionality into unsafe execution.",
    },
    {
        "threat_id": "THREAT-2914",
        "name": "Credential Scope Abuse",
        "category": "SECRET",
        "attack_surface": "AS-2914",
        "trust_boundary": "TB-2909",
        "affected_assets": [
            "ASSET-2906",
            "ASSET-2907",
            "ASSET-2908",
        ],
        "likelihood": 3,
        "impact": 5,
        "persistence": 3,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 4,
        "chain_feasibility": 4,
        "business_consequence":
            "Valid credentials may be used beyond their intended scope.",
    },
    {
        "threat_id": "THREAT-2915",
        "name": "Unauthorized Restricted Data Access",
        "category": "BUSINESS_DATA",
        "attack_surface": "AS-2915",
        "trust_boundary": "TB-2910",
        "affected_assets": [
            "ASSET-2908",
        ],
        "likelihood": 3,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 4,
        "detectability": 3,
        "chain_feasibility": 4,
        "business_consequence":
            "Restricted business information may be disclosed.",
    },
    {
        "threat_id": "THREAT-2916",
        "name": "Unauthorized Restricted Data Modification",
        "category": "BUSINESS_DATA",
        "attack_surface": "AS-2916",
        "trust_boundary": "TB-2910",
        "affected_assets": [
            "ASSET-2908",
        ],
        "likelihood": 3,
        "impact": 5,
        "persistence": 4,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 3,
        "chain_feasibility": 4,
        "business_consequence":
            "Restricted business records may be altered.",
    },
    {
        "threat_id": "THREAT-2917",
        "name": "Restricted Business Data Destruction",
        "category": "BUSINESS_DATA",
        "attack_surface": "AS-2917",
        "trust_boundary": "TB-2910",
        "affected_assets": [
            "ASSET-2908",
        ],
        "likelihood": 3,
        "impact": 5,
        "persistence": 5,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 3,
        "chain_feasibility": 4,
        "business_consequence":
            "Critical business records may be destroyed.",
    },
    {
        "threat_id": "THREAT-2918",
        "name": "Security Telemetry Suppression",
        "category": "OBSERVABILITY",
        "attack_surface": "AS-2918",
        "trust_boundary": "TB-2911",
        "affected_assets": [
            "ASSET-2909",
        ],
        "likelihood": 3,
        "impact": 4,
        "persistence": 2,
        "privilege": 3,
        "blast_radius": 4,
        "detectability": 5,
        "chain_feasibility": 3,
        "business_consequence":
            "Security monitoring may fail to detect malicious AI activity.",
    },
    {
        "threat_id": "THREAT-2919",
        "name": "Forensic Evidence Tampering",
        "category": "OBSERVABILITY",
        "attack_surface": "AS-2919",
        "trust_boundary": "TB-2911",
        "affected_assets": [
            "ASSET-2909",
        ],
        "likelihood": 3,
        "impact": 5,
        "persistence": 4,
        "privilege": 3,
        "blast_radius": 4,
        "detectability": 5,
        "chain_feasibility": 3,
        "business_consequence":
            "Incident reconstruction and accountability may be impaired.",
    },
]


# =============================================================================
# ATTACK CHAIN HYPOTHESES
# =============================================================================

ATTACK_CHAINS = [
    {
        "hypothesis_id": "HYP-2901",
        "name": "Prompt Injection to Privileged Execution",
        "threats": [
            "THREAT-2901",
            "THREAT-2902",
            "THREAT-2907",
            "THREAT-2908",
            "THREAT-2909",
            "THREAT-2911",
        ],
        "business_objective":
            "Unauthorized privileged tool execution",
    },
    {
        "hypothesis_id": "HYP-2902",
        "name": "RAG Poisoning to Persistent Cross-Session Compromise",
        "threats": [
            "THREAT-2903",
            "THREAT-2904",
            "THREAT-2905",
            "THREAT-2906",
        ],
        "business_objective":
            "Persistent compromise affecting future sessions",
    },
    {
        "hypothesis_id": "HYP-2903",
        "name": "Persistent Memory to Destructive Business Impact",
        "threats": [
            "THREAT-2905",
            "THREAT-2906",
            "THREAT-2907",
            "THREAT-2911",
            "THREAT-2912",
            "THREAT-2917",
        ],
        "business_objective":
            "Restricted business record destruction",
    },
    {
        "hypothesis_id": "HYP-2904",
        "name": "Authorization Failure to Destructive Execution",
        "threats": [
            "THREAT-2909",
            "THREAT-2910",
            "THREAT-2911",
            "THREAT-2912",
            "THREAT-2917",
        ],
        "business_objective":
            "Unauthorized destructive privileged action",
    },
    {
        "hypothesis_id": "HYP-2905",
        "name": "Credential Scope Abuse to Restricted Data",
        "threats": [
            "THREAT-2914",
            "THREAT-2911",
            "THREAT-2915",
        ],
        "business_objective":
            "Unauthorized restricted-data access",
    },
    {
        "hypothesis_id": "HYP-2906",
        "name": "Telemetry Evasion During Destructive Impact",
        "threats": [
            "THREAT-2918",
            "THREAT-2919",
            "THREAT-2911",
            "THREAT-2917",
        ],
        "business_objective":
            "Business impact with degraded forensic visibility",
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
    print("\n" + "=" * 96)
    print(f"        {title}")
    print("=" * 96)


def score_threat(threat):
    base = (
        threat["likelihood"]
        * threat["impact"]
    )

    amplifier = (
        threat["persistence"]
        + threat["privilege"]
        + threat["blast_radius"]
        + threat["detectability"]
        + threat["chain_feasibility"]
    )

    return base + amplifier


def classify(score):
    if score >= 40:
        return "CRITICAL"
    if score >= 32:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


# =============================================================================
# MAIN
# =============================================================================

def main():
    print(
        "\n=== Day 29 Lab 4: Integrated Enterprise Threat Model "
        "& Attack Hypothesis Prioritization ==="
    )

    timestamp = datetime.now(timezone.utc).isoformat()

    threat_ids = {
        threat["threat_id"]
        for threat in THREATS
    }

    asset_ids = {
        asset["asset_id"]
        for asset in ASSETS
    }

    for threat in THREATS:
        threat["priority_score"] = score_threat(
            threat
        )
        threat["severity"] = classify(
            threat["priority_score"]
        )

    # ---------------------------------------------------------------------
    # THREAT REGISTER
    # ---------------------------------------------------------------------

    header("INTEGRATED ENTERPRISE THREAT REGISTER")

    for threat in THREATS:
        print(
            f"{threat['threat_id']} | "
            f"{threat['category']} | "
            f"{threat['severity']} | "
            f"Priority={threat['priority_score']} | "
            f"{threat['name']}"
        )

        print(
            f"  Surface: {threat['attack_surface']} | "
            f"Boundary: {threat['trust_boundary']}"
        )

        print(
            "  Assets: "
            + ", ".join(
                threat["affected_assets"]
            )
        )

        print(
            f"  Business Consequence: "
            f"{threat['business_consequence']}"
        )

    # ---------------------------------------------------------------------
    # SEVERITY DISTRIBUTION
    # ---------------------------------------------------------------------

    header("THREAT SEVERITY DISTRIBUTION")

    severity_distribution = Counter(
        threat["severity"]
        for threat in THREATS
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

    # ---------------------------------------------------------------------
    # CATEGORY DISTRIBUTION
    # ---------------------------------------------------------------------

    header("THREAT CATEGORY DISTRIBUTION")

    category_distribution = Counter(
        threat["category"]
        for threat in THREATS
    )

    for category, count in sorted(
        category_distribution.items()
    ):
        print(
            f"{category}: {count}"
        )

    # ---------------------------------------------------------------------
    # PRIORITIZED THREATS
    # ---------------------------------------------------------------------

    prioritized_threats = sorted(
        THREATS,
        key=lambda item: (
            -item["priority_score"],
            item["threat_id"],
        )
    )

    header("PRIORITIZED ENTERPRISE THREATS")

    for rank, threat in enumerate(
        prioritized_threats,
        start=1,
    ):
        print(
            f"{rank:02d} | "
            f"{threat['threat_id']} | "
            f"{threat['severity']} | "
            f"Score={threat['priority_score']} | "
            f"{threat['name']}"
        )

    # ---------------------------------------------------------------------
    # ATTACK CHAIN SCORING
    # ---------------------------------------------------------------------

    threat_map = {
        threat["threat_id"]: threat
        for threat in THREATS
    }

    for chain in ATTACK_CHAINS:
        chain_threats = [
            threat_map[threat_id]
            for threat_id in chain["threats"]
        ]

        chain["aggregate_score"] = sum(
            threat["priority_score"]
            for threat in chain_threats
        )

        chain["critical_threats"] = sum(
            threat["severity"] == "CRITICAL"
            for threat in chain_threats
        )

        chain["high_critical_threats"] = sum(
            threat["severity"]
            in {"HIGH", "CRITICAL"}
            for threat in chain_threats
        )

        chain["unique_categories"] = len({
            threat["category"]
            for threat in chain_threats
        })

        chain["affected_assets"] = sorted({
            asset_id
            for threat in chain_threats
            for asset_id in threat["affected_assets"]
        })

    prioritized_chains = sorted(
        ATTACK_CHAINS,
        key=lambda item: (
            -item["aggregate_score"],
            -item["critical_threats"],
            item["hypothesis_id"],
        )
    )

    header("PRIORITIZED ATTACK HYPOTHESES")

    for rank, chain in enumerate(
        prioritized_chains,
        start=1,
    ):
        print(
            f"{rank:02d} | "
            f"{chain['hypothesis_id']} | "
            f"Aggregate={chain['aggregate_score']} | "
            f"{chain['name']}"
        )

        print(
            "  Threat Chain: "
            + " -> ".join(
                chain["threats"]
            )
        )

        print(
            f"  Critical Threats: "
            f"{chain['critical_threats']}"
        )

        print(
            f"  High/Critical Threats: "
            f"{chain['high_critical_threats']}"
        )

        print(
            f"  Threat Categories: "
            f"{chain['unique_categories']}"
        )

        print(
            "  Affected Assets: "
            + ", ".join(
                chain["affected_assets"]
            )
        )

        print(
            f"  Business Objective: "
            f"{chain['business_objective']}"
        )

    # ---------------------------------------------------------------------
    # RED TEAM EXECUTION PLAN
    # ---------------------------------------------------------------------

    RED_TEAM_PLAN = []

    for execution_order, chain in enumerate(
        prioritized_chains,
        start=1,
    ):
        RED_TEAM_PLAN.append({
            "execution_order":
                execution_order,

            "hypothesis_id":
                chain["hypothesis_id"],

            "test_name":
                chain["name"],

            "business_objective":
                chain["business_objective"],

            "priority_score":
                chain["aggregate_score"],

            "required_evidence": [
                "test input",
                "observed model behavior",
                "trust-boundary transition",
                "authorization result",
                "tool / business impact where applicable",
                "security telemetry",
                "risk rating",
            ],
        })

    header("RED-TEAM EXECUTION PRIORITY")

    for test in RED_TEAM_PLAN:
        print(
            f"{test['execution_order']:02d} | "
            f"{test['hypothesis_id']} | "
            f"Priority={test['priority_score']} | "
            f"{test['test_name']}"
        )

        print(
            f"  Objective: "
            f"{test['business_objective']}"
        )

    # ---------------------------------------------------------------------
    # VALIDATION
    # ---------------------------------------------------------------------

    header("INTEGRATED THREAT-MODEL SECURITY CHECKS")

    checks = {
        "Unique Threat IDs":
            len(THREATS)
            == len(threat_ids),

        "All Affected Asset References Valid":
            all(
                asset_id in asset_ids
                for threat in THREATS
                for asset_id
                in threat["affected_assets"]
            ),

        "Prompt Threats Identified":
            any(
                threat["category"]
                == "PROMPT"
                for threat in THREATS
            ),

        "RAG Threats Identified":
            any(
                threat["category"]
                == "RAG"
                for threat in THREATS
            ),

        "Memory Threats Identified":
            any(
                threat["category"]
                == "MEMORY"
                for threat in THREATS
            ),

        "Agent Threats Identified":
            any(
                threat["category"]
                == "AGENT"
                for threat in THREATS
            ),

        "Authorization Threats Identified":
            any(
                threat["category"]
                == "AUTHORIZATION"
                for threat in THREATS
            ),

        "Tool Threats Identified":
            any(
                threat["category"]
                == "TOOL"
                for threat in THREATS
            ),

        "Credential Threat Identified":
            any(
                threat["category"]
                == "SECRET"
                for threat in THREATS
            ),

        "Business Impact Threats Identified":
            any(
                threat["category"]
                == "BUSINESS_DATA"
                for threat in THREATS
            ),

        "Observability Threats Identified":
            any(
                threat["category"]
                == "OBSERVABILITY"
                for threat in THREATS
            ),

        "All Threats Prioritized":
            all(
                "priority_score" in threat
                and "severity" in threat
                for threat in THREATS
            ),

        "Attack Hypotheses Defined":
            len(ATTACK_CHAINS) > 0,

        "All Attack Hypothesis Threats Valid":
            all(
                threat_id in threat_ids
                for chain in ATTACK_CHAINS
                for threat_id in chain["threats"]
            ),

        "Red Team Execution Plan Generated":
            len(RED_TEAM_PLAN)
            == len(ATTACK_CHAINS),
    }

    checks["Integrated Threat Model Valid"] = all(
        checks.values()
    )

    for check, result in checks.items():
        print(
            f"{check}: {result}"
        )

    # ---------------------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------------------

    header("THREAT MODEL SUMMARY")

    high_critical = [
        threat
        for threat in THREATS
        if threat["severity"]
        in {"HIGH", "CRITICAL"}
    ]

    print(
        f"Threat Scenarios: "
        f"{len(THREATS)}"
    )

    print(
        f"Threat Categories: "
        f"{len(category_distribution)}"
    )

    print(
        f"High / Critical Threats: "
        f"{len(high_critical)}"
    )

    print(
        f"Attack Hypotheses: "
        f"{len(ATTACK_CHAINS)}"
    )

    print(
        f"Prioritized Red-Team Tests: "
        f"{len(RED_TEAM_PLAN)}"
    )

    print(
        f"Highest Priority Threat: "
        f"{prioritized_threats[0]['threat_id']} | "
        f"{prioritized_threats[0]['name']}"
    )

    print(
        f"Highest Priority Attack Hypothesis: "
        f"{prioritized_chains[0]['hypothesis_id']} | "
        f"{prioritized_chains[0]['name']}"
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

        "assets":
            ASSETS,

        "threats":
            THREATS,

        "prioritized_threats":
            prioritized_threats,

        "attack_hypotheses":
            ATTACK_CHAINS,

        "prioritized_attack_hypotheses":
            prioritized_chains,

        "red_team_execution_plan":
            RED_TEAM_PLAN,

        "metrics": {
            "threat_scenarios":
                len(THREATS),

            "threat_categories":
                len(category_distribution),

            "high_critical_threats":
                len(high_critical),

            "attack_hypotheses":
                len(ATTACK_CHAINS),

            "red_team_tests":
                len(RED_TEAM_PLAN),
        },

        "security_checks":
            checks,
    }

    evidence["evidence_hash"] = hash_data(
        evidence
    )

    output = Path(
        "day29-integrated-threat-model-prioritization-evidence.json"
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
        "The integrated threat model converts architecture and "
        "attack-surface observations into prioritized adversarial "
        "hypotheses for the enterprise red-team engagement."
    )

    print(
        "Risk priority accounts for likelihood and impact together "
        "with AI-specific factors including persistence, privilege, "
        "blast radius, detection difficulty, and attack-chain feasibility."
    )

    print(
        "The resulting execution plan focuses the red team on attack "
        "chains most capable of crossing trust boundaries into persistent "
        "compromise, privileged execution, restricted-data access, "
        "destructive business impact, or impaired forensic visibility."
    )

    print("\nCore Principle:")

    print(
        "A professional red-team engagement should prioritize attack "
        "hypotheses according to realistic business consequence and "
        "attack-chain feasibility, not simply test every weakness in "
        "arbitrary order."
    )


if __name__ == "__main__":
    main()