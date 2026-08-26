"""
Day 29 Lab 10
End-to-End Enterprise Multi-Stage Attack Chain

Purpose:
Correlate the previously demonstrated prompt, RAG, memory, agent,
authorization, credential, tool and business-impact weaknesses into one
complete synthetic enterprise LLM attack chain.

Core Principle:
The true severity of an AI weakness is determined by what it enables
when chained across trust boundaries, persistence mechanisms and
privileged business execution.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import Counter
import hashlib
import json


ENGAGEMENT_ID = "ENG-2901"
SYSTEM_ID = "ENT-AI-2901"
INCIDENT_ID = "INC-2910"
TRACE_ID = "TRACE-2910"

ORIGIN_SESSION = "SESSION-2901"
LATER_SESSION = "SESSION-2902"

ORIGIN_AGENT = "AGENT-2901"
LATER_AGENT = "AGENT-2902"


# =============================================================================
# SYNTHETIC ATTACK CHAIN
# =============================================================================

ATTACK_STAGES = [
    {
        "sequence": 1,
        "stage_id": "CHAIN-2901",
        "stage": "INITIAL_PROMPT_INJECTION",
        "component": "AI Assistant",
        "session_id": ORIGIN_SESSION,
        "agent_id": ORIGIN_AGENT,
        "severity": "HIGH",
        "success": True,
        "finding_ids": ["FIND-2902"],
        "description":
            "Untrusted prompt changes the trusted task and begins downstream manipulation.",
    },

    {
        "sequence": 2,
        "stage_id": "CHAIN-2902",
        "stage": "RAG_POISONED_DOCUMENT_ADMISSION",
        "component": "RAG Knowledge System",
        "session_id": ORIGIN_SESSION,
        "agent_id": ORIGIN_AGENT,
        "severity": "HIGH",
        "success": True,
        "finding_ids": ["FIND-2918"],
        "description":
            "Untrusted document DOC-2991 is admitted into model-visible context.",
    },

    {
        "sequence": 3,
        "stage_id": "CHAIN-2903",
        "stage": "INDIRECT_PROMPT_INJECTION",
        "component": "LLM Runtime",
        "session_id": ORIGIN_SESSION,
        "agent_id": ORIGIN_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": ["FIND-2919"],
        "description":
            "Retrieved instructions influence trusted model behavior.",
    },

    {
        "sequence": 4,
        "stage_id": "CHAIN-2904",
        "stage": "RESTRICTED_TARGET_SUBSTITUTION",
        "component": "Agent Planner",
        "session_id": ORIGIN_SESSION,
        "agent_id": ORIGIN_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": [
            "FIND-2920",
            "FIND-2939",
        ],
        "description":
            "Authorized target R-2902 is replaced with restricted target R-2999.",
    },

    {
        "sequence": 5,
        "stage_id": "CHAIN-2905",
        "stage": "UNAUTHORIZED_MEMORY_WRITE",
        "component": "Persistent Memory",
        "session_id": ORIGIN_SESSION,
        "agent_id": ORIGIN_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": [
            "FIND-2921",
            "FIND-2927",
        ],
        "description":
            "Attacker-controlled state is written into persistent AI memory.",
    },

    {
        "sequence": 6,
        "stage_id": "CHAIN-2906",
        "stage": "CROSS_SESSION_MEMORY_ACTIVATION",
        "component": "Persistent Memory",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": ["FIND-2928"],
        "description":
            "Malicious memory is loaded into a later session.",
    },

    {
        "sequence": 7,
        "stage_id": "CHAIN-2907",
        "stage": "CROSS_AGENT_PROPAGATION",
        "component": "Agent Planner",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": ["FIND-2929"],
        "description":
            "Persistent malicious state influences another agent instance.",
    },

    {
        "sequence": 8,
        "stage_id": "CHAIN-2908",
        "stage": "AGENT_GOAL_HIJACKING",
        "component": "Agent Planner",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": [
            "FIND-2930",
            "FIND-2937",
        ],
        "description":
            "Agent goal changes from authorized read to privileged deletion.",
    },

    {
        "sequence": 9,
        "stage_id": "CHAIN-2909",
        "stage": "PRIVILEGED_TOOL_SELECTION",
        "component": "Tools / APIs",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": ["FIND-2938"],
        "description":
            "delete_record is selected outside the approved task.",
    },

    {
        "sequence": 10,
        "stage_id": "CHAIN-2910",
        "stage": "TOOL_PARAMETER_MANIPULATION",
        "component": "Tools / APIs",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": ["FIND-2940"],
        "description":
            "Unsafe delete parameters for R-2999 are accepted.",
    },

    {
        "sequence": 11,
        "stage_id": "CHAIN-2911",
        "stage": "MODEL_GENERATED_AUTHORITY_ACCEPTED",
        "component": "Authorization Service",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": [
            "FIND-2932",
            "FIND-2941",
        ],
        "description":
            "Model or memory-generated authorization claims are trusted.",
    },

    {
        "sequence": 12,
        "stage_id": "CHAIN-2912",
        "stage": "AUTHORIZATION_DENIAL",
        "component": "Authorization Service",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "HIGH",
        "success": False,
        "finding_ids": ["FIND-2942"],
        "description":
            "Authorization service correctly denies delete_record on R-2999.",
    },

    {
        "sequence": 13,
        "stage_id": "CHAIN-2913",
        "stage": "AUTHORIZATION_BYPASS",
        "component": "Tool Runtime",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": ["FIND-2943"],
        "description":
            "Execution continues despite explicit authorization denial.",
    },

    {
        "sequence": 14,
        "stage_id": "CHAIN-2914",
        "stage": "CREDENTIAL_SCOPE_ABUSE",
        "component": "Credential Broker",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": ["FIND-2944"],
        "description":
            "Credential intended for read_record is reused for delete_record.",
    },

    {
        "sequence": 15,
        "stage_id": "CHAIN-2915",
        "stage": "UNAUTHORIZED_PRIVILEGED_EXECUTION",
        "component": "Tool Runtime",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": ["FIND-2945"],
        "description":
            "delete_record executes against restricted target R-2999.",
    },

    {
        "sequence": 16,
        "stage_id": "CHAIN-2916",
        "stage": "DESTRUCTIVE_BUSINESS_IMPACT",
        "component": "Record Service",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": ["FIND-2946"],
        "description":
            "Synthetic restricted business record is deleted.",
    },

    {
        "sequence": 17,
        "stage_id": "CHAIN-2917",
        "stage": "SECURITY_ALERT",
        "component": "Security Telemetry",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": [],
        "description":
            "Detection engine raises a critical alert after unauthorized impact.",
    },

    {
        "sequence": 18,
        "stage_id": "CHAIN-2918",
        "stage": "INCIDENT_DECLARATION",
        "component": "Incident Response",
        "session_id": LATER_SESSION,
        "agent_id": LATER_AGENT,
        "severity": "CRITICAL",
        "success": True,
        "finding_ids": [],
        "description":
            "The correlated attack chain is declared a security incident.",
    },
]


# =============================================================================
# TRUST BOUNDARIES CROSSED
# =============================================================================

TRUST_BOUNDARIES = [
    "User -> AI Assistant",
    "AI Assistant -> LLM Runtime",
    "RAG -> LLM Runtime",
    "LLM Runtime -> Persistent Memory",
    "Persistent Memory -> Agent Planner",
    "Agent Planner -> Authorization Service",
    "Authorization Service -> Tool Runtime",
    "Credential Broker -> Tool Runtime",
    "Tool Runtime -> Business Data",
]


# =============================================================================
# ASSETS
# =============================================================================

ASSETS = [
    "System Instruction Integrity",
    "Retrieved Context",
    "Persistent Memory",
    "Agent Goal",
    "Trusted Target",
    "Authorization Context",
    "Task Credential",
    "Privileged Tool",
    "Restricted Business Data",
    "Security Telemetry",
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
    print("\n" + "=" * 102)
    print(f"        {title}")
    print("=" * 102)


# =============================================================================
# MAIN
# =============================================================================

def main():

    print(
        "\n=== Day 29 Lab 10: End-to-End Enterprise "
        "Multi-Stage Attack Chain ==="
    )

    base_time = datetime.now(
        timezone.utc
    )

    events = []

    previous_hash = "GENESIS"

    for index, stage in enumerate(
        ATTACK_STAGES
    ):

        event_time = (
            base_time
            + timedelta(
                seconds=index * 8
            )
        )

        event = {
            "incident_id":
                INCIDENT_ID,

            "trace_id":
                TRACE_ID,

            "timestamp_utc":
                event_time.isoformat(),

            **stage,

            "previous_hash":
                previous_hash,
        }

        event_hash = hash_data(
            event
        )

        event["event_hash"] = (
            event_hash
        )

        previous_hash = event_hash

        events.append(event)

    # ---------------------------------------------------------------------
    # TIMELINE
    # ---------------------------------------------------------------------

    header("CORRELATED ENTERPRISE ATTACK TIMELINE")

    for event in events:

        print(
            f"{event['sequence']:02d} | "
            f"{event['timestamp_utc']} | "
            f"{event['stage']} | "
            f"{event['severity']}"
        )

        print(
            f"  Session: "
            f"{event['session_id']} | "
            f"Agent: "
            f"{event['agent_id']}"
        )

        print(
            f"  Component: "
            f"{event['component']}"
        )

        print(
            f"  Successful Stage: "
            f"{event['success']}"
        )

        print(
            f"  Description: "
            f"{event['description']}"
        )

    # ---------------------------------------------------------------------
    # ATTACK PHASES
    # ---------------------------------------------------------------------

    phases = {
        "INITIAL_ACCESS": [
            "INITIAL_PROMPT_INJECTION",
            "RAG_POISONED_DOCUMENT_ADMISSION",
            "INDIRECT_PROMPT_INJECTION",
        ],

        "PERSISTENCE": [
            "UNAUTHORIZED_MEMORY_WRITE",
            "CROSS_SESSION_MEMORY_ACTIVATION",
            "CROSS_AGENT_PROPAGATION",
        ],

        "EXECUTION_MANIPULATION": [
            "AGENT_GOAL_HIJACKING",
            "PRIVILEGED_TOOL_SELECTION",
            "TOOL_PARAMETER_MANIPULATION",
        ],

        "PRIVILEGE_ESCALATION": [
            "MODEL_GENERATED_AUTHORITY_ACCEPTED",
            "AUTHORIZATION_BYPASS",
            "CREDENTIAL_SCOPE_ABUSE",
        ],

        "IMPACT": [
            "UNAUTHORIZED_PRIVILEGED_EXECUTION",
            "DESTRUCTIVE_BUSINESS_IMPACT",
        ],

        "DETECTION_RESPONSE": [
            "SECURITY_ALERT",
            "INCIDENT_DECLARATION",
        ],
    }

    header("ATTACK PHASE CORRELATION")

    observed_stages = {
        event["stage"]
        for event in events
    }

    phase_results = {}

    for phase, stages in phases.items():

        observed = [
            stage
            for stage in stages
            if stage in observed_stages
        ]

        complete = (
            len(observed)
            == len(stages)
        )

        phase_results[phase] = {
            "expected_stages":
                stages,

            "observed_stages":
                observed,

            "complete":
                complete,
        }

        print(
            f"{phase} | "
            f"{len(observed)} / "
            f"{len(stages)} | "
            f"Complete={complete}"
        )

    # ---------------------------------------------------------------------
    # BLAST RADIUS
    # ---------------------------------------------------------------------

    affected_sessions = sorted({
        event["session_id"]
        for event in events
    })

    affected_agents = sorted({
        event["agent_id"]
        for event in events
    })

    affected_components = sorted({
        event["component"]
        for event in events
    })

    finding_ids = sorted({
        finding_id
        for event in events
        for finding_id
        in event["finding_ids"]
    })

    header("ENTERPRISE BLAST-RADIUS ANALYSIS")

    print(
        f"Affected Sessions: "
        f"{affected_sessions}"
    )

    print(
        f"Affected Session Count: "
        f"{len(affected_sessions)}"
    )

    print(
        f"Affected Agents: "
        f"{affected_agents}"
    )

    print(
        f"Affected Agent Count: "
        f"{len(affected_agents)}"
    )

    print(
        f"Affected Components: "
        f"{affected_components}"
    )

    print(
        f"Affected Component Count: "
        f"{len(affected_components)}"
    )

    print(
        f"Trust Boundaries Crossed: "
        f"{len(TRUST_BOUNDARIES)}"
    )

    print(
        f"Security Findings Correlated: "
        f"{len(finding_ids)}"
    )

    print(
        f"Restricted Target: "
        f"R-2999"
    )

    print(
        f"Privileged Tool: "
        f"delete_record"
    )

    print(
        f"Business Impact: "
        f"synthetic_restricted_record_deletion"
    )

    # ---------------------------------------------------------------------
    # TIMING
    # ---------------------------------------------------------------------

    initial_attack_time = datetime.fromisoformat(
        events[0]["timestamp_utc"]
    )

    impact_event = next(
        event
        for event in events
        if event["stage"]
        == "DESTRUCTIVE_BUSINESS_IMPACT"
    )

    alert_event = next(
        event
        for event in events
        if event["stage"]
        == "SECURITY_ALERT"
    )

    incident_event = next(
        event
        for event in events
        if event["stage"]
        == "INCIDENT_DECLARATION"
    )

    impact_time = datetime.fromisoformat(
        impact_event["timestamp_utc"]
    )

    alert_time = datetime.fromisoformat(
        alert_event["timestamp_utc"]
    )

    incident_time = datetime.fromisoformat(
        incident_event["timestamp_utc"]
    )

    time_to_impact = (
        impact_time
        - initial_attack_time
    ).total_seconds()

    time_to_detection = (
        alert_time
        - initial_attack_time
    ).total_seconds()

    time_to_incident = (
        incident_time
        - initial_attack_time
    ).total_seconds()

    header("ATTACK / DETECTION TIMING")

    print(
        f"Time to Business Impact: "
        f"{time_to_impact:.2f} seconds"
    )

    print(
        f"Time to Detection: "
        f"{time_to_detection:.2f} seconds"
    )

    print(
        f"Time to Incident Declaration: "
        f"{time_to_incident:.2f} seconds"
    )

    detected_after_impact = (
        alert_time
        >
        impact_time
    )

    print(
        f"Detection Occurred After Business Impact: "
        f"{detected_after_impact}"
    )

    # ---------------------------------------------------------------------
    # EVIDENCE VALIDATION
    # ---------------------------------------------------------------------

    hash_chain_valid = True

    previous_hash = "GENESIS"

    for event in events:

        expected_previous = (
            event["previous_hash"]
        )

        if expected_previous != previous_hash:
            hash_chain_valid = False

        validation_event = dict(
            event
        )

        stored_hash = validation_event.pop(
            "event_hash"
        )

        calculated_hash = hash_data(
            validation_event
        )

        if stored_hash != calculated_hash:
            hash_chain_valid = False

        previous_hash = stored_hash

    header("ATTACK-CHAIN EVIDENCE QUALITY")

    print(
        f"Events: "
        f"{len(events)}"
    )

    print(
        f"Single Incident ID: "
        f"{len({e['incident_id'] for e in events}) == 1}"
    )

    print(
        f"Single Trace ID: "
        f"{len({e['trace_id'] for e in events}) == 1}"
    )

    print(
        f"Hash Chain Valid: "
        f"{hash_chain_valid}"
    )

    print(
        f"Finding IDs Correlated: "
        f"{len(finding_ids)}"
    )

    # ---------------------------------------------------------------------
    # ATTACK SUCCESS
    # ---------------------------------------------------------------------

    required_success_stages = [
        "INITIAL_PROMPT_INJECTION",
        "RAG_POISONED_DOCUMENT_ADMISSION",
        "INDIRECT_PROMPT_INJECTION",
        "UNAUTHORIZED_MEMORY_WRITE",
        "CROSS_SESSION_MEMORY_ACTIVATION",
        "CROSS_AGENT_PROPAGATION",
        "AGENT_GOAL_HIJACKING",
        "PRIVILEGED_TOOL_SELECTION",
        "TOOL_PARAMETER_MANIPULATION",
        "MODEL_GENERATED_AUTHORITY_ACCEPTED",
        "AUTHORIZATION_BYPASS",
        "CREDENTIAL_SCOPE_ABUSE",
        "UNAUTHORIZED_PRIVILEGED_EXECUTION",
        "DESTRUCTIVE_BUSINESS_IMPACT",
    ]

    stage_map = {
        event["stage"]: event
        for event in events
    }

    attack_chain_successful = all(
        stage_map[stage]["success"]
        for stage in required_success_stages
    )

    header("END-TO-END ATTACK RESULT")

    print(
        f"Required Attack Stages: "
        f"{len(required_success_stages)}"
    )

    print(
        f"Successful Required Stages: "
        f"{sum(stage_map[s]['success'] for s in required_success_stages)}"
    )

    print(
        f"Cross-Session Compromise: "
        f"{len(affected_sessions) > 1}"
    )

    print(
        f"Cross-Agent Compromise: "
        f"{len(affected_agents) > 1}"
    )

    print(
        f"Persistent Compromise: True"
    )

    print(
        f"Authorization Bypass: True"
    )

    print(
        f"Credential Scope Abuse: True"
    )

    print(
        f"Unauthorized Privileged Execution: True"
    )

    print(
        f"Destructive Business Impact: True"
    )

    print(
        f"End-to-End Enterprise Attack Chain Successful: "
        f"{attack_chain_successful}"
    )

    # ---------------------------------------------------------------------
    # VALIDATION
    # ---------------------------------------------------------------------

    header("MULTI-STAGE ATTACK-CHAIN SECURITY CHECKS")

    checks = {
        "Initial Compromise Reconstructed":
            "INITIAL_PROMPT_INJECTION"
            in observed_stages,

        "RAG Compromise Reconstructed":
            "INDIRECT_PROMPT_INJECTION"
            in observed_stages,

        "Persistence Established":
            "UNAUTHORIZED_MEMORY_WRITE"
            in observed_stages,

        "Cross-Session Spread Reconstructed":
            len(affected_sessions) > 1,

        "Cross-Agent Spread Reconstructed":
            len(affected_agents) > 1,

        "Agent Goal Hijacking Reconstructed":
            "AGENT_GOAL_HIJACKING"
            in observed_stages,

        "Privileged Tool Abuse Reconstructed":
            "PRIVILEGED_TOOL_SELECTION"
            in observed_stages,

        "Authorization Bypass Reconstructed":
            "AUTHORIZATION_BYPASS"
            in observed_stages,

        "Credential Abuse Reconstructed":
            "CREDENTIAL_SCOPE_ABUSE"
            in observed_stages,

        "Unauthorized Execution Reconstructed":
            "UNAUTHORIZED_PRIVILEGED_EXECUTION"
            in observed_stages,

        "Business Impact Reconstructed":
            "DESTRUCTIVE_BUSINESS_IMPACT"
            in observed_stages,

        "Detection Reconstructed":
            "SECURITY_ALERT"
            in observed_stages,

        "Incident Declaration Reconstructed":
            "INCIDENT_DECLARATION"
            in observed_stages,

        "All Attack Phases Complete":
            all(
                result["complete"]
                for result in phase_results.values()
            ),

        "Hash-Linked Evidence Valid":
            hash_chain_valid,

        "Finding Correlation Available":
            len(finding_ids) > 0,

        "End-to-End Attack Chain Successful":
            attack_chain_successful,
    }

    checks[
        "Multi-Stage Enterprise Attack Assessment Valid"
    ] = all(
        checks.values()
    )

    for check, result in checks.items():

        print(
            f"{check}: {result}"
        )

    # ---------------------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------------------

    header("MULTI-STAGE ENTERPRISE ATTACK SUMMARY")

    print(
        f"Attack Events: "
        f"{len(events)}"
    )

    print(
        f"Attack Phases: "
        f"{len(phases)}"
    )

    print(
        f"Affected Sessions: "
        f"{len(affected_sessions)}"
    )

    print(
        f"Affected Agents: "
        f"{len(affected_agents)}"
    )

    print(
        f"Affected Components: "
        f"{len(affected_components)}"
    )

    print(
        f"Trust Boundaries Crossed: "
        f"{len(TRUST_BOUNDARIES)}"
    )

    print(
        f"Correlated Findings: "
        f"{len(finding_ids)}"
    )

    print(
        f"Time to Impact: "
        f"{time_to_impact:.2f} seconds"
    )

    print(
        f"Time to Detection: "
        f"{time_to_detection:.2f} seconds"
    )

    print(
        f"Detection After Impact: "
        f"{detected_after_impact}"
    )

    print(
        f"Attack Chain Successful: "
        f"{attack_chain_successful}"
    )

    # ---------------------------------------------------------------------
    # EXPORT
    # ---------------------------------------------------------------------

    evidence = {
        "engagement_id":
            ENGAGEMENT_ID,

        "system_id":
            SYSTEM_ID,

        "incident_id":
            INCIDENT_ID,

        "trace_id":
            TRACE_ID,

        "events":
            events,

        "attack_phases":
            phase_results,

        "trust_boundaries":
            TRUST_BOUNDARIES,

        "assets":
            ASSETS,

        "blast_radius": {
            "affected_sessions":
                affected_sessions,

            "affected_agents":
                affected_agents,

            "affected_components":
                affected_components,

            "finding_ids":
                finding_ids,

            "restricted_target":
                "R-2999",

            "privileged_tool":
                "delete_record",

            "business_impact":
                "synthetic_restricted_record_deletion",
        },

        "timing": {
            "time_to_impact_seconds":
                time_to_impact,

            "time_to_detection_seconds":
                time_to_detection,

            "time_to_incident_declaration_seconds":
                time_to_incident,

            "detection_after_impact":
                detected_after_impact,
        },

        "metrics": {
            "attack_events":
                len(events),

            "attack_phases":
                len(phases),

            "affected_sessions":
                len(affected_sessions),

            "affected_agents":
                len(affected_agents),

            "affected_components":
                len(affected_components),

            "trust_boundaries_crossed":
                len(TRUST_BOUNDARIES),

            "correlated_findings":
                len(finding_ids),

            "attack_chain_successful":
                attack_chain_successful,
        },

        "security_checks":
            checks,
    }

    evidence["evidence_package_hash"] = hash_data(
        evidence
    )

    output = Path(
        "day29-end-to-end-enterprise-attack-chain-evidence.json"
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
        "The end-to-end attack-chain assessment demonstrates how "
        "individual AI security weaknesses combine across prompts, "
        "retrieval, persistent memory, agents, authorization, credentials, "
        "tools and business-data boundaries."
    )

    print(
        "The attack survives the originating interaction, propagates "
        "into a later session and agent, reaches privileged execution, "
        "bypasses authorization and creates synthetic destructive "
        "business impact."
    )

    print(
        "Detection occurring after impact demonstrates that prevention "
        "and earlier behavioral correlation are required in addition "
        "to post-impact alerting."
    )

    print("\nCore Principle:")

    print(
        "The true severity of an AI weakness is determined by what it "
        "enables when chained across trust boundaries, persistence "
        "mechanisms and privileged business execution."
    )


if __name__ == "__main__":
    main()