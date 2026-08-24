import json
from pathlib import Path


print("\n=== Day 27 Lab 16: Final Incident Response, Forensics & Detection Engineering Comparative Analysis ===\n")


# ============================================================
# 1. DAY 27 RESEARCH QUESTION
# ============================================================

research_question = (
    "When an LLM attack succeeds or suspicious AI behavior occurs, "
    "can we detect it, reconstruct what happened, determine the blast radius, "
    "preserve useful evidence, contain the incident, recover securely, "
    "and improve the system afterward?"
)


# ============================================================
# 2. OBSERVABILITY / TELEMETRY RESULTS
# ============================================================

observability = {
    "telemetry_completeness_rate": 100.00,
    "prompt_observable": True,
    "rag_observable": True,
    "memory_observable": True,
    "agent_plan_observable": True,
    "tool_selection_observable": True,
    "authorization_observable": True,
    "execution_observable": True,
    "response_observable": True,
    "forensic_reconstruction_possible": True,
}


# ============================================================
# 3. FORENSIC LOGGING RESULTS
# ============================================================

forensics = {
    "forensic_completeness_rate": 100.00,
    "event_integrity_validation_rate": 100.00,
    "hash_chain_valid": True,
    "sequence_valid": True,
    "session_correlation_valid": True,
    "trace_correlation_valid": True,
    "timeline_reconstruction_possible": True,
}


# ============================================================
# 4. INCIDENT RECONSTRUCTION RESULTS
# ============================================================

incident_reconstruction = {
    "incident_id": "INC-2709",
    "total_events": 15,
    "correlated_events": 15,
    "event_correlation_rate": 100.00,
    "expected_attack_stages": 15,
    "observed_attack_stages": 15,
    "attack_stage_reconstruction_rate": 100.00,
    "root_cause_identified": True,
    "cross_session_impact": True,
    "cross_agent_impact": True,
    "unauthorized_system_impact": True,
    "impact_type": "unauthorized_record_deletion",
    "time_to_detection_seconds": 192,
    "time_to_incident_declaration_seconds": 195,
}


# ============================================================
# 5. EVIDENCE PRESERVATION RESULTS
# ============================================================

evidence_preservation = {
    "evidence_artifacts": 8,
    "evidence_collection_rate": 100.00,
    "evidence_hash_validation_rate": 100.00,
    "manifest_completeness_rate": 100.00,
    "chain_of_custody_completeness_rate": 100.00,
    "custody_hash_chain_valid": True,
    "tamper_detection_rate": 100.00,
    "missing_artifact_detection_rate": 100.00,
    "forensic_evidence_package_valid": True,
}


# ============================================================
# 6. INDICATORS / INCIDENT INTELLIGENCE
# ============================================================

incident_intelligence = {
    "total_indicators": 12,
    "indicators_of_compromise": 3,
    "indicators_of_behavior": 9,
    "critical_indicators": 7,
    "risk_score": 100,
    "incident_severity": "CRITICAL",
    "persistent_memory_compromise": True,
    "cross_session_propagation": True,
    "authorization_bypass": True,
    "unauthorized_execution": True,
    "unauthorized_system_impact": True,
    "reusable_detection_rules": 8,
}


# ============================================================
# 7. BLAST-RADIUS ANALYSIS
# ============================================================

blast_radius = {
    "total_inventoried_assets": 15,
    "confirmed_compromised_assets": 10,
    "potentially_exposed_assets": 5,
    "assets_requiring_response_action": 15,
    "confirmed_compromise_rate": 66.67,
    "overall_blast_radius_scope_rate": 100.00,
    "affected_sessions": 2,
    "affected_agents": 2,
    "cross_session_spread": True,
    "cross_agent_spread": True,
    "persistent_memory_compromise": True,
    "privileged_execution_scope": True,
    "authorization_boundary_affected": True,
    "scoping_completeness_rate": 100.00,
}


# ============================================================
# 8. CONTAINMENT / ERADICATION RESULTS
# ============================================================

containment = {
    "containment_actions": 15,
    "successful_containment_actions": 15,
    "containment_action_success_rate": 100.00,
    "attack_retests": 9,
    "blocked_attack_retests": 9,
    "attack_retest_block_rate": 100.00,
    "forensic_preservation_rate": 100.00,
    "malicious_memory_eradicated": True,
    "poisoned_rag_quarantined": True,
    "privileged_tool_revoked": True,
    "authorization_boundary_restored": True,
    "attack_chain_blocked": True,
    "legitimate_utility_preserved": True,
}


# ============================================================
# 9. SECURE RECOVERY RESULTS
# ============================================================

recovery = {
    "recovery_actions": 18,
    "successful_recovery_actions": 18,
    "recovery_action_success_rate": 100.00,
    "post_recovery_security_tests": 8,
    "passed_security_tests": 8,
    "post_recovery_security_pass_rate": 100.00,
    "legitimate_utility_tests": 5,
    "completed_utility_tests": 5,
    "legitimate_workflow_completion_rate": 100.00,
    "false_block_rate": 0.00,
    "privileged_execution_still_restricted": True,
    "recovery_approved": True,
}


# ============================================================
# 10. POST-INCIDENT REVIEW RESULTS
# ============================================================

post_incident_review = {
    "root_causes_identified": 6,
    "control_gaps_identified": 7,
    "corrective_preventive_actions": 8,
    "implemented_actions": 8,
    "corrective_action_completion_rate": 100.00,
    "detection_engineering_rules_added": 6,
    "validation_tests": 8,
    "validation_pass_rate": 100.00,
    "control_gap_action_coverage": 100.00,
    "lessons_learned": 7,
}


# ============================================================
# 11. DETECTION IMPROVEMENT
# ============================================================

detection_improvement = {
    "baseline_time_to_detection_seconds": 192,
    "hardened_time_to_detection_seconds": 8,
    "detection_time_reduction_seconds": 184,
    "detection_time_improvement_percent": 95.83,
    "baseline_time_to_incident_declaration_seconds": 195,
    "hardened_time_to_incident_declaration_seconds": 12,
    "incident_declaration_reduction_seconds": 183,
}


# ============================================================
# 12. INCIDENT ATTACK CHAIN
# ============================================================

attack_chain = [
    "INITIAL_PROMPT_INJECTION",
    "POISONED_RAG_RETRIEVAL",
    "POISONED_CONTEXT_ADMISSION",
    "UNAUTHORIZED_MEMORY_WRITE",
    "MEMORY_PERSISTENCE",
    "CROSS_SESSION_MEMORY_RETRIEVAL",
    "AGENT_PLAN_MANIPULATION",
    "RESTRICTED_TARGET_SELECTION",
    "PRIVILEGED_TOOL_SELECTION",
    "AUTHORIZATION_FAILURE",
    "AUTHORIZATION_BYPASS",
    "UNAUTHORIZED_TOOL_EXECUTION",
    "UNAUTHORIZED_SYSTEM_IMPACT",
    "SECURITY_ALERT",
    "INCIDENT_DECLARATION",
]


# ============================================================
# 13. ROOT CAUSE / CONTROL FAILURE CHAIN
# ============================================================

control_failure_chain = [
    "Instruction trust boundary failed.",
    "Poisoned RAG content entered trusted runtime context.",
    "Untrusted content was persisted into long-lived memory.",
    "Malicious memory state crossed session and agent boundaries.",
    "Compromised agent state influenced privileged tool selection.",
    "Authorization denial failed to terminate execution.",
    "Unauthorized privileged execution caused system impact.",
]


# ============================================================
# 14. CORRECTIVE SECURITY CONTROLS
# ============================================================

corrective_controls = [
    "Instruction hierarchy enforcement",
    "RAG source trust and provenance validation",
    "Persistent memory write authorization",
    "Memory trust metadata and integrity controls",
    "Independent privileged-tool authorization",
    "Fail-closed execution authorization",
    "Cross-component attack correlation",
    "Cross-session and cross-agent propagation detection",
]


# ============================================================
# 15. PRINT REPORT
# ============================================================

print("=" * 84)
print("                 DAY 27 RESEARCH QUESTION")
print("=" * 84)
print()
print(research_question)


print("\n" + "=" * 84)
print("                 AI SECURITY OBSERVABILITY")
print("=" * 84)

print(f"Telemetry Completeness Rate: {observability['telemetry_completeness_rate']:.2f}%")
print(f"Prompt Observable: {observability['prompt_observable']}")
print(f"RAG Observable: {observability['rag_observable']}")
print(f"Memory Observable: {observability['memory_observable']}")
print(f"Agent Plan Observable: {observability['agent_plan_observable']}")
print(f"Tool Selection Observable: {observability['tool_selection_observable']}")
print(f"Authorization Observable: {observability['authorization_observable']}")
print(f"Execution Observable: {observability['execution_observable']}")
print(f"Response Observable: {observability['response_observable']}")
print(f"Forensic Reconstruction Possible: {observability['forensic_reconstruction_possible']}")


print("\n" + "=" * 84)
print("                 FORENSIC LOGGING & INTEGRITY")
print("=" * 84)

print(f"Forensic Completeness Rate: {forensics['forensic_completeness_rate']:.2f}%")
print(f"Event Integrity Validation Rate: {forensics['event_integrity_validation_rate']:.2f}%")
print(f"Hash Chain Valid: {forensics['hash_chain_valid']}")
print(f"Sequence Valid: {forensics['sequence_valid']}")
print(f"Session Correlation Valid: {forensics['session_correlation_valid']}")
print(f"Trace Correlation Valid: {forensics['trace_correlation_valid']}")
print(f"Timeline Reconstruction Possible: {forensics['timeline_reconstruction_possible']}")


print("\n" + "=" * 84)
print("                 RECONSTRUCTED ATTACK CHAIN")
print("=" * 84)

for index, stage in enumerate(attack_chain, start=1):
    print(f"{index:02d}. {stage}")


print("\n" + "=" * 84)
print("                 INCIDENT RECONSTRUCTION")
print("=" * 84)

print(f"Incident ID: {incident_reconstruction['incident_id']}")
print(f"Total Events: {incident_reconstruction['total_events']}")
print(f"Correlated Events: {incident_reconstruction['correlated_events']}")
print(f"Event Correlation Rate: {incident_reconstruction['event_correlation_rate']:.2f}%")
print(
    f"Attack-Stage Reconstruction Rate: "
    f"{incident_reconstruction['attack_stage_reconstruction_rate']:.2f}%"
)
print(f"Root Cause Identified: {incident_reconstruction['root_cause_identified']}")
print(f"Cross-Session Impact: {incident_reconstruction['cross_session_impact']}")
print(f"Cross-Agent Impact: {incident_reconstruction['cross_agent_impact']}")
print(f"Unauthorized System Impact: {incident_reconstruction['unauthorized_system_impact']}")
print(f"Impact Type: {incident_reconstruction['impact_type']}")
print(
    f"Initial Time To Detection: "
    f"{incident_reconstruction['time_to_detection_seconds']} seconds"
)


print("\n" + "=" * 84)
print("                 FORENSIC EVIDENCE PRESERVATION")
print("=" * 84)

print(f"Evidence Artifacts: {evidence_preservation['evidence_artifacts']}")
print(f"Evidence Collection Rate: {evidence_preservation['evidence_collection_rate']:.2f}%")
print(
    f"Evidence Hash Validation Rate: "
    f"{evidence_preservation['evidence_hash_validation_rate']:.2f}%"
)
print(
    f"Manifest Completeness Rate: "
    f"{evidence_preservation['manifest_completeness_rate']:.2f}%"
)
print(
    f"Chain-of-Custody Completeness Rate: "
    f"{evidence_preservation['chain_of_custody_completeness_rate']:.2f}%"
)
print(f"Custody Hash Chain Valid: {evidence_preservation['custody_hash_chain_valid']}")
print(f"Tamper Detection Rate: {evidence_preservation['tamper_detection_rate']:.2f}%")
print(
    f"Missing Artifact Detection Rate: "
    f"{evidence_preservation['missing_artifact_detection_rate']:.2f}%"
)


print("\n" + "=" * 84)
print("                 INCIDENT INTELLIGENCE")
print("=" * 84)

print(f"Total Indicators: {incident_intelligence['total_indicators']}")
print(f"Indicators of Compromise: {incident_intelligence['indicators_of_compromise']}")
print(f"Indicators of Behavior: {incident_intelligence['indicators_of_behavior']}")
print(f"Critical Indicators: {incident_intelligence['critical_indicators']}")
print(f"Incident Risk Score: {incident_intelligence['risk_score']} / 100")
print(f"Incident Severity: {incident_intelligence['incident_severity']}")
print(f"Persistent Memory Compromise: {incident_intelligence['persistent_memory_compromise']}")
print(f"Cross-Session Propagation: {incident_intelligence['cross_session_propagation']}")
print(f"Authorization Bypass: {incident_intelligence['authorization_bypass']}")
print(f"Unauthorized Execution: {incident_intelligence['unauthorized_execution']}")
print(f"Unauthorized System Impact: {incident_intelligence['unauthorized_system_impact']}")


print("\n" + "=" * 84)
print("                 BLAST-RADIUS ANALYSIS")
print("=" * 84)

print(f"Total Inventoried Assets: {blast_radius['total_inventoried_assets']}")
print(f"Confirmed Compromised Assets: {blast_radius['confirmed_compromised_assets']}")
print(f"Potentially Exposed Assets: {blast_radius['potentially_exposed_assets']}")
print(f"Assets Requiring Response Action: {blast_radius['assets_requiring_response_action']}")
print(f"Confirmed Compromise Rate: {blast_radius['confirmed_compromise_rate']:.2f}%")
print(
    f"Overall Blast-Radius Scope Rate: "
    f"{blast_radius['overall_blast_radius_scope_rate']:.2f}%"
)
print(f"Cross-Session Spread: {blast_radius['cross_session_spread']}")
print(f"Cross-Agent Spread: {blast_radius['cross_agent_spread']}")
print(f"Persistent Memory Compromise: {blast_radius['persistent_memory_compromise']}")
print(f"Privileged Execution Scope: {blast_radius['privileged_execution_scope']}")
print(f"Authorization Boundary Affected: {blast_radius['authorization_boundary_affected']}")


print("\n" + "=" * 84)
print("                 CONTAINMENT & ERADICATION")
print("=" * 84)

print(f"Containment Actions: {containment['containment_actions']}")
print(f"Successful Actions: {containment['successful_containment_actions']}")
print(f"Containment Success Rate: {containment['containment_action_success_rate']:.2f}%")
print(f"Attack Retest Block Rate: {containment['attack_retest_block_rate']:.2f}%")
print(f"Forensic Preservation Rate: {containment['forensic_preservation_rate']:.2f}%")
print(f"Malicious Memory Eradicated: {containment['malicious_memory_eradicated']}")
print(f"Poisoned RAG Quarantined: {containment['poisoned_rag_quarantined']}")
print(f"Privileged Tool Revoked: {containment['privileged_tool_revoked']}")
print(f"Authorization Boundary Restored: {containment['authorization_boundary_restored']}")
print(f"Attack Chain Blocked: {containment['attack_chain_blocked']}")
print(f"Legitimate Utility Preserved: {containment['legitimate_utility_preserved']}")


print("\n" + "=" * 84)
print("                 SECURE RECOVERY")
print("=" * 84)

print(f"Recovery Actions: {recovery['recovery_actions']}")
print(f"Successful Recovery Actions: {recovery['successful_recovery_actions']}")
print(f"Recovery Success Rate: {recovery['recovery_action_success_rate']:.2f}%")
print(
    f"Post-Recovery Security Pass Rate: "
    f"{recovery['post_recovery_security_pass_rate']:.2f}%"
)
print(
    f"Legitimate Workflow Completion Rate: "
    f"{recovery['legitimate_workflow_completion_rate']:.2f}%"
)
print(f"False Block Rate: {recovery['false_block_rate']:.2f}%")
print(
    f"Privileged Execution Still Restricted: "
    f"{recovery['privileged_execution_still_restricted']}"
)
print(f"Recovery Approved: {recovery['recovery_approved']}")


print("\n" + "=" * 84)
print("                 ROOT-CAUSE / CONTROL FAILURE CHAIN")
print("=" * 84)

for index, item in enumerate(control_failure_chain, start=1):
    print(f"{index}. {item}")


print("\n" + "=" * 84)
print("                 CORRECTIVE SECURITY CONTROLS")
print("=" * 84)

for index, control in enumerate(corrective_controls, start=1):
    print(f"{index}. {control}")


print("\n" + "=" * 84)
print("                 POST-INCIDENT REVIEW")
print("=" * 84)

print(f"Root Causes Identified: {post_incident_review['root_causes_identified']}")
print(f"Control Gaps Identified: {post_incident_review['control_gaps_identified']}")
print(
    f"Corrective / Preventive Actions: "
    f"{post_incident_review['corrective_preventive_actions']}"
)
print(f"Implemented Actions: {post_incident_review['implemented_actions']}")
print(
    f"Corrective Action Completion Rate: "
    f"{post_incident_review['corrective_action_completion_rate']:.2f}%"
)
print(
    f"Detection Engineering Rules Added: "
    f"{post_incident_review['detection_engineering_rules_added']}"
)
print(f"Validation Pass Rate: {post_incident_review['validation_pass_rate']:.2f}%")
print(
    f"Control Gap Action Coverage: "
    f"{post_incident_review['control_gap_action_coverage']:.2f}%"
)
print(f"Lessons Learned: {post_incident_review['lessons_learned']}")


print("\n" + "=" * 84)
print("                 DETECTION & RESPONSE IMPROVEMENT")
print("=" * 84)

print(
    f"Baseline Time To Detection: "
    f"{detection_improvement['baseline_time_to_detection_seconds']} seconds"
)
print(
    f"Hardened Time To Detection: "
    f"{detection_improvement['hardened_time_to_detection_seconds']} seconds"
)
print(
    f"Detection Time Reduction: "
    f"{detection_improvement['detection_time_reduction_seconds']} seconds"
)
print(
    f"Detection Time Improvement: "
    f"{detection_improvement['detection_time_improvement_percent']:.2f}%"
)
print(
    f"Baseline Time To Incident Declaration: "
    f"{detection_improvement['baseline_time_to_incident_declaration_seconds']} seconds"
)
print(
    f"Hardened Time To Incident Declaration: "
    f"{detection_improvement['hardened_time_to_incident_declaration_seconds']} seconds"
)


# ============================================================
# 16. FINAL READINESS CHECKS
# ============================================================

readiness_checks = {
    "AI Security Telemetry Complete": observability["telemetry_completeness_rate"] == 100,
    "Forensic Integrity Verified": forensics["event_integrity_validation_rate"] == 100,
    "Attack Chain Reconstructed": incident_reconstruction["attack_stage_reconstruction_rate"] == 100,
    "Root Cause Identified": incident_reconstruction["root_cause_identified"],
    "Evidence Preserved": evidence_preservation["forensic_evidence_package_valid"],
    "Incident Severity Classified": incident_intelligence["incident_severity"] == "CRITICAL",
    "Blast Radius Reconstructed": blast_radius["scoping_completeness_rate"] == 100,
    "Incident Contained": containment["attack_chain_blocked"],
    "Known Attack Path Retested": containment["attack_retest_block_rate"] == 100,
    "Recovery Security Validated": recovery["post_recovery_security_pass_rate"] == 100,
    "Legitimate Utility Restored": recovery["legitimate_workflow_completion_rate"] == 100,
    "Corrective Actions Completed": post_incident_review["corrective_action_completion_rate"] == 100,
    "Corrective Actions Validated": post_incident_review["validation_pass_rate"] == 100,
    "Detection Improved": detection_improvement["hardened_time_to_detection_seconds"]
    < detection_improvement["baseline_time_to_detection_seconds"],
}

overall_ready = all(readiness_checks.values())


print("\n" + "=" * 84)
print("                 FINAL AI INCIDENT RESPONSE READINESS CHECKS")
print("=" * 84)

for check, result in readiness_checks.items():
    print(f"{check}: {result}")

print()
print(f"Overall AI Incident Response & Forensic Readiness: {overall_ready}")


# ============================================================
# 17. FINAL FINDINGS
# ============================================================

findings = [
    "Security-relevant AI activity was observable across prompt, RAG, memory, agent, authorization, tool, execution, and response boundaries.",

    "The forensic baseline achieved complete event records, validated event integrity, hash-linked ordering, and session/trace correlation.",

    "The simulated incident was reconstructed across 15 attack stages with a 100.00% attack-stage reconstruction rate.",

    "The attack began with instruction manipulation and poisoned retrieval before persisting malicious state into long-lived memory.",

    "Persistent malicious memory crossed session and agent boundaries, demonstrating that AI incident scope can extend beyond the original interaction.",

    "The compromised execution path reached a privileged delete operation after an authorization denial failed to terminate execution.",

    "The resulting incident caused unauthorized system impact against restricted record R-2799.",

    "Forensic collection preserved eight required evidence artifacts with 100.00% hash validation and complete chain-of-custody records.",

    "Twelve reusable AI security indicators were extracted, including three IoCs and nine IoBs, with seven classified as critical.",

    "Blast-radius analysis identified 10 confirmed compromised assets and five potentially exposed assets.",

    "Fifteen containment actions were successfully performed and all nine post-containment attack retests were blocked.",

    "Recovery restored validated functionality while deliberately keeping the privileged delete capability restricted.",

    "All eight post-recovery adversarial validation tests passed and legitimate workflow completion remained at 100.00%.",

    "Post-incident review identified six root causes, seven control gaps, and eight corrective or preventive actions.",

    "Six new detection-engineering correlation rules were introduced after the incident.",

    "The simulated time to detection improved from 192 seconds to 8 seconds, representing a 95.83% reduction.",

    "The incident demonstrates that AI incident response requires correlation across prompts, retrieval, memory, agents, authorization, tools, and downstream systems rather than investigation of a single suspicious prompt.",

    "Evidence preservation before eradication allowed containment and remediation without destroying the forensic basis required for root-cause analysis.",

    "Recovery required adversarial validation and legitimate-utility testing rather than simply re-enabling affected components.",

    "The Day 27 evidence demonstrates an end-to-end AI security incident-response lifecycle from telemetry generation through post-incident improvement.",
]


print("\n" + "=" * 84)
print("                 FINAL FINDINGS")
print("=" * 84)
print()

for index, finding in enumerate(findings, start=1):
    print(f"{index}. {finding}\n")


# ============================================================
# 18. CONCLUSION
# ============================================================

conclusion = """
Day 27 demonstrated an end-to-end AI security incident-response and
forensic engineering lifecycle.

The lab began by establishing security telemetry across prompt ingestion,
retrieval, context, persistent memory, agent planning, tool routing,
authorization, execution, and response generation.

A multi-stage synthetic incident was then reconstructed from initial
instruction manipulation through poisoned RAG retrieval, persistent memory
compromise, cross-session propagation, privileged tool selection,
authorization bypass, unauthorized execution, and system impact.

Forensic evidence was preserved with artifact hashing, evidence manifests,
event correlation, and a hash-linked chain-of-custody ledger.

The investigation extracted reusable Indicators of Compromise and Indicators
of Behavior, classified the incident as CRITICAL, and reconstructed the blast
radius across sessions, agents, memory stores, retrieval infrastructure,
authorization boundaries, privileged tools, identities, targets, and
downstream services.

Containment and eradication successfully blocked the known attack path while
preserving forensic evidence and legitimate read-only utility.

Controlled recovery restored validated services without automatically
restoring high-risk privileged execution.

Post-recovery adversarial validation achieved a 100.00% security pass rate
while legitimate workflow completion remained at 100.00%.

Finally, the post-incident review converted forensic findings into corrective,
preventive, and detective security improvements. New correlation logic reduced
the simulated time to detection from 192 seconds to 8 seconds, representing a
95.83% improvement.

The complete Day 27 exercise demonstrates that effective LLM incident response
requires observability, correlation, forensic integrity, blast-radius analysis,
evidence preservation, containment, secure recovery, adversarial retesting,
and measurable post-incident improvement.
""".strip()


print("\n" + "=" * 84)
print("                 CONCLUSION")
print("=" * 84)
print()
print(conclusion)


core_principle = (
    "If an AI security event cannot be observed and reconstructed, "
    "it cannot be reliably investigated or improved."
)

print("\nCore Principle:")
print(core_principle)


# ============================================================
# 19. SAVE FINAL EVIDENCE
# ============================================================

final_report = {
    "lab": "Day 27 Lab 16",
    "title": "Final Incident Response, Forensics & Detection Engineering Comparative Analysis",
    "research_question": research_question,
    "observability": observability,
    "forensics": forensics,
    "incident_reconstruction": incident_reconstruction,
    "evidence_preservation": evidence_preservation,
    "incident_intelligence": incident_intelligence,
    "blast_radius": blast_radius,
    "containment": containment,
    "recovery": recovery,
    "post_incident_review": post_incident_review,
    "detection_improvement": detection_improvement,
    "attack_chain": attack_chain,
    "control_failure_chain": control_failure_chain,
    "corrective_controls": corrective_controls,
    "readiness_checks": readiness_checks,
    "overall_ai_incident_response_forensic_readiness": overall_ready,
    "findings": findings,
    "conclusion": conclusion,
    "core_principle": core_principle,
}


json_output = Path("day27-final-incident-response-forensics-analysis.json")
txt_output = Path("day27-final-incident-response-forensics-analysis.txt")

with json_output.open("w", encoding="utf-8") as f:
    json.dump(final_report, f, indent=2)

with txt_output.open("w", encoding="utf-8") as f:
    f.write("DAY 27 FINAL INCIDENT RESPONSE & FORENSICS ASSESSMENT\n")
    f.write("=" * 72 + "\n\n")
    f.write("Research Question:\n")
    f.write(research_question + "\n\n")

    f.write("Key Metrics:\n")
    f.write(
        f"- Telemetry Completeness: "
        f"{observability['telemetry_completeness_rate']:.2f}%\n"
    )
    f.write(
        f"- Attack-Stage Reconstruction: "
        f"{incident_reconstruction['attack_stage_reconstruction_rate']:.2f}%\n"
    )
    f.write(
        f"- Evidence Hash Validation: "
        f"{evidence_preservation['evidence_hash_validation_rate']:.2f}%\n"
    )
    f.write(
        f"- Blast-Radius Scoping: "
        f"{blast_radius['scoping_completeness_rate']:.2f}%\n"
    )
    f.write(
        f"- Containment Success: "
        f"{containment['containment_action_success_rate']:.2f}%\n"
    )
    f.write(
        f"- Post-Recovery Security Pass Rate: "
        f"{recovery['post_recovery_security_pass_rate']:.2f}%\n"
    )
    f.write(
        f"- Legitimate Workflow Completion: "
        f"{recovery['legitimate_workflow_completion_rate']:.2f}%\n"
    )
    f.write(
        f"- Detection Time Improvement: "
        f"{detection_improvement['detection_time_improvement_percent']:.2f}%\n"
    )
    f.write(f"- Incident Severity: {incident_intelligence['incident_severity']}\n")
    f.write(f"- Overall Readiness: {overall_ready}\n\n")

    f.write("Final Findings:\n")
    for index, finding in enumerate(findings, start=1):
        f.write(f"{index}. {finding}\n")

    f.write("\nConclusion:\n")
    f.write(conclusion + "\n\n")
    f.write("Core Principle:\n")
    f.write(core_principle + "\n")


print("\nEvidence files written to:")
print(json_output.resolve())
print(txt_output.resolve())