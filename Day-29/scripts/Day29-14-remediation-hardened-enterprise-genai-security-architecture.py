"""
Day 29 Lab 14
Remediation Plan & Hardened Enterprise GenAI Security Architecture

Purpose:
Translate the consolidated Day 29 findings into a hardened enterprise
GenAI architecture with preventive, detective, and corrective controls.

The architecture must directly address:
- instruction trust;
- RAG provenance and context admission;
- persistent memory;
- agent/task integrity;
- tool/target/parameter controls;
- authorization;
- credentials;
- data protection;
- detection engineering;
- recovery and retesting.

Core Principle:
Effective remediation must break the demonstrated attack chain at multiple
independent trust boundaries rather than relying on a single LLM guardrail.
"""

from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
import hashlib
import json


ENGAGEMENT_ID = "ENG-2901"
SYSTEM_ID = "ENT-AI-2901"
TRACE_ID = "TRACE-2914"


# =============================================================================
# HARDENED SECURITY ZONES
# =============================================================================

SECURITY_ZONES = [
    {
        "zone_id": "ZONE-2901",
        "name": "Untrusted Input Zone",
        "trust_level": 0,
        "components": [
            "Enterprise User Input",
            "External Content",
        ],
    },
    {
        "zone_id": "ZONE-2902",
        "name": "Input Security Mediation Zone",
        "trust_level": 2,
        "components": [
            "Input Gateway",
            "Prompt Security Classifier",
            "Instruction Trust Resolver",
        ],
    },
    {
        "zone_id": "ZONE-2903",
        "name": "RAG Security Zone",
        "trust_level": 2,
        "components": [
            "Source Trust Validator",
            "Document Provenance Validator",
            "Retrieval Authorization",
            "Context Admission Gateway",
        ],
    },
    {
        "zone_id": "ZONE-2904",
        "name": "Trusted LLM Runtime Zone",
        "trust_level": 4,
        "components": [
            "System Prompt",
            "LLM Runtime",
            "Policy Engine",
        ],
    },
    {
        "zone_id": "ZONE-2905",
        "name": "Persistent Memory Security Zone",
        "trust_level": 3,
        "components": [
            "Memory Write Authorization",
            "Memory Provenance Service",
            "Session / Agent Binding",
            "Memory Expiry Enforcement",
            "Memory Integrity Validator",
            "Memory Store",
        ],
    },
    {
        "zone_id": "ZONE-2906",
        "name": "Agent Execution Security Zone",
        "trust_level": 3,
        "components": [
            "Agent Planner",
            "Trusted Goal Binder",
            "Task Binding Service",
            "Tool Allowlist",
            "Target Binder",
            "Parameter Validator",
        ],
    },
    {
        "zone_id": "ZONE-2907",
        "name": "Independent Authorization Zone",
        "trust_level": 5,
        "components": [
            "Identity Service",
            "Policy Decision Point",
            "Authorization Service",
            "Approval Verification",
        ],
    },
    {
        "zone_id": "ZONE-2908",
        "name": "Credential Security Zone",
        "trust_level": 5,
        "components": [
            "Credential Broker",
            "Short-Lived Token Service",
        ],
    },
    {
        "zone_id": "ZONE-2909",
        "name": "Privileged Tool Zone",
        "trust_level": 4,
        "components": [
            "Read Record Tool",
            "Delete Record Tool",
        ],
    },
    {
        "zone_id": "ZONE-2910",
        "name": "Business Data Security Zone",
        "trust_level": 5,
        "components": [
            "Record Service",
            "Restricted Business Records",
            "Resource Authorization",
        ],
    },
    {
        "zone_id": "ZONE-2911",
        "name": "Data Protection Zone",
        "trust_level": 4,
        "components": [
            "Context Data Minimization",
            "Output DLP",
            "Classification Enforcement",
        ],
    },
    {
        "zone_id": "ZONE-2912",
        "name": "AI Security Observability Zone",
        "trust_level": 4,
        "components": [
            "Security Telemetry Pipeline",
            "Detection Engine",
            "Correlation Engine",
            "Tamper-Evident Audit Store",
        ],
    },
]


# =============================================================================
# SECURITY CONTROLS
# =============================================================================

CONTROLS = [
    {
        "control_id": "CTRL-2914-01",
        "name": "Instruction Trust Separation",
        "type": "PREVENTIVE",
        "addresses": ["CF-2901"],
        "zone": "ZONE-2902",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-02",
        "name": "Trusted Task Binding",
        "type": "PREVENTIVE",
        "addresses": ["CF-2901", "CF-2904"],
        "zone": "ZONE-2906",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-03",
        "name": "Trusted Target Binding",
        "type": "PREVENTIVE",
        "addresses": ["CF-2901", "CF-2904"],
        "zone": "ZONE-2906",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-04",
        "name": "RAG Source Provenance Validation",
        "type": "PREVENTIVE",
        "addresses": ["CF-2902"],
        "zone": "ZONE-2903",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-05",
        "name": "Indirect Prompt Injection Detection",
        "type": "PREVENTIVE",
        "addresses": ["CF-2902"],
        "zone": "ZONE-2903",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-06",
        "name": "Fail-Closed RAG Context Admission",
        "type": "PREVENTIVE",
        "addresses": ["CF-2902"],
        "zone": "ZONE-2903",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-07",
        "name": "Authorized Memory Writes",
        "type": "PREVENTIVE",
        "addresses": ["CF-2903"],
        "zone": "ZONE-2905",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-08",
        "name": "Memory Provenance & Trust Classification",
        "type": "PREVENTIVE",
        "addresses": ["CF-2903"],
        "zone": "ZONE-2905",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-09",
        "name": "Session / Agent Memory Isolation",
        "type": "PREVENTIVE",
        "addresses": ["CF-2903"],
        "zone": "ZONE-2905",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-10",
        "name": "Memory Expiry Enforcement",
        "type": "PREVENTIVE",
        "addresses": ["CF-2903"],
        "zone": "ZONE-2905",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-11",
        "name": "Tool Allowlisting",
        "type": "PREVENTIVE",
        "addresses": ["CF-2904"],
        "zone": "ZONE-2906",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-12",
        "name": "Strict Tool Parameter Validation",
        "type": "PREVENTIVE",
        "addresses": ["CF-2904"],
        "zone": "ZONE-2906",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-13",
        "name": "Independent Fail-Closed Authorization",
        "type": "PREVENTIVE",
        "addresses": ["CF-2905"],
        "zone": "ZONE-2907",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-14",
        "name": "External Approval Verification",
        "type": "PREVENTIVE",
        "addresses": ["CF-2905"],
        "zone": "ZONE-2907",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-15",
        "name": "Authorization-to-Execution Binding",
        "type": "PREVENTIVE",
        "addresses": ["CF-2905"],
        "zone": "ZONE-2907",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-16",
        "name": "Short-Lived Task-Bound Credentials",
        "type": "PREVENTIVE",
        "addresses": ["CF-2906"],
        "zone": "ZONE-2908",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-17",
        "name": "Resource-Level Authorization",
        "type": "PREVENTIVE",
        "addresses": ["CF-2904", "CF-2905"],
        "zone": "ZONE-2910",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-18",
        "name": "Sensitive Context Minimization",
        "type": "PREVENTIVE",
        "addresses": ["CF-2907"],
        "zone": "ZONE-2911",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-19",
        "name": "Independent Output DLP",
        "type": "PREVENTIVE",
        "addresses": ["CF-2907"],
        "zone": "ZONE-2911",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-20",
        "name": "AI Attack-Chain Correlation",
        "type": "DETECTIVE",
        "addresses": ["CF-2908"],
        "zone": "ZONE-2912",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-21",
        "name": "Prompt / RAG / Memory Early Detection",
        "type": "DETECTIVE",
        "addresses": ["CF-2908"],
        "zone": "ZONE-2912",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-22",
        "name": "Tamper-Evident AI Audit Logging",
        "type": "DETECTIVE",
        "addresses": ["CF-2908"],
        "zone": "ZONE-2912",
        "status": "IMPLEMENTED",
    },
    {
        "control_id": "CTRL-2914-23",
        "name": "Soft Delete & Business Recovery",
        "type": "CORRECTIVE",
        "addresses": ["CF-2904"],
        "zone": "ZONE-2910",
        "status": "IMPLEMENTED",
    },
]


# =============================================================================
# TRUST BOUNDARIES
# =============================================================================

TRUST_BOUNDARIES = [
    {
        "boundary_id": "HTB-2901",
        "source": "Untrusted Input Zone",
        "destination": "Input Security Mediation Zone",
        "enforcement": [
            "Prompt classification",
            "Instruction trust separation",
            "Input normalization",
        ],
    },
    {
        "boundary_id": "HTB-2902",
        "source": "RAG Security Zone",
        "destination": "Trusted LLM Runtime Zone",
        "enforcement": [
            "Source provenance",
            "Indirect injection scanning",
            "Fail-closed context admission",
        ],
    },
    {
        "boundary_id": "HTB-2903",
        "source": "Trusted LLM Runtime Zone",
        "destination": "Persistent Memory Security Zone",
        "enforcement": [
            "Explicit memory-write authorization",
            "Provenance binding",
            "Trust classification",
        ],
    },
    {
        "boundary_id": "HTB-2904",
        "source": "Persistent Memory Security Zone",
        "destination": "Agent Execution Security Zone",
        "enforcement": [
            "Session binding",
            "Agent binding",
            "Expiry validation",
            "Non-authoritative memory treatment",
        ],
    },
    {
        "boundary_id": "HTB-2905",
        "source": "Trusted LLM Runtime Zone",
        "destination": "Agent Execution Security Zone",
        "enforcement": [
            "Trusted goal binding",
            "Trusted task binding",
        ],
    },
    {
        "boundary_id": "HTB-2906",
        "source": "Agent Execution Security Zone",
        "destination": "Independent Authorization Zone",
        "enforcement": [
            "Independent identity validation",
            "External approval verification",
            "Fail-closed policy decision",
        ],
    },
    {
        "boundary_id": "HTB-2907",
        "source": "Independent Authorization Zone",
        "destination": "Privileged Tool Zone",
        "enforcement": [
            "Authorization-to-execution binding",
            "Tool allowlisting",
            "Target binding",
            "Parameter validation",
        ],
    },
    {
        "boundary_id": "HTB-2908",
        "source": "Credential Security Zone",
        "destination": "Privileged Tool Zone",
        "enforcement": [
            "Short-lived task credential",
            "Tool-bound scope",
            "Target-bound scope",
        ],
    },
    {
        "boundary_id": "HTB-2909",
        "source": "Privileged Tool Zone",
        "destination": "Business Data Security Zone",
        "enforcement": [
            "Resource-level authorization",
            "Transaction validation",
            "Destructive-action approval",
        ],
    },
    {
        "boundary_id": "HTB-2910",
        "source": "All Runtime Zones",
        "destination": "AI Security Observability Zone",
        "enforcement": [
            "Independent telemetry",
            "Correlation identifiers",
            "Hash-linked audit evidence",
        ],
    },
]


# =============================================================================
# ATTACK-CHAIN BREAKPOINTS
# =============================================================================

ATTACK_CHAIN_BREAKPOINTS = [
    {
        "attack_stage": "Prompt Injection",
        "controls": [
            "CTRL-2914-01",
            "CTRL-2914-02",
        ],
    },
    {
        "attack_stage": "Poisoned RAG Admission",
        "controls": [
            "CTRL-2914-04",
            "CTRL-2914-05",
            "CTRL-2914-06",
        ],
    },
    {
        "attack_stage": "Persistent Memory Poisoning",
        "controls": [
            "CTRL-2914-07",
            "CTRL-2914-08",
            "CTRL-2914-09",
            "CTRL-2914-10",
        ],
    },
    {
        "attack_stage": "Agent Goal Hijacking",
        "controls": [
            "CTRL-2914-02",
            "CTRL-2914-11",
        ],
    },
    {
        "attack_stage": "Target / Parameter Manipulation",
        "controls": [
            "CTRL-2914-03",
            "CTRL-2914-12",
        ],
    },
    {
        "attack_stage": "Authorization Bypass",
        "controls": [
            "CTRL-2914-13",
            "CTRL-2914-14",
            "CTRL-2914-15",
        ],
    },
    {
        "attack_stage": "Credential Abuse",
        "controls": [
            "CTRL-2914-16",
        ],
    },
    {
        "attack_stage": "Restricted Business Impact",
        "controls": [
            "CTRL-2914-17",
            "CTRL-2914-23",
        ],
    },
    {
        "attack_stage": "Sensitive Data Disclosure",
        "controls": [
            "CTRL-2914-18",
            "CTRL-2914-19",
        ],
    },
    {
        "attack_stage": "Detection Evasion",
        "controls": [
            "CTRL-2914-20",
            "CTRL-2914-21",
            "CTRL-2914-22",
        ],
    },
]


# =============================================================================
# REMEDIATION TRACKER
# =============================================================================

REMEDIATION_PLAN = [
    {
        "finding_id": "CF-2901",
        "owner": "AI Security Engineering",
        "status": "IMPLEMENTED",
        "retest_required": True,
    },
    {
        "finding_id": "CF-2902",
        "owner": "RAG Platform Team",
        "status": "IMPLEMENTED",
        "retest_required": True,
    },
    {
        "finding_id": "CF-2903",
        "owner": "AI Platform Team",
        "status": "IMPLEMENTED",
        "retest_required": True,
    },
    {
        "finding_id": "CF-2904",
        "owner": "Agent Security Team",
        "status": "IMPLEMENTED",
        "retest_required": True,
    },
    {
        "finding_id": "CF-2905",
        "owner": "Identity Security",
        "status": "IMPLEMENTED",
        "retest_required": True,
    },
    {
        "finding_id": "CF-2906",
        "owner": "Platform Identity Team",
        "status": "IMPLEMENTED",
        "retest_required": True,
    },
    {
        "finding_id": "CF-2907",
        "owner": "Data Security",
        "status": "IMPLEMENTED",
        "retest_required": True,
    },
    {
        "finding_id": "CF-2908",
        "owner": "AI SOC",
        "status": "IMPLEMENTED",
        "retest_required": True,
    },
]


# =============================================================================
# DEPLOYMENT SECURITY GATES
# =============================================================================

DEPLOYMENT_GATES = [
    {
        "gate_id": "GATE-2914-01",
        "name": "Instruction Trust Controls Implemented",
        "required": True,
        "passed": True,
    },
    {
        "gate_id": "GATE-2914-02",
        "name": "RAG Provenance & Admission Controls Implemented",
        "required": True,
        "passed": True,
    },
    {
        "gate_id": "GATE-2914-03",
        "name": "Memory Security Controls Implemented",
        "required": True,
        "passed": True,
    },
    {
        "gate_id": "GATE-2914-04",
        "name": "Agent / Tool Controls Implemented",
        "required": True,
        "passed": True,
    },
    {
        "gate_id": "GATE-2914-05",
        "name": "Fail-Closed Authorization Implemented",
        "required": True,
        "passed": True,
    },
    {
        "gate_id": "GATE-2914-06",
        "name": "Task-Bound Credentials Implemented",
        "required": True,
        "passed": True,
    },
    {
        "gate_id": "GATE-2914-07",
        "name": "Sensitive Data Controls Implemented",
        "required": True,
        "passed": True,
    },
    {
        "gate_id": "GATE-2914-08",
        "name": "Early Detection Controls Implemented",
        "required": True,
        "passed": True,
    },
    {
        "gate_id": "GATE-2914-09",
        "name": "Adversarial Retest Completed",
        "required": True,
        "passed": False,
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
    print("\n" + "=" * 104)
    print(f"        {title}")
    print("=" * 104)


# =============================================================================
# MAIN
# =============================================================================

def main():

    print(
        "\n=== Day 29 Lab 14: Remediation Plan & Hardened "
        "Enterprise GenAI Security Architecture ==="
    )

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    # ---------------------------------------------------------------------
    # ZONES
    # ---------------------------------------------------------------------

    header("HARDENED SECURITY ZONES")

    for zone in SECURITY_ZONES:

        print(
            f"{zone['zone_id']} | "
            f"Trust={zone['trust_level']} | "
            f"{zone['name']}"
        )

        print(
            "  Components: "
            + ", ".join(
                zone["components"]
            )
        )

    # ---------------------------------------------------------------------
    # CONTROLS
    # ---------------------------------------------------------------------

    header("REMEDIATION SECURITY CONTROLS")

    for control in CONTROLS:

        print(
            f"{control['control_id']} | "
            f"{control['type']} | "
            f"{control['status']} | "
            f"{control['name']}"
        )

        print(
            "  Addresses: "
            + ", ".join(
                control["addresses"]
            )
        )

        print(
            f"  Zone: "
            f"{control['zone']}"
        )

    # ---------------------------------------------------------------------
    # CONTROL DISTRIBUTION
    # ---------------------------------------------------------------------

    control_type_distribution = Counter(
        control["type"]
        for control in CONTROLS
    )

    header("CONTROL TYPE DISTRIBUTION")

    for control_type in [
        "PREVENTIVE",
        "DETECTIVE",
        "CORRECTIVE",
    ]:

        print(
            f"{control_type}: "
            f"{control_type_distribution.get(control_type, 0)}"
        )

    # ---------------------------------------------------------------------
    # TRUST BOUNDARIES
    # ---------------------------------------------------------------------

    header("HARDENED TRUST BOUNDARIES")

    for boundary in TRUST_BOUNDARIES:

        print(
            f"{boundary['boundary_id']} | "
            f"{boundary['source']} -> "
            f"{boundary['destination']}"
        )

        print(
            "  Enforcement: "
            + ", ".join(
                boundary["enforcement"]
            )
        )

    # ---------------------------------------------------------------------
    # FINDING CONTROL COVERAGE
    # ---------------------------------------------------------------------

    finding_control_map = {}

    for finding_id in [
        "CF-2901",
        "CF-2902",
        "CF-2903",
        "CF-2904",
        "CF-2905",
        "CF-2906",
        "CF-2907",
        "CF-2908",
    ]:

        mapped_controls = [
            control["control_id"]
            for control in CONTROLS
            if finding_id
            in control["addresses"]
        ]

        finding_control_map[
            finding_id
        ] = mapped_controls

    header("CONSOLIDATED FINDING CONTROL COVERAGE")

    for finding_id, controls in (
        finding_control_map.items()
    ):

        print(
            f"{finding_id} | "
            f"Controls={len(controls)}"
        )

        print(
            "  "
            + ", ".join(
                controls
            )
        )

    # ---------------------------------------------------------------------
    # ATTACK CHAIN BREAKPOINTS
    # ---------------------------------------------------------------------

    header("ATTACK-CHAIN BREAKPOINTS")

    for breakpoint in ATTACK_CHAIN_BREAKPOINTS:

        print(
            f"{breakpoint['attack_stage']}"
        )

        print(
            "  Controls: "
            + ", ".join(
                breakpoint["controls"]
            )
        )

    # ---------------------------------------------------------------------
    # REMEDIATION TRACKER
    # ---------------------------------------------------------------------

    header("REMEDIATION TRACKER")

    for item in REMEDIATION_PLAN:

        print(
            f"{item['finding_id']} | "
            f"{item['owner']} | "
            f"{item['status']} | "
            f"Retest Required="
            f"{item['retest_required']}"
        )

    implementation_rate = (
        sum(
            item["status"]
            == "IMPLEMENTED"
            for item in REMEDIATION_PLAN
        )
        / len(REMEDIATION_PLAN)
        * 100
    )

    # ---------------------------------------------------------------------
    # DEPLOYMENT GATES
    # ---------------------------------------------------------------------

    header("PRE-RETEST DEPLOYMENT SECURITY GATES")

    for gate in DEPLOYMENT_GATES:

        print(
            f"{gate['gate_id']} | "
            f"{'PASS' if gate['passed'] else 'FAIL'} | "
            f"{gate['name']}"
        )

    required_gates = [
        gate
        for gate in DEPLOYMENT_GATES
        if gate["required"]
    ]

    passed_required_gates = [
        gate
        for gate in required_gates
        if gate["passed"]
    ]

    deployment_approved = all(
        gate["passed"]
        for gate in required_gates
    )

    # ---------------------------------------------------------------------
    # VALIDATION
    # ---------------------------------------------------------------------

    control_ids = [
        control["control_id"]
        for control in CONTROLS
    ]

    zone_ids = {
        zone["zone_id"]
        for zone in SECURITY_ZONES
    }

    all_findings_covered = all(
        len(controls) > 0
        for controls
        in finding_control_map.values()
    )

    all_breakpoints_covered = all(
        len(
            breakpoint["controls"]
        ) > 0
        for breakpoint
        in ATTACK_CHAIN_BREAKPOINTS
    )

    checks = {
        "Unique Control IDs":
            len(control_ids)
            == len(set(control_ids)),

        "All Control Zones Valid":
            all(
                control["zone"]
                in zone_ids
                for control in CONTROLS
            ),

        "All Material Findings Have Controls":
            all_findings_covered,

        "All Attack Stages Have Breakpoints":
            all_breakpoints_covered,

        "Instruction Trust Hardened":
            len(
                finding_control_map[
                    "CF-2901"
                ]
            ) > 0,

        "RAG Hardened":
            len(
                finding_control_map[
                    "CF-2902"
                ]
            ) > 0,

        "Memory Hardened":
            len(
                finding_control_map[
                    "CF-2903"
                ]
            ) > 0,

        "Agent / Tool Hardened":
            len(
                finding_control_map[
                    "CF-2904"
                ]
            ) > 0,

        "Authorization Hardened":
            len(
                finding_control_map[
                    "CF-2905"
                ]
            ) > 0,

        "Credential Security Hardened":
            len(
                finding_control_map[
                    "CF-2906"
                ]
            ) > 0,

        "Data Protection Hardened":
            len(
                finding_control_map[
                    "CF-2907"
                ]
            ) > 0,

        "Detection Engineering Hardened":
            len(
                finding_control_map[
                    "CF-2908"
                ]
            ) > 0,

        "All Remediation Marked Implemented":
            implementation_rate
            == 100.0,

        "Adversarial Retest Still Required":
            not next(
                gate["passed"]
                for gate
                in DEPLOYMENT_GATES
                if gate["gate_id"]
                == "GATE-2914-09"
            ),

        "Production Not Yet Approved":
            not deployment_approved,
    }

    checks[
        "Hardened Architecture Assessment Valid"
    ] = all(
        checks.values()
    )

    header("HARDENED ARCHITECTURE SECURITY CHECKS")

    for check, result in checks.items():

        print(
            f"{check}: {result}"
        )

    # ---------------------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------------------

    header("HARDENED ARCHITECTURE SUMMARY")

    print(
        f"Security Zones: "
        f"{len(SECURITY_ZONES)}"
    )

    print(
        f"Trust Boundaries: "
        f"{len(TRUST_BOUNDARIES)}"
    )

    print(
        f"Security Controls: "
        f"{len(CONTROLS)}"
    )

    print(
        f"Preventive Controls: "
        f"{control_type_distribution.get('PREVENTIVE', 0)}"
    )

    print(
        f"Detective Controls: "
        f"{control_type_distribution.get('DETECTIVE', 0)}"
    )

    print(
        f"Corrective Controls: "
        f"{control_type_distribution.get('CORRECTIVE', 0)}"
    )

    print(
        f"Material Findings Covered: "
        f"{sum(len(v) > 0 for v in finding_control_map.values())}"
        f" / {len(finding_control_map)}"
    )

    print(
        f"Attack-Chain Breakpoints: "
        f"{len(ATTACK_CHAIN_BREAKPOINTS)}"
    )

    print(
        f"Remediation Implementation Rate: "
        f"{implementation_rate:.2f}%"
    )

    print(
        f"Required Gates Passed: "
        f"{len(passed_required_gates)}"
        f" / {len(required_gates)}"
    )

    print(
        f"Adversarial Retest Required: "
        f"{not deployment_approved}"
    )

    print(
        f"Deployment Approved: "
        f"{deployment_approved}"
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

        "security_zones":
            SECURITY_ZONES,

        "security_controls":
            CONTROLS,

        "trust_boundaries":
            TRUST_BOUNDARIES,

        "finding_control_map":
            finding_control_map,

        "attack_chain_breakpoints":
            ATTACK_CHAIN_BREAKPOINTS,

        "remediation_plan":
            REMEDIATION_PLAN,

        "deployment_gates":
            DEPLOYMENT_GATES,

        "metrics": {
            "security_zones":
                len(SECURITY_ZONES),

            "trust_boundaries":
                len(TRUST_BOUNDARIES),

            "security_controls":
                len(CONTROLS),

            "preventive_controls":
                control_type_distribution.get(
                    "PREVENTIVE",
                    0
                ),

            "detective_controls":
                control_type_distribution.get(
                    "DETECTIVE",
                    0
                ),

            "corrective_controls":
                control_type_distribution.get(
                    "CORRECTIVE",
                    0
                ),

            "material_findings_covered":
                sum(
                    len(value) > 0
                    for value
                    in finding_control_map.values()
                ),

            "attack_chain_breakpoints":
                len(
                    ATTACK_CHAIN_BREAKPOINTS
                ),

            "remediation_implementation_rate":
                round(
                    implementation_rate,
                    2
                ),

            "required_gates_passed":
                len(
                    passed_required_gates
                ),

            "required_gates_total":
                len(
                    required_gates
                ),

            "deployment_approved":
                deployment_approved,
        },

        "security_checks":
            checks,
    }

    evidence["evidence_hash"] = hash_data(
        evidence
    )

    output = Path(
        "day29-hardened-enterprise-genai-architecture-evidence.json"
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
        "The hardened architecture converts each material red-team "
        "finding into explicit preventive, detective, and corrective "
        "controls at defined enterprise trust boundaries."
    )

    print(
        "The original attack chain is now interrupted at multiple "
        "independent points including instruction handling, RAG admission, "
        "persistent memory, agent planning, authorization, credentials, "
        "tool execution, data protection, and detection."
    )

    print(
        "However, implementation alone does not prove effectiveness. "
        "Production approval remains blocked until the consolidated "
        "findings pass adversarial retesting."
    )

    print("\nCore Principle:")

    print(
        "Effective remediation must break the demonstrated attack chain "
        "at multiple independent trust boundaries rather than relying "
        "on a single LLM guardrail."
    )


if __name__ == "__main__":
    main()