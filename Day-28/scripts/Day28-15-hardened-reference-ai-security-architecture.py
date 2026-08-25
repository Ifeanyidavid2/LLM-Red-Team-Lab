"""
Day 28 Lab 15
Hardened Reference AI Security Architecture

Purpose:
Translate the Day 28 threat model, risk register, control mappings and
architectural choke points into a hardened reference AI architecture.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter


print(
    "\n=== Day 28 Lab 15: "
    "Hardened Reference AI Security Architecture ===\n"
)


# ============================================================
# SECURITY ZONES
# ============================================================

SECURITY_ZONES = [
    {
        "zone_id": "ZONE-2801",
        "name": "Untrusted Input Zone",
        "trust_level": 0,
        "components": [
            "User Prompt",
            "External Content",
        ],
    },

    {
        "zone_id": "ZONE-2802",
        "name": "Security Mediation Zone",
        "trust_level": 2,
        "components": [
            "Input Gateway",
            "Prompt Security Classifier",
            "Instruction Trust Resolver",
        ],
    },

    {
        "zone_id": "ZONE-2803",
        "name": "RAG Security Zone",
        "trust_level": 2,
        "components": [
            "RAG Source Validator",
            "Document Provenance Validator",
            "Retrieval Authorization",
            "Context Admission Gateway",
        ],
    },

    {
        "zone_id": "ZONE-2804",
        "name": "Trusted AI Runtime Zone",
        "trust_level": 4,
        "components": [
            "System Prompt",
            "LLM Runtime",
            "Policy Engine",
        ],
    },

    {
        "zone_id": "ZONE-2805",
        "name": "Persistent Memory Security Zone",
        "trust_level": 3,
        "components": [
            "Memory Write Authorization",
            "Memory Provenance Service",
            "Memory Store",
            "Memory Integrity Validator",
        ],
    },

    {
        "zone_id": "ZONE-2806",
        "name": "Agent Execution Zone",
        "trust_level": 3,
        "components": [
            "Agent Planner",
            "Task Binding Service",
            "Tool Router",
            "Parameter Validator",
        ],
    },

    {
        "zone_id": "ZONE-2807",
        "name": "Independent Authorization Zone",
        "trust_level": 5,
        "components": [
            "Identity Service",
            "Authorization Service",
            "Approval Verification",
            "Policy Decision Point",
        ],
    },

    {
        "zone_id": "ZONE-2808",
        "name": "Secret Security Zone",
        "trust_level": 5,
        "components": [
            "Secret Store",
            "Credential Broker",
        ],
    },

    {
        "zone_id": "ZONE-2809",
        "name": "Privileged Tool Zone",
        "trust_level": 4,
        "components": [
            "Read Record Tool",
            "Delete Record Tool",
        ],
    },

    {
        "zone_id": "ZONE-2810",
        "name": "Business Data Zone",
        "trust_level": 5,
        "components": [
            "Restricted Record",
            "Record Service",
        ],
    },

    {
        "zone_id": "ZONE-2811",
        "name": "AI Security Observability Zone",
        "trust_level": 4,
        "components": [
            "Security Telemetry Pipeline",
            "Detection Engine",
            "Audit Store",
        ],
    },
]


# ============================================================
# TRUST BOUNDARIES
# ============================================================

TRUST_BOUNDARIES = [
    {
        "boundary_id": "TB-2801",
        "source": "ZONE-2801",
        "destination": "ZONE-2802",
        "name": "Untrusted Input Boundary",
        "enforcement": [
            "Prompt classification",
            "Instruction trust separation",
            "Input normalization",
        ],
    },

    {
        "boundary_id": "TB-2802",
        "source": "ZONE-2803",
        "destination": "ZONE-2804",
        "name": "RAG-to-Runtime Boundary",
        "enforcement": [
            "Source provenance validation",
            "Document authorization",
            "Indirect prompt-injection scanning",
            "Fail-closed context admission",
        ],
    },

    {
        "boundary_id": "TB-2803",
        "source": "ZONE-2804",
        "destination": "ZONE-2805",
        "name": "Runtime-to-Memory Boundary",
        "enforcement": [
            "Explicit memory-write authorization",
            "Memory provenance binding",
            "Sensitive-data minimization",
        ],
    },

    {
        "boundary_id": "TB-2804",
        "source": "ZONE-2805",
        "destination": "ZONE-2806",
        "name": "Memory-to-Agent Boundary",
        "enforcement": [
            "Session binding",
            "Agent binding",
            "Expiry validation",
            "Memory treated as non-authoritative context",
        ],
    },

    {
        "boundary_id": "TB-2805",
        "source": "ZONE-2804",
        "destination": "ZONE-2806",
        "name": "LLM-to-Agent Boundary",
        "enforcement": [
            "Trusted goal binding",
            "Task integrity verification",
        ],
    },

    {
        "boundary_id": "TB-2806",
        "source": "ZONE-2806",
        "destination": "ZONE-2807",
        "name": "Agent-to-Authorization Boundary",
        "enforcement": [
            "Independent identity verification",
            "Non-model approval verification",
            "Fail-closed authorization",
        ],
    },

    {
        "boundary_id": "TB-2807",
        "source": "ZONE-2807",
        "destination": "ZONE-2809",
        "name": "Authorization-to-Tool Boundary",
        "enforcement": [
            "Signed authorization context",
            "Tool allowlisting",
            "Target binding",
            "Parameter validation",
        ],
    },

    {
        "boundary_id": "TB-2808",
        "source": "ZONE-2808",
        "destination": "ZONE-2809",
        "name": "Secret-to-Tool Boundary",
        "enforcement": [
            "Short-lived credentials",
            "Task-bound credentials",
            "Least privilege",
        ],
    },

    {
        "boundary_id": "TB-2809",
        "source": "ZONE-2809",
        "destination": "ZONE-2810",
        "name": "Tool-to-Business-Data Boundary",
        "enforcement": [
            "Resource-level authorization",
            "Transaction validation",
            "Destructive-action approval",
        ],
    },

    {
        "boundary_id": "TB-2810",
        "source": "ALL",
        "destination": "ZONE-2811",
        "name": "Security Telemetry Boundary",
        "enforcement": [
            "Immutable event collection",
            "Independent telemetry path",
            "Hash-linked audit records",
        ],
    },
]


# ============================================================
# ARCHITECTURAL CONTROLS
# ============================================================

CONTROLS = [
    {
        "control_id": "ARCH-CTRL-2801",
        "name": "Instruction Trust Separation",
        "zone": "ZONE-2802",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2802",
        "name": "RAG Provenance Validation",
        "zone": "ZONE-2803",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2803",
        "name": "Fail-Closed Context Admission",
        "zone": "ZONE-2803",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2804",
        "name": "Authorized Memory Writes",
        "zone": "ZONE-2805",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2805",
        "name": "Memory Provenance & Integrity",
        "zone": "ZONE-2805",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2806",
        "name": "Session / Agent Memory Isolation",
        "zone": "ZONE-2805",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2807",
        "name": "Agent Goal / Task Binding",
        "zone": "ZONE-2806",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2808",
        "name": "Tool Allowlisting",
        "zone": "ZONE-2806",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2809",
        "name": "Trusted Target Binding",
        "zone": "ZONE-2806",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2810",
        "name": "Strict Parameter Validation",
        "zone": "ZONE-2806",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2811",
        "name": "Fail-Closed Independent Authorization",
        "zone": "ZONE-2807",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2812",
        "name": "External Approval Verification",
        "zone": "ZONE-2807",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2813",
        "name": "Secret Isolation",
        "zone": "ZONE-2808",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2814",
        "name": "Short-Lived Task-Bound Credentials",
        "zone": "ZONE-2808",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2815",
        "name": "Resource-Level Data Authorization",
        "zone": "ZONE-2810",
        "type": "PREVENTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2816",
        "name": "Soft Delete & Recovery",
        "zone": "ZONE-2810",
        "type": "CORRECTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2817",
        "name": "Tamper-Evident AI Security Telemetry",
        "zone": "ZONE-2811",
        "type": "DETECTIVE",
    },

    {
        "control_id": "ARCH-CTRL-2818",
        "name": "Execution Budgets & Rate Limits",
        "zone": "ZONE-2806",
        "type": "PREVENTIVE",
    },
]


# ============================================================
# SECURITY DATA FLOWS
# ============================================================

DATA_FLOWS = [
    {
        "flow_id": "FLOW-2801",
        "source": "User",
        "destination": "Input Gateway",
        "data": "Prompt",
        "trusted": False,
    },

    {
        "flow_id": "FLOW-2802",
        "source": "Input Gateway",
        "destination": "LLM Runtime",
        "data": "Validated User Task",
        "trusted": True,
    },

    {
        "flow_id": "FLOW-2803",
        "source": "Knowledge Store",
        "destination": "RAG Security Gateway",
        "data": "Retrieved Documents",
        "trusted": False,
    },

    {
        "flow_id": "FLOW-2804",
        "source": "RAG Security Gateway",
        "destination": "LLM Runtime",
        "data": "Authorized Context",
        "trusted": True,
    },

    {
        "flow_id": "FLOW-2805",
        "source": "LLM Runtime",
        "destination": "Memory Authorization",
        "data": "Proposed Memory Write",
        "trusted": False,
    },

    {
        "flow_id": "FLOW-2806",
        "source": "Memory Store",
        "destination": "Agent Planner",
        "data": "Validated Memory",
        "trusted": False,
    },

    {
        "flow_id": "FLOW-2807",
        "source": "LLM Runtime",
        "destination": "Agent Planner",
        "data": "Proposed Plan",
        "trusted": False,
    },

    {
        "flow_id": "FLOW-2808",
        "source": "Agent Planner",
        "destination": "Authorization Service",
        "data": "Proposed Tool Action",
        "trusted": False,
    },

    {
        "flow_id": "FLOW-2809",
        "source": "Authorization Service",
        "destination": "Tool Runtime",
        "data": "Authorization Decision",
        "trusted": True,
    },

    {
        "flow_id": "FLOW-2810",
        "source": "Credential Broker",
        "destination": "Tool Runtime",
        "data": "Task-Bound Credential",
        "trusted": True,
    },

    {
        "flow_id": "FLOW-2811",
        "source": "Tool Runtime",
        "destination": "Business Data",
        "data": "Authorized Transaction",
        "trusted": True,
    },

    {
        "flow_id": "FLOW-2812",
        "source": "All Components",
        "destination": "Security Telemetry Pipeline",
        "data": "Security Events",
        "trusted": True,
    },
]


# ============================================================
# DEPLOYMENT SECURITY GATES
# ============================================================

DEPLOYMENT_GATES = [
    {
        "gate_id": "GATE-2801",
        "name": "No Critical Residual Risk",
        "required": True,
        "passed": True,
    },

    {
        "gate_id": "GATE-2802",
        "name": "RAG Provenance Controls Enabled",
        "required": True,
        "passed": True,
    },

    {
        "gate_id": "GATE-2803",
        "name": "Memory Authorization Enabled",
        "required": True,
        "passed": True,
    },

    {
        "gate_id": "GATE-2804",
        "name": "Agent Task Binding Enabled",
        "required": True,
        "passed": True,
    },

    {
        "gate_id": "GATE-2805",
        "name": "Fail-Closed Authorization Enabled",
        "required": True,
        "passed": True,
    },

    {
        "gate_id": "GATE-2806",
        "name": "Privileged Tool Policy Enabled",
        "required": True,
        "passed": True,
    },

    {
        "gate_id": "GATE-2807",
        "name": "Secret Isolation Enabled",
        "required": True,
        "passed": True,
    },

    {
        "gate_id": "GATE-2808",
        "name": "Security Telemetry Enabled",
        "required": True,
        "passed": True,
    },

    {
        "gate_id": "GATE-2809",
        "name": "Adversarial Regression Tests Passed",
        "required": True,
        "passed": True,
    },
]


# ============================================================
# ANALYSIS
# ============================================================

zone_counter = Counter(
    zone["trust_level"]
    for zone in SECURITY_ZONES
)

control_type_counter = Counter(
    control["type"]
    for control in CONTROLS
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

deployment_approved = (
    len(required_gates)
    == len(passed_required_gates)
)


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 96)
    print(f"        {title}")
    print("=" * 96)


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


header("TRUST BOUNDARIES & ENFORCEMENT")

for boundary in TRUST_BOUNDARIES:

    print(
        f"{boundary['boundary_id']} | "
        f"{boundary['source']} -> "
        f"{boundary['destination']} | "
        f"{boundary['name']}"
    )

    print(
        "  Enforcement: "
        + ", ".join(
            boundary["enforcement"]
        )
    )


header("ARCHITECTURAL SECURITY CONTROLS")

for control in CONTROLS:

    print(
        f"{control['control_id']} | "
        f"{control['type']} | "
        f"{control['zone']} | "
        f"{control['name']}"
    )


header("SECURE DATA FLOWS")

for flow in DATA_FLOWS:

    print(
        f"{flow['flow_id']} | "
        f"{flow['source']} -> "
        f"{flow['destination']} | "
        f"{flow['data']} | "
        f"Trusted={flow['trusted']}"
    )


header("DEPLOYMENT SECURITY GATES")

for gate in DEPLOYMENT_GATES:

    print(
        f"{gate['gate_id']} | "
        f"{gate['name']} | "
        f"Required={gate['required']} | "
        f"Passed={gate['passed']}"
    )


# ============================================================
# ARCHITECTURE SUMMARY
# ============================================================

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
    f"Architectural Controls: "
    f"{len(CONTROLS)}"
)

print(
    f"Security Data Flows: "
    f"{len(DATA_FLOWS)}"
)

print(
    f"Deployment Gates: "
    f"{len(DEPLOYMENT_GATES)}"
)

print(
    f"Preventive Controls: "
    f"{control_type_counter.get('PREVENTIVE', 0)}"
)

print(
    f"Detective Controls: "
    f"{control_type_counter.get('DETECTIVE', 0)}"
)

print(
    f"Corrective Controls: "
    f"{control_type_counter.get('CORRECTIVE', 0)}"
)

print(
    f"Required Gates Passed: "
    f"{len(passed_required_gates)} / "
    f"{len(required_gates)}"
)

print(
    f"Deployment Approved: "
    f"{deployment_approved}"
)


# ============================================================
# VALIDATION
# ============================================================

header("HARDENED ARCHITECTURE SECURITY CHECKS")

zone_ids = {
    zone["zone_id"]
    for zone in SECURITY_ZONES
}

checks = {
    "Untrusted Input Zone Present":
        any(
            zone["trust_level"] == 0
            for zone in SECURITY_ZONES
        ),

    "RAG Security Zone Present":
        "ZONE-2803" in zone_ids,

    "Persistent Memory Security Zone Present":
        "ZONE-2805" in zone_ids,

    "Agent Execution Zone Present":
        "ZONE-2806" in zone_ids,

    "Independent Authorization Zone Present":
        "ZONE-2807" in zone_ids,

    "Secret Security Zone Present":
        "ZONE-2808" in zone_ids,

    "Privileged Tool Zone Present":
        "ZONE-2809" in zone_ids,

    "Business Data Zone Present":
        "ZONE-2810" in zone_ids,

    "Observability Zone Present":
        "ZONE-2811" in zone_ids,

    "Instruction Trust Boundary Enforced":
        any(
            boundary["boundary_id"]
            == "TB-2801"
            for boundary in TRUST_BOUNDARIES
        ),

    "RAG Context Boundary Enforced":
        any(
            boundary["boundary_id"]
            == "TB-2802"
            for boundary in TRUST_BOUNDARIES
        ),

    "Memory Write Boundary Enforced":
        any(
            boundary["boundary_id"]
            == "TB-2803"
            for boundary in TRUST_BOUNDARIES
        ),

    "Authorization Boundary Enforced":
        any(
            boundary["boundary_id"]
            == "TB-2806"
            for boundary in TRUST_BOUNDARIES
        ),

    "Tool Execution Boundary Enforced":
        any(
            boundary["boundary_id"]
            == "TB-2807"
            for boundary in TRUST_BOUNDARIES
        ),

    "Business Resource Boundary Enforced":
        any(
            boundary["boundary_id"]
            == "TB-2809"
            for boundary in TRUST_BOUNDARIES
        ),

    "Tamper-Evident Telemetry Present":
        any(
            control["name"]
            == "Tamper-Evident AI Security Telemetry"
            for control in CONTROLS
        ),

    "All Required Deployment Gates Pass":
        deployment_approved,
}


for check, result in checks.items():

    print(
        f"{check}: {result}"
    )


architecture_valid = all(
    checks.values()
)


print(
    f"\nHardened Reference AI Security Architecture Valid: "
    f"{architecture_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 15",

    "title":
        "Hardened Reference AI Security Architecture",

    "security_zones":
        SECURITY_ZONES,

    "trust_boundaries":
        TRUST_BOUNDARIES,

    "controls":
        CONTROLS,

    "data_flows":
        DATA_FLOWS,

    "deployment_gates":
        DEPLOYMENT_GATES,

    "metrics": {
        "security_zones":
            len(SECURITY_ZONES),

        "trust_boundaries":
            len(TRUST_BOUNDARIES),

        "architectural_controls":
            len(CONTROLS),

        "security_data_flows":
            len(DATA_FLOWS),

        "deployment_gates":
            len(DEPLOYMENT_GATES),

        "preventive_controls":
            control_type_counter.get(
                "PREVENTIVE",
                0
            ),

        "detective_controls":
            control_type_counter.get(
                "DETECTIVE",
                0
            ),

        "corrective_controls":
            control_type_counter.get(
                "CORRECTIVE",
                0
            ),

        "required_gates_passed":
            len(
                passed_required_gates
            ),

        "required_gates":
            len(
                required_gates
            ),

        "deployment_approved":
            deployment_approved,
    },

    "security_checks":
        checks,

    "architecture_valid":
        architecture_valid,
}


OUTPUT_FILE = (
    "day28-hardened-reference-ai-security-architecture-evidence.json"
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
    "The hardened reference architecture separates untrusted input, "
    "retrieval, persistent memory, agent execution, authorization, "
    "secrets, privileged tools, business data and security telemetry "
    "into explicit security zones and trust boundaries."
)

print(
    "Model-generated output is never treated as authorization. "
    "Persistent memory is subject to provenance and write authorization, "
    "RAG context is validated before admission, and privileged tool "
    "execution requires independent fail-closed authorization."
)

print(
    "The architecture therefore converts threat-model findings into "
    "concrete enforcement points and deployment security gates rather "
    "than relying on a single guardrail around the LLM."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)