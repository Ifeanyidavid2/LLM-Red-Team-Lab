"""
Day 28 Lab 14
Security Control Mapping & Residual-Risk Reduction

Purpose:
Map prioritized AI risks to security controls, quantify risk reduction,
identify high-value architectural controls, and evaluate residual risk
after the target security architecture is implemented.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter, defaultdict


print(
    "\n=== Day 28 Lab 14: "
    "Security Control Mapping & Residual-Risk Reduction ===\n"
)


# ============================================================
# RISK INPUT
# ============================================================

RISKS = [
    {
        "risk_id": "RISK-2801",
        "name": "Direct Prompt Injection",
        "domain": "PROMPT",
        "inherent_score": 27,
        "target_residual_score": 8,
    },
    {
        "risk_id": "RISK-2802",
        "name": "Indirect RAG Prompt Injection",
        "domain": "RAG",
        "inherent_score": 37,
        "target_residual_score": 8,
    },
    {
        "risk_id": "RISK-2803",
        "name": "RAG Source Poisoning",
        "domain": "RAG",
        "inherent_score": 33,
        "target_residual_score": 8,
    },
    {
        "risk_id": "RISK-2804",
        "name": "Unsafe Context Admission",
        "domain": "RAG",
        "inherent_score": 32,
        "target_residual_score": 7,
    },
    {
        "risk_id": "RISK-2805",
        "name": "Persistent Memory Poisoning",
        "domain": "MEMORY",
        "inherent_score": 42,
        "target_residual_score": 5,
    },
    {
        "risk_id": "RISK-2806",
        "name": "Cross-Session Memory Activation",
        "domain": "MEMORY",
        "inherent_score": 37,
        "target_residual_score": 5,
    },
    {
        "risk_id": "RISK-2807",
        "name": "Cross-Agent Memory Propagation",
        "domain": "MEMORY",
        "inherent_score": 38,
        "target_residual_score": 5,
    },
    {
        "risk_id": "RISK-2808",
        "name": "Agent Goal Hijacking",
        "domain": "AGENT",
        "inherent_score": 33,
        "target_residual_score": 7,
    },
    {
        "risk_id": "RISK-2809",
        "name": "Task Binding Bypass",
        "domain": "AGENT",
        "inherent_score": 33,
        "target_residual_score": 6,
    },
    {
        "risk_id": "RISK-2810",
        "name": "Unsafe Privileged Tool Selection",
        "domain": "TOOL",
        "inherent_score": 34,
        "target_residual_score": 5,
    },
    {
        "risk_id": "RISK-2811",
        "name": "Target Substitution",
        "domain": "TOOL",
        "inherent_score": 34,
        "target_residual_score": 5,
    },
    {
        "risk_id": "RISK-2812",
        "name": "Tool Parameter Manipulation",
        "domain": "TOOL",
        "inherent_score": 34,
        "target_residual_score": 5,
    },
    {
        "risk_id": "RISK-2813",
        "name": "Model-Generated Approval",
        "domain": "AUTHORIZATION",
        "inherent_score": 35,
        "target_residual_score": 4,
    },
    {
        "risk_id": "RISK-2814",
        "name": "Fail-Open Authorization",
        "domain": "AUTHORIZATION",
        "inherent_score": 30,
        "target_residual_score": 3,
    },
    {
        "risk_id": "RISK-2815",
        "name": "Credential Exposure",
        "domain": "SECRET",
        "inherent_score": 32,
        "target_residual_score": 5,
    },
    {
        "risk_id": "RISK-2816",
        "name": "Credential Scope Abuse",
        "domain": "SECRET",
        "inherent_score": 37,
        "target_residual_score": 5,
    },
    {
        "risk_id": "RISK-2817",
        "name": "Restricted Data Disclosure",
        "domain": "BUSINESS",
        "inherent_score": 32,
        "target_residual_score": 5,
    },
    {
        "risk_id": "RISK-2818",
        "name": "Restricted Data Modification",
        "domain": "BUSINESS",
        "inherent_score": 29,
        "target_residual_score": 4,
    },
    {
        "risk_id": "RISK-2819",
        "name": "Restricted Data Destruction",
        "domain": "BUSINESS",
        "inherent_score": 29,
        "target_residual_score": 3,
    },
    {
        "risk_id": "RISK-2820",
        "name": "Security Telemetry Suppression",
        "domain": "OBSERVABILITY",
        "inherent_score": 26,
        "target_residual_score": 6,
    },
    {
        "risk_id": "RISK-2821",
        "name": "Resource Exhaustion",
        "domain": "AVAILABILITY",
        "inherent_score": 19,
        "target_residual_score": 5,
    },
]


RISK_MAP = {
    risk["risk_id"]: risk
    for risk in RISKS
}


# ============================================================
# CONTROL LIBRARY
# ============================================================

CONTROLS = [
    {
        "control_id": "CTRL-2801",
        "name": "Instruction Trust Separation",
        "category": "PREVENTIVE",
        "owner": "AI Security Engineering",
        "implementation_priority": "HIGH",
        "risks": [
            "RISK-2801",
            "RISK-2802",
        ],
    },

    {
        "control_id": "CTRL-2802",
        "name": "Prompt Injection Detection",
        "category": "DETECTIVE",
        "owner": "AI SOC",
        "implementation_priority": "HIGH",
        "risks": [
            "RISK-2801",
            "RISK-2802",
        ],
    },

    {
        "control_id": "CTRL-2803",
        "name": "RAG Provenance Validation",
        "category": "PREVENTIVE",
        "owner": "RAG Security Team",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2802",
            "RISK-2803",
            "RISK-2804",
        ],
    },

    {
        "control_id": "CTRL-2804",
        "name": "Fail-Closed Context Admission",
        "category": "PREVENTIVE",
        "owner": "AI Security Engineering",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2802",
            "RISK-2804",
        ],
    },

    {
        "control_id": "CTRL-2805",
        "name": "Authorized Memory Writes",
        "category": "PREVENTIVE",
        "owner": "AI Platform Team",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2805",
            "RISK-2806",
            "RISK-2807",
        ],
    },

    {
        "control_id": "CTRL-2806",
        "name": "Memory Provenance & Integrity",
        "category": "PREVENTIVE",
        "owner": "AI Platform Team",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2805",
            "RISK-2806",
            "RISK-2807",
        ],
    },

    {
        "control_id": "CTRL-2807",
        "name": "Session / Agent Memory Isolation",
        "category": "PREVENTIVE",
        "owner": "Agent Security Team",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2806",
            "RISK-2807",
        ],
    },

    {
        "control_id": "CTRL-2808",
        "name": "Agent Goal / Task Binding",
        "category": "PREVENTIVE",
        "owner": "Agent Security Team",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2808",
            "RISK-2809",
            "RISK-2810",
        ],
    },

    {
        "control_id": "CTRL-2809",
        "name": "Tool Allowlisting",
        "category": "PREVENTIVE",
        "owner": "Tool Security Team",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2810",
            "RISK-2811",
            "RISK-2812",
        ],
    },

    {
        "control_id": "CTRL-2810",
        "name": "Strict Tool Parameter Validation",
        "category": "PREVENTIVE",
        "owner": "Tool Security Team",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2811",
            "RISK-2812",
        ],
    },

    {
        "control_id": "CTRL-2811",
        "name": "Trusted Target Binding",
        "category": "PREVENTIVE",
        "owner": "Tool Security Team",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2811",
            "RISK-2817",
            "RISK-2818",
            "RISK-2819",
        ],
    },

    {
        "control_id": "CTRL-2812",
        "name": "Fail-Closed Independent Authorization",
        "category": "PREVENTIVE",
        "owner": "Identity Security Team",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2810",
            "RISK-2811",
            "RISK-2812",
            "RISK-2813",
            "RISK-2814",
            "RISK-2818",
            "RISK-2819",
        ],
    },

    {
        "control_id": "CTRL-2813",
        "name": "External Approval Verification",
        "category": "PREVENTIVE",
        "owner": "Identity Security Team",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2813",
            "RISK-2814",
        ],
    },

    {
        "control_id": "CTRL-2814",
        "name": "Secret Isolation",
        "category": "PREVENTIVE",
        "owner": "Platform Security",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2815",
            "RISK-2816",
        ],
    },

    {
        "control_id": "CTRL-2815",
        "name": "Short-Lived Task-Bound Credentials",
        "category": "PREVENTIVE",
        "owner": "Platform Security",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2815",
            "RISK-2816",
        ],
    },

    {
        "control_id": "CTRL-2816",
        "name": "Resource-Level Data Authorization",
        "category": "PREVENTIVE",
        "owner": "Data Security Team",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2817",
            "RISK-2818",
            "RISK-2819",
        ],
    },

    {
        "control_id": "CTRL-2817",
        "name": "DLP & Sensitive Output Controls",
        "category": "PREVENTIVE",
        "owner": "Data Security Team",
        "implementation_priority": "HIGH",
        "risks": [
            "RISK-2817",
        ],
    },

    {
        "control_id": "CTRL-2818",
        "name": "Soft Delete & Recovery",
        "category": "CORRECTIVE",
        "owner": "Business Platform Team",
        "implementation_priority": "HIGH",
        "risks": [
            "RISK-2819",
        ],
    },

    {
        "control_id": "CTRL-2819",
        "name": "Tamper-Evident AI Security Telemetry",
        "category": "DETECTIVE",
        "owner": "AI SOC",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2801",
            "RISK-2802",
            "RISK-2803",
            "RISK-2804",
            "RISK-2805",
            "RISK-2806",
            "RISK-2807",
            "RISK-2808",
            "RISK-2809",
            "RISK-2810",
            "RISK-2811",
            "RISK-2812",
            "RISK-2813",
            "RISK-2814",
            "RISK-2815",
            "RISK-2816",
            "RISK-2817",
            "RISK-2818",
            "RISK-2819",
            "RISK-2820",
        ],
    },

    {
        "control_id": "CTRL-2820",
        "name": "Independent Telemetry Pipeline",
        "category": "DETECTIVE",
        "owner": "AI SOC",
        "implementation_priority": "CRITICAL",
        "risks": [
            "RISK-2820",
        ],
    },

    {
        "control_id": "CTRL-2821",
        "name": "Execution Budgets & Rate Limits",
        "category": "PREVENTIVE",
        "owner": "AI Platform Team",
        "implementation_priority": "HIGH",
        "risks": [
            "RISK-2821",
        ],
    },
]


# ============================================================
# RISK REDUCTION CALCULATION
# ============================================================

for risk in RISKS:

    reduction = (
        risk["inherent_score"]
        - risk["target_residual_score"]
    )

    reduction_percent = (
        reduction
        / risk["inherent_score"]
        * 100
    )

    risk["risk_reduction"] = reduction

    risk["risk_reduction_percent"] = round(
        reduction_percent,
        2
    )


# ============================================================
# CONTROL VALUE
# ============================================================

for control in CONTROLS:

    protected_risks = [
        RISK_MAP[risk_id]
        for risk_id in control["risks"]
    ]

    inherent_exposure = sum(
        risk["inherent_score"]
        for risk in protected_risks
    )

    target_exposure = sum(
        risk["target_residual_score"]
        for risk in protected_risks
    )

    addressable_reduction = (
        inherent_exposure
        - target_exposure
    )

    control["risk_count"] = len(
        protected_risks
    )

    control["inherent_exposure"] = (
        inherent_exposure
    )

    control["target_exposure"] = (
        target_exposure
    )

    control["addressable_risk_reduction"] = (
        addressable_reduction
    )


# ============================================================
# CONTROL PRIORITY
# ============================================================

PRIORITIZED_CONTROLS = sorted(
    CONTROLS,
    key=lambda item: (
        -item["addressable_risk_reduction"],
        -item["risk_count"],
        item["control_id"],
    )
)


# ============================================================
# RISK-TO-CONTROL INDEX
# ============================================================

risk_to_controls = defaultdict(list)

for control in CONTROLS:

    for risk_id in control["risks"]:

        risk_to_controls[
            risk_id
        ].append(
            control["control_id"]
        )


# ============================================================
# CONTROL CATEGORY ANALYSIS
# ============================================================

category_counter = Counter(
    control["category"]
    for control in CONTROLS
)

priority_counter = Counter(
    control["implementation_priority"]
    for control in CONTROLS
)

owner_counter = Counter(
    control["owner"]
    for control in CONTROLS
)


# ============================================================
# TOTAL RISK REDUCTION
# ============================================================

total_inherent_risk = sum(
    risk["inherent_score"]
    for risk in RISKS
)

total_target_residual_risk = sum(
    risk["target_residual_score"]
    for risk in RISKS
)

total_risk_reduction = (
    total_inherent_risk
    - total_target_residual_risk
)

overall_reduction_percent = (
    total_risk_reduction
    / total_inherent_risk
    * 100
)


# ============================================================
# HIGH-VALUE CONTROLS
# ============================================================

high_value_controls = [
    control
    for control in PRIORITIZED_CONTROLS
    if control[
        "addressable_risk_reduction"
    ] >= 50
]


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 94)
    print(f"        {title}")
    print("=" * 94)


header("RISK REDUCTION BY RISK")

for risk in sorted(
    RISKS,
    key=lambda item: (
        -item["risk_reduction_percent"],
        item["risk_id"],
    )
):

    print(
        f"{risk['risk_id']} | "
        f"{risk['domain']} | "
        f"{risk['name']}"
    )

    print(
        f"  Inherent Score: "
        f"{risk['inherent_score']}"
    )

    print(
        f"  Target Residual Score: "
        f"{risk['target_residual_score']}"
    )

    print(
        f"  Absolute Reduction: "
        f"{risk['risk_reduction']}"
    )

    print(
        f"  Risk Reduction: "
        f"{risk['risk_reduction_percent']:.2f}%"
    )


header("RISK-TO-CONTROL MAPPING")

for risk in RISKS:

    controls = risk_to_controls.get(
        risk["risk_id"],
        []
    )

    print(
        f"{risk['risk_id']} | "
        f"{risk['name']} | "
        f"Controls={len(controls)}"
    )

    print(
        "  "
        + ", ".join(
            controls
        )
    )


header("CONTROL RISK-REDUCTION VALUE")

for control in PRIORITIZED_CONTROLS:

    print(
        f"{control['control_id']} | "
        f"{control['implementation_priority']} | "
        f"{control['category']} | "
        f"{control['name']}"
    )

    print(
        f"  Risks Addressed: "
        f"{control['risk_count']}"
    )

    print(
        f"  Inherent Exposure: "
        f"{control['inherent_exposure']}"
    )

    print(
        f"  Target Exposure: "
        f"{control['target_exposure']}"
    )

    print(
        f"  Addressable Risk Reduction: "
        f"{control['addressable_risk_reduction']}"
    )


header("HIGH-VALUE ARCHITECTURAL CONTROLS")

for control in high_value_controls:

    print(
        f"{control['control_id']} | "
        f"Reduction={control['addressable_risk_reduction']} | "
        f"Risks={control['risk_count']} | "
        f"{control['name']}"
    )


header("CONTROL CATEGORY DISTRIBUTION")

for category, count in sorted(
    category_counter.items()
):

    print(
        f"{category}: {count}"
    )


header("CONTROL IMPLEMENTATION PRIORITY")

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


header("CONTROL OWNER DISTRIBUTION")

for owner, count in sorted(
    owner_counter.items()
):

    print(
        f"{owner}: {count}"
    )


# ============================================================
# ARCHITECTURAL CHOKE POINTS
# ============================================================

header("ARCHITECTURAL CONTROL CHOKE POINTS")

choke_points = [
    control
    for control in PRIORITIZED_CONTROLS
    if control["risk_count"] >= 3
]


for control in choke_points:

    print(
        f"{control['control_id']} | "
        f"Risks={control['risk_count']} | "
        f"Reduction={control['addressable_risk_reduction']} | "
        f"{control['name']}"
    )


# ============================================================
# SUMMARY
# ============================================================

header("RESIDUAL-RISK REDUCTION SUMMARY")

print(
    f"Risk Scenarios: "
    f"{len(RISKS)}"
)

print(
    f"Security Controls: "
    f"{len(CONTROLS)}"
)

print(
    f"Total Inherent Risk Score: "
    f"{total_inherent_risk}"
)

print(
    f"Total Target Residual Risk Score: "
    f"{total_target_residual_risk}"
)

print(
    f"Total Risk Reduction: "
    f"{total_risk_reduction}"
)

print(
    f"Overall Risk Reduction: "
    f"{overall_reduction_percent:.2f}%"
)

print(
    f"High-Value Controls: "
    f"{len(high_value_controls)}"
)

print(
    f"Architectural Choke-Point Controls: "
    f"{len(choke_points)}"
)

print(
    f"Control Owners: "
    f"{len(owner_counter)}"
)


# ============================================================
# VALIDATION
# ============================================================

header("CONTROL-MAPPING SECURITY CHECKS")

risk_ids = {
    risk["risk_id"]
    for risk in RISKS
}

control_ids = [
    control["control_id"]
    for control in CONTROLS
]

checks = {
    "Unique Control IDs":
        len(control_ids)
        == len(set(control_ids)),

    "All Control Risk References Valid":
        all(
            risk_id in risk_ids
            for control in CONTROLS
            for risk_id in control["risks"]
        ),

    "Every Risk Has Control Coverage":
        all(
            risk["risk_id"]
            in risk_to_controls
            for risk in RISKS
        ),

    "All Risks Reduced":
        all(
            risk["target_residual_score"]
            < risk["inherent_score"]
            for risk in RISKS
        ),

    "Overall Risk Reduced":
        total_target_residual_risk
        < total_inherent_risk,

    "Critical Controls Identified":
        priority_counter.get(
            "CRITICAL",
            0
        ) > 0,

    "Preventive Controls Identified":
        category_counter.get(
            "PREVENTIVE",
            0
        ) > 0,

    "Detective Controls Identified":
        category_counter.get(
            "DETECTIVE",
            0
        ) > 0,

    "Corrective Controls Identified":
        category_counter.get(
            "CORRECTIVE",
            0
        ) > 0,

    "High-Value Controls Identified":
        len(high_value_controls) > 0,

    "Architectural Choke Points Identified":
        len(choke_points) > 0,
}


for check, result in checks.items():

    print(
        f"{check}: {result}"
    )


control_mapping_valid = all(
    checks.values()
)


print(
    f"\nSecurity Control Mapping Valid: "
    f"{control_mapping_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 14",

    "title":
        "Security Control Mapping & Residual-Risk Reduction",

    "risks":
        RISKS,

    "controls":
        CONTROLS,

    "prioritized_controls":
        PRIORITIZED_CONTROLS,

    "high_value_controls":
        high_value_controls,

    "architectural_choke_points":
        choke_points,

    "metrics": {
        "risk_scenarios":
            len(RISKS),

        "security_controls":
            len(CONTROLS),

        "total_inherent_risk":
            total_inherent_risk,

        "total_target_residual_risk":
            total_target_residual_risk,

        "total_risk_reduction":
            total_risk_reduction,

        "overall_risk_reduction_percent":
            round(
                overall_reduction_percent,
                2
            ),

        "high_value_controls":
            len(
                high_value_controls
            ),

        "architectural_choke_points":
            len(
                choke_points
            ),

        "control_owners":
            len(
                owner_counter
            ),
    },

    "security_checks":
        checks,

    "control_mapping_valid":
        control_mapping_valid,
}


OUTPUT_FILE = (
    "day28-security-control-residual-risk-reduction-evidence.json"
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
    "Security controls have different architectural value depending "
    "on how many high-risk attack paths and trust boundaries they disrupt."
)

print(
    "Controls such as fail-closed authorization, memory integrity, "
    "trusted task binding, tool validation and tamper-evident telemetry "
    "can reduce multiple AI risks simultaneously and therefore represent "
    "high-value architectural choke points."
)

print(
    "Residual-risk analysis verifies that the target architecture is "
    "not merely adding controls, but materially reducing the modeled "
    "business exposure across prompt, RAG, memory, agent, tool, "
    "authorization, secret, business-data and observability domains."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)