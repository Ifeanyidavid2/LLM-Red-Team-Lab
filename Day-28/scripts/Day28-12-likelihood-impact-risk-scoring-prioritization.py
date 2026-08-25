"""
Day 28 Lab 12
Likelihood x Impact Risk Scoring & Prioritization

Purpose:
Convert Day 28 AI threat scenarios into a formal risk-prioritization
model using likelihood, impact, persistence, privilege, blast radius,
detectability and control maturity.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter


print(
    "\n=== Day 28 Lab 12: "
    "Likelihood x Impact Risk Scoring & Prioritization ===\n"
)


# ============================================================
# RISK MODEL
# ============================================================

LIKELIHOOD_SCALE = {
    1: "Rare",
    2: "Unlikely",
    3: "Possible",
    4: "Likely",
    5: "Almost Certain",
}

IMPACT_SCALE = {
    1: "Negligible",
    2: "Minor",
    3: "Moderate",
    4: "Major",
    5: "Severe",
}


# ============================================================
# THREAT RISK REGISTER INPUT
# ============================================================

RISKS = [
    {
        "risk_id": "RISK-2801",
        "name": "Direct Prompt Injection",
        "domain": "PROMPT",
        "likelihood": 5,
        "impact": 4,
        "persistence": 1,
        "privilege": 2,
        "blast_radius": 2,
        "detectability": 2,
        "control_maturity": 3,
    },

    {
        "risk_id": "RISK-2802",
        "name": "Indirect RAG Prompt Injection",
        "domain": "RAG",
        "likelihood": 5,
        "impact": 5,
        "persistence": 2,
        "privilege": 3,
        "blast_radius": 4,
        "detectability": 3,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2803",
        "name": "RAG Source Poisoning",
        "domain": "RAG",
        "likelihood": 4,
        "impact": 5,
        "persistence": 4,
        "privilege": 2,
        "blast_radius": 4,
        "detectability": 3,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2804",
        "name": "Unsafe Context Admission",
        "domain": "RAG",
        "likelihood": 4,
        "impact": 5,
        "persistence": 2,
        "privilege": 3,
        "blast_radius": 4,
        "detectability": 3,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2805",
        "name": "Persistent Memory Poisoning",
        "domain": "MEMORY",
        "likelihood": 5,
        "impact": 5,
        "persistence": 5,
        "privilege": 3,
        "blast_radius": 5,
        "detectability": 4,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2806",
        "name": "Cross-Session Memory Activation",
        "domain": "MEMORY",
        "likelihood": 4,
        "impact": 5,
        "persistence": 5,
        "privilege": 3,
        "blast_radius": 5,
        "detectability": 4,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2807",
        "name": "Cross-Agent Memory Propagation",
        "domain": "MEMORY",
        "likelihood": 4,
        "impact": 5,
        "persistence": 5,
        "privilege": 4,
        "blast_radius": 5,
        "detectability": 4,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2808",
        "name": "Agent Goal Hijacking",
        "domain": "AGENT",
        "likelihood": 4,
        "impact": 5,
        "persistence": 2,
        "privilege": 4,
        "blast_radius": 4,
        "detectability": 3,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2809",
        "name": "Task Binding Bypass",
        "domain": "AGENT",
        "likelihood": 4,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 4,
        "detectability": 3,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2810",
        "name": "Unsafe Privileged Tool Selection",
        "domain": "TOOL",
        "likelihood": 4,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 3,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2811",
        "name": "Target Substitution",
        "domain": "TOOL",
        "likelihood": 4,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 3,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2812",
        "name": "Tool Parameter Manipulation",
        "domain": "TOOL",
        "likelihood": 4,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 3,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2813",
        "name": "Model-Generated Approval",
        "domain": "AUTHORIZATION",
        "likelihood": 4,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 4,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2814",
        "name": "Fail-Open Authorization",
        "domain": "AUTHORIZATION",
        "likelihood": 3,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 4,
        "control_maturity": 1,
    },

    {
        "risk_id": "RISK-2815",
        "name": "Credential Exposure",
        "domain": "SECRET",
        "likelihood": 3,
        "impact": 5,
        "persistence": 3,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 4,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2816",
        "name": "Credential Scope Abuse",
        "domain": "SECRET",
        "likelihood": 4,
        "impact": 5,
        "persistence": 3,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 4,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2817",
        "name": "Restricted Data Disclosure",
        "domain": "BUSINESS",
        "likelihood": 4,
        "impact": 5,
        "persistence": 1,
        "privilege": 4,
        "blast_radius": 4,
        "detectability": 3,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2818",
        "name": "Restricted Data Modification",
        "domain": "BUSINESS",
        "likelihood": 3,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 3,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2819",
        "name": "Restricted Data Destruction",
        "domain": "BUSINESS",
        "likelihood": 3,
        "impact": 5,
        "persistence": 1,
        "privilege": 5,
        "blast_radius": 5,
        "detectability": 3,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2820",
        "name": "Security Telemetry Suppression",
        "domain": "OBSERVABILITY",
        "likelihood": 3,
        "impact": 4,
        "persistence": 2,
        "privilege": 3,
        "blast_radius": 4,
        "detectability": 5,
        "control_maturity": 2,
    },

    {
        "risk_id": "RISK-2821",
        "name": "Resource Exhaustion",
        "domain": "AVAILABILITY",
        "likelihood": 4,
        "impact": 3,
        "persistence": 1,
        "privilege": 1,
        "blast_radius": 3,
        "detectability": 2,
        "control_maturity": 3,
    },
]


# ============================================================
# SCORING
# ============================================================

def classify_inherent(score):

    if score >= 25:
        return "CRITICAL"

    if score >= 18:
        return "HIGH"

    if score >= 10:
        return "MEDIUM"

    return "LOW"


def classify_residual(score):

    if score >= 18:
        return "CRITICAL"

    if score >= 12:
        return "HIGH"

    if score >= 6:
        return "MEDIUM"

    return "LOW"


for risk in RISKS:

    # Core likelihood x impact score
    base_score = (
        risk["likelihood"]
        * risk["impact"]
    )

    # AI-specific amplification factors
    ai_amplifier = (
        risk["persistence"]
        + risk["privilege"]
        + risk["blast_radius"]
        + risk["detectability"]
    )

    inherent_score = (
        base_score
        + ai_amplifier
    )

    # Higher control maturity reduces risk.
    mitigation_credit = (
        risk["control_maturity"]
        * 3
    )

    residual_score = max(
        inherent_score
        - mitigation_credit,
        1
    )

    risk["base_score"] = base_score
    risk["ai_amplifier"] = ai_amplifier
    risk["inherent_score"] = inherent_score
    risk["inherent_rating"] = classify_inherent(
        inherent_score
    )

    risk["mitigation_credit"] = (
        mitigation_credit
    )

    risk["residual_score"] = (
        residual_score
    )

    risk["residual_rating"] = classify_residual(
        residual_score
    )


# ============================================================
# PRIORITY ORDER
# ============================================================

PRIORITIZED_RISKS = sorted(
    RISKS,
    key=lambda item: (
        -item["residual_score"],
        -item["inherent_score"],
        item["risk_id"],
    )
)


# ============================================================
# RISK ACCEPTANCE MODEL
# ============================================================

RISK_TREATMENT = []

for risk in PRIORITIZED_RISKS:

    if risk["residual_rating"] == "CRITICAL":
        treatment = "IMMEDIATE_MITIGATION"

    elif risk["residual_rating"] == "HIGH":
        treatment = "MITIGATE_BEFORE_DEPLOYMENT"

    elif risk["residual_rating"] == "MEDIUM":
        treatment = "MITIGATE_OR_FORMALLY_ACCEPT"

    else:
        treatment = "MONITOR"

    RISK_TREATMENT.append({
        "risk_id": risk["risk_id"],
        "residual_rating":
            risk["residual_rating"],
        "treatment": treatment,
    })


# ============================================================
# ANALYSIS
# ============================================================

inherent_counter = Counter(
    risk["inherent_rating"]
    for risk in RISKS
)

residual_counter = Counter(
    risk["residual_rating"]
    for risk in RISKS
)

domain_counter = Counter(
    risk["domain"]
    for risk in RISKS
)

critical_residual = [
    risk
    for risk in RISKS
    if risk["residual_rating"]
    == "CRITICAL"
]

high_critical_residual = [
    risk
    for risk in RISKS
    if risk["residual_rating"]
    in {"HIGH", "CRITICAL"}
]

persistent_risks = [
    risk
    for risk in RISKS
    if risk["persistence"] >= 4
]

privileged_risks = [
    risk
    for risk in RISKS
    if risk["privilege"] >= 5
]

wide_blast_risks = [
    risk
    for risk in RISKS
    if risk["blast_radius"] >= 5
]


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 90)
    print(f"        {title}")
    print("=" * 90)


header("RISK SCORING MODEL")

print(
    "Base Risk = Likelihood x Impact"
)

print(
    "AI Amplifier = Persistence + Privilege + "
    "Blast Radius + Detectability"
)

print(
    "Inherent Risk = Base Risk + AI Amplifier"
)

print(
    "Residual Risk = Inherent Risk - "
    "(Control Maturity x 3)"
)


header("AI RISK REGISTER")

for risk in RISKS:

    print(
        f"{risk['risk_id']} | "
        f"{risk['domain']} | "
        f"{risk['inherent_rating']} -> "
        f"{risk['residual_rating']} | "
        f"{risk['name']}"
    )

    print(
        f"  Likelihood: "
        f"{risk['likelihood']} "
        f"({LIKELIHOOD_SCALE[risk['likelihood']]})"
    )

    print(
        f"  Impact: "
        f"{risk['impact']} "
        f"({IMPACT_SCALE[risk['impact']]})"
    )

    print(
        f"  Persistence: "
        f"{risk['persistence']}"
    )

    print(
        f"  Privilege: "
        f"{risk['privilege']}"
    )

    print(
        f"  Blast Radius: "
        f"{risk['blast_radius']}"
    )

    print(
        f"  Detectability Difficulty: "
        f"{risk['detectability']}"
    )

    print(
        f"  Control Maturity: "
        f"{risk['control_maturity']}"
    )

    print(
        f"  Base Score: "
        f"{risk['base_score']}"
    )

    print(
        f"  AI Amplifier: "
        f"{risk['ai_amplifier']}"
    )

    print(
        f"  Inherent Score: "
        f"{risk['inherent_score']}"
    )

    print(
        f"  Residual Score: "
        f"{risk['residual_score']}"
    )


header("PRIORITIZED RESIDUAL RISK")

for index, risk in enumerate(
    PRIORITIZED_RISKS,
    start=1
):

    print(
        f"{index:02d} | "
        f"{risk['risk_id']} | "
        f"{risk['residual_rating']} | "
        f"Residual={risk['residual_score']} | "
        f"Inherent={risk['inherent_score']} | "
        f"{risk['name']}"
    )


header("RISK TREATMENT DECISIONS")

for treatment in RISK_TREATMENT:

    print(
        f"{treatment['risk_id']} | "
        f"{treatment['residual_rating']} | "
        f"{treatment['treatment']}"
    )


header("INHERENT RISK DISTRIBUTION")

for rating in [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
]:

    print(
        f"{rating}: "
        f"{inherent_counter.get(rating, 0)}"
    )


header("RESIDUAL RISK DISTRIBUTION")

for rating in [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
]:

    print(
        f"{rating}: "
        f"{residual_counter.get(rating, 0)}"
    )


header("HIGH-PERSISTENCE RISKS")

for risk in persistent_risks:

    print(
        f"{risk['risk_id']} | "
        f"Persistence={risk['persistence']} | "
        f"{risk['name']}"
    )


header("HIGH-PRIVILEGE RISKS")

for risk in privileged_risks:

    print(
        f"{risk['risk_id']} | "
        f"Privilege={risk['privilege']} | "
        f"{risk['name']}"
    )


header("WIDE BLAST-RADIUS RISKS")

for risk in wide_blast_risks:

    print(
        f"{risk['risk_id']} | "
        f"Blast Radius={risk['blast_radius']} | "
        f"{risk['name']}"
    )


header("DOMAIN RISK DISTRIBUTION")

for domain, count in sorted(
    domain_counter.items()
):

    print(
        f"{domain}: {count}"
    )


# ============================================================
# SUMMARY
# ============================================================

header("RISK PRIORITIZATION SUMMARY")

print(
    f"Risk Scenarios: "
    f"{len(RISKS)}"
)

print(
    f"Critical Inherent Risks: "
    f"{inherent_counter.get('CRITICAL', 0)}"
)

print(
    f"Critical Residual Risks: "
    f"{len(critical_residual)}"
)

print(
    f"High/Critical Residual Risks: "
    f"{len(high_critical_residual)}"
)

print(
    f"High-Persistence Risks: "
    f"{len(persistent_risks)}"
)

print(
    f"High-Privilege Risks: "
    f"{len(privileged_risks)}"
)

print(
    f"Wide Blast-Radius Risks: "
    f"{len(wide_blast_risks)}"
)

print(
    f"Risk Domains: "
    f"{len(domain_counter)}"
)


# ============================================================
# VALIDATION
# ============================================================

header("RISK-SCORING SECURITY CHECKS")

risk_ids = [
    risk["risk_id"]
    for risk in RISKS
]

checks = {
    "Unique Risk IDs":
        len(risk_ids)
        == len(set(risk_ids)),

    "Likelihood Values Valid":
        all(
            risk["likelihood"]
            in LIKELIHOOD_SCALE
            for risk in RISKS
        ),

    "Impact Values Valid":
        all(
            risk["impact"]
            in IMPACT_SCALE
            for risk in RISKS
        ),

    "All Risks Scored":
        all(
            "inherent_score" in risk
            and
            "residual_score" in risk
            for risk in RISKS
        ),

    "Residual Risk <= Inherent Risk":
        all(
            risk["residual_score"]
            <= risk["inherent_score"]
            for risk in RISKS
        ),

    "Persistent Risks Identified":
        len(persistent_risks) > 0,

    "Privileged Risks Identified":
        len(privileged_risks) > 0,

    "Blast-Radius Risks Identified":
        len(wide_blast_risks) > 0,

    "Critical / High Risks Identified":
        len(high_critical_residual) > 0,

    "Risk Treatment Generated":
        len(RISK_TREATMENT)
        == len(RISKS),

    "Prioritized Risk Register Generated":
        len(PRIORITIZED_RISKS)
        == len(RISKS),
}


for check, result in checks.items():

    print(
        f"{check}: {result}"
    )


risk_model_valid = all(
    checks.values()
)


print(
    f"\nLikelihood x Impact Risk Model Valid: "
    f"{risk_model_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 12",

    "title":
        "Likelihood x Impact Risk Scoring & Prioritization",

    "likelihood_scale":
        LIKELIHOOD_SCALE,

    "impact_scale":
        IMPACT_SCALE,

    "risks":
        RISKS,

    "prioritized_risks":
        PRIORITIZED_RISKS,

    "risk_treatment":
        RISK_TREATMENT,

    "metrics": {
        "risk_scenarios":
            len(RISKS),

        "critical_inherent":
            inherent_counter.get(
                "CRITICAL",
                0
            ),

        "critical_residual":
            len(
                critical_residual
            ),

        "high_critical_residual":
            len(
                high_critical_residual
            ),

        "high_persistence":
            len(
                persistent_risks
            ),

        "high_privilege":
            len(
                privileged_risks
            ),

        "wide_blast_radius":
            len(
                wide_blast_risks
            ),

        "risk_domains":
            len(
                domain_counter
            ),
    },

    "security_checks":
        checks,

    "risk_model_valid":
        risk_model_valid,
}


OUTPUT_FILE = (
    "day28-likelihood-impact-risk-scoring-evidence.json"
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
    "Likelihood and impact alone do not fully capture AI risk. "
    "Persistent state, privileged execution, broad blast radius "
    "and detection difficulty can materially amplify business risk."
)

print(
    "Residual-risk scoring shows which threats remain unacceptable "
    "after considering current control maturity and therefore require "
    "mitigation before deployment."
)

print(
    "The resulting prioritized risk list provides the input for the "
    "formal AI security risk register, risk ownership, treatment plans "
    "and security architecture decisions."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)