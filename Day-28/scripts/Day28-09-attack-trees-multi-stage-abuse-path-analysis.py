"""
Day 28 Lab 9
Attack Trees & Multi-Stage Abuse-Path Analysis

Purpose:
Model complete attacker objectives and multi-stage abuse paths across
prompt, RAG, memory, agent, authorization, tool, secret and downstream
business-impact trust boundaries.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter, defaultdict


print(
    "\n=== Day 28 Lab 9: "
    "Attack Trees & Multi-Stage Abuse-Path Analysis ===\n"
)


# ============================================================
# ATTACK OBJECTIVES
# ============================================================

ATTACK_OBJECTIVES = [
    {
        "objective_id": "OBJ-2801",
        "name": "Obtain Unauthorized Privileged Execution",
        "business_impact": "critical",
    },
    {
        "objective_id": "OBJ-2802",
        "name": "Compromise Persistent AI State",
        "business_impact": "high",
    },
    {
        "objective_id": "OBJ-2803",
        "name": "Access Restricted Business Data",
        "business_impact": "critical",
    },
    {
        "objective_id": "OBJ-2804",
        "name": "Cause Destructive Business Impact",
        "business_impact": "critical",
    },
    {
        "objective_id": "OBJ-2805",
        "name": "Reduce Detection / Forensic Visibility",
        "business_impact": "high",
    },
]


# ============================================================
# ATTACK NODES
# ============================================================

NODES = [
    {
        "node_id": "NODE-2801",
        "name": "Direct Prompt Injection",
        "domain": "PROMPT",
        "likelihood": 5,
        "impact": 4,
    },
    {
        "node_id": "NODE-2802",
        "name": "Indirect RAG Prompt Injection",
        "domain": "RAG",
        "likelihood": 5,
        "impact": 5,
    },
    {
        "node_id": "NODE-2803",
        "name": "RAG Source Poisoning",
        "domain": "RAG",
        "likelihood": 4,
        "impact": 5,
    },
    {
        "node_id": "NODE-2804",
        "name": "Unsafe Context Admission",
        "domain": "RAG",
        "likelihood": 4,
        "impact": 5,
    },
    {
        "node_id": "NODE-2805",
        "name": "Unauthorized Memory Write",
        "domain": "MEMORY",
        "likelihood": 4,
        "impact": 5,
    },
    {
        "node_id": "NODE-2806",
        "name": "Persistent Memory Poisoning",
        "domain": "MEMORY",
        "likelihood": 5,
        "impact": 5,
    },
    {
        "node_id": "NODE-2807",
        "name": "Cross-Session Poison Activation",
        "domain": "MEMORY",
        "likelihood": 4,
        "impact": 5,
    },
    {
        "node_id": "NODE-2808",
        "name": "Agent Goal Hijacking",
        "domain": "AGENT",
        "likelihood": 4,
        "impact": 5,
    },
    {
        "node_id": "NODE-2809",
        "name": "Task Binding Bypass",
        "domain": "AGENT",
        "likelihood": 4,
        "impact": 5,
    },
    {
        "node_id": "NODE-2810",
        "name": "Trusted Target Substitution",
        "domain": "TOOL",
        "likelihood": 4,
        "impact": 5,
    },
    {
        "node_id": "NODE-2811",
        "name": "Unsafe Privileged Tool Selection",
        "domain": "TOOL",
        "likelihood": 4,
        "impact": 5,
    },
    {
        "node_id": "NODE-2812",
        "name": "Tool Parameter Manipulation",
        "domain": "TOOL",
        "likelihood": 4,
        "impact": 5,
    },
    {
        "node_id": "NODE-2813",
        "name": "Model-Generated Approval",
        "domain": "AUTHORIZATION",
        "likelihood": 4,
        "impact": 5,
    },
    {
        "node_id": "NODE-2814",
        "name": "Authorization Decision Tampering",
        "domain": "AUTHORIZATION",
        "likelihood": 3,
        "impact": 5,
    },
    {
        "node_id": "NODE-2815",
        "name": "Fail-Open Authorization",
        "domain": "AUTHORIZATION",
        "likelihood": 3,
        "impact": 5,
    },
    {
        "node_id": "NODE-2816",
        "name": "Credential Exposure",
        "domain": "SECRET",
        "likelihood": 3,
        "impact": 5,
    },
    {
        "node_id": "NODE-2817",
        "name": "Credential Scope Abuse",
        "domain": "SECRET",
        "likelihood": 4,
        "impact": 5,
    },
    {
        "node_id": "NODE-2818",
        "name": "Restricted Record Access",
        "domain": "BUSINESS",
        "likelihood": 4,
        "impact": 5,
    },
    {
        "node_id": "NODE-2819",
        "name": "Restricted Record Destruction",
        "domain": "BUSINESS",
        "likelihood": 3,
        "impact": 5,
    },
    {
        "node_id": "NODE-2820",
        "name": "Security Telemetry Suppression",
        "domain": "OBSERVABILITY",
        "likelihood": 3,
        "impact": 4,
    },
]


NODE_MAP = {
    node["node_id"]: node
    for node in NODES
}


# ============================================================
# ATTACK PATHS
# ============================================================

ATTACK_PATHS = [
    {
        "path_id": "PATH-2801",
        "objective_id": "OBJ-2801",
        "name": "Prompt Injection to Privileged Execution",
        "steps": [
            "NODE-2801",
            "NODE-2808",
            "NODE-2809",
            "NODE-2811",
            "NODE-2813",
            "NODE-2815",
        ],
    },

    {
        "path_id": "PATH-2802",
        "objective_id": "OBJ-2802",
        "name": "RAG Poisoning to Persistent AI Compromise",
        "steps": [
            "NODE-2803",
            "NODE-2802",
            "NODE-2804",
            "NODE-2805",
            "NODE-2806",
            "NODE-2807",
        ],
    },

    {
        "path_id": "PATH-2803",
        "objective_id": "OBJ-2803",
        "name": "Prompt Injection to Restricted Data Access",
        "steps": [
            "NODE-2801",
            "NODE-2808",
            "NODE-2810",
            "NODE-2812",
            "NODE-2818",
        ],
    },

    {
        "path_id": "PATH-2804",
        "objective_id": "OBJ-2804",
        "name": "Persistent Memory to Destructive Execution",
        "steps": [
            "NODE-2806",
            "NODE-2807",
            "NODE-2808",
            "NODE-2811",
            "NODE-2815",
            "NODE-2819",
        ],
    },

    {
        "path_id": "PATH-2805",
        "objective_id": "OBJ-2804",
        "name": "Credential Abuse to Destructive Business Impact",
        "steps": [
            "NODE-2816",
            "NODE-2817",
            "NODE-2811",
            "NODE-2819",
        ],
    },

    {
        "path_id": "PATH-2806",
        "objective_id": "OBJ-2804",
        "name": "Target Substitution to Restricted Record Destruction",
        "steps": [
            "NODE-2808",
            "NODE-2810",
            "NODE-2812",
            "NODE-2811",
            "NODE-2819",
        ],
    },

    {
        "path_id": "PATH-2807",
        "objective_id": "OBJ-2801",
        "name": "Fake Approval to Authorization Bypass",
        "steps": [
            "NODE-2813",
            "NODE-2814",
            "NODE-2815",
            "NODE-2811",
        ],
    },

    {
        "path_id": "PATH-2808",
        "objective_id": "OBJ-2805",
        "name": "Telemetry Evasion During Privileged Abuse",
        "steps": [
            "NODE-2820",
            "NODE-2815",
            "NODE-2811",
            "NODE-2819",
        ],
    },
]


# ============================================================
# RISK CALCULATION
# ============================================================

def classify(score):

    if score >= 90:
        return "CRITICAL"

    if score >= 65:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


for path in ATTACK_PATHS:

    nodes = [
        NODE_MAP[node_id]
        for node_id in path["steps"]
    ]

    likelihood_total = sum(
        node["likelihood"]
        for node in nodes
    )

    impact_total = sum(
        node["impact"]
        for node in nodes
    )

    domain_count = len(
        {
            node["domain"]
            for node in nodes
        }
    )

    risk_score = (
        likelihood_total
        + impact_total
        + (domain_count * 5)
    )

    path["likelihood_total"] = likelihood_total
    path["impact_total"] = impact_total
    path["domains_crossed"] = domain_count
    path["risk_score"] = risk_score
    path["priority"] = classify(
        risk_score
    )


# ============================================================
# ATTACK TREES
# ============================================================

ATTACK_TREES = [
    {
        "tree_id": "TREE-2801",
        "root_objective":
            "Obtain Unauthorized Privileged Execution",
        "logic": "OR",
        "branches": [
            "PATH-2801",
            "PATH-2807",
            "PATH-2805",
        ],
    },

    {
        "tree_id": "TREE-2802",
        "root_objective":
            "Compromise Persistent AI State",
        "logic": "OR",
        "branches": [
            "PATH-2802",
            "PATH-2804",
        ],
    },

    {
        "tree_id": "TREE-2803",
        "root_objective":
            "Cause Restricted Business Impact",
        "logic": "OR",
        "branches": [
            "PATH-2804",
            "PATH-2805",
            "PATH-2806",
            "PATH-2808",
        ],
    },
]


# ============================================================
# CHOKE POINTS
# ============================================================

node_usage = Counter()

for path in ATTACK_PATHS:
    for node_id in path["steps"]:
        node_usage[node_id] += 1


CHOKE_POINTS = sorted(
    [
        {
            "node_id": node_id,
            "name": NODE_MAP[node_id]["name"],
            "path_count": count,
        }
        for node_id, count in node_usage.items()
        if count >= 2
    ],
    key=lambda item: (
        -item["path_count"],
        item["node_id"]
    )
)


# ============================================================
# CONTROL MAPPING
# ============================================================

CONTROLS = [
    {
        "control_id": "TREE-CTRL-01",
        "name": "Instruction Trust Separation",
        "blocks": [
            "NODE-2801",
            "NODE-2802",
        ],
    },

    {
        "control_id": "TREE-CTRL-02",
        "name": "RAG Provenance & Context Admission",
        "blocks": [
            "NODE-2803",
            "NODE-2804",
        ],
    },

    {
        "control_id": "TREE-CTRL-03",
        "name": "Authorized Memory Persistence",
        "blocks": [
            "NODE-2805",
            "NODE-2806",
            "NODE-2807",
        ],
    },

    {
        "control_id": "TREE-CTRL-04",
        "name": "Agent Goal / Task Binding",
        "blocks": [
            "NODE-2808",
            "NODE-2809",
        ],
    },

    {
        "control_id": "TREE-CTRL-05",
        "name": "Trusted Tool / Target Binding",
        "blocks": [
            "NODE-2810",
            "NODE-2811",
            "NODE-2812",
        ],
    },

    {
        "control_id": "TREE-CTRL-06",
        "name": "Fail-Closed Independent Authorization",
        "blocks": [
            "NODE-2813",
            "NODE-2814",
            "NODE-2815",
        ],
    },

    {
        "control_id": "TREE-CTRL-07",
        "name": "Secret Isolation & Least Privilege",
        "blocks": [
            "NODE-2816",
            "NODE-2817",
        ],
    },

    {
        "control_id": "TREE-CTRL-08",
        "name": "Business Resource Authorization",
        "blocks": [
            "NODE-2818",
            "NODE-2819",
        ],
    },

    {
        "control_id": "TREE-CTRL-09",
        "name": "Tamper-Evident AI Telemetry",
        "blocks": [
            "NODE-2820",
        ],
    },
]


covered_nodes = {
    node_id
    for control in CONTROLS
    for node_id in control["blocks"]
}


# ============================================================
# ANALYSIS
# ============================================================

priority_counter = Counter(
    path["priority"]
    for path in ATTACK_PATHS
)

objective_counter = Counter(
    path["objective_id"]
    for path in ATTACK_PATHS
)

all_domains = Counter(
    NODE_MAP[node_id]["domain"]
    for path in ATTACK_PATHS
    for node_id in path["steps"]
)

high_critical_paths = [
    path
    for path in ATTACK_PATHS
    if path["priority"]
    in {"HIGH", "CRITICAL"}
]


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 86)
    print(f"        {title}")
    print("=" * 86)


header("ATTACK OBJECTIVES")

for objective in ATTACK_OBJECTIVES:

    print(
        f"{objective['objective_id']} | "
        f"{objective['business_impact'].upper()} | "
        f"{objective['name']}"
    )


header("ATTACK NODE LIBRARY")

for node in NODES:

    print(
        f"{node['node_id']} | "
        f"{node['domain']} | "
        f"L={node['likelihood']} | "
        f"I={node['impact']} | "
        f"{node['name']}"
    )


header("MULTI-STAGE ATTACK PATHS")

for path in ATTACK_PATHS:

    print(
        f"{path['path_id']} | "
        f"{path['priority']} | "
        f"Risk={path['risk_score']} | "
        f"{path['name']}"
    )

    print(
        "  Path: "
        + " -> ".join(
            path["steps"]
        )
    )

    print(
        f"  Domains Crossed: "
        f"{path['domains_crossed']}"
    )

    print(
        f"  Likelihood Total: "
        f"{path['likelihood_total']}"
    )

    print(
        f"  Impact Total: "
        f"{path['impact_total']}"
    )


header("ATTACK TREES")

for tree in ATTACK_TREES:

    print(
        f"{tree['tree_id']} | "
        f"{tree['logic']} | "
        f"{tree['root_objective']}"
    )

    for branch in tree["branches"]:
        print(
            f"  -> {branch}"
        )


header("ATTACK-PATH CHOKE POINTS")

for choke in CHOKE_POINTS:

    print(
        f"{choke['node_id']} | "
        f"Paths={choke['path_count']} | "
        f"{choke['name']}"
    )


header("DOMAIN EXPOSURE")

for domain, count in sorted(
    all_domains.items(),
    key=lambda item: (
        -item[1],
        item[0]
    )
):

    print(
        f"{domain}: {count} path appearances"
    )


header("HIGH / CRITICAL ATTACK PATHS")

for path in sorted(
    high_critical_paths,
    key=lambda item: item["risk_score"],
    reverse=True,
):

    print(
        f"{path['path_id']} | "
        f"{path['priority']} | "
        f"Risk={path['risk_score']} | "
        f"{path['name']}"
    )


header("ATTACK-TREE CONTROL MAPPING")

for control in CONTROLS:

    print(
        f"{control['control_id']} | "
        f"{control['name']}"
    )

    print(
        "  Blocks: "
        + ", ".join(
            control["blocks"]
        )
    )


# ============================================================
# SUMMARY
# ============================================================

header("ATTACK-TREE / ABUSE-PATH SUMMARY")

print(
    f"Attack Objectives: "
    f"{len(ATTACK_OBJECTIVES)}"
)

print(
    f"Attack Nodes: "
    f"{len(NODES)}"
)

print(
    f"Attack Paths: "
    f"{len(ATTACK_PATHS)}"
)

print(
    f"Attack Trees: "
    f"{len(ATTACK_TREES)}"
)

print(
    f"High/Critical Paths: "
    f"{len(high_critical_paths)}"
)

print(
    f"Attack Domains Represented: "
    f"{len(all_domains)}"
)

print(
    f"Multi-Path Choke Points: "
    f"{len(CHOKE_POINTS)}"
)

print(
    f"Security Controls: "
    f"{len(CONTROLS)}"
)

print(
    f"Attack Nodes With Control Coverage: "
    f"{len(covered_nodes)} / "
    f"{len(NODES)}"
)


# ============================================================
# VALIDATION
# ============================================================

header("ATTACK-TREE SECURITY CHECKS")

node_ids = [
    node["node_id"]
    for node in NODES
]

path_ids = {
    path["path_id"]
    for path in ATTACK_PATHS
}

objective_ids = {
    objective["objective_id"]
    for objective in ATTACK_OBJECTIVES
}

checks = {
    "Unique Attack Node IDs":
        len(node_ids)
        == len(set(node_ids)),

    "All Path Nodes Valid":
        all(
            node_id in NODE_MAP
            for path in ATTACK_PATHS
            for node_id in path["steps"]
        ),

    "All Objectives Valid":
        all(
            path["objective_id"]
            in objective_ids
            for path in ATTACK_PATHS
        ),

    "All Attack Tree Branches Valid":
        all(
            branch in path_ids
            for tree in ATTACK_TREES
            for branch in tree["branches"]
        ),

    "Prompt Attack Path Identified":
        any(
            NODE_MAP[node_id]["domain"]
            == "PROMPT"
            for path in ATTACK_PATHS
            for node_id in path["steps"]
        ),

    "RAG Attack Path Identified":
        any(
            NODE_MAP[node_id]["domain"]
            == "RAG"
            for path in ATTACK_PATHS
            for node_id in path["steps"]
        ),

    "Memory Attack Path Identified":
        any(
            NODE_MAP[node_id]["domain"]
            == "MEMORY"
            for path in ATTACK_PATHS
            for node_id in path["steps"]
        ),

    "Agent Attack Path Identified":
        any(
            NODE_MAP[node_id]["domain"]
            == "AGENT"
            for path in ATTACK_PATHS
            for node_id in path["steps"]
        ),

    "Authorization Attack Path Identified":
        any(
            NODE_MAP[node_id]["domain"]
            == "AUTHORIZATION"
            for path in ATTACK_PATHS
            for node_id in path["steps"]
        ),

    "Tool Attack Path Identified":
        any(
            NODE_MAP[node_id]["domain"]
            == "TOOL"
            for path in ATTACK_PATHS
            for node_id in path["steps"]
        ),

    "Secret Attack Path Identified":
        any(
            NODE_MAP[node_id]["domain"]
            == "SECRET"
            for path in ATTACK_PATHS
            for node_id in path["steps"]
        ),

    "Business Impact Path Identified":
        any(
            NODE_MAP[node_id]["domain"]
            == "BUSINESS"
            for path in ATTACK_PATHS
            for node_id in path["steps"]
        ),

    "Observability Path Identified":
        any(
            NODE_MAP[node_id]["domain"]
            == "OBSERVABILITY"
            for path in ATTACK_PATHS
            for node_id in path["steps"]
        ),

    "Multi-Path Choke Points Identified":
        len(CHOKE_POINTS) > 0,

    "All Attack Nodes Have Control Coverage":
        all(
            node["node_id"]
            in covered_nodes
            for node in NODES
        ),

    "Attack Trees Created":
        len(ATTACK_TREES) > 0,
}


for check, result in checks.items():

    print(
        f"{check}: {result}"
    )


attack_tree_model_valid = all(
    checks.values()
)


print(
    f"\nAttack Tree / Abuse-Path Model Valid: "
    f"{attack_tree_model_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 9",

    "title":
        "Attack Trees & Multi-Stage Abuse-Path Analysis",

    "objectives":
        ATTACK_OBJECTIVES,

    "nodes":
        NODES,

    "attack_paths":
        ATTACK_PATHS,

    "attack_trees":
        ATTACK_TREES,

    "choke_points":
        CHOKE_POINTS,

    "controls":
        CONTROLS,

    "metrics": {
        "attack_objectives":
            len(ATTACK_OBJECTIVES),

        "attack_nodes":
            len(NODES),

        "attack_paths":
            len(ATTACK_PATHS),

        "attack_trees":
            len(ATTACK_TREES),

        "high_critical_paths":
            len(high_critical_paths),

        "attack_domains":
            len(all_domains),

        "choke_points":
            len(CHOKE_POINTS),

        "security_controls":
            len(CONTROLS),

        "nodes_with_control_coverage":
            len(covered_nodes),
    },

    "security_checks":
        checks,

    "attack_tree_model_valid":
        attack_tree_model_valid,
}


OUTPUT_FILE = (
    "day28-attack-tree-abuse-path-evidence.json"
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
    "Attack trees show that high-impact AI incidents usually require "
    "multiple control failures rather than a single vulnerability."
)

print(
    "Prompt injection, RAG poisoning, persistent memory compromise, "
    "agent goal hijacking, target manipulation, credential abuse, "
    "authorization failure, privileged tool selection and business "
    "impact can combine into complete attack paths."
)

print(
    "The repeated nodes across multiple paths identify architectural "
    "choke points where strong controls can disrupt several attacker "
    "objectives at once."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)