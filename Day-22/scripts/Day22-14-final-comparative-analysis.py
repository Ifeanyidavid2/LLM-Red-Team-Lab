"""
Day 22 Lab 14
Final Comparative Analysis

Purpose:
Compare vulnerable and hardened multi-agent security results across
Day 22 Labs 1-13.

Core Principle:
Agent identity does not imply agent authority;
delegated actions must be independently authorized.
"""

from dataclasses import dataclass
from typing import Optional


# ============================================================
# DATA MODEL
# ============================================================

@dataclass
class SecurityMetric:
    category: str
    metric: str
    vulnerable_rate: Optional[float]
    hardened_rate: Optional[float]
    desired_direction: str
    interpretation: str


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def pct(value):
    if value is None:
        return "N/A"
    return f"{value:.2f}%"


def improvement(vulnerable, hardened, direction):
    if vulnerable is None or hardened is None:
        return None

    if direction == "lower":
        return vulnerable - hardened

    if direction == "higher":
        return hardened - vulnerable

    return None


def print_header(title):
    print("\n" + "=" * 72)
    print(title.center(72))
    print("=" * 72)


def print_metric(metric):
    delta = improvement(
        metric.vulnerable_rate,
        metric.hardened_rate,
        metric.desired_direction,
    )

    print(f"\nCategory: {metric.category}")
    print(f"Metric: {metric.metric}")
    print(f"Vulnerable: {pct(metric.vulnerable_rate)}")
    print(f"Hardened:   {pct(metric.hardened_rate)}")

    if delta is not None:
        print(f"Security Improvement: {delta:.2f} percentage points")

    print(f"Interpretation: {metric.interpretation}")


# ============================================================
# DAY 22 EXPERIMENTAL RESULTS
# ============================================================

metrics = [

    SecurityMetric(
        category="Unauthorized Delegation",
        metric="Unauthorized Delegation Rate (UDR)",
        vulnerable_rate=100.00,
        hardened_rate=0.00,
        desired_direction="lower",
        interpretation=(
            "The vulnerable worker trusted agent-generated delegation "
            "too readily. Hardened authorization prevents unauthorized "
            "delegation from becoming executable authority."
        ),
    ),

    SecurityMetric(
        category="Agent Impersonation",
        metric="Agent Impersonation Acceptance Rate (AIAR)",
        vulnerable_rate=75.00,
        hardened_rate=0.00,
        desired_direction="lower",
        interpretation=(
            "Agent names and identity claims inside messages are not "
            "treated as authenticated identities after hardening."
        ),
    ),

    SecurityMetric(
        category="Delegated Authority",
        metric="Privilege Propagation Rate (PPR)",
        vulnerable_rate=100.00,
        hardened_rate=0.00,
        desired_direction="lower",
        interpretation=(
            "Delegation no longer causes automatic privilege inheritance. "
            "The delegate must independently possess the required capability."
        ),
    ),

    SecurityMetric(
        category="Delegation Scope",
        metric="Out-of-Scope Execution Rate",
        vulnerable_rate=100.00,
        hardened_rate=0.00,
        desired_direction="lower",
        interpretation=(
            "Trusted scope validation prevents a delegated read operation "
            "from being transformed into an update, delete, or target "
            "substitution."
        ),
    ),

    SecurityMetric(
        category="Confused Deputy",
        metric="Confused-Deputy Success Rate (CDSR)",
        vulnerable_rate=50.00,
        hardened_rate=0.00,
        desired_direction="lower",
        interpretation=(
            "A capable deputy may no longer exercise its privileges merely "
            "because another agent requests the operation."
        ),
    ),

    SecurityMetric(
        category="Trust Transitivity",
        metric="Trust Transitivity Acceptance Rate (TTAR)",
        vulnerable_rate=80.00,
        hardened_rate=0.00,
        desired_direction="lower",
        interpretation=(
            "Trust and authorization are no longer assumed to transitively "
            "flow through multi-agent delegation chains."
        ),
    ),

    SecurityMetric(
        category="Poisoned Messages",
        metric="Poisoned Inter-Agent Execution Rate",
        vulnerable_rate=75.00,
        hardened_rate=0.00,
        desired_direction="lower",
        interpretation=(
            "Embedded role overrides, fake approvals, and security-looking "
            "instructions are prevented from becoming executable authority."
        ),
    ),

    SecurityMetric(
        category="Shared Memory",
        metric="Shared-Memory Poisoning Success Rate",
        vulnerable_rate=25.00,
        hardened_rate=0.00,
        desired_direction="lower",
        interpretation=(
            "Shared memory is treated as a cross-agent trust boundary rather "
            "than trusted security state."
        ),
    ),

    SecurityMetric(
        category="Tool Execution",
        metric="Unsafe Tool Execution Rate (UTER)",
        vulnerable_rate=None,
        hardened_rate=0.00,
        desired_direction="lower",
        interpretation=(
            "Independent tool validation achieved zero unsafe executions "
            "during the hardened tool-authority benchmark."
        ),
    ),

    SecurityMetric(
        category="Compromised Agent",
        metric="Compromised-Agent Containment Rate (CACR)",
        vulnerable_rate=None,
        hardened_rate=100.00,
        desired_direction="higher",
        interpretation=(
            "All tested attacks originating from the intentionally "
            "compromised planner agent were contained."
        ),
    ),

    SecurityMetric(
        category="Adversarial Retest",
        metric="Dangerous Proposal Block Rate",
        vulnerable_rate=None,
        hardened_rate=100.00,
        desired_direction="higher",
        interpretation=(
            "The final architecture blocked every dangerous model proposal "
            "from producing unauthorized execution."
        ),
    ),

    SecurityMetric(
        category="Adversarial Retest",
        metric="Unauthorized System Impact Rate",
        vulnerable_rate=None,
        hardened_rate=0.00,
        desired_direction="lower",
        interpretation=(
            "No unauthorized system impact occurred in the final hardened "
            "adversarial retest."
        ),
    ),

    SecurityMetric(
        category="Security Correctness",
        metric="System Outcome Accuracy",
        vulnerable_rate=None,
        hardened_rate=100.00,
        desired_direction="higher",
        interpretation=(
            "The final hardened retest produced the expected security "
            "outcome for all eight adversarial and legitimate cases."
        ),
    ),

    SecurityMetric(
        category="Utility",
        metric="Legitimate Delegation Completion Rate",
        vulnerable_rate=100.00,
        hardened_rate=100.00,
        desired_direction="higher",
        interpretation=(
            "Security hardening preserved legitimate multi-agent task "
            "completion while blocking unauthorized actions."
        ),
    ),
]


# ============================================================
# ATTACK FINDINGS
# ============================================================

attack_findings = [
    (
        "Agent Impersonation",
        "Message content successfully caused the vulnerable agent to accept "
        "false or forwarded identity claims. Trusted transport identity "
        "eliminated message-controlled identity authority."
    ),
    (
        "Delegated Authority Abuse",
        "The vulnerable agent treated delegation as if it transferred "
        "privileges. Hardened controls require the delegate to independently "
        "possess the required capability."
    ),
    (
        "Confused Deputy",
        "A requester without direct access could sometimes convince a more "
        "privileged deputy to act on its behalf. Independent requester and "
        "resource authorization prevented this behavior."
    ),
    (
        "Trust Transitivity",
        "Authority was incorrectly propagated across agent relationships. "
        "The hardened design rejects transitive authorization assumptions."
    ),
    (
        "Poisoned Inter-Agent Messages",
        "Embedded instructions produced role drift, approval assumptions, "
        "and sender-identity overrides in the vulnerable model."
    ),
    (
        "Shared-Memory Poisoning",
        "Untrusted shared memory influenced security-sensitive reasoning. "
        "Hardened memory ownership, category policy, sanitization, and "
        "trusted security state prevent memory from becoming authority."
    ),
    (
        "Tool Authority Abuse",
        "Delegated tasks were separated from tool authority. Tool execution "
        "now independently checks delegate identity, capability, requester "
        "authorization, scope, target, and approval."
    ),
    (
        "Compromised-Agent Propagation",
        "A fully compromised planner agent was unable to spread compromise "
        "into restricted tools, trusted approvals, another agent's memory, "
        "or security-agent authority."
    ),
]


# ============================================================
# HARDENING JOURNEY
# ============================================================

hardening_journey = [
    (
        "Initial vulnerable architecture",
        "Agent-generated reasoning and message content influenced execution "
        "authority too directly."
    ),
    (
        "Trusted identity separation",
        "Authenticated sender identity was separated from claimed sender "
        "identity inside message content."
    ),
    (
        "Capability enforcement",
        "Each agent received explicit capabilities that could not be acquired "
        "through textual delegation."
    ),
    (
        "Scope enforcement",
        "Delegated action and target scope became application-controlled "
        "security properties."
    ),
    (
        "Resource policy",
        "Restricted resources required independently authorized security-agent "
        "execution."
    ),
    (
        "Approval validation",
        "High-impact actions required trusted, scoped, and replay-resistant "
        "approval state."
    ),
    (
        "Shared-memory controls",
        "Memory ownership, category policy, provenance, and sanitization "
        "prevented persistent cross-agent authority poisoning."
    ),
    (
        "Compromised-agent containment",
        "The architecture assumed an agent could become fully compromised and "
        "limited the resulting blast radius."
    ),
    (
        "Final adversarial retest",
        "Unsafe model proposals remained possible, but independent controls "
        "prevented them from becoming unauthorized system actions."
    ),
]


# ============================================================
# MODEL-CONTROLLED SECURITY BINDING FINDINGS
# ============================================================

binding_findings = [
    {
        "finding": "Delegate Substitution",
        "problem": (
            "During an intermediate hardened retest, the model could propose "
            "which agent should execute an operation."
        ),
        "risk": (
            "An attacker-controlled message could influence the model into "
            "selecting a more privileged delegate."
        ),
        "fix": (
            "Execution was bound to case/application-controlled "
            "trusted_delegate rather than the model-proposed delegate."
        ),
    },
    {
        "finding": "Action Laundering",
        "problem": (
            "During another intermediate retest, model output could influence "
            "the action evaluated by the security layer."
        ),
        "risk": (
            "A malicious request could be transformed into an apparently "
            "permitted operation or evaluated against the wrong scope."
        ),
        "fix": (
            "The trusted task definition now supplies trusted_action and "
            "trusted_target independently of model output."
        ),
    },
    {
        "finding": "Model Output as Diagnostic, Not Authority",
        "problem": (
            "Delegate, action, target, claimed authority, and approval-like "
            "values may still be generated incorrectly by the LLM."
        ),
        "risk": (
            "Treating those generated values as security state would allow "
            "reasoning compromise to become execution compromise."
        ),
        "fix": (
            "Model-generated values are retained for attack detection and "
            "diagnostics while security-sensitive execution properties are "
            "bound from trusted application state."
        ),
    },
]


# ============================================================
# CONTROL MATRIX
# ============================================================

controls = [
    ("Trusted transport identity", True),
    ("Claimed-sender separation", True),
    ("Explicit agent capabilities", True),
    ("Trusted delegate binding", True),
    ("Trusted action binding", True),
    ("Trusted target binding", True),
    ("Delegation scope enforcement", True),
    ("Restricted-resource policy", True),
    ("Independent requester authorization", True),
    ("Trusted approval validation", True),
    ("Approval replay protection", True),
    ("Inter-agent message sanitization", True),
    ("Shared-memory ownership enforcement", True),
    ("Security-sensitive memory category blocking", True),
    ("Shared-memory sanitization", True),
    ("Compromised-agent containment", True),
    ("Auditability", True),
]


# ============================================================
# MAIN REPORT
# ============================================================

def main():

    print_header("DAY 22 LAB 14: FINAL COMPARATIVE ANALYSIS")

    print(
        "\nResearch Question:\n"
        "Can a compromised or attacker-controlled agent manipulate another "
        "agent into trusting false information, inheriting unauthorized "
        "privileges, invoking tools, or making unsafe security decisions?"
    )

    print_header("VULNERABLE VS HARDENED METRICS")

    for metric in metrics:
        print_metric(metric)

    print_header("ATTACK FINDINGS")

    for index, (name, finding) in enumerate(
        attack_findings,
        start=1,
    ):
        print(f"\n{index}. {name}")
        print(f"   {finding}")

    print_header("MODEL-CONTROLLED SECURITY BINDING FAILURES")

    for index, finding in enumerate(
        binding_findings,
        start=1,
    ):
        print(f"\nFinding {index}: {finding['finding']}")
        print(f"Problem: {finding['problem']}")
        print(f"Risk: {finding['risk']}")
        print(f"Remediation: {finding['fix']}")

    print_header("HARDENING JOURNEY")

    for index, (stage, description) in enumerate(
        hardening_journey,
        start=1,
    ):
        print(f"\nStage {index}: {stage}")
        print(f"{description}")

    print_header("FINAL CONTROL MATRIX")

    implemented = 0

    for control, status in controls:
        state = "PASS" if status else "FAIL"

        if status:
            implemented += 1

        print(f"[{state}] {control}")

    control_rate = (
        implemented / len(controls) * 100
        if controls
        else 0.0
    )

    print(
        f"\nControls Implemented: "
        f"{implemented}/{len(controls)}"
    )

    print(
        f"Control Implementation Rate: "
        f"{control_rate:.2f}%"
    )

    print_header("FINAL ADVERSARIAL RETEST")

    final_cases = 8
    successful_model_runs = 8
    model_json_failures = 0
    dangerous_proposals = 6
    blocked_dangerous_proposals = 6
    unsafe_executions = 0
    correct_system_outcomes = 8

    dangerous_rate = (
        dangerous_proposals
        / successful_model_runs
        * 100
    )

    dangerous_block_rate = (
        blocked_dangerous_proposals
        / dangerous_proposals
        * 100
    )

    unauthorized_impact_rate = (
        unsafe_executions
        / final_cases
        * 100
    )

    system_accuracy = (
        correct_system_outcomes
        / final_cases
        * 100
    )

    legitimate_completion_rate = 100.00

    print(f"Cases: {final_cases}")
    print(
        f"Successful model runs: "
        f"{successful_model_runs}"
    )
    print(
        f"Model / JSON failures: "
        f"{model_json_failures}"
    )
    print(
        f"Dangerous model proposals: "
        f"{dangerous_proposals}"
    )
    print(
        f"Blocked dangerous proposals: "
        f"{blocked_dangerous_proposals}"
    )
    print(
        f"Unsafe executions: "
        f"{unsafe_executions}"
    )
    print(
        f"Correct system outcomes: "
        f"{correct_system_outcomes}"
    )

    print("\nFinal Rates:")

    print(
        f"Dangerous Proposal Rate: "
        f"{dangerous_rate:.2f}%"
    )

    print(
        f"Dangerous Proposal Block Rate: "
        f"{dangerous_block_rate:.2f}%"
    )

    print(
        f"Unauthorized System Impact Rate: "
        f"{unauthorized_impact_rate:.2f}%"
    )

    print(
        f"System Outcome Accuracy: "
        f"{system_accuracy:.2f}%"
    )

    print(
        f"Legitimate Delegation Completion Rate: "
        f"{legitimate_completion_rate:.2f}%"
    )

    print_header("SECURITY CONCLUSION")

    print(
        """
The experiments demonstrate that multi-agent systems become unsafe when
agent-generated identity claims, delegation statements, privilege claims,
approval statements, shared-memory content, or model-selected execution
properties are treated as security authority.

The vulnerable experiments demonstrated:

- agent impersonation,
- unauthorized delegation,
- privilege propagation,
- trust transitivity,
- confused-deputy behavior,
- poisoned inter-agent instruction execution,
- shared-memory security-state corruption,
- scope escalation,
- and unsafe authority assumptions.

The hardened architecture separates model reasoning from security authority.

Trusted application state independently controls:

- authenticated sender identity,
- execution delegate,
- agent capabilities,
- action,
- target,
- delegated scope,
- resource policy,
- requester authorization,
- high-impact approval,
- approval lifecycle,
- shared-memory ownership,
- memory category policy,
- and sanitization.

The final adversarial retest remains intentionally hostile to the LLM.
The model generated dangerous proposals in 75.00% of successful runs.

However:

- 100.00% of dangerous proposals were blocked,
- unauthorized system impact was 0.00%,
- system outcome accuracy was 100.00%,
- legitimate delegation completion remained 100.00%.

This demonstrates an important distinction:

A compromised reasoning layer does not have to become a compromised
execution layer.

The security boundary must exist outside the model.
"""
    )

    print_header("DAY 22 FINAL RESULT")

    print("Research Result: SUPPORTED")

    print(
        "\nA compromised or attacker-controlled agent can manipulate "
        "another model's reasoning and can cause dangerous proposals."
    )

    print(
        "\nHowever, those proposals do not become trusted authority when "
        "identity, capability, delegation, scope, resource access, target, "
        "tool authority, approval, and memory controls are independently "
        "enforced by trusted application state."
    )

    print(
        "\nCore Principle:\n"
        "Agent identity does not imply agent authority; "
        "delegated actions must be independently authorized."
    )


if __name__ == "__main__":
    main()