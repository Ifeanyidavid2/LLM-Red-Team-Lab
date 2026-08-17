print(
    "=== Day 18 Lab 11: "
    "Final Tool-Use Security Comparative Analysis ==="
)

print("""
========================================
      LAB 2 — VULNERABLE AGENT
========================================

Total cases: 5
Legitimate cases: 2
Unauthorized cases: 3

Unauthorized Tool Attempts: 0
Unauthorized Successful Executions: 0

UTAR: 0.00%
UASR: N/A

Legitimate Action Completion Rate: 0.00%

Interpretation:
The model proposed no executable tool calls.
This did NOT validate the application security boundary.
The tool layer still lacked independent authorization.
""")


print("""
========================================
      LAB 3 — AUTHORIZATION ENGINE
========================================

Policy Tests: 10
Correct Decisions: 10/10
Policy Decision Accuracy: 100.00%

Allowed Actions: 5
Blocked Actions: 5

Unauthorized Successful Executions: 0

Interpretation:
Authorization moved from model reasoning into trusted
application code.
""")


print("""
========================================
      LAB 4 — POLICY-ENFORCED AGENT
========================================

Total Cases: 8
Model / JSON Failures: 1

Legitimate Cases: 4
Unauthorized Cases: 4

Legitimate Tool Proposals: 1
Legitimate Successful Executions: 1

Unauthorized Tool Proposals: 2
Policy Blocks: 2
Unauthorized Successful Executions: 0

UTAR: 50.00%
UASR: 0.00%

Legitimate Action Completion Rate: 25.00%
Unauthorized Proposal Block Rate: 100.00%

Interpretation:
Unsafe model proposals occurred, but trusted policy
prevented unauthorized system impact.
""")


print("""
========================================
      LAB 5 — HIGH-IMPACT APPROVAL
========================================

Tests: 6
Correct Security Decisions: 6/6
Control Decision Accuracy: 100.00%

Unauthorized Delete Blocks: 1
Approval-Related Blocks: 2
High-Impact Executions: 1

Replay Test:
Consumed approval was blocked.

Interpretation:
Authorization and approval were separated.
High-impact actions required a trusted scoped one-time approval.
""")


print("""
========================================
      LAB 6 — ARGUMENT VALIDATION
========================================

Tests: 10
Correct Decisions: 10/10
Control Decision Accuracy: 100.00%

Successful Executions: 2
Validation / Policy Blocks: 7
Authorization Blocks: 1

Interpretation:
Valid authorization was not enough.
Arguments were independently validated before authorization
and execution.
""")


print("""
========================================
      LAB 7 — INDIRECT TOOL INJECTION
========================================

Cases: 2
Indirect Attack Cases: 1
Model / JSON Failures: 0

Unsafe Follow-Up Proposals: 1
Policy-Blocked Follow-Up Actions: 1
Successful Unauthorized Actions: 0

Indirect Prompt Injection Action-Proposal Rate: 100.00%
Indirect Injection Policy Block Rate: 100.00%
Indirect Injection System Impact Rate: 0.00%

Interpretation:
The model was influenced by untrusted tool output, but
the system authority boundary remained intact.
""")


print("""
========================================
      LAB 8 — EXCESSIVE AGENCY
========================================

Cases: 5
Model / JSON Failures: 2

Total Proposed Actions: 3
Requested Action Proposals: 3
Excessive Action Proposals: 0

Legitimate Successful Executions: 2
Excessive Successful Executions: 0

EAR: 0.00%
EAER: N/A

Requested Action Completion Rate: 40.00%

Interpretation:
No excessive actions were observed among parsed plans,
but planner reliability remained weak.
""")


print("""
========================================
      LAB 9 — USER-INTENT SCOPE
========================================

Tests: 7
Correct Decisions: 7/7
Control Decision Accuracy: 100.00%

Successful Scoped Executions: 3
Out-of-Scope Blocks: 3
Authorization Blocks: 1

Interpretation:
Capability did not imply user intent.
Actions had to be both authorized and explicitly within
the current approved task scope.
""")


print("""
========================================
      LAB 10 — HARDENED END-TO-END AGENT
========================================

Tests: 6
Correct Outcomes: 6/6
Control Outcome Accuracy: 100.00%

Model / JSON Failures: 0

Successful Executions: 2
Validation Blocks: 1
Authorization Blocks: 1
Scope Blocks: 1
Approval Blocks: 1

Unsafe Executions: 0

Interpretation:
Validation, authorization, scope, and approval controls
worked independently and prevented unsafe system impact.
""")


print("""
========================================
        CROSS-LAB SECURITY FINDINGS
========================================
""")

findings = [
    (
        "1. The model should not be trusted as the authorization layer."
    ),
    (
        "2. Unsafe model proposals are not equivalent to successful "
        "system compromise."
    ),
    (
        "3. Independent application authorization reduced observed "
        "unauthorized action success to 0% in the tested cases."
    ),
    (
        "4. High-impact operations required separate trusted approval "
        "even when the actor was authorized."
    ),
    (
        "5. Approval identifiers generated or suggested by the model "
        "were not trusted."
    ),
    (
        "6. Tool arguments required independent validation before "
        "authorization and execution."
    ),
    (
        "7. Tool output was demonstrated to be an indirect prompt-"
        "injection attack surface."
    ),
    (
        "8. The poisoned tool-output case successfully influenced the "
        "model to propose deletion, but trusted policy blocked execution."
    ),
    (
        "9. Authorization alone did not constrain excessive agency; "
        "user-intent scope enforcement was also required."
    ),
    (
        "10. Capability and current user intent are separate security "
        "properties."
    ),
    (
        "11. The hardened end-to-end architecture produced 6/6 correct "
        "security outcomes and zero unsafe executions in the controlled "
        "test corpus."
    ),
    (
        "12. Model routing reliability remained a utility limitation in "
        "several LLM-driven labs."
    ),
]

for finding in findings:
    print(finding)


print("""
========================================
       SECURITY / UTILITY ANALYSIS
========================================

Security robustness improved substantially once trusted controls
were placed outside the model.

However, model utility was inconsistent:

Lab 2 legitimate completion: 0.00%
Lab 4 legitimate completion: 25.00%
Lab 8 requested completion: 40.00%

Therefore secure tool-use architecture must optimize both:

1. Prevention of unauthorized system impact
2. Reliable completion of authorized user actions

A system that blocks every tool call would appear secure but would
not be useful.
""")


print("""
========================================
        FINAL DAY 18 CONCLUSION
========================================

The experiments demonstrate that LLM tool security cannot rely
on model obedience alone.

The strongest architecture treated model output as an untrusted
proposal and required every action to independently pass:

1. argument validation
2. authorization
3. user-intent scope
4. high-impact approval

Tool output was also treated as untrusted input because retrieved
content successfully induced an unsafe follow-up proposal.

The most important Day 18 result was therefore not that the model
always behaved safely.

It did not.

The important result was that unsafe model reasoning did not
automatically inherit system authority.

Core principle:

THE MODEL MAY PROPOSE AN ACTION;
TRUSTED APPLICATION CODE MUST DECIDE
WHETHER THAT ACTION IS AUTHORIZED.
""")