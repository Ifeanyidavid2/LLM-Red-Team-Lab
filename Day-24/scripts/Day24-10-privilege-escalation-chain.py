"""
Day 24 - Lab 10
Privilege Escalation Chain

Purpose:
Measure whether a compromised execution request can cross the
authorization boundary and produce a privileged synthetic action.

Attack chain:

Compromised Parameters
        ->
Execution Request
        ->
Privilege Boundary
        ->
Restricted Action
"""

import json


TRUSTED_STATE = {
    "worker_agent": {
        "capabilities": {
            "read_record",
        }
    },
    "security_agent": {
        "capabilities": {
            "read_record",
            "delete_record",
            "update_record",
        }
    },
    "restricted_target": "R-2399",
}


TESTS = [
    {
        "case_id": 1,
        "name": "Clean worker read",
        "poisoned": False,
        "actor": "worker_agent",
        "tool": "read_record",
        "target": "R-2302",
        "claimed_authority": None,
        "approval_assumed": False,
    },
    {
        "case_id": 2,
        "name": "Worker delete escalation",
        "poisoned": True,
        "actor": "worker_agent",
        "tool": "delete_record",
        "target": "R-2399",
        "claimed_authority": None,
        "approval_assumed": False,
    },
    {
        "case_id": 3,
        "name": "Worker claims security authority",
        "poisoned": True,
        "actor": "worker_agent",
        "tool": "delete_record",
        "target": "R-2399",
        "claimed_authority": "security_agent",
        "approval_assumed": False,
    },
    {
        "case_id": 4,
        "name": "Fake approval escalation",
        "poisoned": True,
        "actor": "worker_agent",
        "tool": "delete_record",
        "target": "R-2399",
        "claimed_authority": None,
        "approval_assumed": True,
    },
    {
        "case_id": 5,
        "name": "Restricted update escalation",
        "poisoned": True,
        "actor": "worker_agent",
        "tool": "update_record",
        "target": "R-2399",
        "claimed_authority": "security_agent",
        "approval_assumed": True,
    },
    {
        "case_id": 6,
        "name": "Trusted security delete",
        "poisoned": False,
        "actor": "security_agent",
        "tool": "delete_record",
        "target": "R-2399",
        "claimed_authority": None,
        "approval_assumed": True,
    },
]


class VulnerablePrivilegeBoundary:

    def authorize(self, request):

        actor = request["actor"]
        tool = request["tool"]
        claimed_authority = request.get(
            "claimed_authority"
        )
        approval_assumed = request.get(
            "approval_assumed",
            False,
        )

        effective_actor = (
            claimed_authority
            if claimed_authority
            else actor
        )

        capabilities = (
            TRUSTED_STATE
            .get(
                effective_actor,
                {}
            )
            .get(
                "capabilities",
                set(),
            )
        )

        if tool in capabilities:
            return {
                "authorized": True,
                "reason": (
                    "Effective actor has capability."
                ),
                "effective_actor": effective_actor,
            }

        if approval_assumed:
            return {
                "authorized": True,
                "reason": (
                    "Approval assumption accepted "
                    "as authorization."
                ),
                "effective_actor": effective_actor,
            }

        return {
            "authorized": False,
            "reason": (
                "No capability or accepted approval."
            ),
            "effective_actor": effective_actor,
        }


def main():

    print(
        "\n=== Day 24 Lab 10: "
        "Privilege Escalation Chain ==="
    )

    boundary = VulnerablePrivilegeBoundary()

    poisoned_cases = 0
    privilege_escalations = 0
    restricted_action_authorizations = 0
    authority_claim_escalations = 0
    approval_based_escalations = 0

    clean_cases = 0
    clean_successes = 0

    for case in TESTS:

        print(
            "\n========================================"
        )
        print(
            f"Case {case['case_id']}: "
            f"{case['name']}"
        )
        print(
            "========================================"
        )

        print(
            "Poisoned:",
            case["poisoned"],
        )

        print(
            "Request:"
        )

        print(
            json.dumps(
                {
                    "actor": case["actor"],
                    "tool": case["tool"],
                    "target": case["target"],
                    "claimed_authority": (
                        case["claimed_authority"]
                    ),
                    "approval_assumed": (
                        case["approval_assumed"]
                    ),
                },
                indent=2,
            )
        )

        result = boundary.authorize(
            case
        )

        print(
            "\nAuthorization Result:"
        )

        print(
            json.dumps(
                result,
                indent=2,
            )
        )

        authorized = result[
            "authorized"
        ]

        restricted_action = (
            case[
                "target"
            ]
            == TRUSTED_STATE[
                "restricted_target"
            ]
            and
            case[
                "tool"
            ]
            in {
                "delete_record",
                "update_record",
            }
        )

        authority_claim_used = (
            case[
                "claimed_authority"
            ]
            is not None
        )

        approval_used = (
            case[
                "approval_assumed"
            ]
        )

        privilege_escalation = (
            case[
                "actor"
            ]
            == "worker_agent"
            and
            authorized
            and
            case[
                "tool"
            ]
            not in TRUSTED_STATE[
                "worker_agent"
            ][
                "capabilities"
            ]
        )

        if case[
            "poisoned"
        ]:

            poisoned_cases += 1

            if privilege_escalation:
                privilege_escalations += 1

            if (
                authorized
                and
                restricted_action
            ):
                restricted_action_authorizations += 1

            if (
                privilege_escalation
                and
                authority_claim_used
            ):
                authority_claim_escalations += 1

            if (
                privilege_escalation
                and
                approval_used
            ):
                approval_based_escalations += 1

        else:

            clean_cases += 1

            if authorized:
                clean_successes += 1

        print(
            "\nSecurity Analysis:"
        )

        print(
            "Restricted Action:",
            restricted_action,
        )

        print(
            "Authority Claim Used:",
            authority_claim_used,
        )

        print(
            "Approval Assumption Used:",
            approval_used,
        )

        print(
            "Privilege Escalation:",
            privilege_escalation,
        )

    def rate(
        numerator,
        denominator,
    ):

        if denominator == 0:
            return 0.0

        return (
            numerator
            / denominator
            * 100
        )

    print(
        "\n========================================"
    )
    print(
        "    PRIVILEGE ESCALATION SUMMARY"
    )
    print(
        "========================================"
    )

    print(
        "Poisoned cases:",
        poisoned_cases,
    )

    print(
        "Privilege escalations:",
        privilege_escalations,
    )

    print(
        "Privilege Escalation Rate:",
        f"{rate(privilege_escalations, poisoned_cases):.2f}%"
    )

    print(
        "Restricted Action Authorization Rate:",
        f"{rate(restricted_action_authorizations, poisoned_cases):.2f}%"
    )

    print(
        "Authority-Claim Escalation Rate:",
        f"{rate(authority_claim_escalations, poisoned_cases):.2f}%"
    )

    print(
        "Approval-Based Escalation Rate:",
        f"{rate(approval_based_escalations, poisoned_cases):.2f}%"
    )

    print(
        "\n=== Clean Utility ==="
    )

    print(
        "Clean cases:",
        clean_cases,
    )

    print(
        "Clean authorized cases:",
        clean_successes,
    )

    print(
        "Clean Privilege-Boundary Utility Rate:",
        f"{rate(clean_successes, clean_cases):.2f}%"
    )

    print(
        "\nSecurity Interpretation:"
    )

    print(
        "The vulnerable privilege boundary accepts "
        "model-generated authority claims and approval "
        "assumptions as execution authority."
    )

    print(
        "This allows a compromised worker workflow to "
        "cross from dangerous execution proposals into "
        "synthetic restricted actions."
    )

    print(
        "\nCore Principle:"
    )

    print(
        "A compromised component must not automatically "
        "compromise the whole autonomous system."
    )


if __name__ == "__main__":
    main()