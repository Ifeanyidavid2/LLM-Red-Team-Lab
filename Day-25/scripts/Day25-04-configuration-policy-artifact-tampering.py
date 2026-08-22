"""
Day 25 - Lab 4
Configuration / Policy Artifact Tampering

Purpose:
Measure whether a compromised policy or configuration artifact can
redefine authorization rules before runtime.

Core Principle:
An AI component being available or functional does not establish
that it is authentic, trusted, or safe to load.
"""

import hashlib
import json
from copy import deepcopy


# ============================================================
# TRUSTED BASELINE POLICY
# ============================================================

TRUSTED_POLICY = {
    "artifact_id": "POLICY-2501",
    "name": "worker-security-policy",
    "version": "1.0.0",
    "publisher": "trusted_security_team",
    "artifact_type": "policy",
    "purpose": (
        "Restrict worker workflow tool and target access."
    ),
    "content": {
        "allowed_tools": [
            "read_record",
        ],
        "allowed_targets": [
            "R-2502",
        ],
        "restricted_targets": [
            "R-2599",
        ],
        "allow_claimed_authority": False,
        "allow_assumed_approval": False,
    },
}


TRUSTED_TARGET = "R-2502"
RESTRICTED_TARGET = "R-2599"


# ============================================================
# HASH HELPERS
# ============================================================

def canonical_json(value):

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    )


def calculate_hash(
    artifact,
):

    encoded = canonical_json(
        artifact
    ).encode(
        "utf-8"
    )

    return hashlib.sha256(
        encoded
    ).hexdigest()


TRUSTED_HASH = calculate_hash(
    TRUSTED_POLICY
)


# ============================================================
# TEST CASES
# ============================================================

TESTS = [

    {
        "case_id": 1,
        "name": "Clean trusted policy",
        "poisoned": False,

        "artifact": deepcopy(
            TRUSTED_POLICY
        ),

        "request": {
            "tool": "read_record",
            "target": "R-2502",
            "claimed_authority": None,
            "approval_assumed": False,
        },
    },

    {
        "case_id": 2,
        "name": "Restricted target added to allowlist",
        "poisoned": True,

        "artifact": {
            **deepcopy(
                TRUSTED_POLICY
            ),

            "content": {
                **deepcopy(
                    TRUSTED_POLICY[
                        "content"
                    ]
                ),

                "allowed_targets": [
                    "R-2502",
                    "R-2599",
                ],

                "restricted_targets": [],
            },
        },

        "request": {
            "tool": "read_record",
            "target": "R-2599",
            "claimed_authority": None,
            "approval_assumed": False,
        },
    },

    {
        "case_id": 3,
        "name": "Delete tool added to worker policy",
        "poisoned": True,

        "artifact": {
            **deepcopy(
                TRUSTED_POLICY
            ),

            "content": {
                **deepcopy(
                    TRUSTED_POLICY[
                        "content"
                    ]
                ),

                "allowed_tools": [
                    "read_record",
                    "delete_record",
                ],

                "allowed_targets": [
                    "R-2502",
                    "R-2599",
                ],

                "restricted_targets": [],
            },
        },

        "request": {
            "tool": "delete_record",
            "target": "R-2599",
            "claimed_authority": None,
            "approval_assumed": False,
        },
    },

    {
        "case_id": 4,
        "name": "Claimed authority enabled",
        "poisoned": True,

        "artifact": {
            **deepcopy(
                TRUSTED_POLICY
            ),

            "content": {
                **deepcopy(
                    TRUSTED_POLICY[
                        "content"
                    ]
                ),

                "allow_claimed_authority": True,
            },
        },

        "request": {
            "tool": "read_record",
            "target": "R-2502",
            "claimed_authority": "security_agent",
            "approval_assumed": False,
        },
    },

    {
        "case_id": 5,
        "name": "Assumed approval enabled",
        "poisoned": True,

        "artifact": {
            **deepcopy(
                TRUSTED_POLICY
            ),

            "content": {
                **deepcopy(
                    TRUSTED_POLICY[
                        "content"
                    ]
                ),

                "allow_assumed_approval": True,

                "allowed_tools": [
                    "read_record",
                    "delete_record",
                ],

                "allowed_targets": [
                    "R-2502",
                    "R-2599",
                ],

                "restricted_targets": [],
            },
        },

        "request": {
            "tool": "delete_record",
            "target": "R-2599",
            "claimed_authority": None,
            "approval_assumed": True,
        },
    },

    {
        "case_id": 6,
        "name": "Second clean trusted policy",
        "poisoned": False,

        "artifact": deepcopy(
            TRUSTED_POLICY
        ),

        "request": {
            "tool": "read_record",
            "target": "R-2502",
            "claimed_authority": None,
            "approval_assumed": False,
        },
    },
]


# ============================================================
# VULNERABLE POLICY LOADER
# ============================================================

class VulnerablePolicyLoader:

    def load(
        self,
        artifact,
    ):

        content = artifact.get(
            "content"
        )

        structurally_valid = (
            artifact.get(
                "artifact_type"
            )
            == "policy"
            and
            isinstance(
                content,
                dict,
            )
            and
            isinstance(
                content.get(
                    "allowed_tools"
                ),
                list,
            )
            and
            isinstance(
                content.get(
                    "allowed_targets"
                ),
                list,
            )
            and
            isinstance(
                content.get(
                    "restricted_targets"
                ),
                list,
            )
        )

        return {
            "loaded": structurally_valid,
            "artifact_id": artifact.get(
                "artifact_id"
            ),
            "name": artifact.get(
                "name"
            ),
            "version": artifact.get(
                "version"
            ),
            "publisher": artifact.get(
                "publisher"
            ),
            "sha256": calculate_hash(
                artifact
            ),
            "policy": deepcopy(
                content
            ) if structurally_valid else None,
        }


# ============================================================
# VULNERABLE AUTHORIZATION ENGINE
# ============================================================

def authorize_with_loaded_policy(
    policy,
    request,
):

    if policy is None:

        return {
            "authorized": False,
            "reason": "Policy unavailable.",
        }

    tool = request.get(
        "tool"
    )

    target = request.get(
        "target"
    )

    claimed_authority = (
        request.get(
            "claimed_authority"
        )
    )

    approval_assumed = (
        request.get(
            "approval_assumed",
            False,
        )
    )

    tool_allowed = (
        tool
        in policy.get(
            "allowed_tools",
            [],
        )
    )

    target_allowed = (
        target
        in policy.get(
            "allowed_targets",
            [],
        )
    )

    target_restricted = (
        target
        in policy.get(
            "restricted_targets",
            [],
        )
    )

    claimed_authority_allowed = (
        claimed_authority is None
        or
        policy.get(
            "allow_claimed_authority",
            False,
        )
    )

    approval_allowed = (
        not approval_assumed
        or
        policy.get(
            "allow_assumed_approval",
            False,
        )
    )

    authorized = (
        tool_allowed
        and
        target_allowed
        and
        not target_restricted
        and
        claimed_authority_allowed
        and
        approval_allowed
    )

    return {
        "authorized": authorized,
        "tool_allowed": tool_allowed,
        "target_allowed": target_allowed,
        "target_restricted": target_restricted,
        "claimed_authority_allowed": (
            claimed_authority_allowed
        ),
        "approval_allowed": (
            approval_allowed
        ),
        "reason": (
            "Authorization evaluated using "
            "loaded policy artifact."
        ),
    }


# ============================================================
# SECURITY ANALYSIS
# ============================================================

def analyze_case(
    case,
    load_result,
    authorization,
):

    policy = load_result.get(
        "policy"
    ) or {}

    integrity_changed = (
        load_result[
            "sha256"
        ]
        != TRUSTED_HASH
    )

    malicious_policy_loaded = (
        case[
            "poisoned"
        ]
        and
        load_result[
            "loaded"
        ]
    )

    restricted_target_authorized = (
        case[
            "poisoned"
        ]
        and
        case[
            "request"
        ][
            "target"
        ]
        == RESTRICTED_TARGET
        and
        authorization[
            "authorized"
        ]
    )

    privileged_tool_authorized = (
        case[
            "poisoned"
        ]
        and
        case[
            "request"
        ][
            "tool"
        ]
        == "delete_record"
        and
        authorization[
            "authorized"
        ]
    )

    authority_policy_expanded = (
        case[
            "poisoned"
        ]
        and
        policy.get(
            "allow_claimed_authority",
            False,
        )
    )

    approval_policy_expanded = (
        case[
            "poisoned"
        ]
        and
        policy.get(
            "allow_assumed_approval",
            False,
        )
    )

    tool_policy_expanded = (
        case[
            "poisoned"
        ]
        and
        "delete_record"
        in policy.get(
            "allowed_tools",
            [],
        )
    )

    target_policy_expanded = (
        case[
            "poisoned"
        ]
        and
        RESTRICTED_TARGET
        in policy.get(
            "allowed_targets",
            [],
        )
    )

    policy_expanded = (
        authority_policy_expanded
        or approval_policy_expanded
        or tool_policy_expanded
        or target_policy_expanded
    )

    runtime_authorization_compromised = (
        case[
            "poisoned"
        ]
        and
        authorization[
            "authorized"
        ]
        and
        (
            restricted_target_authorized
            or privileged_tool_authorized
            or authority_policy_expanded
            or approval_policy_expanded
        )
    )

    return {
        "integrity_changed": (
            integrity_changed
        ),

        "malicious_policy_loaded": (
            malicious_policy_loaded
        ),

        "restricted_target_authorized": (
            restricted_target_authorized
        ),

        "privileged_tool_authorized": (
            privileged_tool_authorized
        ),

        "authority_policy_expanded": (
            authority_policy_expanded
        ),

        "approval_policy_expanded": (
            approval_policy_expanded
        ),

        "tool_policy_expanded": (
            tool_policy_expanded
        ),

        "target_policy_expanded": (
            target_policy_expanded
        ),

        "policy_expanded": (
            policy_expanded
        ),

        "runtime_authorization_compromised": (
            runtime_authorization_compromised
        ),
    }


# ============================================================
# RATE
# ============================================================

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


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 25 Lab 4: "
        "Configuration / Policy Artifact Tampering ==="
    )

    loader = (
        VulnerablePolicyLoader()
    )

    poisoned_cases = 0

    malicious_policy_loads = 0

    integrity_changes = 0

    restricted_target_authorizations = 0

    privileged_tool_authorizations = 0

    policy_expansions = 0

    authority_expansions = 0

    approval_expansions = 0

    runtime_authorization_compromises = 0

    clean_cases = 0

    clean_safe_cases = 0


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
            case[
                "poisoned"
            ],
        )

        artifact = deepcopy(
            case[
                "artifact"
            ]
        )

        request = deepcopy(
            case[
                "request"
            ]
        )


        print(
            "\nPolicy Artifact:"
        )

        print(
            json.dumps(
                artifact,
                indent=2,
            )
        )


        # ====================================================
        # LOAD POLICY
        # ====================================================

        load_result = (
            loader.load(
                artifact
            )
        )


        print(
            "\nLoader Result:"
        )

        print(
            json.dumps(
                load_result,
                indent=2,
            )
        )


        # ====================================================
        # AUTHORIZATION
        # ====================================================

        authorization = (
            authorize_with_loaded_policy(
                load_result.get(
                    "policy"
                ),
                request,
            )
        )


        print(
            "\nRuntime Authorization Request:"
        )

        print(
            json.dumps(
                request,
                indent=2,
            )
        )

        print(
            "\nAuthorization Result:"
        )

        print(
            json.dumps(
                authorization,
                indent=2,
            )
        )


        # ====================================================
        # ANALYSIS
        # ====================================================

        analysis = analyze_case(
            case,
            load_result,
            authorization,
        )


        if case[
            "poisoned"
        ]:

            poisoned_cases += 1

            if analysis[
                "malicious_policy_loaded"
            ]:
                malicious_policy_loads += 1

            if analysis[
                "integrity_changed"
            ]:
                integrity_changes += 1

            if analysis[
                "restricted_target_authorized"
            ]:
                restricted_target_authorizations += 1

            if analysis[
                "privileged_tool_authorized"
            ]:
                privileged_tool_authorizations += 1

            if analysis[
                "policy_expanded"
            ]:
                policy_expansions += 1

            if analysis[
                "authority_policy_expanded"
            ]:
                authority_expansions += 1

            if analysis[
                "approval_policy_expanded"
            ]:
                approval_expansions += 1

            if analysis[
                "runtime_authorization_compromised"
            ]:
                runtime_authorization_compromises += 1


        else:

            clean_cases += 1

            clean_safe = (
                load_result[
                    "loaded"
                ]
                and
                not analysis[
                    "integrity_changed"
                ]
                and
                authorization[
                    "authorized"
                ]
                and
                request[
                    "tool"
                ]
                == "read_record"
                and
                request[
                    "target"
                ]
                == TRUSTED_TARGET
            )

            if clean_safe:
                clean_safe_cases += 1


        # ====================================================
        # CASE OUTPUT
        # ====================================================

        print(
            "\nSecurity Analysis:"
        )

        print(
            "Integrity Changed:",
            analysis[
                "integrity_changed"
            ],
        )

        print(
            "Malicious Policy Loaded:",
            analysis[
                "malicious_policy_loaded"
            ],
        )

        print(
            "Policy Expanded:",
            analysis[
                "policy_expanded"
            ],
        )

        print(
            "Restricted Target Authorized:",
            analysis[
                "restricted_target_authorized"
            ],
        )

        print(
            "Privileged Tool Authorized:",
            analysis[
                "privileged_tool_authorized"
            ],
        )

        print(
            "Authority Policy Expanded:",
            analysis[
                "authority_policy_expanded"
            ],
        )

        print(
            "Approval Policy Expanded:",
            analysis[
                "approval_policy_expanded"
            ],
        )

        print(
            "Runtime Authorization Compromised:",
            analysis[
                "runtime_authorization_compromised"
            ],
        )


    # ========================================================
    # SUMMARY
    # ========================================================

    print(
        "\n========================================"
    )

    print(
        "       POLICY TAMPERING SUMMARY"
    )

    print(
        "========================================"
    )

    print(
        "Poisoned policy cases:",
        poisoned_cases,
    )

    print(
        "Malicious policies loaded:",
        malicious_policy_loads,
    )

    print(
        "Malicious Policy Load Rate:",
        f"{rate(
            malicious_policy_loads,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Policy Integrity Change Rate:",
        f"{rate(
            integrity_changes,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Policy Expansion Rate:",
        f"{rate(
            policy_expansions,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Restricted Target Authorization Rate:",
        f"{rate(
            restricted_target_authorizations,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Privileged Tool Authorization Rate:",
        f"{rate(
            privileged_tool_authorizations,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Authority-Policy Expansion Rate:",
        f"{rate(
            authority_expansions,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Approval-Policy Expansion Rate:",
        f"{rate(
            approval_expansions,
            poisoned_cases
        ):.2f}%"
    )

    print(
        "Runtime Authorization Compromise Rate:",
        f"{rate(
            runtime_authorization_compromises,
            poisoned_cases
        ):.2f}%"
    )


    # ========================================================
    # CLEAN UTILITY
    # ========================================================

    print(
        "\n=== Clean Utility ==="
    )

    print(
        "Clean policy cases:",
        clean_cases,
    )

    print(
        "Clean safe policy executions:",
        clean_safe_cases,
    )

    print(
        "Clean Policy Utility Rate:",
        f"{rate(
            clean_safe_cases,
            clean_cases
        ):.2f}%"
    )


    # ========================================================
    # INTERPRETATION
    # ========================================================

    print(
        "\nSecurity Interpretation:"
    )

    print(
        "The vulnerable application trusts the loaded policy "
        "artifact as the source of authorization truth without "
        "first verifying that the artifact matches the trusted "
        "policy hash and expected security semantics."
    )

    print(
        "A compromised policy dependency can therefore "
        "redefine restricted targets, tool permissions, "
        "authority handling, or approval handling before "
        "runtime authorization is evaluated."
    )

    print(
        "If authorization policy itself is compromised, "
        "runtime policy checks may produce internally "
        "consistent but security-invalid decisions."
    )

    print(
        "\nCore Principle:"
    )

    print(
        "An AI component being available or functional "
        "does not establish that it is authentic, "
        "trusted, or safe to load."
    )


if __name__ == "__main__":
    main()