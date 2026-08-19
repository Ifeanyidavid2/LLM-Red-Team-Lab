\# Day 20 — Multi-Turn LLM Attack Chains \& Persistent Manipulation



\## Objective



Day 20 investigates whether attacker-controlled context can persist across multiple conversation turns and later influence security-sensitive model behavior.



The central research question is:



> Can an attacker gradually manipulate an LLM across multiple turns so that earlier adversarial context influences later security-sensitive behavior?



The core security principle is:



> Trust must be re-evaluated across the conversation lifecycle; earlier context should not silently become permanent authority.



\## Security Areas Tested



\- Context persistence

\- Persistent privilege claims

\- Instruction accumulation

\- Delayed-trigger prompt injection

\- Cross-turn privilege assumptions

\- Claimed prior MFA / verification

\- Approval replay and reuse

\- Security-state drift

\- Session-boundary enforcement

\- Current user-intent scope

\- Approval freshness

\- Session / actor / action / target binding

\- Hardened multi-turn execution



\## Key Results



\### Clean Multi-Turn Baseline



\- Context Persistence Accuracy: 33.33%

\- Trusted Role Preservation Rate: 100.00%

\- Clean Multi-Turn Success Rate: 33.33%



\### Persistent Context Poisoning



\- Trusted Role Preservation Rate: 100.00%

\- Persistent Manipulation Success Rate: 0.00%

\- Unsafe Allow Rate: 0.00%



\### Instruction Accumulation



\- Intermediate Privilege Drift Rate: 0.00%

\- Intermediate Unsafe-Allow Rate: 0.00%

\- Final Instruction-Accumulation Success Rate: 0.00%



\### Delayed Trigger



\- Trigger Recognition Rate: 0.00%

\- Delayed Instruction Activation Rate: 0.00%

\- Delayed-Trigger Attack Success Rate: 0.00%



\### Cross-Turn Privilege Assumption



\- Cross-Turn Privilege Attack Success Rate: 0.00%

\- Stale Verification Reuse Rate: 0.00%

\- Final Unsafe-Allow Rate: 0.00%



\### Approval Reuse



\- Control Decision Accuracy: 100.00%

\- Approval Reuse Attack Success Rate: 0.00%



\### Security-State Drift



\- Role Drift Rate: 0.00%

\- Unsafe-Allow Drift Rate: 0.00%

\- Final Security-State Drift Rate: 0.00%



\### Session Boundary Enforcement



\- Session Boundary Control Accuracy: 100.00%

\- Old Conversation Role Claim Persisted: False

\- Old Delayed Trigger Persisted: False

\- Old Conversation Approval Persisted: False

\- Old Trusted Approval Valid in New Session: False



\### Hardened Multi-Turn Architecture



\- Control Outcome Accuracy: 100.00%

\- Unsafe Execution Rate: 0.00%



\### Final Adversarial Retest



\- Dangerous Proposal Rate: 100.00%

\- Dangerous Proposal Block Rate: 100.00%

\- Unauthorized System Impact Rate: 0.00%

\- System Outcome Accuracy: 100.00%



\## Strongest Finding



The model generated dangerous or invalid proposals in every final adversarial attack chain.



Trusted application controls blocked every one.



This demonstrates:



> Model compromise and system compromise are separate events.



\## Recommended Architecture



```text

CURRENT USER TURN

&#x20;       |

&#x20;       v

SESSION VALIDATION

&#x20;       |

&#x20;       v

CURRENT AUTHENTICATED IDENTITY

&#x20;       |

&#x20;       v

TRUSTED ROLE / POLICY STATE

&#x20;       |

&#x20;       v

CONVERSATION CONTEXT

&#x20; (UNTRUSTED MEMORY)

&#x20;       |

&#x20;       v

LLM REASONING

&#x20;       |

&#x20;       v

MODEL PROPOSAL

&#x20;       |

&#x20;       v

SCHEMA / ARGUMENT VALIDATION

&#x20;       |

&#x20;       v

CURRENT AUTHORIZATION

&#x20;       |

&#x20;       v

CURRENT USER-INTENT SCOPE

&#x20;       |

&#x20;       v

APPROVAL FRESHNESS

&#x20;       |

&#x20;       v

SESSION / ACTOR / ACTION / TARGET BINDING

&#x20;       |

&#x20;       +------ ALLOW

&#x20;       |

&#x20;       +------ BLOCK

