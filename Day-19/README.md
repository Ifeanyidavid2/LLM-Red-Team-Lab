\# Day 19 — RAG Security \& Retrieval Poisoning



\## Objective



Day 19 investigates whether malicious or untrusted retrieved documents can manipulate an LLM, distort answers, leak protected information, or override trusted application policy.



The core principle is:



> Retrieved content is evidence, not authority.



\## Security Areas Tested



\- Retrieval poisoning

\- Indirect prompt injection through retrieved documents

\- Retrieval authorization

\- Restricted-document exposure

\- Protected information leakage

\- Source trust and provenance

\- Minimum relevance thresholds

\- Context isolation

\- Suspicious instruction filtering

\- Semantic outcome validation

\- Trusted-source conflict resolution

\- Security vs utility trade-offs



\## Key Results



\### Relevance-Only Retrieval



\- Poisoned Context Exposure Rate: 100.00%

\- Rank-1 Poison Rate: 40.00%

\- Expected Trusted Retrieval Rate: 100.00%



\### Indirect RAG Prompt Injection



\- Semantic Attack Outcome Rate: 50.00%

\- Trusted-Policy Answer Rate: 50.00%



\### Retrieval Authorization



\- Raw Unauthorized Retrieval Exposure Rate: 100.00%

\- Post-Authorization Exposure Rate: 0.00%

\- Retrieval Authorization Block Rate: 100.00%

\- Legitimate Retrieval Success Rate: 100.00%



\### Protected Information Leakage



\- Unsafe Unauthorized Leakage Rate: 100.00%

\- Secure Unauthorized Leakage Rate: 0.00%



\### Trust / Provenance-Aware Retrieval



\- Poisoned Context Exposure Rate: 40.00%

\- Rank-1 Poison Rate: 0.00%

\- Expected Trusted Retrieval Rate: 100.00%

\- Exposure Reduction: 60 percentage points



\### Context Isolation



\- Suspicious-Instruction Precision: 100.00%

\- Suspicious-Instruction Recall: 100.00%

\- False Positive Rate: 0.00%

\- Factual Content Preservation Rate: 100.00%



\### Trusted-Source Conflict Resolution



\- Trusted-Policy Answer Rate: 100.00%

\- Semantic Attack-Outcome Rate: 0.00%



\## Key Finding



The strongest final result came from enforcing source authority outside the model.



When trusted internal policy existed, lower-authority conflicting sources were excluded before generation.



This reduced the tested semantic attack outcome from 50% to 0%.



\## Recommended Architecture



```text

USER QUERY

&#x20;   |

&#x20;   v

IDENTITY / SESSION CONTEXT

&#x20;   |

&#x20;   v

RETRIEVAL

&#x20;   |

&#x20;   v

MINIMUM RELEVANCE THRESHOLD

&#x20;   |

&#x20;   v

DOCUMENT AUTHORIZATION

&#x20;   |

&#x20;   v

TRUST / PROVENANCE RANKING

&#x20;   |

&#x20;   v

SOURCE-AUTHORITY RESOLUTION

&#x20;   |

&#x20;   v

CONTEXT ISOLATION / QUARANTINE

&#x20;   |

&#x20;   v

SELECTED EVIDENCE

&#x20;   |

&#x20;   v

LLM GENERATION

&#x20;   |

&#x20;   v

SEMANTIC OUTPUT VALIDATION

&#x20;   |

&#x20;   +------ ANSWER

&#x20;   |

&#x20;   +------ ESCALATE

