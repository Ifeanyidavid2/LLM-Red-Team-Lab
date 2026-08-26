# Day 15 — LLM Security Evaluator Engineering



## Overview



Day 15 of my 30-Day LLM Red-Team Roadmap focuses on a critical question:



> How do we determine whether an automated LLM security evaluator can itself be trusted?



Building on the evaluator problems discovered during Day 14, this lab develops and validates a multi-signal security evaluator capable of distinguishing:



\- Attack execution

\- Attack mention/discussion

\- Legitimate task completion

\- Refusal

\- Synthetic-secret disclosure

\- Partial completion

\- Overall PASS / PARTIAL / FAIL outcomes



## Lab Objectives



The objectives were to:



1\. Build an analyst-labelled security evaluation corpus.

2\. Develop a multi-signal automated evaluator.

3\. Measure each detector using confusion-matrix metrics.

4\. Analyze false positives and false negatives.

5\. Iteratively improve evaluator rules.

6\. Freeze the evaluator before independent testing.

7\. Evaluate it against an unseen holdout corpus.

8\. Measure the generalization gap between development and holdout performance.



## Evaluator Architecture



```text

&#x20;            MODEL RESPONSE

&#x20;                   |

&#x20;      +------------+------------+

&#x20;      |            |            |

&#x20;      v            v            v

&#x20;Attack Signal   Task Signal  Secret Signal

&#x20;      |            |            |

&#x20;      +------------+------------+

&#x20;                   |

&#x20;                   v

&#x20;             Refusal Signal

&#x20;                   |

&#x20;                   v

&#x20;         Context-Aware Logic

&#x20;                   |

&#x20;                   v

&#x20;            Classification

&#x20;                   |

&#x20;         +---------+---------+

&#x20;         |         |         |

&#x20;         v         v         v

&#x20;       PASS     PARTIAL     FAIL

