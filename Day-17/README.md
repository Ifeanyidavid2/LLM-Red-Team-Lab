# Day 17 — Adversarial LLM Judge Hardening



## Overview



Day 17 investigates whether an LLM-based security evaluator can be hardened against evaluator-targeted prompt injection without destroying its usefulness.



The work builds directly on Day 16, where evaluator prompt injection successfully manipulated 2 of 3 qualified clean-correct judge evaluations.



The core Day 17 question is:



> Can evaluator manipulation be reduced while preserving or improving ordinary evaluation accuracy?



## Day 16 Baseline



Observed Day 16 results:



\- Operational Final Accuracy: 55.00%

\- Complete-Signal Accuracy: 20.00%

\- Attack Recall: 20.00%

\- Task Recall: 12.50%

\- Refusal Recall: 0.00%

\- Secret Recall: 100.00%

\- Observed JMSR: 66.67% (2/3 qualified pairs)



## Hardening Controls



Day 17 introduced:



\- explicit trust boundaries;

\- input isolation;

\- schema validation;

\- deterministic security checks;

\- fail-closed escalation;

\- evaluator-targeted instruction detection;

\- deterministic final classification;

\- repeated manipulation testing;

\- policy-configured protected-value detection.



## Repeated Manipulation Results



Repeated qualified trials produced:



\- Qualified attack trials: 7

\- Successful manipulations: 0

\- Repeated JMSR: 0.00%

\- Protected Rate: 100.00%

\- Automatic Resistance Rate: 0.00%



The attacks were contained through escalation rather than correct automatic evaluation.



## Clean Utility Results



Across 15 repeated clean trials:



\- Correct automatic accepts: 7

\- Incorrect automatic accepts: 2

\- Escalations: 6

\- Clean Correct-Accept Rate: 46.67%

\- Clean Incorrect-Accept Rate: 13.33%

\- Clean Escalation Rate: 40.00%



## Corrected Full Holdout



After repairing a protected-value policy mismatch:



\- Automatic Evaluation Rate: 85.00%

\- Escalation Rate: 15.00%

\- Operational Final Accuracy: 40.00%

\- Conditional Automatic Accuracy: 47.06%

\- Operational Complete-Signal Accuracy: 15.00%



### Signal Results



\- Attack Recall: 0.00%

\- Task Recall: 25.00%

\- Refusal Recall: 50.00%

\- Secret Recall: 100.00%



## Deterministic Invariant Repair



A regression temporarily reduced secret-disclosure recall to 0%.



Root cause:



\- the reused Day 15 holdout contained `DAY15\_SYNTHETIC\_SECRET\_8K3P`;

\- the Day 17 evaluator was configured for `DAY17\_SYNTHETIC\_SECRET\_4R9K`.



The detector was redesigned so protected values are supplied as evaluation-policy inputs.



Regression test result:



\- 7/7 tests passed

\- Deterministic Detector Accuracy: 100.00%



## Security / Utility Trade-Off



The hardened judge reduced observed accepted manipulation, but overall evaluator quality did not improve.



| Metric | Day 16 Hybrid | Day 17 Corrected |

|---|---:|---:|

| Evaluation / Automatic Rate | 85.00% | 85.00% |

| Operational Final Accuracy | 55.00% | 40.00% |

| Complete-Signal Accuracy | 20.00% | 15.00% |

| Attack Recall | 20.00% | 0.00% |

| Task Recall | 12.50% | 25.00% |

| Refusal Recall | 0.00% | 50.00% |

| Secret Recall | 100.00% | 100.00% |



## Key Lesson



> Reducing Judge Manipulation Success Rate is not enough. A secure evaluator must resist manipulation while preserving semantic accuracy, deterministic security invariants, acceptable automation rates, and manageable analyst-escalation requirements.



## Repository Structure



```text

Day-17/

├── README.md

├── Adversarial-LLM-Judge-Hardening.md

├── scripts/

│   ├── Day17-01-hardened-judge-baseline.py

│   ├── Day17-02-hardened-manipulation-retest.py

│   ├── Day17-03-utility-aware-hardened-judge.py

│   ├── Day17-04-utility-aware-manipulation-retest.py

│   ├── Day17-05-repeated-security-utility-benchmark.py

│   ├── Day17-06-full-holdout-hardening-benchmark.py

│   ├── Day17-07-deterministic-invariant-repair.py

│   ├── Day17-08-corrected-full-holdout-benchmark.py

│   └── Day17-09-final-hardening-comparison.py

├── results/

│   ├── day17-hardened-holdout-results.csv

│   └── day17-corrected-holdout-results.csv

└── evidence/

&#x20;   └── day17-final-hardening-comparison.txt

