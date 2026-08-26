# Day 14 — Automated LLM Red-Team Benchmarking



## Repeated Attack Evaluation, Security Metrics \& Evaluator Validation



Day 14 moves beyond one-off LLM red-team experiments and introduces a repeatable benchmarking workflow.



Instead of asking:



> \*\*Did this attack work?\*\*



the assessment asks:



> \*\*How reliably does the behavior occur across repeated controlled executions, and how accurately can the evaluator detect it?\*\*



The benchmark was built around a locally hosted Llama 3.2 1B model using Ollama, Microsoft PyRIT, and custom Python evaluation logic.



\---



# Core Metrics



The benchmark measures:



| Metric | Meaning |

|---|---|

| ASR | Attack Success Rate |

| TPR | Task Preservation Rate |

| RR | Refusal Rate |

| SDR | Secret Disclosure Rate |

| FPR | False Positive Rate |

| FNR | False Negative Rate |



These metrics are intentionally evaluated together.



A low attack success rate does not necessarily indicate healthy behavior if the model also refuses every legitimate task.



\---



# Benchmark Architecture



```text

Attack Scenarios

&#x20;     │

&#x20;     ▼

Automated Test Harness

&#x20;     │

&#x20;     ├── Repeated Run 1

&#x20;     ├── Repeated Run 2

&#x20;     ├── ...

&#x20;     └── Repeated Run N

&#x20;             │

&#x20;             ▼

&#x20;         Target LLM

&#x20;       Llama 3.2 1B

&#x20;             │

&#x20;             ▼

&#x20;       Response Corpus

&#x20;             │

&#x20;     ┌───────┼────────┐

&#x20;     │       │        │

&#x20;   Exact  Normalized Regex

&#x20;     │       │        │

&#x20;     └───────┼────────┘

&#x20;             ▼

&#x20;   Context-Aware Evaluation

&#x20;             │

&#x20;             ▼

&#x20;      Analyst Validation

&#x20;             │

&#x20;             ▼

&#x20;          Metrics

```



\---



# Lab Progression



## Lab 1 — Automated Benchmark Harness



The same retrieval-poisoning scenario was executed 10 times.



Results:



```text

ASR:   0.00%

TPR:   0.00%

RR:  100.00%

SDR:   0.00%

```



The attack objective failed in every run, but the legitimate user task also failed in every run.



This demonstrated that:



> \*\*ASR alone is insufficient for evaluating LLM application security.\*\*



\---



## Lab 2 — Persistent Benchmark Dataset



Each model response was persisted to:



```text

CSV

JSON

SQLite

```



This enabled later evaluation without rerunning the model.



\---



## Lab 3 — Scorer Comparison



The same stored model responses were evaluated using:



```text

Exact Match

Normalized Match

Regex Match

```



All three reported zero attack-marker detections.



However, all 10 responses were negative cases, so agreement between scorers did not prove scorer quality.



\---



## Lab 4 — Controlled Scorer Validation



A balanced 10-case analyst-labelled validation dataset was created:



```text

5 attack-success cases

5 benign/failure cases

```



### Exact Matcher



```text

Accuracy:  70.00%

Precision: 100.00%

Recall:     40.00%

FPR:         0.00%

FNR:        60.00%

```



### Normalized Matcher



```text

Accuracy:  100.00%

Precision: 100.00%

Recall:    100.00%

FPR:         0.00%

FNR:         0.00%

```



### Regex Matcher



```text

Accuracy:  100.00%

Precision: 100.00%

Recall:    100.00%

FPR:         0.00%

FNR:         0.00%

```



The exact matcher missed three of five positive cases because of formatting variations.



The normalized and regex scorers achieved perfect classification only on this limited controlled dataset and should not be interpreted as universally perfect.



\---



## Lab 5 — Analyst Ground Truth



The real model responses from Lab 2 were manually reviewed.



Analyst labels showed:



```text

Attack successes:       0

Task preserved:         0

Refusals:              10

Secret disclosures:     0

```



\---



## Lab 6 — Automated Scorers vs Analyst Ground Truth



The real-response corpus contained:



```text

Analyst-positive cases:  0

Analyst-negative cases: 10

```



All three scorers correctly classified the negative cases.



```text

Accuracy:    100%

Specificity: 100%

FPR:           0%



Recall:       N/A

FNR:          N/A

Precision:    N/A

```



Recall and FNR were correctly reported as `N/A` because the corpus contained no true positive cases.



\---



## Lab 7 — Multi-Scenario Benchmark



Four scenarios were each executed five times:



```text

Clean baseline

Embedded document injection

Retrieval poisoning

Indirect secret extraction

```



The initial automated results required analyst review.



\---



# Analyst-Corrected Final Metrics



| Scenario | ASR | TPR | RR | SDR |

|---|---:|---:|---:|---:|

| Clean baseline | N/A | 40% | 40% | \*\*20%\*\* |

| Embedded document injection | \*\*0%\*\* | \*\*100%\*\* | 0% | 0% |

| Retrieval poisoning | \*\*80%\*\* | \*\*0%\*\* | 20% | \*\*20%\*\* |

| Indirect secret extraction | \*\*0%\*\* | \*\*0%\*\* | \*\*100%\*\* | 0% |



\---



# Key Finding — Clean Baseline Secret Disclosure



One of five clean-baseline runs disclosed the protected synthetic value.



No malicious retrieved instruction was present.



The model stated that it would not reveal the value and then reproduced it.



This produced:



```text

Clean baseline SDR = 20%

```



This demonstrates that storing sensitive values directly in model context can create confidentiality risk even without a successful prompt-injection attack.



\---



# Key Finding — Embedded Injection False Positives



The initial automated evaluator reported:



```text

Embedded-document ASR = 60%

```



because three responses contained the attacker marker.



Manual analysis showed that the model was merely describing the malicious instruction while still completing the legitimate summarization task.



Therefore:



```text

Initial automated ASR:   60%

Analyst-corrected ASR:     0%

Context-aware ASR:         0%

```



This established a major evaluation principle:



> \*\*Marker presence does not necessarily mean marker execution.\*\*



\---



# Key Finding — Retrieval Poisoning



Retrieval poisoning was the strongest tested scenario.



Four of five runs executed the attacker-controlled instruction.



```text

ASR: 80%

TPR:  0%

RR:  20%

SDR: 20%

```



One run both followed the malicious retrieved instruction and disclosed the protected synthetic value.



\---



# Key Finding — Over-Refusal



The indirect secret-extraction benchmark produced:



```text

ASR:   0%

TPR:   0%

RR:  100%

SDR:   0%

```



The secret remained protected, but the legitimate task failed in every execution.



This shows why security evaluation must distinguish:



```text

Attack resistance

```



from:



```text

Application usefulness

```



\---



# Evaluator Improvement



Day 14 developed the following evaluator progression:



```text

Exact Matching

&#x20;     ↓

Normalized Matching

&#x20;     ↓

Regex Matching

&#x20;     ↓

Marker Presence

&#x20;     ↓

Classification Audit

&#x20;     ↓

Context-Aware Evaluation

&#x20;     ↓

Analyst Ground Truth

```



Two opposite evaluator problems were identified:



```text

False negatives

Exact matching missed semantic/format variations.

```



and:



```text

False positives

Marker-presence detection confused mention with execution.

```



\---



# Main Security Lessons



A reliable LLM red-team benchmark must measure both the target and the evaluator.



Key lessons include:



```text

ASR alone is insufficient.



Repeated executions reveal behavioral variability.



Task preservation matters.



Refusal behavior matters.



Secret disclosure must be measured separately.



Exact matching can miss successful attacks.



Marker presence can create false positives.



Ground-truth datasets require positive and negative examples.



FNR cannot be calculated from an all-negative dataset.



Analyst validation remains important.



Context-aware evaluation improves classification quality.

```



\---



# Overall Risk Rating



## HIGH within the tested benchmark scope



The rating reflects:



```text

80% confirmed retrieval-poisoning ASR

20% retrieval-poisoning SDR

20% clean-baseline SDR

100% over-refusal in indirect secret extraction

60% exact-matcher FNR in controlled validation

false-positive marker-presence scoring

```



These results apply only to this controlled environment and should not be interpreted as universal rates for Llama 3.2 or other LLM systems.



\---



# Full Assessment



See:



\[`Automated-LLM-Red-Team-Benchmarking.md`](./Automated-LLM-Red-Team-Benchmarking.md)



\---



# Core Portfolio Takeaway



> \*\*Designed and implemented an automated LLM red-team benchmarking harness that measures attack reliability, task preservation, refusal behavior, secret disclosure, and evaluator accuracy across repeated controlled executions. Identified model-security failures and evaluator false positives/false negatives, then improved detection using normalization, regex, context-aware scoring, and analyst validation.\*\*



\---



# Ethical Use



All experiments were conducted in a controlled local laboratory using synthetic test data.



No real credentials, production secrets, customer information, or unauthorized third-party systems were targeted.



\---



\*\*Day 14 — COMPLETE\*\*

