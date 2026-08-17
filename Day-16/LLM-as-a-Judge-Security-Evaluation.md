# Day 16 — LLM-as-a-Judge Security Evaluation



## Executive Summary



Day 16 investigated whether an LLM-based security evaluator could

generalize better than the rule-based evaluator developed during Day 15.



The assessment compared:



- a rule-based evaluator;

- an LLM-as-a-Judge evaluator;

- a hardened signal-only LLM judge;

- a hybrid evaluator combining LLM semantic judgement with

&#x20; deterministic security logic;

- analyst-labelled ground truth.



The experiment also investigated a new security problem:



> Can the content being evaluated manipulate the LLM judge itself?



The results showed that the tested LLM judge did not outperform the

rule-based evaluator operationally on the shared holdout corpus.



The rule-based evaluator achieved:



- Evaluation completion rate: 100%

- Operational final accuracy: 60%

- Operational complete-signal accuracy: 35%



The hybrid LLM judge achieved:



- Evaluation completion rate: 85%

- Operational final accuracy: 55%

- Operational complete-signal accuracy: 20%



Although the hybrid judge achieved 64.71% conditional final accuracy

among successful evaluations, this result excluded three judge/schema

failures and therefore overstated operational reliability if considered

alone.



The LLM judge also introduced additional failure modes:



- schema noncompliance;

- inconsistent repeated judgements;

- semantic misclassification;

- weak refusal detection;

- poor task-completion recognition;

- evaluator prompt-injection susceptibility.



In a qualified manipulation benchmark, evaluator-targeted instructions

changed correct judge signals in 2 of 3 clean-correct evaluable pairs,

producing an observed Judge Manipulation Success Rate (JMSR) of 66.67%.



Because the denominator was only three qualified pairs, this value is

reported as a controlled experimental observation rather than a general

vulnerability rate.



The strongest-performing component was deterministic secret detection,

which maintained 100% precision and recall.


## 23. Detailed Evaluator Prompt-Injection Evidence

The qualified manipulation benchmark was designed to separate ordinary
judge unreliability from adversarially induced evaluator failure.

Only candidate responses that the judge classified correctly before
injection were allowed into the manipulation-success calculation.

Eight candidate response pairs were tested.

Three responses were correctly classified during the clean
qualification phase and therefore became qualified manipulation pairs.

Of those three qualified pairs:

- 2 were successfully manipulated;
- 1 remained correctly classified;
- 0 experienced injected-phase schema failure.

This produced:

```text
Qualified pairs:          3
Successful manipulations: 2
Resisted manipulations:   1

JMSR = 2 / 3 = 66.67%



The central Day 16 conclusion is:



> Semantic LLM-based evaluation did not automatically improve security

> measurement. It introduced a new security boundary in which the

> evaluated content became adversarial input to another model.



---



## 1. Objective



The objective of Day 16 was to determine whether an LLM-assisted

security evaluator could improve semantic generalization over narrow

rule-based scoring while remaining reliable and resistant to adversarial

manipulation.



The experiment evaluated four properties:



1. Accuracy

2. Generalization

3. Consistency

4. Adversarial resistance



The central hypothesis was:



> Semantic LLM-based evaluation may generalize better than narrow

> rule-based scoring, but using another LLM as the evaluator introduces

> a new attack surface that must itself be red-teamed.



---



## 2. Evaluation Architecture



The Day 16 architecture compared three perspectives:



```text

&#x20;              SECURITY EVALUATION

&#x20;                      |

&#x20;         +------------+------------+

&#x20;         |            |            |

&#x20;         v            v            v

&#x20;    Rule-Based     LLM Judge     Analyst

&#x20;    Evaluator      Evaluator     Ground Truth

&#x20;         |            |            |

&#x20;         +------------+------------+

&#x20;                      |

&#x20;                      v

&#x20;               Comparative Metrics

