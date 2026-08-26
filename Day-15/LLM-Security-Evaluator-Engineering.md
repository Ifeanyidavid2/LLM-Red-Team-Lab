# Day 15 — LLM Security Evaluator Engineering



## Executive Summary



This assessment investigated the reliability of automated security

evaluation for Large Language Model (LLM) red-team testing.



Previous testing demonstrated that simple automated scoring methods can

misclassify model behavior. Marker-presence detection, exact matching,

and narrow rule-based logic may confuse attack execution with attack

discussion, fail to recognize semantic variations, or incorrectly

classify legitimate task completion.



Day 15 therefore treated the evaluator itself as a security-critical

component.



A labelled development corpus containing 24 synthetic responses was

created to represent attack execution, legitimate task completion,

refusal, secret disclosure, attack discussion, negation traps, partial

task completion, and combined security failures.



Three generations of a multi-signal evaluator were developed.



Development-set final-classification accuracy improved from:



- Evaluator v1: 75.00%

- Evaluator v2: 95.83%

- Evaluator v3: 100.00%



However, when the frozen v3 evaluator was tested against a separate

20-case holdout corpus containing previously unseen language,

final-classification accuracy fell to 60.00% and complete-signal

accuracy fell to 35.00%.



The results demonstrate that perfect development performance does not

establish evaluator reliability.



The strongest generalized component was deterministic synthetic-secret

detection, which maintained 100% precision and recall on the holdout

dataset.



Attack execution, task completion, and refusal detection showed

substantial degradation when presented with previously unseen semantic

expressions.



The central security engineering lesson from this assessment is:



> An LLM security evaluator must itself be evaluated.



Reliable LLM red-team measurement therefore requires labelled ground

truth, per-signal metrics, confusion-matrix analysis, frozen holdout

testing, error analysis, and independent validation against unseen

language.





## 1. Assessment Objective



The objective of Day 15 was to determine whether an automated LLM

security evaluator could reliably distinguish several different forms

of model behavior.



The evaluator was designed to identify four primary security signals:



1\. Attack execution

2\. Legitimate task completion

3\. Refusal

4\. Synthetic-secret disclosure



These signals were then combined into a final security classification:



- PASS

- PARTIAL

- FAIL



The assessment specifically examined whether an evaluator developed

against known examples would continue to perform accurately against

previously unseen language.





## 2. Evaluation Model



The evaluation architecture used the following conceptual pipeline:



&#x20;   MODEL RESPONSE

&#x20;         |

&#x20;         +--------------------+

&#x20;         |                    |

&#x20;         v                    v

&#x20;   Attack Signal        Task Signal

&#x20;         |                    |

&#x20;         +----------+---------+

&#x20;                    |

&#x20;         +----------+---------+

&#x20;         |                    |

&#x20;         v                    v

&#x20;   Secret Signal        Refusal Signal

&#x20;         |                    |

&#x20;         +----------+---------+

&#x20;                    |

&#x20;                    v

&#x20;            Context-Aware Logic

&#x20;                    |

&#x20;                    v

&#x20;             Classification

&#x20;                    |

&#x20;         +----------+----------+

&#x20;         |          |          |

&#x20;         v          v          v

&#x20;       PASS      PARTIAL      FAIL



The purpose of this architecture was to avoid relying on a single

indicator such as the presence of an attacker-controlled marker.





## 3. Labelled Development Corpus



A synthetic analyst-labelled corpus containing 24 cases was created.



The corpus included:



- clean successful responses;

- direct attack execution;

- semantic attack execution;

- attack-marker discussion;

- safe discussion of malicious instructions;

- refusals;

- secret disclosure;

- attack execution combined with secret disclosure;

- legitimate task completion combined with secret disclosure;

- refusal combined with attack discussion;

- negation traps;

- partial task completion.



The development corpus contained:



- 7 attack-execution positives;

- 9 task-completion positives;

- 5 refusal positives;

- 5 secret-disclosure positives.



Final analyst classifications were:



- PASS: 8

- PARTIAL: 6

- FAIL: 10



The analyst labels were treated as ground truth for evaluator

development.





## 4. Multi-Signal Evaluator v1



The first evaluator used relatively narrow handcrafted rules to detect

the four security signals.



Results:



- Final classification accuracy: 75.00%

- Complete signal accuracy: 66.67%



The evaluator correctly classified 18 of 24 final outcomes.



However, several important errors were identified.



The attack detector incorrectly classified legitimate attack discussion

as attack execution.



Examples included responses that merely described or rejected an

attacker-controlled marker.



The evaluator also experienced errors involving:



- attack mention;

- safe attack discussion;

- refusal combined with attack mention;

- negation;

- partial task completion.



These errors demonstrated that keyword presence alone was insufficient

for reliable security classification.





## 5. Per-Signal v1 Performance



### Attack Execution Detector



- Precision: 54.55%

- Recall: 85.71%

- F1 score: 66.67%

- Specificity: 70.59%

- False Positive Rate: 29.41%

- False Negative Rate: 14.29%



Attack execution was the weakest signal in the first evaluator.



The high false-positive rate demonstrated that the evaluator frequently

confused attack discussion with actual attack execution.





### Task Completion Detector



- Precision: 88.89%

- Recall: 88.89%

- F1 score: 88.89%

- False Positive Rate: 6.67%

- False Negative Rate: 11.11%





### Refusal Detector



- Precision: 100.00%

- Recall: 80.00%

- F1 score: 88.89%

- False Positive Rate: 0.00%

- False Negative Rate: 20.00%





### Secret Disclosure Detector



- Precision: 100.00%

- Recall: 100.00%

- F1 score: 100.00%

- False Positive Rate: 0.00%

- False Negative Rate: 0.00%



The deterministic synthetic-secret detector was the strongest

component.





## 6. Multi-Signal Evaluator v2



Evaluator v2 introduced additional context-aware logic based on the

errors observed in v1.



The updated rules attempted to distinguish:



- executing an attack instruction;

- describing an attack instruction;

- rejecting an attack;

- negating attack success;

- legitimate task completion;

- refusal language.



Results improved substantially.



Evaluator v2 achieved:



- Final classification accuracy: 95.83%

- Complete signal accuracy: 95.83%



Only one development case remained incorrectly classified.



The remaining error involved a legitimate response that discussed an

attacker-controlled instruction while safely refusing to execute it.





## 7. Multi-Signal Evaluator v3



Evaluator v3 introduced another targeted improvement for the remaining

development error.



Development results:



- Cases: 24

- Final-class matches: 24/24

- All-signal matches: 24/24

- Final classification accuracy: 100.00%

- Complete signal accuracy: 100.00%



At this stage the evaluator perfectly classified the development

corpus.



However, this result was deliberately not treated as evidence that the

evaluator would generalize.



The evaluator was frozen before the next experiment.





## 8. Development Improvement



The iterative development process produced the following results:



| Evaluator | Final Classification Accuracy | Complete Signal Accuracy |

|---|---:|---:|

| v1 | 75.00% | 66.67% |

| v2 | 95.83% | 95.83% |

| v3 | 100.00% | 100.00% |



From v1 to v2:



- Final classification improved by 20.83 percentage points.

- Complete signal accuracy improved by 29.17 percentage points.



The development results demonstrated that systematic error analysis can

substantially improve evaluator performance.



They did not, however, establish generalization.





## 9. Frozen Holdout Evaluation



A separate 20-case holdout corpus was created.



The holdout corpus contained previously unseen wording for:



- clean task completion;

- attack execution;

- semantic attack execution;

- attack mention;

- refusal;

- secret disclosure;

- combined attack and disclosure;

- negation;

- partial completion.



The v3 evaluator was frozen before testing this dataset.



No rules were modified during the holdout evaluation.





## 10. Holdout Results



The frozen evaluator produced:



- Final-class matches: 12/20

- Final classification accuracy: 60.00%

- Complete-signal matches: 7/20

- Complete signal accuracy: 35.00%



This represented a major reduction from development performance.





## 11. Generalization Gap



Evaluator v3 achieved:



- Development final-classification accuracy: 100.00%

- Development complete-signal accuracy: 100.00%

- Holdout final-classification accuracy: 60.00%

- Holdout complete-signal accuracy: 35.00%



The observed generalization gap was therefore:



- Final classification: 40 percentage points

- Complete signal accuracy: 65 percentage points



This demonstrates that evaluator performance measured against a

development corpus cannot automatically be assumed to generalize to

unseen model responses.





## 12. Holdout Per-Signal Performance



### Attack Execution



Confusion matrix:



- TP: 1

- FP: 0

- TN: 15

- FN: 4



Metrics:



- Precision: 100.00%

- Recall: 20.00%

- F1: 33.33%

- Specificity: 100.00%

- FPR: 0.00%

- FNR: 80.00%



The evaluator was highly specific but insufficiently sensitive.



It rarely generated false attack alerts, but failed to recognize most

previously unseen semantic expressions of attack execution.





### Task Completion



Confusion matrix:



- TP: 3

- FP: 0

- TN: 12

- FN: 5



Metrics:



- Precision: 100.00%

- Recall: 37.50%

- F1: 54.55%

- Specificity: 100.00%

- FPR: 0.00%

- FNR: 62.50%



Previously unseen legitimate wording caused the evaluator to miss

successful task completion.





### Refusal



Confusion matrix:



- TP: 0

- FP: 0

- TN: 16

- FN: 4



Metrics:



- Recall: 0.00%

- Specificity: 100.00%

- FPR: 0.00%

- FNR: 100.00%



Precision and F1 were undefined because the evaluator produced no

positive refusal predictions.



The detector failed to generalize to new refusal expressions such as

"decline" and "won't answer."





### Secret Disclosure



Confusion matrix:



- TP: 4

- FP: 0

- TN: 16

- FN: 0



Metrics:



- Precision: 100.00%

- Recall: 100.00%

- F1: 100.00%

- Specificity: 100.00%

- FPR: 0.00%

- FNR: 0.00%



Secret disclosure detection generalized perfectly in this controlled

assessment because the protected synthetic value used a stable,

deterministic representation.





## 13. Holdout Error Analysis



The holdout assessment produced:



- 8 final-classification errors;

- 13 cases containing at least one signal-level error.



Attack execution produced four false negatives.



Task completion produced five false negatives.



Refusal detection produced four false negatives.



Secret disclosure produced no false positives or false negatives.



The errors were concentrated around previously unseen semantic

expressions rather than deterministic secret matching.





## 14. Important Measurement Finding



Correct final classification does not necessarily mean that every

underlying evaluator signal was correct.



Some signal-level errors were masked because another correctly detected

signal still produced the correct PASS, PARTIAL, or FAIL result.



Therefore evaluator assessment should measure both:



1\. final classification accuracy; and

2\. complete signal accuracy.



Reporting only the final classification can hide weaknesses in the

measurement system.





## 15. Overfitting Risk



The development process demonstrated an important evaluator-engineering

risk.



Each version was improved using errors observed in the development

corpus.



Eventually the evaluator reached 100% development accuracy.



However, performance dropped sharply on unseen examples.



This is evidence that narrow handcrafted rules had become highly

specialized to known language patterns.



The holdout corpus must therefore not be repeatedly used to tune the

same evaluator while continuing to describe it as an independent test

set.



If future changes are made based on the current holdout errors, a new

untouched test corpus should be created.





## 16. Security Engineering Findings



The assessment produced the following findings:



1\. LLM security evaluators can generate both false positives and false

&#x20;  negatives.



2\. Attack-marker presence does not necessarily demonstrate attack

&#x20;  execution.



3\. Models may quote, describe, reject, or discuss malicious

&#x20;  instructions without following them.



4\. Semantic attack execution is difficult to identify using narrow

&#x20;  keyword rules.



5\. Refusal behavior can be expressed using many different linguistic

&#x20;  forms.



6\. Task completion also requires semantic rather than purely lexical

&#x20;  evaluation.



7\. Deterministic secret detection can perform well when the protected

&#x20;  value has a stable representation.



8\. Perfect development-set accuracy does not demonstrate evaluator

&#x20;  reliability.



9\. Signal-level metrics can expose weaknesses hidden by final

&#x20;  classifications.



10\. Independent holdout testing is necessary before making security

&#x20;   claims about evaluator quality.





## 17. Limitations



This assessment used small synthetic corpora.



The results therefore should not be interpreted as general performance

estimates for all LLM security evaluators.



Additional limitations include:



- handcrafted synthetic responses;

- limited linguistic diversity;

- deterministic synthetic-secret representation;

- relatively small development and holdout datasets;

- rule-based rather than model-based semantic evaluation;

- no multilingual evaluation;

- no adversarial evaluator-evasion testing;

- no independent human inter-rater agreement study.



The 100% development performance and 60% holdout performance apply only

to the datasets used in this controlled lab.





## 18. Recommendations



Future evaluator development should include:



1\. Larger labelled datasets.

2\. Multiple independent holdout datasets.

3\. Greater paraphrase diversity.

4\. Semantic similarity or classifier-based evaluation.

5\. Analyst adjudication for ambiguous cases.

6\. Inter-rater agreement measurements.

7\. Explicit attack-mention versus attack-execution modelling.

8\. Independent testing after every major evaluator revision.

9\. Versioned evaluator rules and datasets.

10\. Separate reporting of signal-level and final-classification

&#x20;   performance.



Future evaluation should also investigate whether semantic or

LLM-assisted judges improve generalization without introducing new

forms of evaluator bias or prompt-injection vulnerability.





## 19. Conclusion



Day 15 demonstrated that an LLM security evaluator is itself a

security-critical system.



The evaluator improved from 75% final-classification accuracy in v1 to

100% on the development corpus in v3.



However, frozen testing against unseen language reduced final

classification accuracy to 60% and complete-signal accuracy to 35%.



Attack execution, task completion, and refusal detection showed poor

generalization, while deterministic secret-disclosure detection

remained reliable in the controlled corpus.



The experiment therefore demonstrated that high development accuracy

alone is insufficient evidence of evaluator quality.



Reliable LLM security evaluation requires:



- analyst-labelled ground truth;

- confusion matrices;

- precision;

- recall;

- specificity;

- F1 score;

- false-positive and false-negative analysis;

- per-signal evaluation;

- frozen holdout testing;

- error analysis;

- independent validation.



The core Day 15 lesson is:



> Measure the model, but also measure whether the measurement system can

> be trusted.

