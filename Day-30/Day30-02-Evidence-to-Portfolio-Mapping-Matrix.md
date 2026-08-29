# Day 30 Lab 02 — Evidence-to-Portfolio Mapping Matrix



## Lab Objective



The objective of this lab is to map technical LLM red-team activities, evidence, security capabilities, business impact, and professional claims into a structured portfolio-ready format.



## Evidence Mapping Principle



A professional security claim should be supported by traceable evidence.



The mapping model used in this lab is:



TECHNICAL ACTIVITY



↓



TOOL OR METHOD



↓



EVIDENCE PRODUCED



↓



SECURITY CAPABILITY



↓



SECURITY OR BUSINESS IMPACT



↓



DEFENSIBLE PROFESSIONAL CLAIM



## Evidence-to-Portfolio Mapping Matrix



| # | Technical Activity | Tool / Method | Evidence Produced | Security Capability | Security / Business Impact | Professional Claim |

|---|---|---|---|---|---|---|

| 1 | Prompt Injection Testing | Manual adversarial prompting / PyRIT | Test cases, prompts, outputs, screenshots | Prompt Injection Assessment | Identifies instruction hierarchy and control weaknesses | Performed structured LLM prompt-injection security testing and documented exploitable control weaknesses |

| 2 | Jailbreak Assessment | PyRIT / Garak / manual testing | Probe outputs, failure cases, test logs | LLM Jailbreak Assessment | Identifies safety-control bypass conditions | Conducted adversarial jailbreak testing against LLM safety controls and analyzed model failure behavior |

| 3 | Automated LLM Security Testing | PyRIT / Garak | Automated scan results, logs, reports | Automated AI Security Testing | Improves repeatability and test coverage | Executed automated LLM adversarial security assessments using structured red-team tooling |

| 4 | RAG Security Assessment | Retrieval manipulation tests | Prompt/output evidence, poisoning scenarios | RAG Security Testing | Identifies retrieval poisoning and context manipulation risk | Assessed retrieval-augmented generation systems for prompt injection, poisoning, and context-trust weaknesses |

| 5 | Vector / Embedding Security | Adversarial retrieval analysis | Similarity results, test cases, findings | Vector Database Security | Identifies malicious retrieval and embedding abuse | Evaluated vector-search and embedding security risks affecting LLM retrieval integrity |

| 6 | Evaluator / Judge Security | Adversarial evaluator testing | Scoring inconsistencies, bypass evidence | LLM Evaluation Security | Identifies unreliable security scoring and model-judge manipulation | Tested LLM evaluators and model judges for adversarial manipulation and scoring weaknesses |

| 7 | Agent & Tool Security | Tool-call abuse scenarios | Tool execution evidence, logs, findings | Agentic AI Security | Identifies unauthorized actions and excessive agency | Assessed AI-agent tool use for unsafe actions, excessive permissions, and control-boundary failures |

| 8 | Persistent Memory Security | Memory poisoning / persistence tests | Memory changes, stored context evidence | AI Memory Security | Identifies long-term manipulation and data integrity risk | Evaluated persistent-memory features for poisoning, manipulation, and cross-session security risks |

| 9 | Multi-Agent Security | Agent-to-agent manipulation scenarios | Interaction logs, attack-flow evidence | Multi-Agent Security | Identifies trust-boundary weaknesses | Assessed multi-agent AI workflows for trust, delegation, and inter-agent manipulation risks |

| 10 | Multi-Stage Attack Chains | Chained attack scenarios | Attack sequence, evidence chain, impact analysis | AI Attack-Chain Analysis | Demonstrates realistic compound attack risk | Designed and analyzed multi-stage adversarial attack chains against LLM-enabled systems |

| 11 | AI Supply-Chain Security | Model / artifact trust assessment | Artifact findings, integrity observations | AI Supply-Chain Security | Identifies compromised dependency and model risk | Assessed AI model and artifact supply-chain risks with focus on provenance, integrity, and trust |

| 12 | Security Evaluation & Regression | Benchmarking / repeat testing | Baselines, comparison results, regression evidence | LLM Security Evaluation | Detects control degradation over time | Performed repeatable LLM security evaluations and regression testing to identify changes in security behavior |

| 13 | LLM Incident Response | Incident analysis methodology | Timeline, evidence map, findings | AI Incident Response | Supports containment and investigation | Applied incident-response and forensic analysis techniques to LLM security scenarios |

| 14 | Detection Engineering | Detection logic / telemetry analysis | Detection rules, indicators, event patterns | AI Detection Engineering | Improves visibility into malicious AI activity | Developed detection concepts and telemetry-based indicators for LLM security events |

| 15 | AI Threat Modeling | Threat modeling methodology | Assets, trust boundaries, threats, controls | AI Threat Modeling | Identifies threats before deployment | Performed structured threat modeling for LLM architectures, data flows, trust boundaries, and attack surfaces |

| 16 | AI Risk Assessment | Risk scoring and prioritization | Risk register, likelihood, impact, treatment | AI Risk Management | Supports risk-based security decisions | Conducted AI security risk assessments and prioritized findings using likelihood, impact, and remediation criteria |

| 17 | Security Architecture Review | Architecture and control assessment | Control mapping, architecture findings | AI Security Architecture | Reduces design-level security weaknesses | Reviewed LLM security architecture and mapped technical controls to identified threats and risks |

| 18 | Enterprise LLM Red-Team Assessment | End-to-end assessment methodology | Scope, findings, evidence, risk ratings, remediation | Enterprise AI Security Assessment | Provides decision-ready security assurance | Conducted end-to-end enterprise-style LLM red-team assessments from scoping through remediation and retesting |



## Portfolio Claim Standard



Every professional claim should satisfy the following conditions:



1\. The activity was actually performed.

2\. Evidence exists.

3\. The evidence can be reproduced or explained.

4\. The security relevance can be articulated.

5\. The business impact can be explained.

6\. The claim does not exaggerate the level of experience demonstrated.



## Strong vs Weak Claims



### Weak Claim



I know LLM red teaming.



### Strong Claim



Performed structured adversarial testing against LLM systems using manual and automated techniques, documented security weaknesses, analyzed impact, and developed remediation recommendations.



### Weak Claim



I know PyRIT.



### Strong Claim



Used PyRIT to execute structured adversarial LLM security tests, capture model responses, analyze failure conditions, and document reproducible evidence.



## Portfolio Use Cases



The evidence mapping from this lab can support:



\- GitHub project descriptions

\- CV technical project bullets

\- LinkedIn project descriptions

\- Interview responses

\- Consulting capability statements

\- Security assessment reports

\- Recruiter conversations

\- Professional portfolio case studies



## Lab 02 Conclusion



This lab converts technical learning into traceable professional evidence.



The key professional principle is:



CLAIM



↓



EVIDENCE



↓



REPRODUCIBILITY



↓



SECURITY IMPACT



↓



PROFESSIONAL CREDIBILITY



A security claim is strongest when another person can inspect the evidence, understand the methodology, reproduce the logic, and see how the technical result affects security or business risk.


