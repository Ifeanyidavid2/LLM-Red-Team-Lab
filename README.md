# LLM Red Team Lab

## 30-Day LLM & GenAI Security Research Portfolio

A hands-on cybersecurity portfolio documenting a structured 30-day progression through LLM red teaming, adversarial AI security testing, security evaluation, threat modeling, evidence engineering, risk assessment, detection, and professional security reporting.

This repository focuses on a central question:

> How can LLM and GenAI systems be assessed systematically, with findings supported by reproducible technical evidence rather than isolated adversarial prompts?

---

## Professional Focus

This laboratory explores security risks across the broader GenAI application stack rather than treating the language model as the only security boundary.

Core areas include:

* LLM red teaming

* Prompt injection and jailbreak assessment

* Instruction-hierarchy security

* PyRIT adversarial testing

* Garak security probing

* RAG security and retrieval poisoning

* Indirect prompt injection

* Persistent memory security

* Multi-agent trust analysis

* LLM evaluator security

* Adversarial judge hardening

* AI threat modeling

* MITRE ATLAS concepts

* OWASP LLM / GenAI security concepts

* AI security risk assessment

* Detection engineering

* Forensic reconstruction

* Security regression testing

* Evidence-driven reporting

---

## Security Assessment Philosophy

The portfolio follows an evidence-first methodology:

```text

DEFINE THE OBJECTIVE

&#x20;       ↓

UNDERSTAND THE ARCHITECTURE

&#x20;       ↓

MODEL THE THREAT

&#x20;       ↓

IDENTIFY THE ATTACK SURFACE

&#x20;       ↓

DESIGN ADVERSARIAL TESTS

&#x20;       ↓

EXECUTE IN A CONTROLLED LAB

&#x20;       ↓

COLLECT EVIDENCE

&#x20;       ↓

ANALYZE THE RESULT

&#x20;       ↓

ASSESS SECURITY IMPACT

&#x20;       ↓

RECOMMEND CONTROLS

&#x20;       ↓

RETEST

&#x20;       ↓

COMMUNICATE THE RISK

```

A failed adversarial prompt is not automatically proof that a system is secure.

A useful security conclusion requires understanding why the test succeeded or failed, what trust boundary was exercised, what control was involved, and what evidence supports the conclusion.

---

## 30-Day Learning Journey

The repository documents progressive development from foundational LLM security concepts toward enterprise-style GenAI security assessment.

| Phase                       | Focus                                                                                   |

| --------------------------- | --------------------------------------------------------------------------------------- |

| Foundation                  | LLM architecture, threat concepts, prompt security and adversarial thinking             |

| Adversarial Testing         | Prompt injection, jailbreaks, transformations and automated probing                     |

| PyRIT Engineering           | Structured attack orchestration, scoring, evidence persistence and multi-turn testing   |

| Security Evaluation         | Evaluator engineering, holdout testing, judge attacks and hardening                     |

| GenAI Architecture Security | RAG, memory, agents, multi-agent systems and trust boundaries                           |

| Advanced Assurance          | Supply-chain security, benchmarking, regression testing, detection and forensics        |

| Enterprise Security         | Threat modeling, risk assessment, security architecture and enterprise-style assessment |

| Professional Capstone       | Evidence inventory, portfolio mapping, verified claims and professional presentation    |

Each `Day-*` directory contains the technical material and supporting artifacts produced during that stage of the program.

---

## Featured Technical Capabilities

### Adversarial LLM Testing

Designed and documented controlled adversarial scenarios involving prompt manipulation, instruction conflicts, jailbreak techniques and related LLM security behavior.

### Microsoft PyRIT

Used PyRIT within a controlled laboratory environment to support structured adversarial testing, prompt transformations, response scoring, multi-turn workflows and evidence-oriented assessment.

### Garak

Used Garak for automated LLM security probing and generation of structured assessment output within the laboratory environment.

### LLM Security Evaluation

Developed security-evaluation workflows using labelled and holdout datasets to examine whether security behavior could be measured consistently.

### Adversarial Judge Hardening

Evaluated manipulation weaknesses affecting LLM-based judges and compared hardened approaches against adversarial scenarios.

### RAG Security

Assessed retrieval-augmented generation security risks including retrieval poisoning, untrusted context and knowledge-layer trust.

### AI Threat Modeling

Applied attack-surface enumeration, trust-boundary analysis, abuse-path reasoning and AI-focused threat-modeling concepts.

### Detection & Forensics

Extended LLM red teaming beyond vulnerability discovery by incorporating adversarial activity reconstruction, evidence correlation and detection-oriented analysis.

### AI Risk Assessment

Translated technical AI security observations into structured risk information including affected assets, consequences, ownership, treatment, controls and residual risk.

---

## Featured Capstone

### Day 30 — LLM Red-Team Professional Capstone

The final Day 30 package transforms the technical work into an evidence-backed professional security portfolio.

**Start here:**

\[View the Day 30 Professional Capstone](./Day-30/README.md)

The Day 30 portfolio includes:

1\. \[30-Day Capability and Evidence Inventory](./Day-30/Day30-01-30-Day-Capability-and-Evidence-Inventory.md)

2\. \[Evidence-to-Portfolio Mapping Matrix](./Day-30/Day30-02-Evidence-to-Portfolio-Mapping-Matrix.md)

3\. \[Portfolio Evidence Register](./Day-30/Day30-03-Portfolio-Evidence-Register.md)

4\. \[Professional Portfolio Presentation Layer](./Day-30/Day30-04-Professional-Portfolio-Presentation-Layer.md)

5\. \[LLM Red-Team Professional Capstone](./Day-30/Day30-05-LLM-Red-Team-Professional-Capstone.md)

---

## Verified Evidence Highlights

Day 30 established a formal evidence register separating artifacts that had completed review from artifacts that were present but not yet fully verified.

Representative VERIFIED capability evidence includes:

| Evidence ID  | Capability                                                 |

| ------------ | ---------------------------------------------------------- |

| DAY30-EV-005 | LLM Security Evaluator Engineering                         |

| DAY30-EV-007 | Adversarial LLM Judge Hardening                            |

| DAY30-EV-008 | RAG Retrieval-Poisoning Security Assessment                |

| DAY30-EV-011 | Formal AI Security Risk Assessment                         |

| DAY30-EV-014 | Enterprise-Style Prompt-Injection and Jailbreak Assessment |

| DAY30-EV-016 | AI Detection and Forensic Reconstruction                   |

The evidence register is available here:

\[View Portfolio Evidence Register](./Day-30/Day30-03-Portfolio-Evidence-Register.md)

---

## GenAI Attack Surface

The security methodology considers multiple interconnected trust boundaries:

```text

USER

&#x20; ↓

APPLICATION

&#x20; ↓

PROMPT / INSTRUCTION LAYER

&#x20; ↓

MODEL

&#x20; ↓

RAG / KNOWLEDGE

&#x20; ↓

MEMORY

&#x20; ↓

AGENTS

&#x20; ↓

TOOLS / APIs

&#x20; ↓

DOWNSTREAM SYSTEMS

&#x20; ↓

LOGGING / DETECTION

```

This architecture-oriented perspective allows testing to move beyond:

```text

Can I break the prompt?

```

toward:

```text

What trust boundary can be crossed?

&#x20;       ↓

What component can be influenced?

&#x20;       ↓

What security control failed?

&#x20;       ↓

What downstream impact could occur?

&#x20;       ↓

What evidence supports the finding?

```

---

## Tools & Technologies

| Category            | Tools / Technologies                                                       |

| ------------------- | -------------------------------------------------------------------------- |

| LLM Red Teaming     | Microsoft PyRIT, Garak                                                     |

| Local AI Testing    | Ollama, local LLM environments                                             |

| Programming         | Python, PowerShell                                                         |

| Data / Evidence     | JSON, JSONL, CSV, TXT, Markdown                                            |

| Security Evaluation | Labelled datasets, holdout testing, comparative evaluation                 |

| Threat Modeling     | Attack surfaces, trust boundaries, attack paths, STRIDE-oriented reasoning |

| AI Threat Knowledge | MITRE ATLAS concepts                                                       |

| GenAI Security      | OWASP LLM / GenAI security concepts                                        |

| Security Operations | Detection engineering, forensic reconstruction, telemetry analysis         |

| Risk                | Risk registers, control mapping, residual-risk analysis                    |

| Version Control     | Git, GitHub                                                                |

---

## Evidence-Driven Reporting

Technical evidence throughout the portfolio uses multiple formats depending on the assessment objective:

* Markdown security reports

* JSON structured evidence

* JSONL testing output

* CSV evaluation results

* TXT validation records

* HTML-generated assessment reports

* Python assessment scripts

The goal is reproducibility and traceability:

```text

SECURITY CLAIM

&#x20;     ↓

CAPABILITY

&#x20;     ↓

ASSESSMENT

&#x20;     ↓

ARTIFACT

&#x20;     ↓

EVIDENCE

```

---

## Professional Claim Standard

This portfolio intentionally distinguishes between learning, laboratory use and verified evidence.

**Used** — direct evidence supports hands-on laboratory interaction.

**Applied** — a framework or methodology was incorporated into an assessment.

**Studied** — the concept was covered during training but available evidence does not support a stronger operational claim.

**PRESENT** — an artifact exists but has not completed the defined evidence-review process.

**VERIFIED** — the artifact has been reviewed sufficiently to support the associated professional claim.

Laboratory exercises are not represented as unauthorized testing of production systems.

The governing principle is:

> **Evidence before claim.**

---

## What This Portfolio Demonstrates

This repository demonstrates progression from learning individual adversarial techniques toward developing a structured LLM and GenAI security-assessment methodology.

The portfolio emphasizes the ability to connect:

```text

ADVERSARIAL BEHAVIOR

&#x20;       ↓

SYSTEM ARCHITECTURE

&#x20;       ↓

TRUST BOUNDARY

&#x20;       ↓

CONTROL FAILURE

&#x20;       ↓

TECHNICAL EVIDENCE

&#x20;       ↓

SECURITY IMPACT

&#x20;       ↓

BUSINESS RISK

&#x20;       ↓

REMEDIATION

```

The intended outcome is not simply tool familiarity.

It is the development of repeatable security reasoning supported by technical evidence.

---

## Repository Navigation

Browse the `Day-*` folders for individual exercises and assessment artifacts.

For a high-level professional review, begin with:

**\[Day 30 — Professional Capstone](./Day-30/README.md)**

For the full integrated assessment methodology:

**\[LLM Red-Team Professional Capstone](./Day-30/Day30-05-LLM-Red-Team-Professional-Capstone.md)**

For evidence traceability:

**\[Portfolio Evidence Register](./Day-30/Day30-03-Portfolio-Evidence-Register.md)**

---

## Responsible Use

All adversarial testing documented in this repository is intended for authorized security research, controlled laboratory experimentation, defensive AI security learning and professional capability development.

Techniques documented here should only be applied to systems for which appropriate authorization has been obtained.

---

## Author

**Ifeanyi David Ezechukwukere**

Cybersecurity | LLM Red Teaming | GenAI Security

GitHub: \[Ifeanyidavid2](https://github.com/Ifeanyidavid2)

---

## Current Status

**30-Day LLM Red-Team Training Program — COMPLETE**

**Day 30 Professional Capstone — VALIDATED**

**Portfolio — READY FOR PROFESSIONAL PRESENTATION**

