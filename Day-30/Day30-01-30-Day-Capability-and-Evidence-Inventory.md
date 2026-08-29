# Day 30 Lab 01 — 30-Day LLM Red-Team Capability & Evidence Inventory



## Lab Objective



The objective of this lab is to consolidate the technical, analytical, governance, detection, remediation, and communication capabilities developed throughout the 30-day LLM Red-Team learning program.



The inventory maps practical laboratory work to professional security competencies and identifies evidence that can be used to support portfolio, CV, LinkedIn, recruiter, interview, and consulting claims.



## Core Professional Principle



> Technical skill becomes professional capability when it can be explained, evidenced, reproduced, scoped responsibly, and translated into business risk and security decisions.



## Capability Model



The portfolio follows the professional evidence chain:



CAPABILITY

↓

TECHNIQUE

↓

EXECUTION

↓

EVIDENCE

↓

FINDING

↓

BUSINESS IMPACT

↓

REMEDIATION

↓

RETEST

↓

SECURITY DECISION



A professional claim should therefore be supported by reproducible evidence rather than knowledge alone.



# 1. LLM Security Foundations



## Capability



Understand the security properties, trust assumptions, attack surfaces, and failure modes associated with Large Language Model applications.



## Demonstrated Knowledge



\- LLM architecture fundamentals

\- Prompt engineering

\- Instruction hierarchy

\- Prompt injection

\- Jailbreaking

\- OWASP LLM security risks

\- AI application trust boundaries

\- Adversarial testing principles



## Professional Value



Provides the foundational knowledge required to reason about security weaknesses in LLM-enabled applications.



# 2. Prompt Injection & Jailbreak Assessment



## Capability



Design and execute controlled adversarial tests to determine whether an LLM application can be manipulated into violating intended instructions, policies, or security boundaries.



## Techniques



\- Direct prompt injection

\- Jailbreak testing

\- Instruction hierarchy manipulation

\- Role manipulation

\- Context manipulation

\- Adversarial prompt variation

\- Safety-control validation



## Evidence Types



\- Test cases

\- Prompts

\- Model responses

\- Pass/fail classifications

\- Findings

\- Risk ratings

\- Retest evidence



## Professional Outcome



Ability to distinguish successful adversarial manipulation from expected model behavior and document security-relevant failures.



# 3. Automated LLM Security Testing



## Capability



Use structured and automated approaches to execute repeatable adversarial evaluations.



## Tooling and Techniques



\- PyRIT

\- Garak

\- Python

\- Structured test harnesses

\- Automated evaluators

\- Security scoring

\- Benchmarking

\- Regression testing



## Professional Value



Moves LLM security testing from isolated manual prompts toward repeatable security assessment workflows.



# 4. RAG Security Assessment



## Capability



Assess Retrieval-Augmented Generation architectures for security weaknesses across ingestion, retrieval, context construction, authorization, and generation.



## Techniques



\- Indirect prompt injection

\- Retrieval poisoning

\- Knowledge-base poisoning

\- Context manipulation

\- Cross-context information exposure

\- Retrieval authorization testing

\- Source-trust analysis



## Security Impact



Potential impacts include:



\- Unauthorized information disclosure

\- Manipulated model responses

\- Poisoned enterprise knowledge

\- Cross-user or cross-business-unit leakage

\- Compromised downstream decisions



# 5. Embedding & Vector Database Security



## Capability



Analyze security risks associated with embeddings and vector-based retrieval infrastructure.



## Areas Assessed



\- Vector database access controls

\- Metadata security

\- Namespace isolation

\- Sensitive-data exposure

\- Retrieval authorization

\- Embedding-related confidentiality risks

\- Poisoned vector content



# 6. LLM Evaluator & Judge Security



## Capability



Assess the reliability and security of automated evaluators used to classify LLM behavior.



## Techniques



\- Evaluator engineering

\- Adversarial judge testing

\- Scoring validation

\- False-positive analysis

\- False-negative analysis

\- Judge manipulation testing

\- Regression evaluation



## Professional Value



Demonstrates that security testing must evaluate both the target model and the systems responsible for judging its behavior.



# 7. Agent & Tool Security



## Capability



Assess AI systems capable of interacting with tools, APIs, external services, or business workflows.



## Techniques



\- Tool-call manipulation

\- Excessive-agency testing

\- Authorization-boundary testing

\- Parameter manipulation

\- Goal manipulation

\- Target substitution

\- Privileged action testing

\- Approval-bypass testing



## Business Risk



Compromise of an agent may move the impact from unsafe text generation to unauthorized business actions.



# 8. Persistent Memory Security



## Capability



Assess whether malicious or untrusted information can persist across sessions and influence future model or agent behavior.



## Techniques



\- Memory poisoning

\- Cross-session manipulation

\- Persistent instruction testing

\- Memory trust-boundary analysis

\- Stored-context integrity testing



## Security Significance



Persistent memory can convert a single adversarial interaction into a long-lived security condition.



# 9. Multi-Agent Security



## Capability



Assess trust relationships and attack paths between multiple AI agents.



## Areas Assessed



\- Agent-to-agent trust

\- Delegation

\- Message integrity

\- Identity assumptions

\- Privilege propagation

\- Compromised-agent behavior

\- Trust-boundary violations



# 10. Multi-Stage AI Attack Chains



## Capability



Construct and analyze attack scenarios in which multiple weaknesses combine to create greater business impact.



## Example Attack Progression



PROMPT INJECTION

↓

CONTEXT MANIPULATION

↓

MEMORY POISONING

↓

AGENT GOAL MANIPULATION

↓

TOOL ABUSE

↓

AUTHORIZATION FAILURE

↓

BUSINESS IMPACT



## Professional Value



Demonstrates an ability to assess systemic risk rather than treating vulnerabilities as isolated technical findings.



# 11. AI Supply-Chain Security



## Capability



Assess risks associated with models, artifacts, dependencies, and other components entering an AI system.



## Areas Assessed



\- Model provenance

\- Artifact integrity

\- Dependency trust

\- Model trust

\- Supply-chain compromise

\- Integrity verification

\- Deployment controls



# 12. Security Evaluation, Benchmarking & Regression



## Capability



Measure whether security controls remain effective after changes to an AI system.



## Techniques



\- Security benchmarks

\- Baseline comparison

\- Regression testing

\- Pass-rate measurement

\- Control validation

\- Residual-risk assessment



## Professional Value



Supports evidence-based decisions about whether remediation actually corrected identified weaknesses.



# 13. LLM Incident Response & Forensics



## Capability



Analyze simulated AI security incidents and reconstruct attack activity from available telemetry.



## Techniques



\- Event reconstruction

\- Timeline analysis

\- Evidence correlation

\- Root-cause analysis

\- Detection-gap analysis

\- Recovery validation

\- Post-incident review



## Security Outcome



Connects offensive AI testing with defensive security operations.



# 14. Detection Engineering



## Capability



Translate observed LLM attack behavior into security monitoring and detection requirements.



## Techniques



\- Telemetry analysis

\- Detection-rule design

\- Coverage measurement

\- Detection-gap analysis

\- Early-detection assessment

\- Alert validation



## Professional Value



Demonstrates the ability to convert red-team findings into defensive improvements.



# 15. AI Threat Modeling



## Capability



Systematically identify assets, trust boundaries, threats, attack paths, and security controls within LLM-enabled architectures.



## Techniques



\- Architecture decomposition

\- Asset identification

\- Trust-boundary mapping

\- Attack-surface mapping

\- Threat hypothesis development

\- Attack trees

\- Attack-path prioritization

\- Control mapping



# 16. AI Risk Assessment



## Capability



Translate technical weaknesses into structured risk assessments.



## Risk Factors



\- Likelihood

\- Exploitability

\- Business impact

\- Data sensitivity

\- Privilege

\- Blast radius

\- Persistence

\- Detectability

\- Existing controls

\- Residual risk



# 17. Security Architecture



## Capability



Design security controls for hardened enterprise GenAI architectures.



## Control Areas



\- Identity

\- Authorization

\- Least privilege

\- Tool isolation

\- RAG security

\- Memory security

\- Data protection

\- DLP

\- Logging

\- Monitoring

\- Human approval

\- Deployment gates

\- Incident response



# 18. Enterprise LLM Red-Team Assessment



## Flagship Capability



Conduct an integrated, end-to-end assessment of a synthetic enterprise GenAI environment.



## Assessment Lifecycle



SCOPE

↓

ARCHITECTURE RECONNAISSANCE

↓

ATTACK-SURFACE MAPPING

↓

THREAT MODELING

↓

ADVERSARIAL TESTING

↓

ATTACK CHAINING

↓

EVIDENCE COLLECTION

↓

DETECTION ANALYSIS

↓

BUSINESS-IMPACT ASSESSMENT

↓

RISK RATING

↓

ROOT-CAUSE ANALYSIS

↓

REMEDIATION

↓

RETEST

↓

EXECUTIVE SECURITY DECISION



# 19. Measurable Portfolio Evidence



Examples of measurable security results demonstrated during the advanced labs include:



\- 100% telemetry coverage during incident reconstruction testing

\- 100% forensic reconstruction of the simulated Day 27 incident

\- Detection time reduced from 192 seconds to 8 seconds during post-incident improvement validation

\- 18 of 18 recovery actions successfully completed

\- 8 of 8 post-recovery security tests passed

\- 5 of 5 legitimate utility tests passed

\- 0% false-block rate during recovery validation

\- 33 adversarial retests executed during the Day 29 enterprise assessment

\- 33 of 33 adversarial retests passed

\- 8 of 8 material findings closed

\- 0 Critical residual risks

\- 0 High residual risks



# 20. Evidence Types Produced



The portfolio contains multiple forms of evidence, including:



\- Python assessment scripts

\- JSON evidence

\- Markdown security assessments

\- Threat models

\- Attack-surface inventories

\- Attack trees

\- Attack-chain analysis

\- Detection evidence

\- Incident timelines

\- Root-cause analysis

\- Findings registers

\- Remediation plans

\- Retest results

\- Risk assessments

\- Executive security decisions



# 21. Professional Skills Matrix



|Capability|Practical Evidence|Professional Application|

|---|---|---|

|Prompt Injection Testing|Adversarial test cases and findings|LLM application security testing|

|Jailbreak Testing|Safety-boundary assessments|AI safety validation|

|RAG Security|Indirect injection and poisoning assessments|Enterprise GenAI security|

|Memory Security|Persistent manipulation testing|Stateful AI security|

|Agent Security|Tool and authorization abuse assessments|Autonomous-agent security|

|Multi-Agent Security|Trust-boundary testing|Agentic AI architecture|

|AI Supply Chain|Artifact trust assessments|Secure AI deployment|

|Threat Modeling|Attack surfaces and attack trees|Security architecture|

|Risk Assessment|Formal risk ratings|Security governance|

|Detection Engineering|Detection rules and telemetry analysis|AI SOC integration|

|Incident Response|Forensic reconstruction|AI incident handling|

|Regression Testing|Adversarial retesting|Continuous AI assurance|

|Security Architecture|Hardened GenAI architecture|Enterprise AI security|

|Executive Reporting|Security decisions and business impact|Leadership communication|



# 22. Tools & Technical Environment



## Primary Tools



\- Python

\- PyRIT

\- Garak

\- Git

\- GitHub

\- PowerShell

\- Markdown

\- JSON



## Supporting Security Concepts



\- OWASP LLM security risks

\- Threat modeling

\- Adversarial testing

\- Security evaluation

\- Detection engineering

\- Incident response

\- Risk assessment

\- Security architecture



# 23. Evidence-to-Claim Standard



A professional portfolio claim should satisfy the following test:



1\. Can I explain the capability?

2\. Can I identify where I demonstrated it?

3\. Can I show evidence?

4\. Can I explain the security impact?

5\. Can I explain the remediation?

6\. Can I reproduce or describe the assessment methodology?

7\. Can I discuss limitations honestly?

8\. Can I explain the result to both technical and non-technical stakeholders?



If these conditions are satisfied, the capability can be presented as evidence-backed practical experience.



# 24. Lab 01 Conclusion



The 30-day portfolio demonstrates progression from foundational LLM security concepts to integrated enterprise AI security assessment.



The strongest professional capability demonstrated is not the execution of any single adversarial technique.



It is the ability to connect:



TECHNICAL TESTING

↓

SECURITY EVIDENCE

↓

ROOT CAUSE

↓

BUSINESS IMPACT

↓

RISK

↓

REMEDIATION

↓

RETESTING

↓

SECURITY DECISION



This evidence inventory will serve as the foundation for the final Day 30 professional portfolio and methodology.


