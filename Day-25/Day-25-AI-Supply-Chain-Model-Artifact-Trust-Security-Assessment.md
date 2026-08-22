\# Day 25 — AI Supply-Chain, Model \& Artifact Trust Security Assessment



\## LLM Red Team Lab — AI Supply-Chain Security Research



\*\*Assessment Type:\*\* AI / LLM Supply-Chain Security Assessment  

\*\*Focus Area:\*\* Model, Prompt, Dataset, Dependency, Tool, Configuration \& Artifact Trust  

\*\*Testing Methodology:\*\* Synthetic Adversarial Security Testing  

\*\*Environment:\*\* Python / PyRIT-Lab  

\*\*Day:\*\* 25  

\*\*Status:\*\* Completed



\---



\# Executive Summary



Modern AI applications depend on significantly more than the large language model itself.



An AI-enabled application may load and trust:



\- Models

\- Model adapters

\- Prompt templates

\- System instructions

\- Configuration files

\- Security policies

\- Datasets

\- Knowledge bases

\- Retrieval artifacts

\- Tool packages

\- Python packages

\- Third-party dependencies

\- Model metadata

\- Build metadata

\- Software Bill of Materials (SBOM) references

\- Provenance attestations

\- Integrity hashes

\- Runtime configuration



Every one of these components represents a potential supply-chain trust boundary.



Day 25 investigated what happens when an attacker compromises an AI component \*\*before the application starts\*\* and whether a component that appears legitimate, loads correctly, and remains functional can nevertheless introduce malicious behavior into the AI runtime.



The central research question was:



> \*\*Can a compromised model, prompt template, adapter, dependency, dataset, tool package, configuration, or AI artifact cross the supply-chain trust boundary and cause runtime compromise?\*\*



The assessment constructed a synthetic AI supply-chain environment and systematically evaluated multiple compromise scenarios, including:



\- Prompt-template poisoning

\- Security-policy tampering

\- Dataset poisoning

\- Model and adapter substitution

\- Tool-package compromise

\- Dependency confusion

\- Artifact substitution

\- Metadata spoofing

\- Provenance spoofing

\- Weak integrity verification

\- Transitive dependency compromise

\- Pre-runtime-to-runtime propagation



The vulnerable architecture demonstrated that structurally valid and functionally usable artifacts could still be malicious.



The vulnerable end-to-end architecture ultimately produced:



| Metric | Vulnerable Result |

|---|---:|

| Artifact Trust Bypass Rate | 100.00% |

| Malicious Artifact Load Rate | 100.00% |

| Supply-Chain Propagation Rate | 100.00% |

| Runtime Compromise Rate | 100.00% |

| Unauthorized System Impact Rate | 100.00% |

| Attack Chain Completion Rate | 100.00% |

| Legitimate Workflow Completion Rate | 100.00% |



A hardened architecture was then implemented using independently enforced controls for:



\- Trusted artifact source

\- Artifact identity

\- Version binding

\- Publisher identity

\- Provenance verification

\- Full artifact integrity

\- Capability policy

\- Runtime action binding

\- Runtime target binding

\- Runtime authorization



The hardened architecture achieved:



| Metric | Hardened Result |

|---|---:|

| Supply-Chain Containment Rate | 100.00% |

| Malicious Artifact Load Rate | 0.00% |

| Unauthorized System Impact Rate | 0.00% |

| Attack Chain Completion Rate | 0.00% |

| Legitimate Workflow Completion Rate | 100.00% |



A subsequent adversarial retest deliberately assumed that individual earlier security controls had already failed.



Even under these conditions:



\- Defense-in-Depth Containment Rate remained \*\*100.00%\*\*

\- Unsafe Runtime Execution Rate remained \*\*0.00%\*\*

\- Unauthorized System Impact Rate remained \*\*0.00%\*\*

\- Attack Chain Completion Rate remained \*\*0.00%\*\*



The assessment therefore demonstrates that AI supply-chain security cannot depend on successful loading, expected filenames, package versions, metadata claims, hash fields, or model functionality.



The core security principle established by Day 25 is:



> \*\*An AI component being available or functional does not establish that it is authentic, trusted, or safe to load.\*\*



\---



\# 1. Introduction



AI systems increasingly depend on complex chains of external and internal artifacts.



A traditional software application may depend on libraries and configuration files.



An AI application can additionally depend on:



\- Foundation models

\- Fine-tuned models

\- LoRA adapters

\- Prompt libraries

\- System prompts

\- Vector databases

\- Embedding models

\- Retrieval datasets

\- Agent definitions

\- MCP servers

\- Tool packages

\- Safety policies

\- Model configuration

\- Evaluation artifacts



This expands the traditional software supply chain into an \*\*AI supply chain\*\*.



An application may therefore contain secure runtime authorization logic while still becoming compromised because an attacker modified an artifact that the application trusted before runtime.



The Day 25 assessment moves outward from the autonomous runtime security problem examined previously and evaluates the security of the components entering that runtime.



The primary distinction is:



```text

Day 24:

Can compromise propagate through an already-running autonomous system?



Day 25:

Can compromise enter the autonomous system through artifacts trusted before runtime?

```



This creates a broader trust question.



A component can be:



\- Available

\- Loadable

\- Compatible

\- Functional

\- Correctly named

\- Correctly versioned

\- Metadata-compatible



while still being malicious.



\---



\# 2. Research Question



The primary Day 25 research question is:



> \*\*What happens if the model, prompt template, adapter, dependency, dataset, tool package, configuration, or AI artifact is compromised before the application even starts?\*\*



A secondary question is:



> \*\*Can independently enforced supply-chain and runtime controls contain a malicious artifact even when one or more earlier trust controls have already failed?\*\*



\---



\# 3. Core Security Principle



The central principle guiding the assessment is:



> \*\*An AI component being available or functional does not establish that it is authentic, trusted, or safe to load.\*\*



This principle separates five concepts that are frequently treated as equivalent:



```text

Artifact Availability

&#x20;       !=

Artifact Authenticity

&#x20;       !=

Artifact Integrity

&#x20;       !=

Artifact Authorization

&#x20;       !=

Runtime Execution Authority

```



A secure AI architecture must establish each property independently.



\---



\# 4. Assessment Objectives



The Day 25 assessment was designed to:



1\. Build a controlled synthetic AI supply-chain environment.

2\. Define trusted artifact identities and expected dependencies.

3\. Establish a trusted artifact baseline.

4\. Evaluate prompt-template poisoning.

5\. Evaluate configuration and policy tampering.

6\. Evaluate dataset and knowledge poisoning.

7\. Evaluate model and adapter substitution.

8\. Evaluate tool-package and dependency compromise.

9\. Evaluate dependency confusion.

10\. Evaluate artifact substitution.

11\. Evaluate metadata spoofing.

12\. Evaluate provenance spoofing.

13\. Evaluate weak hash and integrity verification.

14\. Evaluate transitive dependency compromise.

15\. Measure pre-runtime compromise propagation into runtime.

16\. Construct a vulnerable end-to-end supply-chain attack chain.

17\. Implement hardened supply-chain trust controls.

18\. Perform adversarial defense-in-depth retesting.

19\. Compare vulnerable and hardened architectures.

20\. Produce a portfolio-ready AI supply-chain security assessment.



\---



\# 5. Threat Model



\## 5.1 Attacker Objective



The synthetic attacker attempts to introduce a malicious AI or software artifact into the trusted application supply chain.



The attacker's ultimate objective is to cause the runtime to perform behavior that would not have been authorized under the legitimate application state.



Examples include:



\- Selecting a restricted target

\- Performing a privileged action

\- Changing authorization behavior

\- Introducing fake approval

\- Expanding application capabilities

\- Modifying security policy

\- Causing unauthorized system impact



\---



\## 5.2 Potential Compromise Points



The attack surface includes:



```text

&#x20;                AI APPLICATION SUPPLY CHAIN



External / Public Sources

&#x20;         |

&#x20;         v

+--------------------------+

| Artifact Resolution      |

+--------------------------+

&#x20;         |

&#x20;         v

+--------------------------+

| Model / Adapter          |

+--------------------------+

&#x20;         |

&#x20;         +-------------------+

&#x20;         |                   |

&#x20;         v                   v

+------------------+   +------------------+

| Prompt Template  |   | Dataset / KB     |

+------------------+   +------------------+

&#x20;         |                   |

&#x20;         +---------+---------+

&#x20;                   |

&#x20;                   v

&#x20;         +------------------+

&#x20;         | Security Policy  |

&#x20;         +------------------+

&#x20;                   |

&#x20;                   v

&#x20;         +------------------+

&#x20;         | Tool Package     |

&#x20;         +------------------+

&#x20;                   |

&#x20;                   v

&#x20;         +------------------+

&#x20;         | Dependencies     |

&#x20;         +------------------+

&#x20;                   |

&#x20;                   v

&#x20;         +------------------+

&#x20;         | AI Runtime       |

&#x20;         +------------------+

&#x20;                   |

&#x20;                   v

&#x20;         +------------------+

&#x20;         | Protected State  |

&#x20;         +------------------+

```



Each transition represents a security boundary.



\---



\# 6. Trusted Artifact Model



The baseline environment defined five primary artifact classes.



| Artifact | Example ID | Security Role |

|---|---|---|

| Model | MODEL-2501 | Performs project analysis |

| Prompt Template | PROMPT-2501 | Provides trusted instructions |

| Policy | POLICY-2501 | Restricts runtime capabilities |

| Dataset | DATA-2501 | Provides reference information |

| Tool Package | TOOL-2501 | Exposes approved record operations |



Trusted publishers included:



\- `trusted\_ai\_team`

\- `trusted\_security\_team`

\- `trusted\_data\_team`



Each artifact contained security-relevant properties such as:



```text

artifact\_id

name

version

publisher

artifact\_type

purpose

capabilities

dependencies

sha256

```



\---



\# 7. Artifact Trust Requirements



The baseline established that artifact trust is broader than successful loading.



A trusted artifact must satisfy multiple independent conditions.



\## 7.1 Identity



The artifact must be the exact expected artifact.



\## 7.2 Version



The artifact must match an explicitly authorized version.



\## 7.3 Publisher



The publisher must be authenticated rather than merely named.



\## 7.4 Type



The artifact must match the expected artifact class.



\## 7.5 Purpose



The artifact's role must correspond to its authorized application purpose.



\## 7.6 Capability



The artifact must not introduce capabilities beyond its authorized scope.



\## 7.7 Dependencies



Dependencies must be explicitly declared and independently trusted.



\## 7.8 Integrity



Security-relevant artifact content must match trusted integrity evidence.



\## 7.9 Provenance



The artifact must have verifiable origin and build history.



\---



\# 8. Lab Methodology



The assessment was divided into sixteen labs.



| Lab | Assessment Area |

|---|---|

| Lab 1 | Synthetic AI Supply-Chain Environment |

| Lab 2 | Trusted Artifact \& Model Baseline |

| Lab 3 | Prompt-Template Supply-Chain Poisoning |

| Lab 4 | Configuration / Policy Artifact Tampering |

| Lab 5 | Dataset / Knowledge Artifact Poisoning |

| Lab 6 | Model / Adapter Substitution |

| Lab 7 | Tool Package / Dependency Compromise |

| Lab 8 | Dependency Confusion \& Artifact Substitution |

| Lab 9 | Artifact Metadata \& Provenance Spoofing |

| Lab 10 | Hash / Integrity Verification Bypass |

| Lab 11 | Transitive Dependency Compromise |

| Lab 12 | Compromised Artifact → Runtime Propagation |

| Lab 13 | Vulnerable End-to-End Supply-Chain Attack Chain |

| Lab 14 | AI Supply-Chain Trust \& Containment Controls |

| Lab 15 | Hardened AI Supply-Chain Adversarial Retest |

| Lab 16 | Final Comparative Analysis |



\---



\# 9. Lab 1 — Synthetic AI Supply-Chain Environment



\## Objective



Create a controlled AI artifact ecosystem for testing supply-chain trust.



\## Trusted Components



The environment contained:



\- Model artifact

\- Prompt-template artifact

\- Policy artifact

\- Dataset artifact

\- Tool-package artifact



All artifacts were initially associated with trusted publishers and known SHA-256 digests.



\## Baseline Result



The environment confirmed:



\- All artifact identities valid

\- All integrity checks valid

\- All trusted artifacts loaded

\- Legitimate workflow completed



The baseline workflow performed:



```json

{

&#x20; "action": "read\_record",

&#x20; "target": "R-2502"

}

```



\## Security Lesson



Before adversarial testing begins, the trusted system state must be explicitly defined.



Without a known-good baseline, compromise cannot be measured reliably.



\---



\# 10. Lab 2 — Trusted Artifact \& Model Baseline



\## Objective



Expand the baseline from simple file integrity into a broader artifact trust model.



Each artifact was evaluated for:



\- Identity

\- Version

\- Publisher

\- Type

\- Purpose

\- Capabilities

\- Dependency declarations

\- Dependency availability

\- Integrity



\## Result



```text

Registered Artifacts: 5

Trusted Artifacts: 5

Artifact Trust Validation Rate: 100.00%

Model Direct Trust Valid: True

Model Dependency Trust Valid: True

Model Fully Trusted: True

```



\## Security Finding



A model may itself be authentic while depending on a malicious:



\- Prompt template

\- Dataset

\- Policy

\- Adapter

\- Library

\- Tool package



Model trust therefore requires dependency trust.



\---



\# 11. Lab 3 — Prompt-Template Supply-Chain Poisoning



\## Objective



Determine whether a structurally valid prompt template could be modified while retaining expected identifying metadata.



Attack cases introduced instructions that attempted to:



\- Delete restricted records

\- Substitute restricted targets

\- Introduce fake approval

\- Introduce false security authority



\## Results



```text

Malicious Artifact Load Rate: 100.00%

Artifact Integrity Change Rate: 100.00%

Runtime Compromise Rate: 100.00%

Privilege Proposal Rate: 25.00%

Restricted Target Selection Rate: 50.00%

Approval-Assumption Rate: 25.00%

Authority-Assumption Rate: 25.00%



Clean Prompt Artifact Utility Rate: 100.00%

```



\## Security Finding



The vulnerable loader accepted prompt-template artifacts because they were structurally valid and usable even when the content no longer matched trusted integrity.



\## Security Impact



A poisoned prompt dependency can modify runtime behavior \*\*before the user provides any malicious prompt\*\*.



This demonstrates that prompt injection can also exist as a supply-chain problem.



\---



\# 12. Lab 4 — Configuration / Policy Artifact Tampering



\## Objective



Determine whether modification of configuration or security-policy artifacts can alter runtime authorization behavior.



Potential malicious changes include:



\- Expanding permitted targets

\- Expanding available actions

\- Changing approval requirements

\- Modifying privilege rules

\- Weakening access-control conditions



\## Security Finding



Policy artifacts represent executable security state.



A compromised policy artifact can make malicious runtime behavior appear authorized.



\## Key Principle



```text

Configuration != harmless data



Security configuration can define execution authority.

```



Therefore policy artifacts require the same trust protections as executable code.



\---



\# 13. Lab 5 — Dataset / Knowledge Artifact Poisoning



\## Objective



Determine whether attacker-controlled knowledge artifacts can influence runtime security decisions.



Poisoned knowledge may contain:



\- False target mappings

\- False authorization claims

\- False approval information

\- Malicious operational instructions

\- Incorrect security classifications



\## Security Finding



A knowledge artifact may appear to contain factual information while actually carrying attacker-controlled security context.



\## Security Principle



> Retrieved knowledge must not automatically become authorization, identity, approval, privilege, or policy state.



Dataset authenticity and provenance therefore form part of the AI application's security boundary.



\---



\# 14. Lab 6 — Model / Adapter Substitution



\## Objective



Determine whether a malicious model or adapter can remain functionally compatible while changing security-sensitive behavior.



A substituted model may:



\- Produce expected natural-language responses

\- Load successfully

\- Match expected interfaces

\- Pass superficial functionality tests



while also:



\- Selecting restricted targets

\- Expanding capabilities

\- Generating privileged operations

\- Manipulating security decisions



\## Security Finding



Functional equivalence is not authenticity.



```text

Model loads successfully

&#x20;       !=

Correct model loaded

```



A model must therefore be bound to trusted identity and integrity information.



\---



\# 15. Lab 7 — Tool Package / Dependency Compromise



\## Objective



Evaluate whether a malicious package can preserve the expected API while changing security-sensitive implementation behavior.



A compromised dependency may:



\- Rewrite parameters

\- Redirect targets

\- Expand tool capabilities

\- Bypass authorization

\- Return false validation results

\- Alter runtime state



\## Security Finding



API compatibility does not establish package trust.



A malicious dependency may remain invisible to the application because its function signatures remain unchanged.



\---



\# 16. Lab 8 — Dependency Confusion \& Artifact Substitution



\## Objective



Evaluate weak dependency-resolution behavior.



Attack scenarios included:



\- Higher-version public substitution

\- Same-version malicious substitution

\- Publisher impersonation

\- Artifact naming confusion

\- Typosquatting



\## Vulnerable Pattern



```text

Trusted private package:

internal-ai-tools 1.0.0



Attacker publishes:

internal-ai-tools 9.9.9



Weak resolver:

"9.9.9 is newer, therefore use it."

```



This is unsafe because:



```text

Higher Version

&#x20;   !=

Trusted Artifact

```



\## Security Finding



Dependency resolution itself is a security boundary.



A package manager or artifact loader must not treat version precedence as trust precedence.



\---



\# 17. Lab 9 — Artifact Metadata \& Provenance Spoofing



\## Objective



Determine whether malicious artifacts could clone trusted metadata and receive false trust decisions.



Spoofed metadata included:



\- Artifact ID

\- Name

\- Version

\- Publisher

\- Source

\- Build ID

\- Commit

\- Signature-status claim

\- Provenance claim

\- SBOM reference



\## Results



```text

Poisoned provenance cases: 6

Metadata spoof successes: 6

Metadata Spoof Success Rate: 100.00%

False Trust Decision Rate: 100.00%

Signature Claim Spoof Rate: 100.00%

Provenance Claim Spoof Rate: 100.00%

SBOM Claim Spoof Rate: 100.00%

Malicious Artifact Load Rate: 100.00%

Metadata-Induced Runtime Compromise Rate: 100.00%



Clean Provenance Utility Rate: 100.00%

```



\## Security Finding



The malicious artifact could present metadata identical to the trusted artifact while containing different behavior.



\## Critical Principle



> \*\*Metadata claims are assertions, not proof.\*\*



The following field:



```json

{

&#x20; "signature\_verified": true

}

```



does not prove that a signature was cryptographically verified.



Similarly:



```json

{

&#x20; "publisher": "trusted\_ai\_team"

}

```



does not authenticate the publisher.



\---



\# 18. Lab 10 — Hash / Integrity Verification Bypass



\## Objective



Determine whether the presence of SHA-256 verification alone guarantees artifact integrity.



The lab evaluated:



1\. Full trusted hash verification

2\. Metadata-only hashing

3\. Stale digest reuse

4\. Attacker-controlled digest fields

5\. Excluded security-sensitive fields

6\. Weak canonicalization

7\. Content-only verification with tampered metadata



\## Results



```text

Poisoned integrity cases: 6

False integrity acceptances: 6

False Integrity Acceptance Rate: 100.00%

Integrity Bypass Rate: 100.00%

Malicious Artifact Load Rate: 100.00%

Integrity-Bypass Runtime Compromise Rate: 100.00%



Clean Integrity Utility Rate: 100.00%

```



\## Security Finding



Using a strong cryptographic algorithm does not guarantee secure integrity verification.



The architecture must also answer:



```text

What exactly is hashed?



Who supplied the expected digest?



Can the digest be replaced?



Does the hash cover metadata?



Does the hash cover security-sensitive fields?



Is stale verification state reused?

```



\## Critical Principle



> \*\*Cryptographic strength cannot compensate for incorrect trust architecture.\*\*



\---



\# 19. Lab 11 — Transitive Dependency Compromise



\## Objective



Determine whether a trusted top-level component can become compromised in effect through a malicious dependency.



Example:



```text

Trusted AI Application

&#x20;      |

&#x20;      +---- Trusted Model

&#x20;      |

&#x20;      +---- Trusted Tool Package

&#x20;                   |

&#x20;                   +---- Malicious Dependency

```



The top-level artifact may have:



\- Correct identity

\- Correct publisher

\- Correct hash

\- Correct version



while the runtime still becomes compromised because a transitive dependency is malicious.



\## Security Finding



Trust must recurse through the dependency graph.



```text

Trusted Parent

&#x20;    !=

Trusted Dependency Tree

```



\## Defensive Requirement



The application should validate:



\- Direct dependencies

\- Transitive dependencies

\- Version constraints

\- Publisher identities

\- Integrity

\- Provenance

\- Capability changes



\---



\# 20. Lab 12 — Compromised Artifact to Runtime Propagation



\## Objective



Determine whether pre-runtime artifact compromise can survive artifact loading and influence runtime behavior.



The attack path can be represented as:



```text

Supply-Chain Compromise

&#x20;       |

&#x20;       v

Malicious Artifact

&#x20;       |

&#x20;       v

Artifact Loader

&#x20;       |

&#x20;       v

Application Context

&#x20;       |

&#x20;       v

AI Runtime

&#x20;       |

&#x20;       v

Security-Sensitive Decision

&#x20;       |

&#x20;       v

Protected Resource

```



\## Result



The vulnerable architecture demonstrated substantial pre-runtime-to-runtime propagation.



The tested propagation rate was:



```text

Pre-Runtime → Runtime Propagation Rate: 83.33%

Clean Utility Rate: 100.00%

```



Some attack paths were prevented by independent runtime restrictions.



\## Security Finding



This result is important because it demonstrates that:



> \*\*Supply-chain compromise does not have to become runtime compromise when runtime authority is independently enforced.\*\*



This became a central design principle for the hardened architecture.



\---



\# 21. Lab 13 — Vulnerable End-to-End Supply-Chain Attack Chain



\## Objective



Combine the individual supply-chain weaknesses into a complete vulnerable architecture.



\## Attack Chain



```text

Attacker-Controlled Artifact

&#x20;         |

&#x20;         v

Weak Source Trust

&#x20;         |

&#x20;         v

Weak Artifact Resolution

&#x20;         |

&#x20;         v

Metadata Accepted

&#x20;         |

&#x20;         v

Integrity Bypassed

&#x20;         |

&#x20;         v

Malicious Artifact Loaded

&#x20;         |

&#x20;         v

Capability Expansion

&#x20;         |

&#x20;         v

Runtime Behavior Manipulated

&#x20;         |

&#x20;         v

Restricted Target Selected

&#x20;         |

&#x20;         v

Privileged Action Executed

&#x20;         |

&#x20;         v

Unauthorized System Impact

```



\## Vulnerable Results



| Metric | Result |

|---|---:|

| Artifact Trust Bypass Rate | 100.00% |

| Malicious Artifact Load Rate | 100.00% |

| Supply-Chain Propagation Rate | 100.00% |

| Runtime Compromise Rate | 100.00% |

| Unauthorized System Impact Rate | 100.00% |

| Attack Chain Completion Rate | 100.00% |

| Legitimate Workflow Completion Rate | 100.00% |



\## Critical Observation



The legitimate workflow completion rate was also 100%.



This means the vulnerable architecture was \*\*functional\*\*.



The application could appear healthy while remaining fully exploitable.



This reinforces the Day 25 core principle:



> Functionality is not evidence of trust.



\---



\# 22. Lab 14 — AI Supply-Chain Trust \& Containment Controls



\## Objective



Design a hardened architecture that assumes incoming AI artifacts are untrusted until multiple independent trust requirements succeed.



\## Hardened Verification Pipeline



```text

Incoming Artifact

&#x20;     |

&#x20;     v

+----------------------+

| SOURCE\_TRUST         |

+----------------------+

&#x20;     |

&#x20;     v

+----------------------+

| ARTIFACT\_IDENTITY    |

+----------------------+

&#x20;     |

&#x20;     v

+----------------------+

| VERSION\_BINDING      |

+----------------------+

&#x20;     |

&#x20;     v

+----------------------+

| PUBLISHER\_IDENTITY   |

+----------------------+

&#x20;     |

&#x20;     v

+----------------------+

| PROVENANCE           |

+----------------------+

&#x20;     |

&#x20;     v

+----------------------+

| FULL\_INTEGRITY       |

+----------------------+

&#x20;     |

&#x20;     v

+----------------------+

| CAPABILITY\_POLICY    |

+----------------------+

&#x20;     |

&#x20;     v

&#x20;     LOAD

&#x20;     |

&#x20;     v

+----------------------+

| RUNTIME ACTION       |

| BINDING              |

+----------------------+

&#x20;     |

&#x20;     v

+----------------------+

| RUNTIME TARGET       |

| BINDING              |

+----------------------+

&#x20;     |

&#x20;     v

+----------------------+

| AUTHORIZATION        |

+----------------------+

&#x20;     |

&#x20;     v

Protected Resource

```



\## Attack Cases



The hardened architecture was tested against:



\- Higher-version public substitution

\- Full trusted metadata clone

\- Self-asserted trusted hash

\- Capability expansion

\- Multi-control bypass attempts



\## Results



```text

Poisoned attack cases: 5

Contained attacks: 5

Containment Rate: 100.00%

Malicious Artifact Load Rate: 0.00%

Unauthorized System Impact Rate: 0.00%

Attack Chain Completion Rate: 0.00%



Clean cases: 2

Successful clean workflows: 2

Legitimate Workflow Completion Rate: 100.00%

```



\## Observed Containment Stages



```text

ARTIFACT\_IDENTITY: 2

FULL\_INTEGRITY: 1

SOURCE\_TRUST: 2

```



\## Security Finding



No malicious artifact reached authorized runtime execution.



At the same time, legitimate workflows remained functional.



\---



\# 23. Lab 15 — Hardened AI Supply-Chain Adversarial Retest



\## Objective



Determine whether the architecture still provides protection when earlier controls are deliberately assumed to have failed.



This tests \*\*defense in depth\*\* rather than simple first-control prevention.



\## Adversarial Strategy



The retest progressively assumed bypass of:



```text

SOURCE\_TRUST

ARTIFACT\_IDENTITY

VERSION\_BINDING

PUBLISHER\_IDENTITY

PROVENANCE

FULL\_INTEGRITY

CAPABILITY\_POLICY

```



The attacker was therefore injected progressively deeper into the trust chain.



\---



\## Case: Source Trust Assumed Bypassed



The artifact passed `SOURCE\_TRUST`.



It was stopped at:



```text

ARTIFACT\_IDENTITY

```



\---



\## Case: Identity Validation Assumed Bypassed



The malicious artifact crossed:



```text

SOURCE\_TRUST

ARTIFACT\_IDENTITY

```



It was stopped at:



```text

VERSION\_BINDING

```



\---



\## Case: Provenance Controls Assumed Bypassed



The malicious artifact crossed:



```text

SOURCE\_TRUST

ARTIFACT\_IDENTITY

VERSION\_BINDING

PUBLISHER\_IDENTITY

PROVENANCE

```



It was stopped at:



```text

FULL\_INTEGRITY

```



\---



\## Case: Integrity Assumed Bypassed



The malicious artifact crossed six trust boundaries.



It was stopped at:



```text

CAPABILITY\_POLICY

```



\---



\## Case: Malicious Artifact Assumed Loaded



The malicious artifact crossed all seven pre-runtime controls.



It successfully reached the runtime.



However, it was stopped at:



```text

RUNTIME\_ACTION\_BINDING

```



No unauthorized action executed.



\---



\# 24. Hardened Retest Results



```text

Poisoned retest cases: 6

Contained attacks: 6



Defense-in-Depth Containment Rate: 100.00%

Malicious Load Survival Rate: 33.33%

Unsafe Runtime Execution Rate: 0.00%

Unauthorized System Impact Rate: 0.00%

Attack Chain Completion Rate: 0.00%



Average Trust Boundaries Crossed: 4.67 / 7

Maximum Trust Boundaries Crossed: 7 / 7



Legitimate Workflow Completion Rate: 100.00%

```



Observed block stages included:



```text

ARTIFACT\_IDENTITY

VERSION\_BINDING

FULL\_INTEGRITY

CAPABILITY\_POLICY

RUNTIME\_ACTION\_BINDING

```



\---



\# 25. Why the 33.33% Malicious Load Survival Rate Matters



The hardened adversarial retest intentionally allowed some malicious artifacts to survive the pre-runtime trust chain.



This is not a failure of the architecture.



It tests a stronger security property:



> \*\*If a malicious artifact is somehow loaded, does it automatically obtain execution authority?\*\*



The answer was no.



Even malicious artifacts that reached the runtime were prevented from executing unsafe actions because runtime authority remained independently enforced.



This creates an important separation:



```text

Artifact Loaded

&#x20;     !=

Action Authorized

```



That separation significantly limits supply-chain blast radius.



\---



\# 26. Vulnerable vs Hardened Comparison



| Metric | Vulnerable | Hardened |

|---|---:|---:|

| Malicious Artifact Load Rate | 100.00% | 0.00% |

| Unauthorized System Impact Rate | 100.00% | 0.00% |

| Attack Chain Completion Rate | 100.00% | 0.00% |

| Legitimate Workflow Completion Rate | 100.00% | 100.00% |



\## Change



```text

Malicious Artifact Load:

100% → 0%



Unauthorized System Impact:

100% → 0%



Attack Chain Completion:

100% → 0%



Legitimate Workflow Completion:

100% → 100%

```



\## Relative Risk Reduction



```text

Malicious Artifact Loading: 100.00%

Unauthorized System Impact: 100.00%

Attack Chain Completion: 100.00%

```



The controls therefore reduced tested unauthorized impact without reducing legitimate workflow utility in the synthetic benchmark.



\---



\# 27. AI Artifact Trust-Chain Model



The final Day 25 trust model can be represented as:



```text

&#x20;              AI ARTIFACT TRUST CHAIN



&#x20;                    SOURCE

&#x20;                      |

&#x20;                      v

&#x20;                 IDENTITY

&#x20;                      |

&#x20;                      v

&#x20;                  VERSION

&#x20;                      |

&#x20;                      v

&#x20;                 PUBLISHER

&#x20;                      |

&#x20;                      v

&#x20;                PROVENANCE

&#x20;                      |

&#x20;                      v

&#x20;                 INTEGRITY

&#x20;                      |

&#x20;                      v

&#x20;              DEPENDENCY TRUST

&#x20;                      |

&#x20;                      v

&#x20;                 CAPABILITY

&#x20;                      |

&#x20;                      v

&#x20;              LOAD AUTHORITY

&#x20;                      |

&#x20;                      v

&#x20;               RUNTIME ACTION

&#x20;                      |

&#x20;                      v

&#x20;               RUNTIME TARGET

&#x20;                      |

&#x20;                      v

&#x20;                AUTHORIZATION

&#x20;                      |

&#x20;                      v

&#x20;               SYSTEM IMPACT

```



Every arrow represents a trust transition.



No earlier component should automatically grant authority to a later component.



\---



\# 28. Major Security Findings



\## Finding 1 — Availability Does Not Establish Authenticity



An artifact being present in a repository does not establish that it came from the expected source.



\---



\## Finding 2 — Successful Loading Does Not Establish Trust



A malicious component may:



\- Parse correctly

\- Load correctly

\- Execute correctly

\- Produce valid output



while still violating security policy.



\---



\## Finding 3 — Functional Compatibility Can Hide Substitution



A malicious model, adapter, or package can preserve the expected interface.



Therefore:



```text

Interface Compatibility

&#x20;       !=

Artifact Authenticity

```



\---



\## Finding 4 — Prompt Templates Are Supply-Chain Artifacts



Prompt templates influence runtime behavior and should receive:



\- Integrity protection

\- Version control

\- Provenance

\- Change review

\- Deployment authorization



\---



\## Finding 5 — Security Policies Are Executable Trust State



Tampering with a policy artifact can redefine what the application considers authorized.



Security policies therefore require strong supply-chain controls.



\---



\## Finding 6 — Datasets Can Carry Security-Sensitive Instructions



A poisoned dataset can influence:



\- Target selection

\- Approval assumptions

\- Authority assumptions

\- Operational decisions



Knowledge must not become authority merely because the model retrieved it.



\---



\## Finding 7 — Model Identity Must Be Verified



Model names and metadata are insufficient.



Trust should bind the model to:



\- Expected source

\- Expected publisher

\- Expected version

\- Expected digest

\- Expected provenance

\- Expected capabilities



\---



\## Finding 8 — Dependencies Can Compromise Trusted Models



An authentic model does not guarantee a trustworthy application.



Its supporting dependency graph must also be validated.



\---



\## Finding 9 — Metadata Cannot Authenticate Itself



Self-declared fields such as:



```text

publisher

source

signature\_verified

provenance\_verified

sbom\_reference

build\_id

commit

```



cannot serve as independent proof.



\---



\## Finding 10 — SHA-256 Alone Is Not a Trust Architecture



Secure integrity verification depends on:



\- What is hashed

\- How it is serialized

\- Where the trusted digest originates

\- Whether metadata is included

\- Whether security-sensitive fields are included

\- Whether verification state is fresh



\---



\## Finding 11 — Dependency Resolution Is Security-Sensitive



Package resolution should never assume:



```text

Newest == Trusted

```



or:



```text

Available == Authorized

```



\---



\## Finding 12 — Trust Must Be Transitive



Every security-relevant dependency must be validated.



\---



\## Finding 13 — Capability Declaration Is Not Capability Authorization



A component claiming that it supports:



```text

delete\_record

```



does not mean the application should grant that capability.



Capabilities require independent authorization.



\---



\## Finding 14 — Artifact Loading Must Be Fail-Closed



When trust verification fails, the system should not:



\- Warn and continue

\- Silently fall back

\- Accept self-declared trust

\- Use the nearest matching artifact



It should reject the artifact.



\---



\## Finding 15 — Runtime Controls Remain Necessary



Perfect supply-chain prevention should not be assumed.



Runtime controls provide containment when malicious artifacts survive pre-runtime verification.



\---



\# 29. Security Control Recommendations



\## 29.1 Trusted Source Enforcement



Use approved artifact sources.



Examples:



\- Private model registries

\- Internal package repositories

\- Approved Hugging Face organizations

\- Controlled object storage

\- Signed release repositories



Avoid automatic fallback to arbitrary public sources.



\---



\## 29.2 Artifact Identity Binding



Applications should define exact expected artifact identities.



Avoid trust decisions based only on:



\- Filename

\- Display name

\- Repository search result

\- Package description



\---



\## 29.3 Version Pinning



Use explicitly authorized versions.



Prefer:



```text

model == 1.0.0

```



over:



```text

model >= 1.0.0

```



where security requirements demand deterministic artifact selection.



\---



\# 30. Publisher Authentication



Publisher identity should be cryptographically or administratively authenticated.



A metadata string such as:



```json

{

&#x20; "publisher": "trusted\_ai\_team"

}

```



must not independently establish publisher trust.



\---



\# 31. Provenance Verification



AI artifacts should maintain verifiable provenance information.



Useful provenance properties include:



\- Source repository

\- Build system

\- Build identity

\- Commit

\- Builder identity

\- Release pipeline

\- Artifact digest

\- Signing identity



Where appropriate, organizations can align this process with supply-chain frameworks such as SLSA-style provenance practices.



\---



\# 32. Full Artifact Integrity



Integrity validation should cover the complete security-relevant artifact representation.



Avoid:



\- Metadata-only hashing

\- Partial hashing

\- Ignoring security-sensitive fields

\- Trusting artifact-supplied digests

\- Reusing stale verification state



Expected digests should originate from trusted infrastructure independent of the artifact being validated.



\---



\# 33. Dependency Locking



Applications should use deterministic dependency resolution where possible.



Controls may include:



\- Lockfiles

\- Exact versions

\- Repository restrictions

\- Hash pinning

\- Namespace controls

\- Private package indexes



\---



\# 34. Transitive Dependency Validation



Do not stop verification at direct dependencies.



The dependency graph should be recursively evaluated.



```text

Application

&#x20;  |

&#x20;  +-- Model

&#x20;  |

&#x20;  +-- Tool Package

&#x20;         |

&#x20;         +-- Dependency A

&#x20;                |

&#x20;                +-- Dependency B

```



A compromise of `Dependency B` may still affect the application.



\---



\# 35. SBOM Controls



Maintain an inventory of security-relevant AI and software components.



An AI-oriented SBOM or component inventory may include:



\- Models

\- Adapters

\- Prompt packages

\- Datasets

\- Embedding models

\- Libraries

\- Tool packages

\- Runtime dependencies



However:



> An SBOM reference should not be trusted merely because an artifact claims to have one.



The SBOM must be independently associated with the verified artifact.



\---



\# 36. Capability Allowlisting



Artifacts should not define their own effective authority.



For example:



```json

{

&#x20; "capabilities": \[

&#x20;   "read\_record",

&#x20;   "delete\_record"

&#x20; ]

}

```



should be interpreted as:



```text

Capabilities requested

```



not:



```text

Capabilities granted

```



The application must independently enforce capability policy.



\---



\# 37. Runtime Action Binding



Even a trusted artifact should not determine unrestricted runtime actions.



Example:



```text

User Task:

Read R-2502



Model proposes:

Delete R-2599

```



The application must bind execution to trusted task state.



\---



\# 38. Runtime Target Binding



Targets must be independently validated.



A model or dependency should not be able to transform:



```text

R-2502

```



into:



```text

R-2599

```



without trusted authorization.



\---



\# 39. Least Privilege



AI components should receive only the capabilities necessary for their task.



Examples:



```text

Summarization model:

READ



Security administration workflow:

READ + controlled UPDATE



Destructive administration:

separate privileged authorization

```



This limits the consequence of supply-chain compromise.



\---



\# 40. Fail-Closed Loading



A secure loader should behave approximately as follows:



```python

if not trusted\_source:

&#x20;   reject()



if not expected\_identity:

&#x20;   reject()



if not expected\_version:

&#x20;   reject()



if not verified\_publisher:

&#x20;   reject()



if not verified\_provenance:

&#x20;   reject()



if not full\_integrity\_match:

&#x20;   reject()



if not capabilities\_allowed:

&#x20;   reject()



load\_artifact()

```



Security verification failures should not silently degrade into insecure fallback behavior.



\---



\# 41. Defense-in-Depth Architecture



The Day 25 assessment demonstrates why no single control is sufficient.



A mature architecture assumes:



```text

Source validation may fail.



Identity validation may fail.



Version binding may fail.



Publisher verification may fail.



Provenance verification may fail.



Integrity verification may fail.



Capability policy may fail.

```



Therefore runtime authorization must still remain independent.



This creates multiple containment opportunities.



\---



\# 42. Example Hardened Attack Path



```text

Malicious Artifact

&#x20;      |

&#x20;      v

SOURCE\_TRUST

&#x20;      |

&#x20;  \[bypassed]

&#x20;      |

&#x20;      v

ARTIFACT\_IDENTITY

&#x20;      |

&#x20;  \[bypassed]

&#x20;      |

&#x20;      v

VERSION\_BINDING

&#x20;      |

&#x20;  \[bypassed]

&#x20;      |

&#x20;      v

PUBLISHER\_IDENTITY

&#x20;      |

&#x20;  \[bypassed]

&#x20;      |

&#x20;      v

PROVENANCE

&#x20;      |

&#x20;  \[bypassed]

&#x20;      |

&#x20;      v

FULL\_INTEGRITY

&#x20;      |

&#x20;  \[bypassed]

&#x20;      |

&#x20;      v

CAPABILITY\_POLICY

&#x20;      |

&#x20;  \[bypassed]

&#x20;      |

&#x20;      v

Malicious Artifact Loaded

&#x20;      |

&#x20;      v

RUNTIME\_ACTION\_BINDING

&#x20;      |

&#x20;      X

&#x20;    BLOCKED

```



Even catastrophic failure of the entire pre-runtime verification chain does not automatically require unauthorized system impact.



\---



\# 43. Security Architecture Principle



The Day 25 architecture can be summarized as:



```text

Trust the artifact only for what has actually been verified.



Trust the runtime only for what has actually been authorized.

```



This avoids converting artifact identity into execution authority.



\---



\# 44. Detection \& Monitoring Recommendations



Preventive controls should be supplemented with monitoring.



Recommended events include:



\- Artifact source changes

\- Artifact digest changes

\- Model version changes

\- Prompt-template changes

\- Policy changes

\- Dataset changes

\- Dependency changes

\- Provenance verification failures

\- Signature verification failures

\- SBOM changes

\- Capability changes

\- Runtime target deviations

\- Runtime action deviations



\---



\# 45. Suggested Security Telemetry



Example artifact-load event:



```json

{

&#x20; "event": "ai\_artifact\_load",

&#x20; "artifact\_id": "MODEL-2501",

&#x20; "version": "1.0.0",

&#x20; "publisher\_verified": true,

&#x20; "provenance\_verified": true,

&#x20; "integrity\_verified": true,

&#x20; "capabilities\_allowed": true,

&#x20; "load\_authorized": true

}

```



Example rejection event:



```json

{

&#x20; "event": "ai\_artifact\_rejected",

&#x20; "artifact\_id": "MODEL-2501",

&#x20; "reason": "FULL\_INTEGRITY",

&#x20; "severity": "high"

}

```



\---



\# 46. Secure AI Deployment Pipeline



A secure deployment process may follow:



```text

Developer / AI Engineer

&#x20;       |

&#x20;       v

Source Repository

&#x20;       |

&#x20;       v

Controlled Build

&#x20;       |

&#x20;       v

Security Testing

&#x20;       |

&#x20;       v

Artifact Signing

&#x20;       |

&#x20;       v

Provenance Generation

&#x20;       |

&#x20;       v

Trusted Artifact Registry

&#x20;       |

&#x20;       v

Deployment Verification

&#x20;       |

&#x20;       v

Capability Enforcement

&#x20;       |

&#x20;       v

Runtime Authorization

&#x20;       |

&#x20;       v

Monitoring

```



\---



\# 47. Relationship to Traditional Software Supply-Chain Security



AI supply-chain security shares many concerns with traditional software supply chains:



\- Dependency confusion

\- Package substitution

\- Typosquatting

\- Compromised publishers

\- Build-system compromise

\- Artifact tampering

\- Provenance spoofing

\- Integrity failures



However, AI systems introduce additional artifact classes:



\- Models

\- Adapters

\- Prompts

\- Datasets

\- Embeddings

\- Retrieval indexes

\- Agent configurations



These components can alter application behavior without necessarily containing traditional executable code.



\---



\# 48. AI-Specific Trust Challenge



Traditional security often asks:



> Is this code trusted?



AI security must additionally ask:



> Is this model trusted?



> Is this prompt trusted?



> Is this dataset trusted?



> Is this adapter trusted?



> Is this retrieved knowledge trusted?



> Is this tool definition trusted?



> Is this agent configuration trusted?



And critically:



> Even if the artifact is trusted, is the requested runtime action authorized?



\---



\# 49. Risk Matrix



| Threat | Likelihood | Impact | Risk |

|---|---|---|---|

| Prompt-template poisoning | Medium | High | High |

| Dataset poisoning | Medium | High | High |

| Model substitution | Medium | Critical | High |

| Adapter substitution | Medium | High | High |

| Tool-package compromise | Medium | Critical | Critical |

| Dependency confusion | Medium | High | High |

| Metadata spoofing | High under weak validation | High | High |

| Integrity bypass | Medium | Critical | Critical |

| Transitive dependency compromise | Medium | High | High |

| Runtime authority inheritance | Medium | Critical | Critical |



\*Risk ratings are qualitative assessments for the synthetic architecture and are not production-environment measurements.\*



\---



\# 50. MITRE ATLAS / ATT\&CK-Relevant Security Concepts



The Day 25 work demonstrates concepts relevant to AI and software supply-chain threat modeling, including:



\- Supply-chain compromise

\- Model poisoning

\- Data poisoning

\- Dependency compromise

\- Trusted relationship abuse

\- Execution through compromised components

\- Defense evasion through metadata spoofing

\- Privilege expansion through compromised policy

\- Persistence through trusted artifacts



Exact technique mapping should be validated against the current MITRE ATLAS and ATT\&CK catalogs before using the mappings in formal production reporting.



\---



\# 51. OWASP-Relevant Security Concepts



The assessment is relevant to AI security concerns including:



\- Supply-chain vulnerabilities

\- Excessive agency

\- Improper output handling

\- Data and model poisoning

\- System-prompt compromise

\- Excessive trust in external components



Exact OWASP LLM / GenAI category numbering should be checked against the current OWASP release when preparing compliance or formal assessment documentation.



\---



\# 52. NIST-Relevant Security Concepts



The project demonstrates security engineering concepts consistent with:



\- Supply-chain risk management

\- Software integrity

\- Provenance

\- Access control

\- Least privilege

\- Configuration management

\- Continuous monitoring

\- Secure development

\- Risk management



The assessment is a technical learning project and should not be interpreted as formal NIST certification or compliance validation.



\---



\# 53. Limitations



The Day 25 environment is intentionally synthetic.



It uses simulated:



\- AI artifacts

\- Models

\- Package repositories

\- Provenance claims

\- Signature status

\- SBOM references

\- Dependency graphs

\- Protected records

\- Runtime operations



The project demonstrates architectural security properties rather than exploitation of a production AI provider, public model registry, package repository, or enterprise deployment pipeline.



\---



\# 54. Cryptographic Limitation



Signature and provenance verification were represented using synthetic validation logic.



The labs did not implement a complete production cryptographic trust system involving:



\- PKI certificate chains

\- Hardware-backed keys

\- Sigstore

\- Transparency logs

\- Real signing authorities

\- Production SLSA attestations



Therefore the project demonstrates \*\*trust-boundary logic\*\*, not production cryptographic assurance.



\---



\# 55. Model Security Limitation



The synthetic model and adapter artifacts represent security-sensitive model behavior.



The assessment does not claim to demonstrate compromise of a real commercial or open-source foundation model.



The purpose is to evaluate architectural trust assumptions surrounding model loading and use.



\---



\# 56. Dataset Security Limitation



Dataset poisoning was modeled using controlled synthetic knowledge artifacts.



Real-world dataset poisoning may involve:



\- Large-scale corpus manipulation

\- Training-data poisoning

\- Fine-tuning poisoning

\- RAG corpus poisoning

\- Embedding manipulation

\- Retrieval-ranking attacks



Those areas could be evaluated separately in deeper research.



\---



\# 57. Key Defensive Lessons



The assessment produced ten major defensive lessons:



1\. \*\*Do not trust artifacts because they load successfully.\*\*

2\. \*\*Do not trust models because they behave normally during superficial tests.\*\*

3\. \*\*Do not trust publisher names without authentication.\*\*

4\. \*\*Do not trust metadata that authenticates itself.\*\*

5\. \*\*Do not trust hashes supplied by the artifact being verified.\*\*

6\. \*\*Do not trust only the top-level dependency.\*\*

7\. \*\*Do not treat artifact capabilities as granted privileges.\*\*

8\. \*\*Do not allow supply-chain trust to become runtime authority.\*\*

9\. \*\*Do not rely on one trust control.\*\*

10\. \*\*Preserve independent runtime authorization even after artifact verification.\*\*



\---



\# 58. Portfolio Skills Demonstrated



Day 25 demonstrates practical capability in:



\- AI Red Teaming

\- LLM Security

\- AI Supply-Chain Security

\- Model Security

\- Model Artifact Trust

\- Prompt Security

\- Prompt Supply-Chain Security

\- Dataset Poisoning Analysis

\- Model Substitution Testing

\- Adapter Security

\- Dependency Security

\- Dependency Confusion Testing

\- Tool Package Security

\- Artifact Integrity Verification

\- SHA-256 Integrity Analysis

\- Provenance Validation

\- Metadata Spoofing Analysis

\- SBOM Security Concepts

\- Transitive Dependency Analysis

\- Capability Security

\- Least Privilege

\- Runtime Authorization

\- Trust-Boundary Analysis

\- Defense in Depth

\- Security Architecture

\- Threat Modeling

\- Adversarial Testing

\- Python Security Automation

\- Quantitative Security Analysis



\---



\# 59. Portfolio Value



This project goes beyond demonstrating individual prompt attacks.



It evaluates how AI security connects to:



```text

Software Supply Chain

&#x20;       +

AI Artifact Supply Chain

&#x20;       +

Runtime Authorization

&#x20;       +

Agent Security

```



The assessment demonstrates an understanding that secure AI deployment requires protecting the entire lifecycle:



```text

Build

&#x20; |

&#x20; v

Package

&#x20; |

&#x20; v

Publish

&#x20; |

&#x20; v

Resolve

&#x20; |

&#x20; v

Verify

&#x20; |

&#x20; v

Load

&#x20; |

&#x20; v

Authorize

&#x20; |

&#x20; v

Execute

&#x20; |

&#x20; v

Monitor

```



\---



\# 60. Final Findings



The Day 25 assessment supports the following conclusions.



\### 1. AI supply-chain compromise can begin before runtime.



The attacker does not necessarily need to attack the user prompt.



\---



\### 2. Prompt templates are security-sensitive artifacts.



A poisoned template can alter runtime behavior before user interaction begins.



\---



\### 3. Policy artifacts can redefine effective authorization.



Security configuration must therefore receive integrity and provenance protection.



\---



\### 4. Datasets can become attack vectors.



Knowledge must remain separate from identity, approval, privilege, and policy state.



\---



\### 5. Models can be functionally compatible while malicious.



Successful inference is not evidence of model authenticity.



\---



\### 6. Tool packages can preserve APIs while changing behavior.



Interface compatibility does not establish trust.



\---



\### 7. Dependency confusion can redirect applications toward attacker-controlled artifacts.



Version precedence must not replace trust policy.



\---



\### 8. Metadata spoofing can create false trust.



Metadata must be cryptographically or independently bound to artifact identity and digest.



\---



\### 9. Strong hashes can be used insecurely.



Integrity verification depends on architecture, not merely algorithm strength.



\---



\### 10. Trust must extend through transitive dependencies.



A trusted top-level artifact may still rely on compromised lower-level components.



\---



\### 11. Supply-chain compromise can propagate into runtime.



Pre-runtime trust failures can become runtime security failures.



\---



\### 12. Runtime authorization can contain supply-chain compromise.



A loaded malicious artifact does not have to receive execution authority.



\---



\### 13. Defense in depth remains effective when individual controls fail.



Independent downstream controls prevented unauthorized execution during the adversarial retest.



\---



\### 14. Security improvements did not reduce legitimate utility in the benchmark.



The hardened architecture preserved:



```text

Legitimate Workflow Completion Rate: 100.00%

```



while reducing:



```text

Unauthorized System Impact:

100.00% → 0.00%



Attack Chain Completion:

100.00% → 0.00%

```



\---



\# 61. Final Comparative Result



\## Vulnerable Architecture



```text

Artifact Trust Bypass Rate:           100.00%

Malicious Artifact Load Rate:         100.00%

Supply-Chain Propagation Rate:        100.00%

Runtime Compromise Rate:              100.00%

Unauthorized System Impact Rate:      100.00%

Attack Chain Completion Rate:         100.00%

Legitimate Workflow Completion Rate:  100.00%

```



\## Hardened Architecture



```text

Containment Rate:                     100.00%

Malicious Artifact Load Rate:           0.00%

Unauthorized System Impact Rate:        0.00%

Attack Chain Completion Rate:           0.00%

Legitimate Workflow Completion Rate:  100.00%

```



\## Hardened Adversarial Retest



```text

Defense-in-Depth Containment Rate:    100.00%

Malicious Load Survival Rate:          33.33%

Unsafe Runtime Execution Rate:          0.00%

Unauthorized System Impact Rate:        0.00%

Attack Chain Completion Rate:           0.00%

Average Trust Boundaries Crossed:      4.67 / 7

Maximum Trust Boundaries Crossed:      7 / 7

Legitimate Workflow Completion Rate: 100.00%

```



\---



\# 62. Conclusion



Day 25 demonstrated that AI security begins before an AI application starts executing.



A model, adapter, prompt template, policy, dataset, tool package, dependency, or configuration artifact can become an attacker-controlled entry point into the AI runtime.



The vulnerable architecture demonstrated how weak assumptions around:



\- Artifact availability

\- Package resolution

\- Metadata

\- Publisher identity

\- Provenance

\- Hash verification

\- Dependency trust

\- Capability declarations



can allow malicious artifacts to become trusted application components.



The end-to-end vulnerable architecture produced a:



```text

100.00% Artifact Trust Bypass Rate

100.00% Malicious Artifact Load Rate

100.00% Supply-Chain Propagation Rate

100.00% Runtime Compromise Rate

100.00% Unauthorized System Impact Rate

100.00% Attack Chain Completion Rate

```



The hardened architecture changed the trust model.



Instead of asking:



> "Can this component load?"



the architecture asks:



> "Did this component come from an authorized source?"



> "Is this the exact artifact expected?"



> "Is this version authorized?"



> "Is the publisher authenticated?"



> "Is its provenance independently verified?"



> "Does its complete security-relevant representation match trusted integrity evidence?"



> "Are its dependencies trusted?"



> "Are its requested capabilities permitted?"



> "Is the runtime action authorized?"



> "Is the runtime target authorized?"



This reduced the tested:



```text

Unauthorized System Impact Rate:

100.00% → 0.00%



Attack Chain Completion Rate:

100.00% → 0.00%

```



while maintaining:



```text

Legitimate Workflow Completion Rate:

100.00%

```



The hardened adversarial retest further demonstrated that even when individual earlier controls were assumed compromised, independent downstream controls continued to prevent unsafe execution.



The final architectural lesson is therefore:



> \*\*Supply-chain trust should determine whether an artifact may enter the system, but it should never independently determine what that artifact may do once it gets there.\*\*



\---



\# 63. Core Principle



> ## \*\*An AI component being available or functional does not establish that it is authentic, trusted, or safe to load.\*\*



\---



\# 64. Portfolio Artifact



\*\*Project:\*\* LLM Red Team Lab  

\*\*Day:\*\* 25  

\*\*Assessment:\*\* AI Supply-Chain, Model \& Artifact Trust Security Assessment  

\*\*Artifact:\*\* `Day-25-AI-Supply-Chain-Model-Artifact-Trust-Security-Assessment.md`



\### Supporting Evidence



The completed Day 25 repository should contain:



```text

Day-25/

│

├── Day-25-AI-Supply-Chain-Model-Artifact-Trust-Security-Assessment.md

│

├── evidence/

│   └── day25-final-comparative-analysis.txt

│

└── scripts/

&#x20;   ├── Day25-01-synthetic-ai-supply-chain-environment.py

&#x20;   ├── Day25-02-trusted-artifact-model-baseline.py

&#x20;   ├── Day25-03-prompt-template-supply-chain-poisoning.py

&#x20;   ├── Day25-04-configuration-policy-artifact-tampering.py

&#x20;   ├── Day25-05-dataset-knowledge-artifact-poisoning.py

&#x20;   ├── Day25-06-model-adapter-substitution.py

&#x20;   ├── Day25-07-tool-package-dependency-compromise.py

&#x20;   ├── Day25-08-dependency-confusion-artifact-substitution.py

&#x20;   ├── Day25-09-artifact-metadata-provenance-spoofing.py

&#x20;   ├── Day25-10-hash-integrity-verification-bypass.py

&#x20;   ├── Day25-11-transitive-dependency-compromise.py

&#x20;   ├── Day25-12-compromised-artifact-runtime-propagation.py

&#x20;   ├── Day25-13-end-to-end-ai-supply-chain-attack-chain.py

&#x20;   ├── Day25-14-ai-supply-chain-trust-containment-controls.py

&#x20;   ├── Day25-15-hardened-ai-supply-chain-adversarial-retest.py

&#x20;   └── Day25-16-final-comparative-analysis.py

```



\---



\*\*End of Day 25 Assessment\*\*

