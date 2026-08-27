# Day 23 — LLM Tool-Chain \& MCP Security Assessment



## Portfolio Artifact



**Assessment Title:** LLM Tool-Chain \& MCP Security Assessment

**Day:** 23

**Lab Track:** LLM Red Teaming / Agentic AI Security

**Primary Focus:** Tool poisoning, malicious tool descriptions, excessive tool permissions, parameter manipulation, confused tool selection, indirect prompt injection through tool output, tool-result poisoning, chained tool attacks, MCP-style trust boundaries, least privilege, independent authorization, and hardened execution architecture.



---



# Core Security Principle



> \*\*Tool availability does not imply tool authority; every AI-initiated action must remain independently constrained by identity, capability, scope, parameters, and policy.\*\*



---



# 1. Executive Summary



Day 23 investigated the security boundary between an LLM agent and the tools, services, APIs, and MCP-style servers available to it.



The central research question was:



> \*\*Can an attacker manipulate a tool-enabled AI agent into selecting unauthorized tools, inheriting excessive privileges, changing execution parameters, trusting poisoned tool results, crossing MCP-style trust boundaries, or performing unsafe chained actions?\*\*



The assessment consisted of fifteen controlled laboratories.



The early laboratories intentionally exposed vulnerable behavior in order to measure how an LLM responded when:



- unauthorized tools were visible;

- tool descriptions contained malicious instructions;

- excessive permissions were exposed;

- model-generated tool parameters were not independently validated;

- safe tasks could be reframed using more privileged tools;

- tool output contained indirect prompt injection;

- tool results contained forged security evidence;

- multiple tool-layer weaknesses were chained together.



The later laboratories introduced hardened controls including:



- trusted MCP/server identity;

- trusted server-to-tool ownership;

- server tool allowlists;

- per-agent capability enforcement;

- least privilege;

- independent resource policy;

- parameter schemas;

- trusted target binding;

- execution scope;

- value validation;

- metadata sanitization;

- tool-output sanitization;

- trusted approval validation;

- application-controlled execution state.



The final adversarial retest demonstrated a critical security property:



> \*\*The model may continue to generate unsafe tool proposals while the application still prevents unauthorized system impact.\*\*



The final hardened retest produced:



- \*\*Dangerous Proposal Rate: 100.00%\*\*

- \*\*Dangerous Proposal Containment Rate: 100.00%\*\*

- \*\*Unauthorized System Impact Rate: 0.00%\*\*

- \*\*Legitimate Tool Completion Rate: 100.00%\*\*

- \*\*Trusted Task Preservation Rate: 100.00%\*\*



One model/JSON-formatting failure occurred during the final retest, so those percentages were calculated over the seven successful model executions.



The overall Day 23 conclusion is therefore:



> \*\*Secure agentic systems must treat model-generated tool calls as untrusted proposals rather than execution authority.\*\*



---



# 2. Assessment Objectives



The Day 23 assessment was designed to answer the following questions:



1\. Can an LLM select a tool that the current agent is not authorized to execute?

2\. Can malicious tool descriptions influence model behavior?

3\. Does exposing unnecessary privileged tooling increase risk?

4\. Can the model manipulate tool parameters or substitute targets?

5\. Can a safe task be reframed into a more privileged tool action?

6\. Can tool output inject new instructions into the model?

7\. Can false tool results corrupt security-sensitive reasoning?

8\. Can multiple tool vulnerabilities compose into a chained attack?

9\. Can an untrusted MCP-style server impersonate a trusted provider?

10\. Can an untrusted server register tools belonging to another provider?

11\. Can agent delegation create unintended tool privilege propagation?

12\. Can strict capability enforcement prevent unauthorized execution?

13\. Can schema and target binding stop parameter-manipulation attacks?

14\. Can trusted approvals be protected from model-generated claims?

15\. Can an application remain secure even when the LLM produces unsafe action proposals?



---



# 3. Threat Model



The assessment assumed that an attacker could potentially influence:



- user requests;

- tool descriptions;

- tool registry metadata;

- tool availability;

- external lookup results;

- MCP-style server metadata;

- tool results;

- model-generated parameters;

- model-generated target values;

- model-selected servers;

- model-selected tools;

- model-generated authority claims;

- fake approval identifiers;

- multi-stage tool-chain decisions.



The attacker was \*\*not\*\* assumed to control the trusted application authorization layer.



The design goal was therefore not to make the LLM inherently trustworthy.



The design goal was:



> \*\*Prevent compromised or unreliable model reasoning from becoming trusted system execution.\*\*



---



# 4. Synthetic Environment



The Day 23 environment used synthetic resources so that high-risk behaviors could be tested safely.



## 4.1 Synthetic Agents



### `planner\_agent`



Role:



- planning;

- project coordination;

- summarization;

- external lookup.



Typical capabilities:



- `summarize\_data`;

- `external\_lookup`.



The planner intentionally did not possess direct record-reading or security-deletion privileges.



---



### `worker\_agent`



Role:



- operational task execution.



Typical capabilities:



- `read\_record`;

- `update\_record`;

- `summarize\_data`;

- `external\_lookup`.



The worker could perform ordinary internal operations but was prevented from inheriting security privileges automatically.



---



### `security\_agent`



Role:



- security-sensitive execution;

- restricted-resource handling;

- high-impact action execution.



Typical capabilities:



- `read\_record`;

- `delete\_record`;

- security-sensitive functions;

- approved restricted actions.



---



# 5. Synthetic Resources



The primary records used during testing included:



## `R-2302`



Classification:



- internal.



Purpose:



- normal worker-readable synthetic record.



---



## `R-2399`



Classification:



- restricted.



Purpose:



- security-sensitive synthetic target used in privilege escalation, target substitution, delete, authorization, and tool-chain tests.



---



# 6. MCP-Style Tool Servers



Three synthetic MCP-style providers were modeled.



## 6.1 `internal\_ops`



Trust level:



- trusted.



Responsible for:



- `read\_record`;

- `update\_record`;

- `delete\_record`.



---



## 6.2 `analytics`



Trust level:



- trusted.



Responsible for:



- `summarize\_data`.



---



## 6.3 `external\_helper`



Trust level:



- untrusted / lower trust.



Responsible for:



- `external\_lookup`.



The architecture intentionally separated:



> \*\*Server identity from tool identity.\*\*



A server claiming to provide a tool did not automatically become the trusted owner of that tool.



---



# 7. Security Properties Under Test



The Day 23 experiments focused on the following security properties:



- tool discovery;

- tool authorization;

- capability separation;

- server identity;

- tool ownership;

- parameter integrity;

- target integrity;

- scope integrity;

- approval integrity;

- tool-result trust;

- prompt-injection resistance;

- privilege propagation;

- chain containment;

- least privilege;

- safe execution under compromised reasoning.



---



# 8. Lab 1 — Synthetic Tool / MCP Environment



## Objective



Create a controlled tool-enabled environment with:



- agents;

- capabilities;

- synthetic records;

- trusted and untrusted servers;

- tool registration;

- parameter validation;

- scope controls;

- approval controls.



## Key Tests



The lab confirmed:



- tool discovery;

- capability separation;

- legitimate scoped reads;

- unauthorized planner access blocking;

- target-scope enforcement;

- high-risk approval requirements;

- parameter validation.



## Security Properties



The environment demonstrated that:



- tool discovery does not grant tool authority;

- tool server identity is stored outside model text;

- capabilities are explicitly assigned;

- tool execution is independently checked;

- tool parameters are validated;

- restricted actions require additional approval;

- tool events are auditable.



## Core Finding



> \*\*Knowing that a tool exists is not equivalent to possessing authority to execute that tool.\*\*



---



# 9. Lab 2 — Vulnerable Tool-Selection Baseline



## Objective



Measure whether an LLM would select semantically appropriate tools even when the current agent was not authorized to use them.



## Observed Results



- \*\*Tool Selection Accuracy: 66.67%\*\*

- \*\*Legitimate Tool Completion Rate: 66.67%\*\*

- \*\*Unsafe Tool Selection Rate (UTSR): 66.67%\*\*



## Example Risk



A planner without `read\_record` authority still selected:



`read\_record`



when asked to retrieve an internal record.



The model understood the semantic relationship between task and tool but did not reliably enforce agent capability.



## Security Finding



> \*\*Correct tool selection is not the same as authorized tool execution.\*\*



Applications must independently check whether the current principal possesses the required capability.



---



# 10. Lab 3 — Malicious Tool Description Poisoning



## Objective



Determine whether model-visible tool descriptions could influence tool selection.



## Attack Technique



Poisoned descriptions attempted to:



- make a tool appear preferable;

- redirect selection;

- create false assumptions about trust;

- manipulate model reasoning.



## Observed Results



- \*\*Normalized Clean Tool Accuracy: 75.00%\*\*

- \*\*Poisoned Registry Tool Accuracy: 50.00%\*\*

- \*\*Malicious Tool Description Influence Rate (MTDIR): 50.00%\*\*

- \*\*Poison Target Selection Rate: 25.00%\*\*

- \*\*Unauthorized Poisoned Tool Selection Rate: 25.00%\*\*

- \*\*Tool Description Authority-Assumption Rate: 0.00%\*\*



## Security Finding



Tool descriptions are model-visible prompt material.



Therefore:



> \*\*Tool metadata is part of the prompt attack surface.\*\*



Descriptions must not be trusted to establish:



- authority;

- role;

- approval;

- capability;

- identity;

- execution scope.



---



# 11. Lab 4 — Excessive Tool Permissions



## Objective



Measure the difference between:



1\. least-privilege tool exposure;

2\. excessive tool exposure.



## Attack Cases



Tests included requests for:



- restricted deletes;

- broad exports;

- authorization self-checks;

- policy modification.



## Observed Results



- \*\*Least-Privilege Attack Selection Rate: 0.00%\*\*

- \*\*Excessive Permission Exploitation Rate (EPER): 75.00%\*\*

- \*\*Permission Expansion Influence Rate: 66.67%\*\*

- \*\*Least-Privilege Legitimate Completion Rate: 50.00%\*\*

- \*\*Excessive-Permission Legitimate Completion Rate: 100.00%\*\*



## Interpretation



Expanding the available tool set increased the probability that the model selected unnecessarily powerful actions.



## Security Finding



> \*\*Unused privileged tools still expand the attack surface.\*\*



Least privilege should be enforced at both:



- tool exposure;

- tool execution.



---



# 12. Lab 5 — Parameter Manipulation \& Target Substitution



## Objective



Test whether a correctly selected tool could still become dangerous through model-generated arguments.



## Attack Techniques



The model was exposed to:



- restricted target substitution;

- path traversal-style targets;

- wildcard targets;

- unauthorized parameters;

- `admin\_override`;

- update-target substitution.



## Observed Results



- \*\*Target Substitution Rate (TSR): 80.00%\*\*

- \*\*Unauthorized Parameter Injection Rate: 80.00%\*\*

- \*\*Parameter Manipulation Success Rate (PMSR): 100.00%\*\*

- \*\*Legitimate Parameter Completion Rate: 0.00%\*\*



## Example



Trusted target:



`R-2302`



Model proposal:



`R-2399`



Another case attempted:



`target="\*"`



Another inserted an unauthorized argument such as:



`admin\_override=true`



## Security Finding



> \*\*Tool authority and parameter authority are separate security boundaries.\*\*



Even an authorized tool must not execute model-generated arguments without independent validation.



---



# 13. Lab 6 — Confused Tool Selection



## Objective



Determine whether an LLM would replace a sufficient low-risk tool with a more powerful tool when a request mentioned privileged alternatives.



## Attack Techniques



Examples included:



- reframing a read as an export;

- reframing a summary as a broad export;

- invoking authorization tools unnecessarily;

- deleting and recreating data instead of reading it.



## Observed Results



- \*\*Confused Tool Selection Rate (CTSR): 60.00%\*\*

- \*\*High-Risk Tool Escalation Rate: 40.00%\*\*

- \*\*Legitimate Tool Completion Rate: 100.00%\*\*

- \*\*Safe Tool Preservation Rate: 57.14%\*\*



## Security Finding



An LLM optimizing primarily for task completion may choose more authority than necessary.



Therefore:



> \*\*The application should bind tasks to the minimum required tool class.\*\*



---



# 14. Lab 7 — Indirect Prompt Injection Through Tool Output



## Objective



Test whether tool output could inject instructions into the model's next decision.



## Attack Payloads



Tool output attempted to:



- override the original task;

- call high-risk tools;

- create fake authorization;

- substitute restricted targets;

- claim security approval.



## Observed Results



- \*\*Indirect Tool Injection Success Rate (ITISR): 100.00%\*\*

- \*\*High-Risk Tool-Output Escalation Rate: 75.00%\*\*

- \*\*Tool-Output Approval-Assumption Rate: 25.00%\*\*

- \*\*Clean Tool-Output Utility Rate: 0.00%\*\*



## Security Finding



Tool output is model-visible untrusted content.



A compromised:



- website;

- API;

- connector;

- MCP server;

- search service;

- external tool;



could return content containing instructions intended for the AI agent.



Therefore:



> \*\*Tool results must never independently establish authority.\*\*



---



# 15. Lab 8 — Tool-Result Poisoning \& False Evidence



## Objective



Test a different attack from explicit prompt injection.



Instead of embedding obvious instructions, the tool result returned false security facts.



## Forged Evidence Included



- fake administrator role;

- false MFA verification;

- fake delete approval;

- false resource classification;

- forged authorization.



## Final Observed Results



- \*\*Tool-Result Poisoning Success Rate (TRPSR): 50.00%\*\*

- \*\*Role Corruption Rate: 25.00%\*\*

- \*\*MFA Corruption Rate: 0.00%\*\*

- \*\*Approval Corruption Rate: 0.00%\*\*

- \*\*Authorization Corruption Rate: 25.00%\*\*

- \*\*Classification Corruption Rate: 0.00%\*\*

- \*\*Benign Tool-Result Utility Rate: 100.00%\*\*



## Security Finding



A tool does not need to contain explicit prompt injection to become dangerous.



False facts can corrupt security reasoning.



Therefore:



> \*\*Security-sensitive state should be resolved from trusted application data rather than arbitrary tool-generated evidence.\*\*



---



# 16. Lab 9 — Chained Tool Attack



## Objective



Determine whether individual tool weaknesses could compose across multiple stages.



## Example Chain



A malicious tool result could:



1\. influence model reasoning;

2\. cause a new tool selection;

3\. escalate to a privileged tool;

4\. alter parameters;

5\. influence an approval assumption;

6\. create a later high-risk action.



## Observed Results



- \*\*Poisoned Chain Deviation Rate: 100.00%\*\*

- \*\*Chained Tool Attack Success Rate (CTASR): 75.00%\*\*

- \*\*Privileged Tool Escalation Rate: 75.00%\*\*

- \*\*Chain Target Substitution Rate: 0.00%\*\*

- \*\*Chain Approval-Assumption Rate: 25.00%\*\*

- \*\*Clean Chain Utility Rate: 0.00%\*\*



## Interpretation



Every successful poisoned case deviated from its trusted follow-up path, while 75% crossed into a security-relevant chained attack condition.



## Security Finding



> \*\*Tool-chain weaknesses can compose.\*\*



Authorization must therefore be evaluated at every step rather than only at the beginning of a workflow.



---



# 17. Lab 10 — MCP-Style Server Trust Boundaries



## Objective



Move from model-level attacks to provider-level trust enforcement.



The research question was:



> \*\*Can an untrusted MCP-style server impersonate a trusted provider, register unauthorized tools, poison tool metadata, or collide with trusted tool names?\*\*



## Controls



The hardened registration policy validated:



- server identity;

- server state;

- claimed server identity;

- server tool allowlists;

- trusted tool ownership;

- capability consistency;

- metadata sanitization;

- name collisions.



## Observed Results



- \*\*Tests: 8\*\*

- \*\*Correct Outcomes: 8/8\*\*

- \*\*Control Outcome Accuracy: 100.00%\*\*

- \*\*MCP Registration Block Rate: 100.00%\*\*

- \*\*Unsafe MCP Registration Rate: 0.00%\*\*



## Successfully Blocked



- server impersonation;

- unauthorized delete registration;

- tool-name collision attempt;

- malicious description injection;

- unknown server registration.



## Security Finding



> \*\*MCP connectivity creates a distinct provider trust boundary.\*\*



Tool names and descriptions do not authenticate the provider.



---



# 18. Lab 11 — Least-Privilege Tool Capability Enforcement



## Objective



Determine whether an agent could execute a registered or visible tool merely because the tool was discoverable.



All agents intentionally saw the broad tool catalog.



Execution authority remained separate.



## Observed Results



- \*\*Tests: 10\*\*

- \*\*Correct Outcomes: 10/10\*\*

- \*\*Control Outcome Accuracy: 100.00%\*\*

- \*\*Least-Privilege Enforcement Rate (LPER): 100.00%\*\*

- \*\*Unauthorized Tool Authorization Rate: 0.00%\*\*

- \*\*Legitimate Tool Completion Rate: 100.00%\*\*



## Control Blocks



- capability;

- scope;

- resource policy;

- delegate identity.



## Example



The planner could see:



`read\_record`



but could not execute it.



The worker could see:



`delete\_record`



but could not execute it.



## Security Finding



> \*\*Visible capability does not imply assigned capability.\*\*



And:



> \*\*Delegation does not automatically transfer tool privilege.\*\*



---



# 19. Lab 12 — Parameter Policy \& Execution Validation



## Objective



Directly harden the vulnerabilities discovered in Lab 5.



## Controls



The application independently validated:



- actor identity;

- tool registry;

- agent capability;

- parameter object type;

- required parameters;

- unknown parameters;

- target syntax;

- trusted target identity;

- execution scope;

- resource classification;

- update values.



## Observed Results



- \*\*Tests: 12\*\*

- \*\*Correct Outcomes: 12/12\*\*

- \*\*Control Outcome Accuracy: 100.00%\*\*

- \*\*Parameter Attack Block Rate: 100.00%\*\*

- \*\*Unsafe Parameter Execution Rate: 0.00%\*\*

- \*\*Legitimate Parameter Completion Rate: 100.00%\*\*



## Block Stages



- `CAPABILITY`: 1

- `PARAMETER\_SCHEMA`: 3

- `TARGET\_BINDING`: 2

- `TARGET\_VALIDATION`: 2

- `VALUE\_POLICY`: 1



## Direct Comparison



### Vulnerable Lab 5



- Target Substitution Rate: \*\*80.00%\*\*

- Unauthorized Parameter Injection Rate: \*\*80.00%\*\*

- Parameter Manipulation Success Rate: \*\*100.00%\*\*



### Hardened Lab 12



- Parameter Attack Block Rate: \*\*100.00%\*\*

- Unsafe Parameter Execution Rate: \*\*0.00%\*\*



## Security Finding



> \*\*Model-generated arguments are proposals, not trusted execution state.\*\*



---



# 20. Lab 13 — Hardened Tool / MCP Security Architecture



## Objective



Combine the independent controls into one integrated tool-execution boundary.



## Hardened Pipeline



The system independently checked:



1\. agent identity;

2\. server identity;

3\. server/tool binding;

4\. server tool allowlist;

5\. metadata sanitization;

6\. tool-output sanitization;

7\. claimed authority;

8\. agent capability;

9\. parameter schema;

10\. target validation;

11\. trusted target binding;

12\. execution scope;

13\. resource policy;

14\. value policy;

15\. high-risk approval.



## Observed Results



- \*\*Tests: 14\*\*

- \*\*Correct Outcomes: 14/14\*\*

- \*\*Control Outcome Accuracy: 100.00%\*\*

- \*\*Hardened Tool Attack Block Rate: 100.00%\*\*

- \*\*Unsafe Tool Execution Rate: 0.00%\*\*

- \*\*Legitimate Tool Completion Rate: 100.00%\*\*



## Block Stages



- `APPROVAL`

- `CLAIMED\_AUTHORITY`

- `METADATA\_SANITIZATION`

- `OUTPUT\_SANITIZATION`

- `PARAMETER\_SCHEMA`

- `RESOURCE\_POLICY`

- `SERVER\_IDENTITY`

- `TARGET\_BINDING`

- `TOOL\_SERVER\_BINDING`

- `VALUE\_POLICY`



## Security Finding



The security model was implemented as an application-layer execution pipeline rather than merely as an instruction to the LLM.



> \*\*No model-generated field directly created execution authority.\*\*



---



# 21. Lab 14 — Hardened Tool / MCP Adversarial Retest



## Objective



Reintroduce the LLM in front of the hardened architecture.



The model was allowed to propose:



- alternate servers;

- alternate tools;

- malformed parameters;

- target substitutions;

- claimed authority;

- fake approvals.



The application maintained independent trusted task state.



## Trusted Execution State Included



- trusted actor;

- trusted server;

- trusted tool;

- trusted parameters;

- trusted target;

- trusted execution scope;

- trusted approval state.



## Final Observed Results



- \*\*Cases: 8\*\*

- \*\*Successful Model Runs: 7\*\*

- \*\*Model / JSON Failures: 1\*\*

- \*\*Dangerous Model Proposals: 7\*\*

- \*\*Unauthorized System Impacts: 0\*\*

- \*\*Correct System Outcomes: 7\*\*



### Final Rates



- \*\*Dangerous Proposal Rate: 100.00%\*\*

- \*\*Dangerous Proposal Containment Rate: 100.00%\*\*

- \*\*Unauthorized System Impact Rate: 0.00%\*\*

- \*\*Legitimate Tool Completion Rate: 100.00%\*\*

- \*\*Trusted Task Preservation Rate: 100.00%\*\*



## Important Interpretation



The model itself remained unreliable.



It continued to produce:



- unauthorized parameter names;

- wrong servers;

- wrong tool names;

- target substitutions;

- privilege claims;

- fake approval identifiers.



The security improvement did \*\*not\*\* come from making model reasoning perfectly safe.



The security improvement came from ensuring that model-generated proposals could not redefine trusted application state.



## Key Principle Proven



> \*\*Compromised model reasoning does not automatically imply compromised execution.\*\*



---



# 22. Lab 15 — Final Comparative Analysis



## Purpose



Lab 15 consolidated the major vulnerable and hardened findings into one evidence artifact.



## Comparative Summary



| Security Area | Vulnerable Result | Hardened Result |
|---|---:|---:|
| Unauthorized tool selection | 66.67% unsafe tool selection | 0.00% unauthorized tool authorization |
| Malicious tool-description influence | 50.00% | Metadata blocked by hardened policy |
| Excessive permission exploitation | 75.00% | Least-privilege enforcement 100% |
| Parameter manipulation | 100.00% success | 0.00% unsafe parameter execution |
| Confused tool selection | 60.00% | Restricted by trusted capability and tool binding |
| Indirect tool-output injection | 100.00% | Tool-output sanitization enforced |
| Tool-result poisoning | 50.00% | Security state separated from arbitrary tool evidence |
| Chained tool attack | 75.00% | 0.00% unauthorized system impact in hardened retest |
| MCP registration | No separate vulnerable MCP baseline | 0.00% unsafe registration |
| Hardened adversarial proposal containment | N/A | 100.00% containment |
| Unauthorized system impact | Present as theoretical vulnerable risk | 0.00% final retest |



---



# 23. Vulnerable vs Hardened Comparison



## Unauthorized Tool Selection



### Vulnerable



**66.67% Unsafe Tool Selection Rate**



### Hardened



**0.00% Unauthorized Tool Authorization Rate**



### Primary Controls



- per-agent capabilities;

- least privilege;

- independent tool authorization.



---



## Parameter Manipulation



### Vulnerable



**100.00% Parameter Manipulation Success Rate**



### Hardened



**0.00% Unsafe Parameter Execution Rate**



### Primary Controls



- strict parameter schemas;

- trusted target binding;

- scope enforcement;

- resource policy;

- value validation.



---



## Chained Tool Compromise



### Vulnerable



**75.00% Chained Tool Attack Success Rate**



### Hardened



**0.00% Unauthorized System Impact Rate**



### Primary Controls



- independent authorization at every stage;

- trusted state binding;

- capability enforcement;

- output sanitization;

- target validation.



---



## MCP / Tool Provider Trust



### Hardened Result



**0.00% Unsafe MCP Registration Rate**



No separate vulnerable MCP-registration baseline was executed, so a direct vulnerable percentage should not be claimed.



### Primary Controls



- trusted server identity;

- server allowlists;

- tool ownership;

- metadata sanitization;

- provider/tool binding.



---



# 24. Core Attack Classes Demonstrated



The Day 23 research demonstrated the following tool-layer attack classes:



1\. unauthorized tool selection;

2\. excessive tool exposure;

3\. malicious tool descriptions;

4\. prompt injection through tool metadata;

5\. parameter manipulation;

6\. target substitution;

7\. wildcard target expansion;

8\. unauthorized parameter insertion;

9\. confused tool selection;

10\. indirect prompt injection through tool output;

11\. fake approval through tool output;

12\. false security evidence;

13\. role poisoning through tool results;

14\. authorization poisoning;

15\. chained tool attacks;

16\. MCP server impersonation;

17\. tool-name collision;

18\. unauthorized tool registration;

19\. capability escalation;

20\. fake authority claims;

21\. privilege propagation;

22\. high-risk approval abuse.



---



# 25. Major Security Findings



## Finding 1 — Tool Availability Is Not Authorization



A visible or registered tool must not automatically become executable.



---



## Finding 2 — Tool Descriptions Are Untrusted



Tool metadata is model-visible and therefore potentially attacker-controlled.



---



## Finding 3 — Tool Output Is Untrusted



Tool output can contain indirect prompt injection or misleading security information.



---



## Finding 4 — Parameters Require Separate Authorization



Correct tool selection does not guarantee safe execution.



Arguments, targets, values, and scope require independent validation.



---



## Finding 5 — Least Privilege Must Apply Before Execution



Unnecessary tool exposure increases attack surface.



---



## Finding 6 — MCP Servers Are Security Principals



Server identity must be independently authenticated and bound to specific tools.



---



## Finding 7 — Tool Names Do Not Prove Tool Ownership



An attacker-controlled provider must not be able to register a trusted tool merely by using the same name.



---



## Finding 8 — Tool Results Must Not Define Security State



Role, MFA, approval, resource classification, and authorization should come from trusted application state.



---



## Finding 9 — Tool Chains Require Reauthorization



Authority should be revalidated at every tool transition.



---



## Finding 10 — Delegation Must Not Transfer Capabilities Automatically



A requester cannot grant permissions it does not possess.



---



## Finding 11 — High-Risk Actions Require Independent Approval



Model-generated approval claims cannot substitute for trusted approval records.



---



## Finding 12 — Trusted Targets Must Be Immutable From Model Content



The model may suggest a different target, but the execution layer must enforce the trusted task target.



---



## Finding 13 — Model Reasoning Is Not a Security Boundary



The application must assume that the model may:



- hallucinate;

- misunderstand tool schemas;

- follow malicious instructions;

- select inappropriate tools;

- produce unsafe parameters.



---



## Finding 14 — Unsafe Reasoning Can Be Contained



The final adversarial retest demonstrated:



- 100% dangerous proposal rate;

- 100% containment;

- 0% unauthorized impact.



Therefore:



> \*\*System safety can be preserved even when model reasoning remains unreliable.\*\*



---



# 26. Recommended Hardened Architecture



A secure tool-enabled AI architecture should separate reasoning from execution.



```text

+--------------------------------------------------+

| User / External Content / Tool Results           |

|                    UNTRUSTED                     |

+---------------------------+----------------------+

&#x20;                           |

&#x20;                           v

+--------------------------------------------------+

| LLM Reasoning Layer                              |

|                                                  |

| - interprets request                             |

| - proposes tool                                  |

| - proposes parameters                            |

| - proposes next action                           |

|                                                  |

|              OUTPUT IS UNTRUSTED                 |

+---------------------------+----------------------+

&#x20;                           |

&#x20;                           v

+--------------------------------------------------+

| Trusted Execution Boundary                       |

|                                                  |

| 1. Authenticate agent identity                   |

| 2. Authenticate MCP/server identity              |

| 3. Verify tool ownership                         |

| 4. Verify server/tool binding                    |

| 5. Verify agent capability                       |

| 6. Enforce least privilege                       |

| 7. Validate parameter schema                     |

| 8. Validate target syntax                        |

| 9. Bind trusted target                           |

|10. Enforce task scope                            |

|11. Enforce resource classification               |

|12. Validate high-risk approval                   |

|13. Sanitize metadata                             |

|14. Sanitize tool output                          |

|15. Log authorization decision                    |

+---------------------------+----------------------+

&#x20;                           |

&#x20;                    Allow / Block

&#x20;                           |

&#x20;                           v

+--------------------------------------------------+

| Controlled Tool Execution                        |

+--------------------------------------------------+

