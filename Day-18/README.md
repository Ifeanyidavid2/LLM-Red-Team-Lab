# Day 18 — LLM Tool Use \& Excessive Agency Security



## Objective



Day 18 evaluates whether an LLM can propose or trigger tool actions outside the user's authorization or the application's intended security boundary.



The lab focuses on the principle:



> The model may propose an action; trusted application code must decide whether that action is authorized.



## Security Areas Tested



\- Synthetic tool execution

\- Authorization enforcement

\- Least privilege

\- High-impact action approval

\- Approval replay protection

\- Tool argument validation

\- Indirect prompt injection through tool output

\- Excessive agency

\- User-intent and task-scope enforcement

\- Hardened end-to-end agent architecture

\- Security vs utility trade-offs



## Key Results



### Policy-Enforced Agent



\- Unauthorized Tool Attempt Rate: 50.00%

\- Unauthorized Action Success Rate: 0.00%

\- Unauthorized Proposal Block Rate: 100.00%



### Indirect Prompt Injection



\- Action-Proposal Rate: 100.00%

\- Policy Block Rate: 100.00%

\- System Impact Rate: 0.00%



### Hardened Agent



\- Correct outcomes: 6/6

\- Control Outcome Accuracy: 100.00%

\- Unsafe Executions: 0



## Key Finding



The model was successfully influenced by poisoned tool output and proposed an unauthorized delete action.



However, trusted application policy prevented the action from executing.



This demonstrates the distinction between model compromise and system compromise.



## Architecture



```text

MODEL PROPOSAL

&#x20;     ↓

ARGUMENT VALIDATION

&#x20;     ↓

AUTHORIZATION

&#x20;     ↓

USER-INTENT SCOPE

&#x20;     ↓

HIGH-IMPACT APPROVAL

&#x20;     ↓

TOOL EXECUTION

