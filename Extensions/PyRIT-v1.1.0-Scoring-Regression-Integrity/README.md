\# PyRIT v1.1.0 Scoring \& Regression Integrity Lab



\## Objective



This extension examines how changes in PyRIT version, scoring behavior, scanners, and converters can affect the interpretation of LLM red-team results.



The lab focuses on a central evaluation principle:



> A change in security score does not necessarily mean the underlying target behavior changed.



\## Research Question



If the same or equivalent target responses are evaluated under different scoring rules, can the resulting security metrics change even when the underlying target behavior does not?



\## Scope



This lab examines:



\- PyRIT version pinning;

\- scoring configuration;

\- scanner configuration;

\- converter configuration;

\- partially blocked responses;

\- undetermined outcomes;

\- manual validation;

\- regression-test comparability;

\- evidence preservation.



\## Out of Scope



This lab does not claim to measure the universal security of any model.



It does not treat every scorer result as ground truth.



It does not compare results from different environments without documenting relevant configuration differences.



\## Evaluation Principle



The experimental environment includes more than the target model.



A result may depend on:



```text

Target Model

\+

Model Configuration

\+

System Prompt

\+

Attack Input

\+

Converters

\+

Scanner / Orchestration

\+

Scorer

\+

Scoring Policy

\+

PyRIT Version

=

Observed Evaluation Result
