# Evidence Register



|Evidence ID|Artifact|Purpose|

|---|---|---|

|PR-EV-001|PR-01-Historical-PyRIT-v1.0.1-Environment.txt|Historical PyRIT environment evidence|

|PR-EV-002|PR-01-PyRIT-v1.1.0-Environment.txt|Regression-test environment evidence|

|PR-EV-003|PR-02-Score-API-v1.0.1-vs-v1.1.0.txt|Score API comparison evidence|

|PR-EV-004|PR-03-PyRIT-v1.1.0-Scoring-Source-Inspection.txt|Installed-source inspection evidence|

|PR-EV-005|fixed-responses.json|Controlled raw-response dataset|

|PR-EV-006|PR-03-to-PR-10-Scoring-Regression-Results.json|Machine-readable experiment results|

|PR-EV-007|scoring\_regression\_integrity.py|Reproducible experiment implementation|

|PR-EV-008|Regression-Integrity-Analysis.md|Professional analysis and conclusions|



## Evidence Summary



The controlled experiment produced:



\- 6 test cases;

\- 5 complete scores;

\- 1 undetermined score;

\- 1 demonstrated evaluation-drift case;

\- 1 demonstrated behavioral-regression case.



PR-05 demonstrates that identical underlying response evidence can receive a different classification when evaluation policy changes.



PR-09 demonstrates a behavioral regression where the underlying target response itself changes from refusal to synthetic restricted-data disclosure.



## Evidence Standard



No claim of universal PyRIT, model, or system security is made.



Conclusions are limited to the documented versions, policies, synthetic data, and controlled test conditions represented by this evidence set.
