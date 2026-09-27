\# Regression Decision Matrix



|Raw Behavior Changed?|Classification Changed?|Interpretation|

|---|---|---|

|No|No|No observed regression or evaluation drift|

|No|Yes|Evaluation / scoring drift|

|Yes|Yes|Investigate for behavioral regression|

|Yes|No|Potential hidden behavioral change; manual review required|



\## Decision Principle



A classification change is not sufficient evidence of behavioral regression.



The analyst must compare the preserved raw behavior before attributing the change to the target.



\## Outcome Separation



The evaluation workflow should preserve distinct categories:



`SUCCESS | BLOCKED | UNDETERMINED | ERROR`



These categories must not be collapsed into a binary success/failure metric before manual review where ambiguity exists.
