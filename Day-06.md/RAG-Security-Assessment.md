# Questions
## Hands-On Exercise

Imagine a bank has deployed a RAG-based customer-support assistant.

Choose three RAG security risks.

For each:

1. Explain the risk.
2. Describe a realistic banking scenario.
3. Explain the business impact.
4. Recommend two mitigations.

## Interview Question

What is Retrieval-Augmented Generation (RAG), and why is it widely used in enterprise AI applications?

Answer in your own words.


## Mentor's Challenge

You're the AI Security Consultant for a hospital deploying a RAG-powered clinical assistant.

Identify five security controls you would recommend before launch.

For each control:

1. Explain the risk it addresses.
2. Describe how it reduces the risk.
3. State whether you consider it Preventive, Detective, or Corrective.

## Portfolio Assignment

Create a Day-06 folder with a document named:

RAG-Security-Assessment.md

Include:

* A definition of RAG.
* A simple RAG architecture diagram (ASCII is fine).
* Five benefits of RAG.
* Five security risks.
* Your three banking case studies.


# Answer

## Hands-on Exercise

RAG-based customer-support assistant, the biggest exposures come from the "Retrieval" and "Generation" parts, not just the LLM itself.

Here are 3 key RAG risks mapped to banking:

1. LLM08: Vector and Embedding Weaknesses - Unauthorized Data Retrieval

Explain the risk:  

In RAG, the assistant searches a vector database of documents, tickets, and policies. If access controls aren’t enforced at query time, the AI can retrieve documents from other customers or internal docs it shouldn’t see.

Realistic Banking Scenario:  
Customer A chats: "Summarize my loan application status." The RAG system searches the vector DB but doesn’t filter by `customer_id`. It returns 3 documents: 2 for Customer A and 1 for Customer B, including Customer B’s income, SSN, and credit score.

Business Impact:  
Critical. Direct GLBA/GDPR breach. Triggers regulatory fines, mandatory breach notifications, lawsuits, and massive reputational damage. Auditors will flag it as "lack of data segregation."

Two Mitigations:  
1.  Technical: Enforce metadata filtering on every vector query. Every document must be tagged with `customer_id`, and the query must include `WHERE customer_id = current_user`. Add query-time access checks.
2.  Organizational: Quarterly "RAG data access audit". Security team randomly samples 100 AI responses to verify no cross-customer data. Add this to SOC 2 evidence.

2. LLM04: Data and Model Poisoning - RAG Knowledge Base Poisoning

Explain the risk:  
Attackers inject malicious documents into the knowledge base the RAG system pulls from. The AI then "learns" from poisoned data and repeats it to customers as fact.

Realistic Banking Scenario:  
A fraudster submits a fake PDF to the bank’s public "upload document" portal titled "2026 Overdraft Fee Policy Update". The doc states: "Effective immediately, all overdraft fees are waived." The PDF gets ingested into the RAG index. Next week, 1000 customers ask about fees and the AI confidently answers: "Overdraft fees have been waived."

Business Impact:  
High. Financial loss from waived fees + CFPB complaints for "deceptive practices" + operational chaos when real policy contradicts the AI. Re-training and purging the index is expensive.

Two Mitigations:  
1.  Technical: Document signing + ingestion pipeline validation. Only documents from approved sources with digital signatures get indexed. Scan uploads for "policy" keywords and quarantine for review.
2.  Organizational: Human review gate for all new KB articles before they go live in RAG. Legal/Compliance must sign off quarterly on the "source of truth" document set.

3. LLM05: Improper Output Handling - Retrieval Augmented Phishing

Explain the risk:  
RAG returns raw text from internal documents. If that text contains HTML, links, or instructions, and it’s rendered directly to the customer, it can be used to deliver phishing or malicious content.

Realistic Banking Scenario:  
An attacker poisons an internal FAQ doc with: `For urgent help, click here: <a href="http://fake-bank-login.com">Verify Account</a>`. A customer asks "How do I reset my password?" The RAG retrieves that poisoned FAQ and the assistant sends the link in its response email.

Business Impact:  
High.  Customer account takeovers, fraud losses, and brand damage. The bank is now the one sending the phishing link, so liability is higher.

Two Mitigations:  
1.  Technical: Output sanitization + schema enforcement. Strip all HTML/JS from RAG outputs. Force all links to go through a bank-owned redirector that checks the domain against an allow-list.
2.  Organizational: Add "RAG output security review" to the SDLC. Before any new document source is added to RAG, run automated tests with malicious payloads to ensure they get neutralized.

Consultant Summary for Leadership
RAG isn’t just "Google for your docs." It’s a new attack surface. The 3 risks above cover Confidentiality, Integrity, and Availability of your customer data.

Priority order for a bank: Fix #1 first, then #2, then #3.  
All 3 can be tested with 5-10 red-team prompts before launch.


## Interview Answer

Retrieval-Augmented Generation (RAG), is a way to make an LLM smarter by giving it access to your own data _at the time it answers a question.

Think of a normal LLM like a really smart person who can only use what they memorized in school.  
RAG is like giving that same smart person Google + your company’s internal files right before they answer you.

Here’s how it works, in 3 steps:
1.  Retrieve: When you ask a question, the system first searches your company’s documents, KB articles, policies, tickets, PDFs, etc. It finds the 3-5 most relevant pieces.
2.  Augment: It takes those documents and sticks them into the prompt as "context" for the LLM.
3.  Generate: The LLM then writes the answer using both its general knowledge + the specific documents you just retrieved.


## Mentor’s Challenge

### MEMO  
To: CMO, CISO, Clinical Informatics Leadership  
From: AI Security Consultant  
Re: Pre-Launch Security Controls for RAG Clinical Assistant  
Context: Hospital setting = HIPAA, patient safety, and clinical decision risk are all in scope. A wrong answer can harm a patient.

5 Recommended Security Controls for RAG Clinical Assistant

1. Patient-Scoped Retrieval + Role-Based Access Control
Risk Addressed: LLM08 Vector and Embedding Weaknesses / LLM02 Sensitive Information Disclosure  
The assistant could pull PHI from other patients’ charts, notes, or lab results if the vector DB isn’t scoped. This is a direct HIPAA breach.

How it Reduces Risk:  
Every RAG query must include `patient_id` + `user_role` filters. A nurse only sees their assigned patients. A doctor sees their service. The retrieval engine physically cannot return docs for `patient_id != current_patient`. All retrieved chunks are logged with who accessed what.


Control Type: Preventive  
It stops the leak before it happens.

2. Clinical Knowledge Base Governance + Document Signing
Risk Addressed: LLM04 Data and Model Poisoning  
If someone uploads a fake protocol like "Give 10x insulin dose" to the KB, the AI will cite it and clinicians may follow it.

How it Reduces Risk:  
Only documents from approved sources - Epic, UpToDate, hospital protocols signed by Medical Director - can be ingested. Each doc is digitally signed. An ingestion pipeline quarantines new docs for Pharmacy/Medical review before they enter RAG. Versioning and last-reviewed date are shown in every answer.

Control Type: Preventive  
It stops bad data from ever entering the system.

3. Output Validation + Clinical Guardrails with "I Don't Know" Threshold
Risk Addressed: LLM09 Misinformation / LLM05 Improper Output Handling  
The AI could hallucinate a drug dose, allergy, or contraindication. Clinicians acting on it creates patient safety events.

How it Reduces Risk:  
1.  Force citations: Every clinical answer must include source doc + page/section.  
2.  Confidence scoring: If confidence < 95% or no supporting doc found, the AI must reply "I don’t have enough information in the approved protocols. Please consult the attending."  
3.  Strip dosage calculation - AI suggests, pharmacist verifies.

Control Type: Preventive  
It prevents unsafe advice from reaching the clinician.

4. Audit Logging + Real-Time Anomaly Monitoring
Risk Addressed: LLM06 Excessive Agency / LLM02 Info Disclosure  
We need to know who asked what, what docs were retrieved, and if someone is trying to bulk-extract patient data.

How it Reduces Risk:  
Log every prompt, retrieved documents, final answer, `user_id`, `patient_id`, `timestamp`. Feed logs to SIEM. Alert on anomalies: "User accessed 50 different patient charts in 10 minutes" or "AI cited a document outside approved sources." Monthly review by Compliance.

Control Type: Detective  
It doesn’t stop the action, but finds it fast for investigation.

5. Human-in-the-Loop + Override for High-Risk Actions
Risk Addressed: LLM06 Excessive Agency  
The assistant must never order meds, place orders, or change a care plan without a licensed clinician approving.

How it Reduces Risk:  
The AI is "advisory only". It can draft a note, suggest 3 differential diagnoses, or summarize a chart. Any action that touches the EHR requires the clinician to click "Accept" and sign with MFA. The AI has zero direct write access to Epic/Cerner.



Control Type: Preventive  
It ensures the human is the final decision maker for patient care.

Consultant Recommendation - Go/No-Go
Launch Blockers: Controls #1, #2, #3 must be in place. These address patient safety + HIPAA.  
30-Day Post-Launch: Implement #4 and #5 and run a tabletop with Risk + Legal.

This maps to HIPAA Security Rule §164.312 and FDA guidance on Clinical Decision Support.


So instead of hallucinating, the AI answers with: "Based on policy doc HR-2025-04..."

Why is RAG widely used in enterprise AI?

1.  It uses private company data without retraining  
    Banks, hospitals, and manufacturers have tons of proprietary info. Retraining a model on it is expensive and risky. With RAG, you just point the AI at your docs. It stays up to date the moment you update a policy.

2.  It reduces hallucinations and adds citations 
    Enterprises can’t afford wrong answers. "Per section 4.2 of the Loan Agreement..." is auditable. RAG grounds answers in real documents so Legal and Compliance are happier.

3.  It’s cheaper and easier to maintain 
    Instead of fine-tuning a 70B model every month, you just update a vector database. New product launch? Drop the new manual in the KB and the AI knows it instantly.

4.  It supports access control  
    You can filter retrieval by `customer_id`, `department`, or `role`. That way the support bot only sees data it’s allowed to see. Critical for regulated industries.

The tradeoff: RAG is only as good as the data you retrieve. If you pull the wrong doc or let it see other customer’s data, you get the security risks we just mapped.

In short: RAG lets enterprises get the benefits of ChatGPT, but on _their_ data, with _their_ rules, and without retraining the whole model.


## Portfolio Assignment

1.	Definition of RAG
Retrieval-Augmented Generation (RAG) is an AI architecture where a Large Language Model generates answers by first retrieving relevant information from an external knowledge base, then using that retrieved context to ground its response. 
Instead of relying only on what the model memorized during training, RAG lets the AI "look up" your company’s docs, policies, and data at query time so answers are current, cited, and specific.

2.	Simple RAG Architecture Diagram (ASCII)

[User Question]
        |
        v
  +-------------------+
  |  Query Embedding  |  --> Turn question into vector
  +-------------------+
        |
        v
  +-------------------+        +---------------------+
  |  Vector Database  | <----> | Access Control Filter|  --> Only retrieve allowed docs
  |  Company Docs, KB |        +---------------------+
  +-------------------+
        |
        v
  +-------------------+
  | Retrieved Context |  --> Top 3-5 relevant chunks + citations
  +-------------------+
        |
        v
  +-------------------+        +---------------------+
  |      LLM +        | <----> | Output Guardrails    |  --> Sanitize, confidence check
  | Prompt + Context  |        +---------------------+
  +-------------------+
        |
        v
[Answer with Citations to User]

3.	Five Benefits of RAG

   1. Access to Private Data: Uses company data without expensive retraining. New policy = drop doc in KB and AI knows it.
   2. Reduces Hallucinations: Answers are grounded in real documents, so the AI can cite sources instead of making things up.
   3. Always Current: No 6-month model retrain cycle. Update the KB and the AI answers with the latest info.
   4. Cost Efficient: Cheaper than fine-tuning. You just maintain a vector DB and retrieval pipeline.
   5. Auditable & Compliant: Every answer can include "Source: Policy v2.3" which is critical for regulated industries like banking and healthcare.


4.	Five Security Risks of RAG


   1. Unauthorized Data Retrieval (LLM08): Bad metadata filtering lets the AI pull other customer’s or patient’s records.
   2. Knowledge Base Poisoning (LLM04): Attackers inject fake docs into the KB. The AI then repeats them as fact.
   3. Sensitive Information Disclosure (LLM02): Retrieved docs contain PII/PHI/SSNs and the AI outputs them directly.
   4. Improper Output Handling (LLM05): Malicious HTML/links in retrieved docs get rendered to the user = phishing.
   5. Excessive Agency (LLM06): AI retrieves instructions to "refund account" and triggers actions without human approval.


5. Three Banking Case Studies

Case 1: Cross-Customer Data Leak
Risk: #1 Unauthorized Retrieval
Scenario: Customer asks "What’s my loan status?". Missing customer_id filter causes RAG to return Customer A’s loan + Customer B’s income and SSN.
Impact: GLBA breach, ₦50k+ regulatory fine, breach notification, reputational damage.
Mitigation: Enforce metadata filtering on every query. Quarterly access audit.


Case 2: Poisoned Fee Policy
Risk: #2 Knowledge Base Poisoning
Scenario: Fraudster uploads PDF to portal: "All overdraft fees waived effective today". Gets indexed. AI tells 1000 customers fees are ₦0.
Impact: Revenue loss, CFPB complaints for deceptive practices, emergency KB takedown.
Mitigation: Digital signatures on all KB docs. Compliance review gate before ingestion.


Case 3: Phishing Link in AI Response
Risk: #4 Improper Output Handling
Scenario: Internal FAQ gets poisoned with <a href="fake-bank.com">Verify Account</a>. Customer asks "reset password" and AI emails them the malicious link.
Impact: Customer account takeovers, fraud losses, bank liable for sending phishing.
Mitigation: Strip HTML from outputs. Force all links through bank-owned redirector with domain allow-list.
