# Question
## Hands-on Exercise

Imagine an insurance company uses a vector database to support an AI claims assistant.

Choose three security risks related to embeddings or vector databases.

For each:

1. Explain the risk.
2. Describe a realistic insurance scenario.
3. Explain the business impact.
4. Recommend two mitigations.

## Interview Question

What is the role of embeddings in a Retrieval-Augmented Generation (RAG) system?

Answer in your own words.

## Mentor's Challenge

You are the AI Security Consultant for an insurance company deploying an AI claims assistant.

Recommend five security controls specifically for the vector database.

For each control:

1. Explain the risk it addresses.
2. Describe how it reduces the risk.
3. Classify it as Preventive, Detective, or Corrective.

## Portfolio Assignment

Create a Day-07 folder with a document named:

Embeddings-and-Vector-Database-Security.md

Include:

* A definition of embeddings.
* A definition of vector databases.
* A simple architecture diagram.
*Five business benefits.
* Five security risks.
* Your three insurance case studies.


# Answer
## Hands-on Exercise

RAG Security Briefing: Insurance Claims Assistant using Vector DB

For insurance, the stakes are PHI, claim amounts, and fraud detection. Vector DBs add new attack surfaces beyond normal databases.

Risk 1: Embedding Inversion / Sensitive Data Reconstruction 
LLM08: Vector and Embedding Weaknesses

Explain the risk:  
Embeddings are dense vectors of text. If not protected, attackers can query the vector DB and use "embedding inversion" attacks to reconstruct chunks of the original PHI or claim notes that were embedded.

Realistic Insurance Scenario:  
The claims assistant embeds all FNOL notes, doctor reports, and adjuster memos.  
Attacker asks the assistant 1000 times: "Describe claim #A123" with slight variations. They collect the retrieved vector chunks. Using an open-source inversion model, they reconstruct: "Patient Jane Doe DOB 05/12/1981 diagnosed with Stage 3 cancer. Settlement offer $250,000."

Business Impact:  
1.  HIPAA/State Privacy Breach: PHI leak = ₦50k-₦1.5M OCR fine per violation category.
2.  Legal: Lawsuit from claimant for privacy violation. Damages for emotional harm.
3.  Reputational: "Insurer AI exposed cancer diagnoses" kills trust with brokers and providers.

2 Mitigations:  
1.  Preventive - Encrypt Embeddings at Rest + Access Control: Store vectors encrypted. Enforce `policy_id` + `adjuster_id` filters on every search. Use per-tenant vector indexes so one adjuster can’t search another’s book.
2.  Preventive - Minimize What You Embed: Never embed full PHI. Use redaction pipeline before embedding: replace "Jane Doe DOB 05/12/1981" with "[REDACTED PATIENT]". Only embed the clinical facts needed for claims decisions.

Risk 2: Vector Database Poisoning via Malicious Claim Docs  
LLM04: Data and Model Poisoning

Explain the risk:  
Attackers submit fake claim documents or public notes that get embedded. The poisoned vectors sit next to real claims. When the AI retrieves "similar claims", it pulls the fake data and learns wrong fraud patterns or payout rules.

Realistic Insurance Scenario:  
Fraud ring submits 200 fake "whiplash" claims with embedded notes: "Standard payout for soft tissue injury is ₦50,000. No imaging required."  
6 months later, a legitimate claim comes in. The RAG retrieves the 200 poisoned examples as "similar cases". The AI recommends: "Approve ₦50,000, no MRI needed per precedent."

Business Impact:  
1.  Financial: ₦10M+ in overpayments because AI learned from fake data.
2.  Operational: Special Investigation Unit has to manually review 6 months of AI-recommended claims.
3.  Regulatory: State DOI audit finding for inadequate claims controls.

2 Mitigations:  
1.  Preventive - Source Provenance + Reputation Scoring: Only embed docs from Core Claims System and Medical Review. Tag each embedding with `source=verified` vs `source=public_upload`. Down-weight public docs in retrieval.
2.  Detective - Embedding Drift Monitoring: Run weekly job to cluster embeddings. Alert if 200 new embeddings suddenly appear with identical language around "payout ₦50k". Quarantine cluster for SIU review before it’s used.

Risk 3: Cross-Tenant / Cross-Line of Business Data Leakage  
LLM02: Sensitive Information Disclosure via Retrieval

Explain the risk:  
The vector DB holds embeddings from Health, Auto, and Workers Comp. If the retriever isn’t scoped, a Health claims rep can retrieve Auto claim data or vice versa. Embeddings don’t have row-level security by default.

Realistic Insurance Scenario:  
Health adjuster asks: "What did we pay for similar back surgery claims?"  
Missing LOB filter causes retriever to return vectors from Workers Comp: "Claim WC-9921: Back surgery, paid ₦450,000, employer: BigCo Manufacturing, employee SSN **-*-7788."  
The AI summarizes this to the health adjuster.

Business Impact:  
1.  Privacy Violation: You just disclosed employer + employee + WC settlement to wrong team. Workers Comp data is extra sensitive.
2.  Contract Breach: ASO/self-funded employer contracts prohibit sharing claim data across LOBs. Risk of losing ₦20M account.
3.  Audit Failure: NAIC and state exams will cite lack of data segregation.

2 Mitigations:  
1.  Preventive - Hard Tenant/Lob Partitioning: Use separate vector collections or namespaces per LOB: `health_claims`, `auto_claims`, `wc_claims`. API rejects queries without `lob=` parameter.
2.  Detective - Retrieval Logging + Anomaly Detection: Log every retrieved embedding ID + LOB + user. Alert if Health user retrieves from WC collection. Monthly audit by Compliance.

Summary for Leadership

|Risk        |	Core Threat            |	Must-Have Control        |
|------------|-------------------------|---------------------------|
|Embedding Inversion  |	Reconstruct PHI from vectors  |	Redact before embedding + encrypt vectors  |
|Vector DB Poisoning  |	Fake claims corrupt AI recommendations  |	Source tagging + drift monitoring  |
|Cross-LOB Leakage  |	Wrong team sees other LOB’s claims  |	Namespace partitioning + LOB filters    |

Recommendation: Treat your vector DB with the same controls as your data warehouse. It’s not just "search" — it’s PHI storage.


## Interview Answer

In a RAG system, embeddings are how the AI "finds" the right information before it answers.

Here’s the role broken down in plain terms:

1. The "Translation" Layer
An embedding turns text into numbers. It takes your question, and it takes every document in your knowledge base, and converts both into a long list of numbers called a vector. 
	
Think of it like this: "claim denied for pre-existing condition" and "coverage excluded due to prior illness" get turned into vectors that are mathematically very close to each other, even though the words are different.

2. The "Search Engine" Layer
Once everything is numbers, the system can do math to find similarity. When you ask a question, RAG:
1.  Converts your question into an embedding
2.  Looks through the vector database to find the 3-5 document embeddings that are mathematically "closest" to your question
3.  Pulls those actual documents back

Without embeddings, you’d only get keyword matches. With embeddings, you get _meaning_ matches.

3. The "Context Feeder" Layer
Those retrieved documents are then stuffed into the prompt along with your question and sent to the LLM. The LLM reads them and generates the answer grounded in that context.

So: Embeddings = the bridge between your question and your company’s data

Analogy:  
LLM = The smart person who can talk  
Vector DB = The company filing cabinet  
Embeddings = The index cards that let the smart person instantly find the right files before answering

Without embeddings, RAG can’t retrieve. It would just be a standard LLM guessing from memory.


## Mentor’s Challenge

MEMO 
To: CISO, Claims, Data Architecture  
From: AI Security Consultant  
Re: Vector Database Security Controls for AI Claims Assistant  
Context: Vector DBs store embeddings of PHI, claim notes, and policy docs. They are NOT like normal SQL databases — they need new controls.

5 Security Controls for the Vector Database

1. Namespace / Tenant Partitioning + Query-Time Filtering
Risk Addressed: LLM02 Sensitive Information Disclosure / Cross-LOB Leakage  
Embeddings from Health, Auto, WC, and Life are all mixed. Without controls, a Health adjuster could retrieve Workers Comp settlement amounts and SSNs.

How it Reduces Risk:  
1.  Physically or logically separate vectors by `LOB`, `line_of_business`, and `tenant_id`. Use separate collections: `health_claims_2026`, `wc_claims_2026`. 
2.  Enforce at API: Every query MUST include `lob=user.lob`. The DB rejects queries without it. This prevents "ask anything" across all data.

Control Type: Preventive  
Stops cross-customer/cross-LOB retrieval before it happens.

2. Encrypt Embeddings at Rest + In Transit + Key Rotation
Risk Addressed: LLM08 Vector and Embedding Weaknesses / Embedding Inversion  
If an attacker steals the vector DB backup, they can run embedding inversion attacks to reconstruct PHI like diagnoses, DOB, and claim amounts.

How it Reduces Risk:  
All vectors are AES-256 encrypted on disk and TLS 1.3 in transit. Use a KMS/HSM with quarterly key rotation. Even if storage is exfiltrated, vectors are useless without the key. Access to KMS requires MFA + just-in-time approval.

Control Type: Preventive  
Stops data theft from becoming a PHI breach.

3. Input Redaction + "Embed Only What's Needed" Pipeline
Risk Addressed: LLM02 Sensitive Information Disclosure  
If you embed full claim notes with "Jane Doe DOB 05/12/1981 Cancer Stage 3", that PHI now lives forever in the vector DB.

How it Reduces Risk:  
Before embedding, run a PII/PHI redaction engine. Replace `Jane Doe` → `[PATIENT]`, `05/12/1981` → `[DOB]`, `SSN **-*-1234` → `[SSN]`. Only embed the clinical facts: "diagnosis: cancer stage 3, procedure: chemo". The original doc stays in the EHR with strict access. 

Control Type: Preventive  
Minimizes the blast radius if the vector DB is compromised.

4. Retrieval Audit Logging + Anomaly Detection
Risk Addressed: LLM08 Unauthorized Access / Insider Threat  
We won’t know if an adjuster is bulk-querying 5000 claims or if an attacker is trying to scrape the DB via the AI.
How it Reduces Risk:  
Log every vector search: `user_id`, `timestamp`, `filters_used`, `top_k_doc_ids_returned`, `query_embedding_hash`. Send to SIEM. Alert on anomalies: "User accessed >100 different claim_ids in 1 hour" or "Query returned docs from 3 different LOBs". Monthly review by Compliance.

Control Type: Detective  
Doesn’t block, but finds abuse fast for investigation and forensics.

5. Embedding Provenance + Quarantine for New Data
Risk Addressed: LLM04 Data and Model Poisoning  
Fraudsters or bad integrations could upload fake claim documents. If embedded, the AI will learn from them and recommend wrong payouts.

How it Reduces Risk:  
1.  Tag every embedding with `source_system` + `approved_by` + `ingestion_date`. 
2.  New data from public portals or 3rd parties goes into a `quarantine` namespace for 7 days. SIU/Claims Lead must approve before it moves to `production` namespace. 
3.  Run weekly "drift detection" to flag clusters of 50+ new embeddings with similar language.
Control Type: Preventive for quarantine, Detective for drift detection.  
Stops poisoned data from entering the retrieval pool.


### Priority for Go-Live

Blockers: #1, #2, #3. These map to HIPAA Security Rule §164.312 and Minimum Necessary.  
90 Days Post-Launch: #4 and #5 to mature monitoring.

Vector DBs are part of your PHI environment. Treat them with the same controls as your claims data warehouse.


## Portfolio Assignment

Here’s the full pack for Embeddings + Vector DBs in Insurance:

1. Definition of Embeddings
Embeddings are numerical representations of text, images, or data.  
A model converts a chunk of text like "denied due to pre-existing condition" into a long list of numbers called a vector. 

Vectors with similar meaning end up mathematically close together. This lets an AI find "similar" content even if the exact words don’t match.

2. Definition of Vector Database
Vector Database is a specialized database designed to store, index, and search millions of those embeddings fast.  
Instead of searching by keywords, it searches by "meaning" using math to find the closest vectors to your query.

Think: The filing system for all your AI’s knowledge.

3. Simple Architecture Diagram (ASCII)

[Claim Document / Policy] 
        |
        v
+---------------------+  --> 1. Chunk + Redact PHI
|  Embedding Model    | 
+---------------------+  --> 2. Turn into vector [0.12, -0.45, ...]
        |
        v
+---------------------+  --> 3. Store with metadata: {claim_id, LOB, date}
|  Vector Database    |       Index for fast similarity search
+---------------------+
        ^
        | 6. Retrieve top 5
        |
[User Question] --> +---------------------+ --> 5. Convert to vector
                     |  Embedding Model    |
                     +---------------------+
                              |
                              v
                     +---------------------+
                     |    LLM + Context    | --> 7. Generate answer with citations
                     +---------------------+
                              |
                              v
                        [AI Claims Answer]


4. Five Business Benefits for Insurance
* Faster Claims Decisions: Adjuster asks "is PT covered post-surgery?" AI retrieves policy + similar claims in 2s instead of 20 min searching.
* Consistent Adjudication: AI grounds answers in the latest policy + precedent, reducing variance between adjusters.
* Fraud Detection: Find "similar claims" to flag patterns like 10 whiplash claims from same clinic.
* No Retraining Needed: Update a policy PDF in the vector DB and the AI knows it instantly.
* Better Member Experience: Chatbot can answer "What’s my deductible?" using the member’s specific plan doc + cite it.

5. Five Security Risks
* Embedding Inversion: Attacker reconstructs PHI from stolen vectors.
* Cross-Tenant Leakage: Health adjuster retrieves Workers Comp or other member’s data due to missing filters.
* Vector DB Poisoning: Fake claim docs get embedded and corrupt future claim recommendations.
* Sensitive Data in Vectors: PII/PHI embedded with no redaction = breach if DB is exposed.
* Lack of Auditability: Can’t trace which docs the AI retrieved for a claim = compliance/audit failure.

6. Three Insurance Case Studies

Case Study 1: PHI Reconstruction from Leaked Vectors
Risk: Embedding Inversion  
Scenario: Vector DB backup is misconfigured to public S3. Attacker downloads embeddings of all 2025 claim notes. Uses open-source model to reconstruct: "Member ID 88291, Diagnosis: HIV, Treatment: Antiretrovirals".  
Impact: HIPAA Breach. ₦1.2M OCR fine, breach notifications to 40,000 members, class action.  
Lesson: Encrypt vectors + redact PHI before embedding.

Case Study 2: Poisoned "Fraud Precedent" Causes Overpayment
Risk: Vector DB Poisoning  
Scenario: Law firm submits 150 fake public "provider appeal letters" to portal stating "Standard chiropractic settlement = ₦25,000". Gets embedded. 3 months later, AI recommends ₦25k on 80 real claims citing the fake letters as precedent.  
Impact: ₦2M in overpayments. SIU must claw back. State DOI audit finding.  
Lesson: Tag data by source. Quarantine public submissions before embedding.

Case Study 3: Cross-LOB Leak to Health Team
Risk: Cross-Tenant Data Leakage  
Scenario: Health adjuster asks "What did we pay for lumbar fusion?" Missing `LOB=Health` filter. Vector DB returns top hit from WC: "WC Claim 4412: Lumbar Fusion, Paid ₦380,000, Employer: MegaCorp, SSN **-*-9988". AI summarizes this.  
Impact: Breach of ASO employer contract. Lose ₦18M account. NAIC exam finding.  
Lesson: Enforce namespace partitioning + query-time LOB filters.


