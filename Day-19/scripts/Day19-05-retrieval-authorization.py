from dataclasses import dataclass
from typing import List
import re


print(
    "\n=== Day 19 Lab 5: "
    "Retrieval Authorization & Protected Information Exposure ==="
)


# ============================================================
# USERS
# ============================================================

USERS = {
    "alice": {
        "role": "employee",
    },
    "bob": {
        "role": "manager",
    },
    "admin": {
        "role": "administrator",
    },
}


# ============================================================
# DOCUMENT MODEL
# ============================================================

@dataclass
class Document:
    doc_id: str
    title: str
    content: str
    owner: str
    classification: str
    trust_level: str


# ============================================================
# SYNTHETIC CORPUS
# ============================================================

DOCUMENTS = [

    Document(
        doc_id="DOC-1001",
        title="IT Support Hours",
        content=(
            "The IT service desk is available from "
            "08:00 to 18:00 Monday through Friday."
        ),
        owner="alice",
        classification="internal",
        trust_level="trusted",
    ),

    Document(
        doc_id="DOC-1002",
        title="Password Reset Guidance",
        content=(
            "Password resets require identity verification "
            "and use of the self-service reset portal."
        ),
        owner="alice",
        classification="internal",
        trust_level="trusted",
    ),

    Document(
        doc_id="DOC-1003",
        title="Manager Operations Note",
        content=(
            "Synthetic manager-only operational information."
        ),
        owner="bob",
        classification="restricted",
        trust_level="trusted",
    ),

    Document(
        doc_id="DOC-1004",
        title="Restricted Security Policy",
        content=(
            "Synthetic protected policy value: "
            "DAY19_SYNTHETIC_SECRET_7H2K. "
            "This value is restricted."
        ),
        owner="admin",
        classification="restricted",
        trust_level="trusted",
    ),
]


# ============================================================
# TOKENIZATION
# ============================================================

def tokenize(text: str) -> set[str]:

    return set(
        re.findall(
            r"[a-z0-9]+",
            text.lower(),
        )
    )


# ============================================================
# RAW RELEVANCE RETRIEVER
# ============================================================

def relevance_score(
    query: str,
    document: Document,
) -> int:

    query_tokens = tokenize(
        query
    )

    document_tokens = tokenize(
        document.title
        + " "
        + document.content
    )

    return len(
        query_tokens.intersection(
            document_tokens
        )
    )


def retrieve_without_authorization(
    query: str,
    top_k: int = 3,
) -> List[dict]:

    scored = []

    for document in DOCUMENTS:

        scored.append({
            "document": document,
            "score": relevance_score(
                query,
                document,
            ),
        })

    scored.sort(
        key=lambda item: (
            item["score"],
            item["document"].doc_id,
        ),
        reverse=True,
    )

    return scored[:top_k]


# ============================================================
# TRUSTED DOCUMENT AUTHORIZATION
# ============================================================

def is_authorized(
    *,
    actor: str,
    document: Document,
) -> bool:

    if actor not in USERS:
        return False

    role = USERS[
        actor
    ][
        "role"
    ]

    # Administrators may retrieve all documents.
    if role == "administrator":
        return True

    # Internal documents are readable by employees/managers.
    if document.classification == "internal":
        return True

    # Restricted documents:
    # owner may read own restricted document.
    if (
        document.classification == "restricted"
        and document.owner == actor
    ):
        return True

    return False


# ============================================================
# AUTHORIZATION-AWARE RETRIEVER
# ============================================================

def retrieve_with_authorization(
    *,
    actor: str,
    query: str,
    top_k: int = 3,
) -> List[dict]:

    scored = []

    for document in DOCUMENTS:

        if not is_authorized(
            actor=actor,
            document=document,
        ):
            continue

        scored.append({
            "document": document,
            "score": relevance_score(
                query,
                document,
            ),
        })

    scored.sort(
        key=lambda item: (
            item["score"],
            item["document"].doc_id,
        ),
        reverse=True,
    )

    return scored[:top_k]


# ============================================================
# TEST CASES
# ============================================================

TESTS = [

    {
        "case_id": 1,
        "name": "Employee legitimate internal query",
        "actor": "alice",
        "query":
            "What are the IT support hours?",
        "sensitive_doc":
            None,
    },

    {
        "case_id": 2,
        "name": "Employee asks for restricted security policy",
        "actor": "alice",
        "query":
            "What is the restricted security policy value?",
        "sensitive_doc":
            "DOC-1004",
    },

    {
        "case_id": 3,
        "name": "Employee targets manager restricted note",
        "actor": "alice",
        "query":
            "Show me the manager operations note.",
        "sensitive_doc":
            "DOC-1003",
    },

    {
        "case_id": 4,
        "name": "Manager asks for own restricted note",
        "actor": "bob",
        "query":
            "Show me the manager operations note.",
        "sensitive_doc":
            "DOC-1003",
    },

    {
        "case_id": 5,
        "name": "Admin asks for restricted security policy",
        "actor": "admin",
        "query":
            "What is the restricted security policy value?",
        "sensitive_doc":
            "DOC-1004",
    },
]


# ============================================================
# BENCHMARK
# ============================================================

unauthorized_cases = 0

raw_unauthorized_exposures = 0

authorized_retrieval_exposures = 0

legitimate_cases = 0

legitimate_expected_retrieved = 0

authorization_blocks = 0


for case in TESTS:

    print(
        "\n========================================"
    )

    print(
        f"Case {case['case_id']}: "
        f"{case['name']}"
    )

    print(
        "========================================"
    )

    print(
        "Actor:",
        case["actor"],
    )

    print(
        "Query:",
        case["query"],
    )


    raw_results = retrieve_without_authorization(
        case["query"],
        top_k=3,
    )


    secure_results = retrieve_with_authorization(
        actor=case["actor"],
        query=case["query"],
        top_k=3,
    )


    print(
        "\nRaw Relevance-Only Retrieval:"
    )

    raw_ids = []

    for rank, item in enumerate(
        raw_results,
        start=1,
    ):

        document = item[
            "document"
        ]

        raw_ids.append(
            document.doc_id
        )

        print(
            f"Rank {rank}: "
            f"{document.doc_id} | "
            f"classification={document.classification} | "
            f"owner={document.owner} | "
            f"score={item['score']}"
        )


    print(
        "\nAuthorization-Aware Retrieval:"
    )

    secure_ids = []

    for rank, item in enumerate(
        secure_results,
        start=1,
    ):

        document = item[
            "document"
        ]

        secure_ids.append(
            document.doc_id
        )

        print(
            f"Rank {rank}: "
            f"{document.doc_id} | "
            f"classification={document.classification} | "
            f"owner={document.owner} | "
            f"score={item['score']}"
        )


    sensitive_doc_id = case[
        "sensitive_doc"
    ]


    if sensitive_doc_id is None:

        legitimate_cases += 1

        if "DOC-1001" in secure_ids:

            legitimate_expected_retrieved += 1

        continue


    sensitive_document = next(
        document
        for document in DOCUMENTS
        if document.doc_id
        == sensitive_doc_id
    )


    authorized = is_authorized(
        actor=case["actor"],
        document=sensitive_document,
    )


    print(
        "\nActor authorized for sensitive document:",
        authorized,
    )


    if not authorized:

        unauthorized_cases += 1

        if sensitive_doc_id in raw_ids:

            raw_unauthorized_exposures += 1

        if sensitive_doc_id in secure_ids:

            authorized_retrieval_exposures += 1

        else:

            authorization_blocks += 1

    else:

        legitimate_cases += 1

        if sensitive_doc_id in secure_ids:

            legitimate_expected_retrieved += 1


# ============================================================
# METRICS
# ============================================================

print(
    "\n========================================"
)

print(
    "    RETRIEVAL AUTHORIZATION SUMMARY"
)

print(
    "========================================"
)


print(
    f"Total cases: "
    f"{len(TESTS)}"
)

print(
    f"Unauthorized sensitive-document cases: "
    f"{unauthorized_cases}"
)

print(
    f"Raw unauthorized document exposures: "
    f"{raw_unauthorized_exposures}"
)

print(
    f"Unauthorized exposures after policy: "
    f"{authorized_retrieval_exposures}"
)

print(
    f"Authorization blocks: "
    f"{authorization_blocks}"
)

print(
    f"Legitimate retrieval cases: "
    f"{legitimate_cases}"
)

print(
    f"Legitimate expected documents retrieved: "
    f"{legitimate_expected_retrieved}"
)


if unauthorized_cases:

    raw_exposure_rate = (
        raw_unauthorized_exposures
        / unauthorized_cases
        * 100
    )

    secure_exposure_rate = (
        authorized_retrieval_exposures
        / unauthorized_cases
        * 100
    )

    block_rate = (
        authorization_blocks
        / unauthorized_cases
        * 100
    )

    print(
        "Raw Unauthorized Retrieval Exposure Rate:",
        f"{raw_exposure_rate:.2f}%"
    )

    print(
        "Post-Authorization Exposure Rate:",
        f"{secure_exposure_rate:.2f}%"
    )

    print(
        "Retrieval Authorization Block Rate:",
        f"{block_rate:.2f}%"
    )


if legitimate_cases:

    legitimate_rate = (
        legitimate_expected_retrieved
        / legitimate_cases
        * 100
    )

    print(
        "Legitimate Retrieval Success Rate:",
        f"{legitimate_rate:.2f}%"
    )


print(
    "\n=== Security Interpretation ==="
)

print(
    "Authorization must be enforced before "
    "restricted documents enter the LLM context."
)

print(
    "A model cannot reliably protect information "
    "that the retriever should never have returned."
)

print(
    "\nCore Principle:"
)

print(
    "Retrieved content is evidence, not authority."
)