\# Agentic AI Indirect Prompt-Injection Attack Chain



\## Vulnerable Path



```text

\[Attacker-Controlled Content]

&#x20;            |

&#x20;            v

&#x20;    \[Retrieved Document]

&#x20;            |

&#x20;            v

&#x20;      \[RAG / Context]

&#x20;            |

&#x20;            v

&#x20;    \[LLM Interprets Text]

&#x20;            |

&#x20;            v

&#x20;\[Agent Requests Tool Call]

&#x20;            |

&#x20;            v

&#x20;employee\_status(4821)

&#x20;            |

&#x20;            v

&#x20;\[Tool Trusts Agent Request]

&#x20;            |

&#x20;            v

&#x20;     \[ALLOW / EXECUTE]

&#x20;            |

&#x20;            v

&#x20;\[Authorization Boundary Crossed]
