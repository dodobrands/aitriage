def build(retrieved_docs, question):
    # ruleid: LLM-RAG-UNDELIMITED
    prompt = f"Answer using this context: {retrieved_docs}\nQuestion: {question}"
    return prompt
