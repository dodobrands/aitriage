def build(retrieved_docs, question):
    plain = f"Question: {question}"
    prompt = f"<context>{retrieved_docs}</context>\nQuestion: {question}"
    return plain, prompt
