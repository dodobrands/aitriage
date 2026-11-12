def retrieve(store, question):
    # ruleid: LLM-VECTOR-NO-TENANT-FILTER
    return store.similarity_search(question, k=4)
