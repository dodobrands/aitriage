def retrieve(store, question, user):
    return store.similarity_search(question, k=4, filter={"tenant_id": user.tenant_id})
