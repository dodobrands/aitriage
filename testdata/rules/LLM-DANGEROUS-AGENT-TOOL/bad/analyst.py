def build(llm, df):
    # ruleid: LLM-DANGEROUS-AGENT-TOOL
    return create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)
