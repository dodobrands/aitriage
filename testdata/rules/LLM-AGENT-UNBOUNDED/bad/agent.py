from langchain.agents import AgentExecutor

# ruleid: LLM-AGENT-UNBOUNDED
executor = AgentExecutor(agent=agent, tools=tools, max_iterations=None)
