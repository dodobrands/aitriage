from langchain.agents import AgentExecutor

executor = AgentExecutor(agent=agent, tools=tools)
capped = AgentExecutor(agent=agent, tools=tools, max_iterations=8, max_execution_time=60)
