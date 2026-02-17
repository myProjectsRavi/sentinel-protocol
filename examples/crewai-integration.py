import os

from crewai import Agent, Crew, Task
from crewai.llm import LLM


llm = LLM(
    model="gpt-4.1-mini",
    api_key=os.environ.get("OPENAI_API_KEY", ""),
    base_url="http://127.0.0.1:8787/v1",
    headers={"x-sentinel-target": "openai"},
)

agent = Agent(
    role="Security Analyst",
    goal="Summarize risk with safe tool usage",
    backstory="You follow strict security rules for agent execution.",
    llm=llm,
)

task = Task(
    description="Provide three recommendations for reducing prompt-injection risk.",
    expected_output="Three concise recommendations.",
    agent=agent,
)

crew = Crew(agents=[agent], tasks=[task], verbose=True)
result = crew.kickoff()
print(result)
