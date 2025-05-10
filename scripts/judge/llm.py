import asyncio.selector_events
import getpass
import os, asyncio
from typing import Tuple, List, Literal
from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
import random

system_template = """
    You are an experienced reverse engineering expert.
    Please assess the readability of each pair of the following decompiled code snippets, where differences originate from some variables being assigned different types.
    You should disregard differences in variable and type names, and instead focus on both:
    1. The syntactic clarity of the code, and
    2. The logical rationality of its contextual semantics.

    Please return 0 if decompiled_code_0 has better readability, or 1 if decompiled_code_1 has better readability.
"""

prompt_template = ChatPromptTemplate.from_messages(
    [
        ("system", system_template), 
        ("user", "decompiled_code_0:\n{code1}\n\ndecompiled_code_1:\n{code2}\n")
    ]
)

class ReadabilityJudgment(BaseModel):
    choice: Literal[0, 1] = Field(
        description = "0 if decompiled_code_0 has better readability, 1 if decompiled_code_1 has better readability."
    )

async def judge_code_pair(code_pair: Tuple[str, str]):
    prompt = prompt_template.invoke({
        "code1": code_pair[0],
        "code2": code_pair[1]
    })
    llm = init_chat_model(
        model = os.environ.get("MODEL"),
        temperature = 0.4,
        base_url = os.environ.get("BASE_URL"),
    )
    try:
        structured_llm = llm.with_structured_output(ReadabilityJudgment)
        result = structured_llm.invoke(prompt)
        print(result.choice)
        return result.choice
    except Exception as e:
        print(f"Exception occurred in judge_code_pair: {e}")
        raise
    finally:
        if hasattr(llm, 'aclose') and callable(llm.aclose):
            await llm.aclose()

async def judge_readability(decompiled_code_pairs: List[Tuple[str, str]]):
    tasks = []
    for code_pair in decompiled_code_pairs:
        tasks.append(judge_code_pair(code_pair))

    results = await asyncio.gather(*tasks)
    return results

if __name__ == "__main__":
    pass