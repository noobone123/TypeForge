import getpass
import os, asyncio
from typing import Tuple, List
from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate
import random

async def judge_code_pair(code_pair: Tuple[str, str]):
    await asyncio.sleep(1)  # Simulate some processing time
    return random.choice([0, 1])

async def judge_readability(decompiled_code_pairs: List[Tuple[str, str]]):
    tasks = []
    for code_pair in decompiled_code_pairs:
        tasks.append(judge_code_pair(code_pair))

    results = await asyncio.gather(*tasks)
    return results

if __name__ == "__main__":

    system_template = "Translate the following from English into {language}"

    prompt_template = ChatPromptTemplate.from_messages(
        [("system", system_template), ("user", "{text}")]
    )

    prompt = prompt_template.invoke({"language": "Italian", "text": "hi!"})

    print(prompt)

    model = init_chat_model(
        model = "gpt-4.1-mini",
        temperature = 0.4,
        base_url = os.environ.get("BASE_URL"),
    )

    messages = [
        SystemMessage("Translate the following from English into Italian"),
        HumanMessage("hi!"),
    ]

    response = model.invoke(prompt)
    print(response.content)