import asyncio.selector_events
import getpass
import os, asyncio, logging
from typing import Tuple, List, Literal, Optional, Any
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

async def judge_code_pair(code_pair: Tuple[str, str]) -> int:
    """
    Judge a pair of code snippets for readability.
    
    Args:
        code_pair: A tuple of two code snippets to compare
        
    Returns:
        0 if the first code is more readable, 1 if the second is more readable
    """
    llm = None
    prompt = prompt_template.invoke({
        "code1": code_pair[0],
        "code2": code_pair[1]
    })
    
    try:
        # Use try/except to handle potential import errors
        try:
            llm = init_chat_model(
                model=os.environ.get("MODEL"),
                temperature=0.4,
                base_url=os.environ.get("BASE_URL"),
            )
        except (ImportError, AttributeError) as e:
            print(f"Failed to initialize chat model: {e}")
            return random.choice([0, 1])
            
        structured_llm = llm.with_structured_output(ReadabilityJudgment)
        result = await structured_llm.ainvoke(prompt)
        print(f"Judge result: {result.choice}")
        return result.choice
    except Exception as e:
        print(f"Exception occurred in judge_code_pair: {e}")
        # Return a random choice in case of error instead of crashing the entire process
        return random.choice([0, 1])
    finally:
        # Ensure resources are cleaned up
        if llm and hasattr(llm, 'aclose') and callable(llm.aclose):
            try:
                await llm.aclose()
            except Exception as e:
                print(f"Error closing LLM: {e}")

async def judge_readability(decompiled_code_pairs: List[Tuple[str, str]]) -> List[int]:
    """
    Judge readability of decompiled code pairs concurrently.
    
    Args:
        decompiled_code_pairs: List of tuples of decompiled code pairs
        
    Returns:
        List of judgments (0 or 1) for each pair
    """
    if not decompiled_code_pairs:
        print("No code pairs to judge")
        return []
    
    # TODO: if len(decompiled_code_pairs) > 10, do random sample.
    print(f"Judging {len(decompiled_code_pairs)} code pairs")
    
    tasks = []
    # Create task for each code pair
    for i, code_pair in enumerate(decompiled_code_pairs):
        tasks.append(judge_code_pair(code_pair))

    # Process all pairs concurrently with proper error handling
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # Handle any exceptions in results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"Error in pair {i}: {result}")
                final_results.append(random.choice([0, 1]))
            else:
                final_results.append(result)
        return final_results
    except Exception as e:
        print(f"Error in judge_readability: {e}")
        # Return fallback results if needed
        return [random.choice([0, 1]) for _ in range(len(decompiled_code_pairs))]

if __name__ == "__main__":
    pass