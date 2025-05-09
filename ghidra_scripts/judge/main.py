import pathlib
import json
import argparse
import asyncio
import time
from tqdm import tqdm
import os
import dotenv
import getpass
import aiofiles
import double_elimination
from typing import List, Dict, Any, Tuple

async def process_global_morph(morph_file: pathlib.Path) -> str:
    """
    Process a global morph file asynchronously.
    
    Args:
        morph_file: Path to the global morph TypeConstraint json file
        
    Returns:
        Result message or error message
    """
    try:
        async with aiofiles.open(morph_file, 'r') as f:
            content = await f.read()
            data = json.loads(content)
            result = await double_elimination.run_async(data)
            return f"Successfully processed global morph: {morph_file.name}"
    except Exception as e:
        return f"Error processing {morph_file.name}: {str(e)}"

async def process_range_morph_single(morph_file: pathlib.Path) -> str:
    """
    Process a range morph file with a single morph asynchronously.
    
    Args:
        morph_file: Path to the range morph TypeConstraint json file
        
    Returns:
        Result message or error message
    """
    try:
        async with aiofiles.open(morph_file, 'r') as f:
            content = await f.read()
            data = json.loads(content)
            # Process single range morph here
            # Currently just a placeholder
            return f"Successfully processed single range morph: {morph_file.name}"
    except Exception as e:
        return f"Error processing {morph_file.name}: {str(e)}"

async def process_range_morph_element(morph_file: pathlib.Path, element_index: int, element_data: Dict[str, Any]) -> Tuple[int, Dict[str, Any], str]:
    """
    Process a single element in a range morph asynchronously.
    
    Args:
        morph_file: Path to the range morph file
        element_index: Index of the element in the range morph
        element_data: Data of the element
        
    Returns:
        Tuple of (element_index, element_data, result_message)
    """
    try:
        # Process the element here - placeholder for actual processing
        await asyncio.sleep(1)  # Simulate processing time
        return (element_index, element_data, f"Successfully processed element {element_index}")
    except Exception as e:
        return (element_index, element_data, f"Error processing element {element_index}: {str(e)}")

async def process_range_morph_multi(morph_file: pathlib.Path) -> str:
    """
    Process a range morph file with multiple morphs asynchronously.
    
    Args:
        morph_file: Path to the range morph file
        
    Returns:
        Result message or error message
    """
    try:
        async with aiofiles.open(morph_file, 'r') as f:
            content = await f.read()
            data = json.loads(content)
            
            # Process elements in parallel using asyncio
            morph_elements = data.get("rangeMorph", [])
            tasks = []
            for i, element in enumerate(morph_elements):
                tasks.append(process_range_morph_element(morph_file, i, element))
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks)
            
            # Process results if needed
            # ...
                
            return f"Successfully processed multi-element range morph: {morph_file.name}"
    except Exception as e:
        return f"Error processing {morph_file.name}: {str(e)}"

async def update_progress(result: str, pbar: tqdm) -> None:
    """Update progress bar asynchronously"""
    if result is not None:
        pbar.update()
        pbar.set_description_str(f"Last: {result[:30]}...")

async def process_task(task_func, morph_file: pathlib.Path, pbar: tqdm) -> None:
    """Process a task and update progress"""
    result = await task_func(morph_file)
    await update_progress(result, pbar)

async def async_dispatch(judge_candidates: List[pathlib.Path]) -> None:
    """
    Dispatch the judge candidates asynchronously.
    
    Args:
        judge_candidates: List of paths to judge candidate files
    """
    global_morph = []
    range_morph_single = []
    range_morph_multi = []
    
    # Sort candidates into appropriate categories
    for candidate in judge_candidates:
        if "global" in candidate.name:
            global_morph.append(candidate)
        elif "range" in candidate.name:
            async with aiofiles.open(candidate, 'r') as f:
                content = await f.read()
                data = json.loads(content)
                morphs = data.get("rangeMorph", [])
                if len(morphs) == 1:
                    range_morph_single.append(candidate)
                elif len(morphs) > 1:
                    range_morph_multi.append(candidate)
                else:
                    print(f"Error: No range morph found in {candidate.name}")

    all_tasks = []
    pbars = []
    bar_location = 0
    
    # Create tasks for global morphs
    if global_morph:
        total = len(global_morph)
        pbar = tqdm(total=total, desc="[Global Morphs]", position=bar_location, dynamic_ncols=True)
        pbars.append(pbar)
        bar_location += 1
        
        for morph_file in global_morph:
            all_tasks.append(process_task(process_global_morph, morph_file, pbar))
    
    # Create tasks for single range morphs
    if range_morph_single:
        total = len(range_morph_single)
        pbar = tqdm(total=total, desc="[Single range morphs]", position=bar_location, dynamic_ncols=True)
        pbars.append(pbar)
        bar_location += 1
        
        for morph_file in range_morph_single:
            all_tasks.append(process_task(process_range_morph_single, morph_file, pbar))
    
    # Create tasks for multi-element range morphs
    if range_morph_multi:
        total = len(range_morph_multi)
        pbar = tqdm(total=total, desc="[Multi range morphs]", position=bar_location, dynamic_ncols=True)
        pbars.append(pbar)
        bar_location += 1
        
        for morph_file in range_morph_multi:
            all_tasks.append(process_task(process_range_morph_multi, morph_file, pbar))
    
    # Run all tasks concurrently
    await asyncio.gather(*all_tasks)
    
    # Close progress bars
    for pbar in pbars:
        pbar.close()

async def main():
    """Main entry point for the async program"""
    try:
        # load environment variables from .env file
        dotenv.load_dotenv()
    except ImportError:
        print("Error: `python-dotenv` is not installed. Please install it to load environment variables from .env file.")
        exit(1)
    
    # Set up environment variables
    if os.environ.get("LANGSMITH_TRACING") == "true":
        if "LANGSMITH_API_KEY" not in os.environ:
            os.environ["LANGSMITH_API_KEY"] = getpass.getpass(
                prompt="Enter your LangSmith API key (optional): "
            )
        if "LANGSMITH_PROJECT" not in os.environ:
            os.environ["LANGSMITH_PROJECT"] = getpass.getpass(
                prompt='Enter your LangSmith Project Name (default = "default"): '
            )
        if not os.environ.get("LANGSMITH_PROJECT"):
            os.environ["LANGSMITH_PROJECT"] = "default"

    if "OPENAI_API_KEY" not in os.environ:
        os.environ["OPENAI_API_KEY"] = getpass.getpass(
            prompt="Enter your OpenAI API key (required if using OpenAI): "
        )
    if not os.environ.get("OPENAI_API_KEY"):
        os.environ["OPENAI_API_KEY"] = getpass.getpass("Enter API key for OpenAI: ")
    if not os.environ.get("MODEL"):
        os.environ["MODEL"] = getpass.getpass("Enter the model name (default = gpt-4.1-mini): ")
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Selecting Best-fit composite data types by comparing the readability of decompiled code variants.")
    parser.add_argument("inference", type=str, help="Path to the directory containing the inferred TypeConstraint json files.")

    args = parser.parse_args()
    inference_dir = pathlib.Path(args.inference)

    if not inference_dir.exists():
        print(f"Error: {inference_dir} does not exist.")
        exit(1)

    # List the dir, filter all json files
    json_files = list(inference_dir.glob("*.json"))

    if not json_files:
        print(f"Error: No json files found in {inference_dir}.")
        exit(1)
    
    print(f"Found {len(json_files)} json files in {inference_dir}.")

    # If there are `morph` in the filename, add them in judge candidate list
    judge_candidates = []
    for json_file in json_files:
        if "morph" in json_file.name:
            judge_candidates.append(json_file)
    
    if not judge_candidates:
        print(f"Error: No morph json files found in {inference_dir}.")
        exit(1)
    
    print(f"Found {len(judge_candidates)} morph json files in {inference_dir}.")
    
    # Dispatch processing tasks asynchronously
    await async_dispatch(judge_candidates)

if __name__== "__main__":
    # Run the async main function
    asyncio.run(main())
    
    # ppp: just a git test ...