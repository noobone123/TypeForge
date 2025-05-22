import pathlib
import json
import argparse
import asyncio
import time
from pydantic import constr
from tqdm import tqdm
import os
import dotenv
import getpass
import aiofiles
import double_elimination
import copy
from typing import List, Dict, Any, Tuple, final

async def process_global_morph(morph_file: pathlib.Path):
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
            morph_data = json.loads(content)
            result = await double_elimination.run_async(morph_data, morph_file.name, "global")
            return ("Global", morph_file, result)
    except Exception as e:
        return ("Global", morph_file, f"Error processing {morph_file.name}: {str(e)}")

async def process_range_morph_single(morph_file: pathlib.Path):
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
            assert len(data["rangeMorph"]) == 1, f"Error: {morph_file.name} should have exactly one range morph."
            morph_data = data["rangeMorph"][0]
            start_offset = morph_data["startOffset"]
            end_offset = morph_data["endOffset"]
            result = await double_elimination.run_async(morph_data, morph_file.name, "range", (start_offset, end_offset))
            return ("Range-single", morph_file, result)
    except Exception as e:
        return ("Range-single", morph_file, f"Error processing {morph_file.name}: {str(e)}")

async def process_range_morph_multi(morph_file: pathlib.Path):
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
            assert len(morph_elements) > 1, f"Error: {morph_file.name} should have at least two range morphs."
            for i, element in enumerate(morph_elements):
                tasks.append(process_range_morph_element(morph_file, element))
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks)
            return ("Range-multi", morph_file, results)
    except Exception as e:
        return ("Range-multi", morph_file, f"Error processing {morph_file.name}: {str(e)}")

async def process_range_morph_element(morph_file: pathlib.Path, element_data: Dict[str, Any]) -> Dict[str, Any]:
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
        start_offset = element_data["startOffset"]
        end_offset = element_data["endOffset"]
        result = await double_elimination.run_async(element_data, morph_file.name, "range", (start_offset, end_offset))
        return result
    except Exception as e:
        return f"Error processing {morph_file.name}: {str(e)}"

class Task:
    """A class to encapsulate task execution and progress tracking."""
    
    def __init__(self, task_func, morph_file: pathlib.Path, pbar: tqdm):
        self.task_func = task_func
        self.morph_file = morph_file
        self.pbar = pbar
    
    async def execute(self) -> None:
        """Execute the task and handle progress updates."""
        try:
            result = await self.task_func(self.morph_file)
            await self._update_progress(result)
        except Exception as e:
            error_msg = f"Error processing {self.morph_file.name}: {str(e)}"
            await self._update_progress(error_msg)
            print(error_msg)
    
    async def _update_progress(self, result: Tuple[str, pathlib.Path, Any]) -> None:
        """Update progress bar with the result."""
        self.pbar.update()
        type = result[0]
        if type == "Global":
            champion = result[2]
            if isinstance(champion, str) and "Error" in champion:
                return
            else:
                self.pbar.update()
                file = result[1]
                # `global_morph.json` -> `global_morph_final.json`
                new_file = file.with_name(f"{file.stem}_final{file.suffix}")
                async with aiofiles.open(new_file, 'w') as f:
                    await f.write(json.dumps(champion, indent=4))

        elif type == "Range-single":
            champion = result[2]
            if isinstance(champion, str) and "Error" in champion:
                return
            else:
                self.pbar.update()
                file = result[1]
                # `range_morph_single.json` -> `range_morph_single_final.json`
                new_file = file.with_name(f"{file.stem}_final{file.suffix}")
                final_info = self._merge_constraints([champion])
                async with aiofiles.open(new_file, 'w') as f:
                    await f.write(json.dumps(final_info, indent=4))

        elif type == "Range-multi":
            champion = result[2]
            if isinstance(champion, str) and "Error" in champion:
                return
            else:
                self.pbar.update()
                file = result[1]
                # `range_morph_multi.json` -> `range_morph_multi_final.json`
                new_file = file.with_name(f"{file.stem}_final{file.suffix}")
                final_info = self._merge_constraints(champion)
                async with aiofiles.open(new_file, 'w') as f:
                    await f.write(json.dumps(final_info, indent=4))

    def _merge_constraints(self, constraints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge constraints from multiple range morphs."""
        if len(constraints) == 1:
            final_type = constraints[0]["finalType"]
            final_type_info = constraints[0]["types"][final_type]
            return {
                final_type: final_type_info
            }
        else:
            # Need to merge multiple ranges' final layouts.
            final_type_name = None
            final_type_info = None
            correct_member = {}
            for c in constraints:
                final_type = c["finalType"]
                if final_type_name is None and final_type_info is None:
                    final_type_name = final_type
                    final_type_info = copy.deepcopy(c["types"][final_type])

                start_offset = c["startOffset"]
                end_offset = c["endOffset"]
                start_int = int(start_offset, 16)
                end_int = int(end_offset, 16)
                # Removing some member info
                for offset in final_type_info["layout"].copy():
                    offset_int = int(offset, 16)
                    if start_int <= offset_int < end_int:
                        del final_type_info["layout"][offset]

                for offset, field_data in c["types"][final_type]["layout"].items():
                    offset_int = int(offset, 16)
                    if start_int <= offset_int < end_int:
                        correct_member[offset] = field_data
            
            for offset, member_info in correct_member.items():
                final_type_info["layout"][offset] = member_info
            
            # Sort final_type_info["layout"] by offset
            final_type_info["layout"] = dict(sorted(final_type_info["layout"].items(), key=lambda x: int(x[0], 16)))

            return {
                final_type_name: final_type_info
            }

async def process_task(task_func, morph_file: pathlib.Path, pbar: tqdm) -> None:
    """
    Process a task using the Task class.
    
    Args:
        task_func: Async function to execute
        morph_file: Path to the morph file
        pbar: Progress bar to update
    """
    task = Task(task_func, morph_file, pbar)
    await task.execute()

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

def main():
    """Main entry point for the async program"""
    start_time = time.time()
    # Dispatch processing tasks asynchronously
    asyncio.run(async_dispatch(judge_candidates))
    end_time = time.time()
    print(f"Total time taken: {end_time - start_time} seconds")

if __name__== "__main__":
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

    # If there are `_morph_final.json` suffix in the filename, delete that file
    for json_file in list(inference_dir.glob("*.json")):
        if "_morph_final.json" in json_file.name:
            print(f"Deleting {json_file.name} ...")
            json_file.unlink()

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

    # Run the async main function
    main()