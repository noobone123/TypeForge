import pathlib
import json
import argparse
import multiprocessing
from multiprocessing import Pool
import time
from tqdm import tqdm
from functools import partial

def update_progress(result, pbar: tqdm):
    pbar.update()
    tqdm.write(result)

def process_global_morph(morph_file):
    """
    Process a global morph file.
    
    Args:
        morph_file: Path to the global morph TypeConstraint json file
    """
    try:
        with open(morph_file, 'r') as f:
            data = json.load(f)
                
        return f"Successfully processed global morph: {morph_file.name}"
    except Exception as e:
        return f"Error processing {morph_file.name}: {str(e)}"

def process_range_morph_single(morph_file):
    """
    Process a range morph file with a single morph (Morph only occurs at one range).
    
    Args:
        morph_file: Path to the range morph TypeConstraint json file
    """
    try:
        with open(morph_file, 'r') as f:
            data = json.load(f)
                
        return f"Successfully processed single range morph: {morph_file.name}"
    except Exception as e:
        return f"Error processing {morph_file.name}: {str(e)}"

def process_range_morph_multi(morph_file):
    """
    Process a range morph file with multiple morphs (Morph occurs at multiple ranges).
    This function processes each element in the range morph in parallel and aggregates the results.
    The final result is a TypeConstraint that contains all the processed range morphs.
    
    Args:
        morph_file: Path to the range morph file
    """
    try:
        with open(morph_file, 'r') as f:
            data = json.load(f)
            # morphs = data["rangeMorph"]
            
            # # Create a list of tasks for parallel processing
            # tasks = [(morph_file, idx, morph) for idx, morph in enumerate(morphs)]
            
            # # Process all elements in parallel
            # with Pool(processes = min(len(morphs), multiprocessing.cpu_count())) as pool:
            #     results = list(tqdm(pool.imap(process_range_morph_element, tasks), 
            #                         total = len(tasks),
            #                         desc = f"Processing {morph_file.name}"))
            
            # # Update the file with all processed elements
            # for idx, processed_element, _ in results:
            #     data["rangeMorph"][idx] = processed_element
                
            # with open(morph_file, 'w') as out_f:
            #     json.dump(data, out_f, indent=2)
                
        return f"Successfully processed multi-element range morph: {morph_file.name}"
    except Exception as e:
        return f"Error processing {morph_file.name}: {str(e)}"

def process_range_morph_element(args):
    """
    Process a single element in a range morph with multiple elements.
    
    Args:
        args: Tuple of (morph_file, element_index, element_data)
    """
    morph_file, element_index, element_data = args
    try:
        # Process the element here
        # This is a placeholder for the actual processing logic
        time.sleep(1)  # Simulate processing time
        
        # Return the processed element
        return (element_index, element_data, f"Successfully processed element {element_index}")
    except Exception as e:
        return (element_index, element_data, f"Error processing element {element_index}: {str(e)}")

def dispatch(judge_candidates: list[pathlib.Path]) -> None:
    """
    Dispatch the judge candidates into multiple processes for parallel processing.
    """
    global_morph = []
    range_morph_single = []
    range_morph_multi = []
    
    for candidate in judge_candidates:
        if "global" in candidate.name:
            global_morph.append(candidate)
        elif "range" in candidate.name:
            with open(candidate, 'r') as f:
                data = json.load(f)
                morphs = data.get("rangeMorph", [])
                if len(morphs) == 1:
                    range_morph_single.append(candidate)
                elif len(morphs) >= 1:
                    range_morph_multi.append(candidate)
                else:
                    print(f"Error: No range morph found in {candidate.name}")

    pools_info = []
    bar_location = 0

    if global_morph:
        total = len(global_morph)
        pbar = tqdm(total = total, desc = "[Global Morphs]", 
                    position = bar_location, 
                    dynamic_ncols = True)
        pool = Pool(processes = min(total, multiprocessing.cpu_count()))
        pools_info.append((pool, pbar))
        bar_location += 1

        for morph_file in global_morph:
            pool.apply_async(
                process_global_morph,
                args = (morph_file,),
                callback = partial(update_progress, pbar = pbar)
            )

    if range_morph_single:
        total = len(range_morph_single)
        pbar = tqdm(total = total, desc = "[Single range morphs]", position = bar_location, dynamic_ncols = True)
        pool = Pool(processes = min(total, multiprocessing.cpu_count()))
        pools_info.append((pool, pbar))
        bar_location += 1

        for morph_file in range_morph_single:
            pool.apply_async(
                process_range_morph_single,
                args = (morph_file,),
                callback = partial(update_progress, pbar = pbar)
            )

    if range_morph_multi:
        total = len(range_morph_multi)
        pbar = tqdm(total = total, desc = "[Multi range morphs]", position = bar_location, dynamic_ncols = True)
        pool = Pool(processes = min(total, multiprocessing.cpu_count()))
        pools_info.append((pool, pbar))
        bar_location += 1

        for morph_file in range_morph_multi:
            pool.apply_async(
                process_range_morph_multi,
                args = (morph_file,),
                callback = partial(update_progress, pbar = pbar)
            )

    for pool, pbar in pools_info:
        pool.close()
        pool.join()
        pbar.close()
    

if __name__== "__main__":
    parser = argparse.ArgumentParser(description = "Selecting Best-fit composite data types by comparing the readability of decompiled code variants.")
    parser.add_argument("inference", type = str, help = "Path to the directory containing the inferred TypeConstraint json files.")

    inference_dir = parser.parse_args().inference
    inference_dir = pathlib.Path(inference_dir)

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

    dispatch(judge_candidates)