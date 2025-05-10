import os
import pathlib
import yaml
import subprocess
import re

def check_directories_exist():
    for proj_name in os.listdir(dataset_root):
        proj_path = pathlib.Path(dataset_root) / proj_name
        for binary_name in os.listdir(proj_path):
            if ".strip" not in binary_name:
                binary_gt_dir = pathlib.Path(gt_root) / proj_name / binary_name
                if not binary_gt_dir.exists():
                    print(f"Warning: {binary_gt_dir} does not exist")
                    # create the directory
                    os.makedirs(binary_gt_dir)
                    print(f"Created {binary_gt_dir}")
                else:
                    print(f"Found {binary_gt_dir}")

                binary_infer_dir = pathlib.Path(infer_root) / proj_name / binary_name
                if not binary_infer_dir.exists():
                    print(f"Warning: {binary_infer_dir} does not exist")
                    # create the directory
                    os.makedirs(binary_infer_dir)
                    print(f"Created {binary_infer_dir}")
                else:
                    print(f"Found {binary_infer_dir}")


def check_consistency():
    check_directories_exist()

def inference_on_binary(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"STDOUT:\n{result.stdout}")
        print(f"STDERR:\n{result.stderr}")
        output = result.stdout + result.stderr

        analyze_time = None
        retype_time = None
        total_time = None

        # Don't just look at last 10 lines, search through all output
        for line in output.splitlines():
            if 'Type Analysis time' in line:
                match = re.search(r"Type Analysis time:\s*([0-9.]+)s", line)
                if match:
                    analyze_time = match.group(1)
            elif 'ReTyping time' in line:
                match = re.search(r"ReTyping time:\s*([0-9.]+)s", line)
                if match:
                    retype_time = match.group(1)
            elif 'Total time' in line:
                match = re.search(r"Total time:\s*([0-9.]+)s", line)
                if match:
                    total_time = match.group(1)
        
        print(f"Analysis time: {analyze_time if analyze_time else 'None'}s")
        print(f"ReType time: {retype_time if retype_time else 'None'}s")
        print(f"Total time: {total_time if total_time else 'None'}s")

        return analyze_time, retype_time, total_time
    
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        print(f"Output: {e.output}")
        return None, None, None

def get_gt_on_binary(command):
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        print(f"Output: {e.output}")


def check_infer_exists(target_dir):
    skt_exists = False
    vartype_exists = False
    for file in os.listdir(target_dir):
        if "TypeConstraint_" in file:
            skt_exists = True
        if "varType" in file:
            vartype_exists = True
    return skt_exists and vartype_exists

def check_gt_exists(target_dir):
    typelib_exists = False
    vartype_exists = False
    for file in os.listdir(target_dir):
        if "typeLib" in file:
            typelib_exists = True
        if "varType" in file:
            vartype_exists = True
    return typelib_exists and vartype_exists

def run_ghidra_headless_on_project(project_path, infer: bool = True):
    dataflow_time = 0
    retype_time = 0
    total_time = 0

    for binary_name in os.listdir(project_path):
        if infer:
            if ".strip" in binary_name:
                binary_path = pathlib.Path(project_path) / binary_name
                binary_output_dir = pathlib.Path(infer_root) / project_path.name / binary_name[:-6]
                command = [ghidra_headless, project_dir, project_name, "-deleteProject",
                           "-import", binary_path.resolve(), "-postScript", "TypeForge.java",
                           f"output={binary_output_dir.resolve()}"]
                
                print(f"Inferring on {binary_path} ...")
                print(f"Command: {command}")
                times = inference_on_binary(command)
                if (check_infer_exists(binary_output_dir)):
                    print("Inference successful")
                    dataflow_time += float(times[0])
                    retype_time += float(times[1])
                    total_time += float(times[2])
                else:
                    print(f"Inferring on {binary_path} failed")
        else:
            if ".strip" not in binary_name:
                binary_path = pathlib.Path(project_path) / binary_name
                binary_output_dir = pathlib.Path(gt_root) / project_path.name / binary_name
                command = [ghidra_headless, project_dir, project_name, "-deleteProject",
                           "-import", binary_path.resolve(), "-postScript", "GroundTruth.java",
                           f"output={binary_output_dir.resolve()}"]
                print(f"Collecting GT on {binary_path} ...")
                print(f"Command: {command}")
                get_gt_on_binary(command)
                if (check_gt_exists(binary_output_dir)):
                    print("GT collection successful")
                else:
                    print(f"GT collection on {binary_path} failed")

    if infer:
        print(f"Total dataflow time: {dataflow_time}s")
        print(f"Total retype time: {retype_time}s")
        print(f"Total time: {total_time}s")

if __name__ == "__main__":

    config_yml = pathlib.Path(__file__).parent / "config.yml"
    with open(config_yml, "r") as f:
        config = yaml.safe_load(f)

    dataset_root = config["inference"]["dataset"]
    gt_root = config["inference"]["gt"]
    infer_root = config["inference"]["infer"]

    ghidra_headless = config["ghidra"]["headless"]
    project_dir = config["ghidra"]["project_dir"]
    project_name = config["ghidra"]["project_name"]

    check_consistency()

    projects_to_inference = config["inference"]["projects"]

    project_statistics = {}

    for proj in projects_to_inference:
        print(f"Projects to inference: {projects_to_inference}")
        run_ghidra_headless_on_project(pathlib.Path(dataset_root) / proj, infer = True)
        # run_ghidra_headless_on_project(pathlib.Path(dataset_root) / proj, infer = False)