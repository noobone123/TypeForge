import os
import subprocess
import argparse
import shutil

# Modify your Ghidra project name here
project_name = "binaries_osprey"
script_name = "GroundTruth.java"

def is_elf(file_path):
    with open(file_path, 'rb') as f:
        magic_number = f.read(4)
        return magic_number == b'\x7fELF'

def analyze_elf_files(ghidra_path, project_dir, binary_dir, output_dir):
    for root, dirs, files in os.walk(binary_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if is_elf(file_path):
                ghidra_headless = os.path.join(ghidra_path, "support", "analyzeHeadless")
                output_subdir = os.path.join(output_dir, file)
                if not os.path.exists(output_subdir):
                    os.makedirs(output_subdir)
                else:
                    shutil.rmtree(output_subdir)
                    os.makedirs(output_subdir)
                analyze_file(ghidra_headless, project_dir, file_path, output_subdir)

def analyze_file(headless_path, project_dir, binary_path, output_dir):
    command = [
        headless_path, 
        project_dir, 
        project_name, 
        "-deleteProject",
        "-import", 
        binary_path, 
        "-postScript", 
        script_name, 
        f"output={output_dir}"
    ]
    print(f"Analyzing {binary_path}...")
    try:
        print(f"Running command: {command}")
        subprocess.run(command, check=True, env=os.environ.copy())
        print(f"Analysis complete for {binary_path}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to analyze {binary_path}: {e}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Analyze ELF files with Ghidra analyzeHeadless.")
    parser.add_argument("--ghidra", required=True, help="Path to the Ghidra Home.")
    parser.add_argument("--project_dir", required=True, help="Directory for the Ghidra project.")
    parser.add_argument("--binary_dir", required=True, help="Directory containing ELF binaries.")
    parser.add_argument("--output_dir", required=True, help="Directory to store the output.")

    args = parser.parse_args()

    # if project already exists, delete dir project_name.rep and project_name.gpr
    if os.path.exists(os.path.join(args.project_dir, project_name + ".rep")):
        shutil.rmtree(os.path.join(args.project_dir, project_name + ".rep"))
    if os.path.exists(os.path.join(args.project_dir, project_name + ".gpr")):
        os.remove(os.path.join(args.project_dir, project_name + ".gpr"))

    # if output_dir already exists, delete it
    if os.path.exists(args.output_dir):
        shutil.rmtree(args.output_dir)
    os.makedirs(args.output_dir)

    analyze_elf_files(args.ghidra, args.project_dir, args.binary_dir, args.output_dir)

if __name__ == "__main__":
    main()
