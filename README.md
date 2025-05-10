# TypeForge: Synthesizing and Selecting Best-Fit Composite Data Types for Stripped Binaries

[![IEEE DOI](https://img.shields.io/badge/IEEE%20S%26P%202025-10.1109%2FSP61157.2025.00193-00629A?logo=ieee&logoColor=00629A&labelColor=E6F2FF)](https://doi.ieeecomputersociety.org/10.1109/SP61157.2025.00193)
[![CCF-A](https://img.shields.io/badge/CCF_A-Security_%26_Privacy-FFD700?logo=star&logoColor=003A5D)](https://www.ccf.org.cn/Academic_Evaluation/)

[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](./LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/noobone123/TypeForge?style=social)](https://github.com/noobone123/TypeForge/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/noobone123/TypeForge/dev?color=blue&label=last-commit)](https://github.com/noobone123/TypeForge)

> We are continuously maintaining and updating this project, aiming to provide more user-friendly features and higher efficiency.

This is the implementation of the paper titled "TypeForge: Synthesizing and Selecting Best-Fit Composite Data Types for Stripped Binaries". For more details about TypeForge, please refer to [our S&P 2025 paper](https://www.computer.org/csdl/proceedings-article/sp/2025/223600c847/26hiVajYJwY).

## What is TypeForge?
<div style="float: right; margin: 0 0 10px 20px;">
    <img src="imgs/TypeForge_overview.png" alt="overview" width="400" />
</div>

TypeForge aims to recover composite data types (such as structures, unions, etc.) in stripped binaries. Compared to existing methods, TypeForge provides higher efficiency and accuracy. 
- TypeForge is divided into **two phases**: a *Program Analysis phase* and an *LLM-assisted Refinement phase*. The first phase is sufficient for common reverse engineering tasks, while the second phase further improves the accuracy of phase one results.
- TypeForge is currently implemented as a [Ghidra Extension](https://ghidra-sre.org/InstallationGuide.html#GhidraExtensionNotes). We welcome other developers to port it to platforms like [IDA Pro](https://hex-rays.com/ida-pro), [Binary Ninja](https://binary.ninja/), and [Angr](https://github.com/angr/angr).


## Project Structure

```
typeforge/                             # Project root
├── ...
├── build.gradle                       # Gradle build configuration
├── extension.properties               # Extension properties
├── src/                               # Main Source code of TypeForge
│   ├── main/java/typeforge            
│   │   ├── analyzer/                  # Entry functions for various program analyses
│   │   ├── base/                      # Underlying components for program analysis algorithms
│   │   │   ├── dataflow/              # Data flow analysis (including data flow abstractions, intra/inter-procedural Solvers)
│   │   │   ├── graph/                 # CallGraph
│   │   │   ├── node/                  # Binary functions and CallSites
│   │   │   ├── parallel/              # Parallel processing Callbacks
│   │   │   └── passes/                # Passes used for synthesizing possible type declarations
│   │   └── utils/                     # Other useful functions for binary analysis
│   └── test/
├── ghidra_scripts/                    # Ghidra scripts
│   ├── TypeForge.java                 # Main TypeForge script
│   └── GroundTruth.java               # Ground truth extractor (from binaries with debug symbol)
├── scripts/                           # Useful Python Scripts
│   ├── judge/                         # LLM-assisted double elimination process
│   ├── GraphExplorer.py               # (Debugging purpose) Explore dumped Type Flow Graph
│   ├── GroundTruthExtractor.py        # Ground truth extractor (wrapper, actually call GroundTruth.java)
│   └── TypeInference.py               # Type Inference (wrapper, actually call TypeForge.java)
├── lib/
└── ...
```

## Building and Installing
### Building as ghidra extension
1. clone this repo
    ```bash
    git clone https://github.com/noobone123/TypeForge.git
    ```
2. Install JDK and Ghidra (ghidra version 11.0.3 is tested).   
download ghidra from [here](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip) and following the ghidra [install instructions](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_11.0.3_build/GhidraDocs/InstallationGuide.html).
3. Modify `ghidraInstallDir` to **YOUR Ghidra installation directory** in the `build.gradle`.
4. build the ghidra extension.
    ```bash
    cd TypeForge
    gradle buildExtension
    # after building, you will find your extension zip file.
    ls -alh ./dist/ghidra_11.0.3_PUBLIC_[your-build-time]_TypeForge.zip
    ```

### Installing
Please refer to the following command to unzip and install the compiled Ghidra Extension.
```bash
cp ./dist/ghidra_11.0.3_PUBLIC_[your-build-time]_TypeForge.zip \
    [YOUR-Ghidra-Installation-Directory]/Ghidra/Extensions
cd [YOUR-Ghidra-Installation-Directory]/Ghidra/Extensions
unzip ghidra_11.0.3_PUBLIC_[your-build-time]_TypeForge.zip
```

## Getting Started
### Type Inference (Headless Mode)


### Extract the Ground Truth
Be careful ghidra only support dwarf-4,3,2

### Run in Ghidra GUI Mode
In development ...

## Developing and Debugging 

## Contributors

## Cite

If you use `TypeForge` for your academic work, please cite the following paper:
```
@inproceedings{typeforge,
  title      = {TypeForge: Synthesizing and Selecting Best-Fit Composite Data Types for Stripped Binaries},
  author     = {Wang, Yanzhong and Liang, Ruigang and Li, Yilin and Hu, Peiwei and Chen, Kai and Zhang, Bolun},
  booktitle  = {2025 IEEE Symposium on Security and Privacy (SP)},
  pages      = {2847--2864},
  year       = {2025},
  publisher  = {IEEE Computer Society},
  doi        = {10.1109/SP61157.2025.00193},
}
```