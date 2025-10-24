# Evaluation of TypeForge

We upload some evaluate data from an early version of TypeForge, which includes the Binary, Ground Truth and Inferred Results (specifically, the results before the LLM refinement stage).

You can find these data here: 
1. TypeForge_Dataset: https://drive.google.com/file/d/1Mn_V7gh42l5fJXlVM2OCK9YeYS4igUHA/view?usp=sharing
2. TypeForge_GroundTruth: https://drive.google.com/file/d/10jgukb2IVKJpPGcm61jts510XqqEzOzI/view?usp=sharing
3. TypeForge_Inferred: https://drive.google.com/file/d/1tHruIgS2glZR9LpakVFPeHMVDzLW4AqU/view?usp=sharing

In these data, you may find `coreutils-osprey`, which is the CoreUtils dataset provided by the Osprey authors (please note their version might differ slightly from ours).

We want to note a few important points about above evaluate data:
1. **Early Version**: These inferred results are from an early version of TypeForge, as the TypeForge is under continuous maintenance, they may not accurately represent TypeForge's current capabilities.
For instance, after our paper submission, we fixed a **critical bug** that caused the performance on the Composite Data Type Identification task to be much lower than expected. (You can see details here: [commit-1](https://github.com/noobone123/TypeForge/commit/028ce182c1f3103bc02989b6870e9c209919e30a)
and [commit-2](https://github.com/noobone123/TypeForge/commit/a027cc197dca339bcf93831c95925593ec3b12cb). To evaluate the capabilities of the latest version of TypeForge, you should compile and rerun it on the dataset.

2. **Pre-LLM Stage**: The results are before the LLM refinement stage. You can run the [judge script](https://github.com/noobone123/TypeForge/tree/main/scripts/judge) to get the LLM-refined results yourself,
or, of course, apply any other heuristic refinement methods you prefer (see [demo](https://github.com/noobone123/TypeForge/tree/main/demo) for the input/output data format).

3. **Evaluate Script**:  We are not providing a specific evaluation script at this time, as creating a perfectly accurate evaluator is also a challenging research problem in itself.
The main difficulty lies in aligning variables across different compilers, optimization levels, and stripped vs. unstripped binaries.
To aid researchers in this evaluation, we have stored essential variable metadata (e.g., Location and First Used Address) in `varType.json` for each binary.
This metadata is what we used internally for alignment and comparison. We believe this data will be valuable for developing and standardizing future evaluation methodologies.
There is also some discussion on this alignment challenge [here](https://github.com/noobone123/TypeForge/issues/18).
