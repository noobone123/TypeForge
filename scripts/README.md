# TypeForge (Python Scripts)

## Setup
TypeForge uses `uv` to manage Python packages and dependencies. To setup, you should:
1. Install python package manager `uv`
2. Create new virtual environment and install dependencies

    ```bash
    uv venv .venv
    uv pip install --requirement requirements.txt    
    ```
3. Active this virtual environment

    ```bash
    source .venv/bin/activate
    ```

If you want to add other packages, just run:
```bash
uv pip install [package]
uv pip freeze > requirements.txt
# `uv add` need a `pyproject.toml` but we did not create it.
```

## Type Inference (Batch Mode)
If a series of binaries need to be processed, you should:
1. Update the `config.yml` to specify the required metadata.
2. Prepare the dataset:
   The directory structure for each project in the dataset should follow this format: `dataset_root/project_name`. Each project should contain pairs of binaries: one with debug symbols (named `binary_name`, used only for Ground Truth Extraction) and one stripped binary (named `binary_name.strip`, used during Type Inference).
3. Update the `projects` field in `config.yml` to include all projects you want to process. All binaries under these projects will be processed.
4. Run the script:

   ```bash
   python3 ./TypeInference.py
   ```

## Extract Ground Truth (Batch Mode)
The preparation steps are the same as above. You only need to modify the following code in `TypeInference.py`:

```python
# Set `infer = False` to collect ground truth instead of performing inference
run_ghidra_headless_on_project(pathlib.Path(dataset_root) / proj, infer = False)
```