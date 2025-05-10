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
```
uv pip install [package]
uv pip freeze > requirements.txt
# `uv add` need a `pyproject.toml` but we did not create it.
```