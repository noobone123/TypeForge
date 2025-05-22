# LLM-Assisted Double Elimination

## Setup
1. Create `.env` file in current directory and fill as following:

    ```bash
    LANGSMITH_TRACING="false"
    LANGSMITH_API_KEY="[your_langsmith_apikey]"
    LANGSMITH_PROJECT="typeforge" # or any other project name
    OPENAI_API_KEY="[your_openai_apikey]"
    BASE_URL="[your_url]"
    MODEL="gpt-4.1-mini"
    ```
2. The directory containing inferred type constraints (including a series of JSON files)

## Judge
1. Run `uv run main.py [inferred_dir]` to refinement the inferred results.
2. The JSON file with the suffix `_morph_final.json` contains the final inferred type.