# LLM-Assisted Double Elimination

**(Warning)** We are currently refactoring this module using `asyncio` to achieve higher execution efficiency. The refactoring is still in progress, so this module is temporarily unavailable.

## Setup
1. create `.env` file in current directory and fill as following:

    ```bash
    LANGSMITH_TRACING="false"
    LANGSMITH_API_KEY="[your_langsmith_apikey]"
    LANGSMITH_PROJECT="typeforge" # or any other project name
    OPENAI_API_KEY="[your_openai_apikey]"
    BASE_URL="[your_url]"
    MODEL="gpt-4.1-mini"
    ```