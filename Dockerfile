FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY data ./data

RUN pip install --upgrade pip && pip install -e .

COPY . .

# Default: run the red-team attack suite + defense gate (fully offline).
CMD ["llm-guardrails", "redteam"]
