# Project-standard base (python:3.11-slim, house norm across connectors).
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /opt/connector

# libmagic1 before pip: python-magic (a pycti dependency) binds the native libmagic
# at import time, so the connector dies at start without it.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# searches.yml (and optionally config.yml) are mounted at /opt/connector at runtime.
CMD ["python", "-m", "src.main"]
