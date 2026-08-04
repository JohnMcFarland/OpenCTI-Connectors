# Project-standard base (CLAUDE.md: python:3.11-slim, house norm across connectors).
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /opt/connector

# libmagic1 before pip: python-magic (a pycti dependency) binds the native libmagic
# at import time, so the system package must be present before the pip install or the
# connector dies at process start before it can register.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Run as the package entrypoint (src/main.py).
CMD ["python", "-m", "src.main"]
