FROM python:3.11-slim

# Install libmagic1 before pip install. Required by pycti via python-magic.
# Omitting this causes import failures at connector startup on python:3.11-slim.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/opencti-connector-observable-gate

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Run from the src directory so that unqualified module imports resolve
# correctly (from config import ..., from api_client import ...).
# Relative imports are not used; this is the canonical entrypoint pattern
# for this connector suite.
WORKDIR /opt/opencti-connector-observable-gate/src

ENTRYPOINT ["python", "main.py"]
