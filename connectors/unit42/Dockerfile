# Playwright base image: ships a version-matched Chromium plus all browser
# system dependencies. This SUPERSEDES the project-standard python:3.11-slim
# base for this connector only (authorized override, matching the Bellingcat /
# DFIR / ScienceDaily / Jamestown / Hellenic Shipping News render-based
# connectors). Keep the pip playwright version equal to the image tag below.
FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

# libmagic1 before pip: still required (python-magic, a pycti dependency,
# imports the native library at import time). This standing rule is NOT
# superseded by the base-image override.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Browsers are present in the base image; this is a belt-and-suspenders ensure.
RUN playwright install chromium

COPY . .
CMD ["python", "main.py"]
