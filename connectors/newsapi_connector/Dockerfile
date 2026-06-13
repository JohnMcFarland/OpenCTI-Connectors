# Playwright base image: ships a version-matched Chromium plus all browser
# system dependencies. Keep the pip playwright version (requirements.txt) equal
# to the image tag below.
FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

# libmagic1 before pip: required by python-magic, a pycti dependency that imports
# the native library at import time.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Browsers are present in the base image; this is a belt-and-suspenders ensure.
RUN playwright install chromium

COPY . .

# Persistent state (cursors, daily budget, dedup cache) is mounted here.
RUN mkdir -p /app/state
CMD ["python", "main.py"]
