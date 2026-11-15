# REGIONAL-LIVEPDF-V1: PDFs are rendered by the pdf-renderer service, so this
# connector no longer needs the Playwright base image. Project-standard base.
FROM python:3.11-slim

# libmagic1 before pip (python-magic, a pycti dependency, loads it at import).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
CMD ["python", "main.py"]
