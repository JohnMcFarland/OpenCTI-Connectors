# Self-contained build (context = this folder), the same pattern as the other
# Crucible-integrated connectors. The shared microservices/ package is NOT
# copied in: it is volume-mounted at /microservices (the parent of /app, where
# main.py looks for it) by docker-compose.yml / docker-compose.override.yml.
# Without the mount the connector runs standalone with its default
# report_type. PDF rendering is delegated to the pdf-renderer service, so
# there are no Playwright or WeasyPrint dependencies.
FROM python:3.11-slim-bookworm

# libmagic1: required by python-magic, a pycti dependency.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py config.yml ./
CMD ["python", "main.py"]
