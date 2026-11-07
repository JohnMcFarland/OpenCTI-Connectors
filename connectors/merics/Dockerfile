# Build context is connectors/ (see docker-compose.yml) so the shared
# microservices/ package lands beside the connector, matching main.py's
# sys.path insert of the parent directory. PDF rendering is delegated to the
# centralised pdf-renderer service, so no Playwright or WeasyPrint deps.
FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/merics
COPY merics/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY microservices/ /app/microservices/
COPY merics/ .
CMD ["python", "main.py"]
