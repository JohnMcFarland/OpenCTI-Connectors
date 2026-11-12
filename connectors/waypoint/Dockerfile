# Waypoint: one connector for every article source in sources.yml.
#
# Self-contained build (context = this folder). Not copied in:
# - the shared microservices/ package (pdf-renderer client, Crucible
#   classifier): volume-mounted at /microservices, the parent of /app, where
#   the engine looks for it. Required.
# - sources.yml: mounted read-only at /app/sources.yml, so adding, disabling
#   or tuning a source is an edit and a restart, never a rebuild.
# PDF rendering is delegated to the pdf-renderer service, so there are no
# Playwright or WeasyPrint dependencies.
FROM python:3.11-slim-bookworm

# libmagic1: required by python-magic, a pycti dependency.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py config.yml ./
COPY engine ./engine
# Per-source health (status.json); mount a volume here.
VOLUME ["/data"]
CMD ["python", "main.py"]
