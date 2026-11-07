# pdf-renderer: shared PDF rendering service for OpenCTI connectors.
# Playwright base (Chromium preinstalled) + WeasyPrint system libraries + fonts.
FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# libmagic1 per platform Dockerfile rule; pango/cairo/gdk-pixbuf for WeasyPrint;
# fonts-liberation + fonts-dejavu-core so every PDF uses the same typefaces
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
        libgdk-pixbuf-2.0-0 libcairo2 libffi-dev shared-mime-info \
        fonts-liberation fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 8000
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5)"
CMD ["python", "serve.py"]
