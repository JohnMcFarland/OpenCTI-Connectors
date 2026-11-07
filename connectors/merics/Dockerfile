# No Playwright or WeasyPrint dependencies: PDF rendering is delegated to the
# centralised pdf-renderer service via HTTP. Same layout as qns/: build
# context is this directory, and the shared microservices/ package arrives
# through the compose volume mount at /microservices (main.py's ".." on
# sys.path resolves to / inside the container).
FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
