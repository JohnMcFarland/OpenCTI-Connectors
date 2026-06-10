FROM python:3.11-slim

# libmagic1 is required by pycti via python-magic.
# Must be installed via apt BEFORE the pip install step to prevent ImportError
# at connector runtime. This is a hard requirement for all connectors in this
# project — omitting it causes pycti to fail on import.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first to leverage Docker layer caching.
# Requirements layer is only rebuilt when requirements.txt changes,
# not on every source file change.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy connector source files
COPY connector.py graph_fetcher.py note_builder.py ./

ENTRYPOINT ["python", "connector.py"]
