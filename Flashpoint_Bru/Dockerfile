# =============================================================================
# Dockerfile — Flashpoint Ignite Connector
# =============================================================================
# Builds the connector image for deployment via docker-compose.override.yml.
#
# BASE IMAGE: python:3.11-slim
# Consistent with all other custom connectors in this instance. The slim
# variant reduces image size by omitting documentation and non-essential
# packages, while retaining pip and the standard library.
#
# BUILD COMMAND (always use --no-cache after source or requirements changes):
#   sudo docker compose build --no-cache connector-flashpoint
#
# LIBMAGIC1:
# Required by pycti via python-magic for file type detection (used when
# handling media attachments from Flashpoint alerts). Without libmagic1,
# the connector will start but will fail when processing media-type alerts
# that attempt to attach binary content to Incident objects.
# This is a hard requirement for all custom connectors in this instance
# that handle file attachments.
# =============================================================================

FROM python:3.11-slim

# Install system dependencies before pip packages.
# libmagic1: required by pycti → python-magic for MIME type detection.
# --no-install-recommends: keeps the image lean by excluding optional packages.
# Cleanup of apt lists after install reduces the final image layer size.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/opencti-connector-flashpoint

# Copy requirements first to leverage Docker layer caching.
# If requirements.txt is unchanged, this layer is cached and pip install
# is skipped on subsequent builds — significantly faster for code-only changes.
COPY requirements.txt .

# Install Python dependencies.
# --no-cache-dir: do not cache the pip download cache in the image layer,
# reducing image size.
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code. This layer is invalidated on any source change, but
# because requirements are installed in a separate prior layer, dependencies
# are not re-installed on source-only changes.
COPY src/ .

# Entry point: run the connector directly via Python.
# main.py handles the try/except/traceback/exit(1) pattern for fatal errors.
ENTRYPOINT ["python", "main.py"]
