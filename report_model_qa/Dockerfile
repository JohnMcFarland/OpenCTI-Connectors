FROM python:3.11-slim@sha256:4057d02a202f69bfbfe10f65300519f612eb00fc595b8499f77d3cfe5b1b9fd4

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /opt/connector

# System deps:
# - ca-certificates: TLS
# - libmagic1: required by python-magic (pycti dependency)
# - file: optional but useful; shares libmagic backend
# - poppler-utils: provides pdftotext (strong text extraction)
# - tesseract-ocr (+ eng): OCR fallback for image-based PDFs
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     ca-certificates \
     libmagic1 \
     file \
     poppler-utils \
     tesseract-ocr \
     tesseract-ocr-eng \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/connector/requirements.txt
RUN pip install --no-cache-dir -r /opt/connector/requirements.txt

COPY src/ /opt/connector/src/

ENV PYTHONPATH="/opt/connector/src"

CMD ["python", "-u", "/opt/connector/src/connector.py"]
