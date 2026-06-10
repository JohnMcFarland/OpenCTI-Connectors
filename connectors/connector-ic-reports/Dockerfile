FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 \
    libxslt1.1 \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/opencti-connector

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
