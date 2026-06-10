FROM python:3.12-slim

WORKDIR /opt/connector

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libmagic1 \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Run the connector
CMD ["python", "-u", "/opt/connector/src/main.py"]
