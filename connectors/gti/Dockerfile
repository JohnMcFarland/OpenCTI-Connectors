FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY src /opt/opencti-connector-gti-reports

RUN pip install --no-cache-dir -r /opt/opencti-connector-gti-reports/requirements.txt

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
