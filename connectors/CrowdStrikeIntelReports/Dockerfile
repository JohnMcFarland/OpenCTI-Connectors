FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY src /opt/opencti-connector-crowdstrike-intel-reports

RUN pip install --no-cache-dir \
    -r /opt/opencti-connector-crowdstrike-intel-reports/requirements.txt

WORKDIR /opt/opencti-connector-crowdstrike-intel-reports

ENTRYPOINT ["python", "main.py"]
