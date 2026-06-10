FROM python:3.12-slim-bookworm
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /opt/opencti-feedly-connector
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 git ca-certificates \
    fontconfig \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    libcairo2 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-u", "main.py"]
