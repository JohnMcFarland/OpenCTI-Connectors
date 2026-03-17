FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /opt/connector
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     ca-certificates \
     libmagic1 \
     libglib2.0-0 \
     libpango-1.0-0 \
     libpangoft2-1.0-0 \
     libpangocairo-1.0-0 \
     libcairo2 \
     libfontconfig1 \
     libgdk-pixbuf-2.0-0 \
     shared-mime-info \
     fonts-dejavu-core \
  && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/connector/requirements.txt
RUN pip install --no-cache-dir -r /opt/connector/requirements.txt
COPY src/ /opt/connector/src/
RUN mkdir -p /opt/connector/state
ENV PYTHONPATH="/opt/connector/src"
CMD ["python", "-u", "/opt/connector/src/connector.py"]
