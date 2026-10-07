FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

COPY src /opt/opencti-connector-team-cymru-scout

RUN apk --no-cache add git build-base libffi-dev && \
    cd /opt/opencti-connector-team-cymru-scout && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
