FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 \
        poppler-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY report_model_qa/src/util/graph.py               /app/util/graph.py
COPY report_model_qa/src/util/entity_kb.py           /app/util/entity_kb.py
COPY report_model_qa/src/util/relationship_policy.py /app/util/relationship_policy.py
COPY report_model_qa/src/util/note_gql.py            /app/util/note_gql.py
COPY report_model_qa/src/util/object_probe.py        /app/util/object_probe.py
COPY report_enrichment/src/util/defang.py            /app/util/defang.py
RUN touch /app/util/__init__.py

COPY report_model_qa/src/util/graph.py               /app/qa/graph.py
COPY report_model_qa/src/util/entity_kb.py           /app/qa/entity_kb.py
COPY report_model_qa/src/util/relationship_policy.py /app/qa/relationship_policy.py
COPY report_model_qa/src/util/note_gql.py            /app/qa/note_gql.py
COPY report_model_qa/src/util/object_probe.py        /app/qa/object_probe.py
COPY report_model_qa/src/rules/pdf_suggestions.py    /app/qa/pdf_suggestions.py
COPY report_model_qa/src/rules/reconciliation.py     /app/qa/reconciliation.py
RUN touch /app/qa/__init__.py

COPY report_enrichment/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -r /app/requirements.txt

COPY report_enrichment/src/ /app/src/
RUN rm -rf /app/src/util/

ENV PYTHONPATH=/app

CMD ["python", "/app/src/connector.py"]
