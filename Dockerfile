# The gateway: MCP over Streamable HTTP on 8765 (/mcp) and the admin API on 8766.
# Built by docker-compose.yml; see the README for running it on its own.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

# alert-triage-agent is not on PyPI. An editable install keeps its data/ folder next to the
# package, where triage.data looks for it.
ARG TRIAGE_REPO=https://github.com/steve-alex999/alert-triage-agent.git
ARG TRIAGE_REF=main
ADD ${TRIAGE_REPO}#${TRIAGE_REF} /opt/alert-triage-agent
RUN pip install -e /opt/alert-triage-agent

WORKDIR /app
COPY pyproject.toml README.md ./
COPY gateway ./gateway
RUN pip install -e .
COPY policy.yaml ./
COPY scripts ./scripts

# Bake the embedding model into the image, as triage's image does, so containers start without
# downloading it. --build-arg EMBEDDING_PROVIDER=hash skips the model.
ARG EMBEDDING_PROVIDER=fastembed
ENV EMBEDDING_PROVIDER=$EMBEDDING_PROVIDER FASTEMBED_CACHE_PATH=/models MCP_GUARD_DB=/data/guard.db
RUN if [ "$EMBEDDING_PROVIDER" = fastembed ]; then python -c "from triage.embeddings import FastEmbedder; FastEmbedder()"; fi

EXPOSE 8765 8766
HEALTHCHECK --interval=5s --timeout=3s --start-period=60s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8766/tools')"
# Inside a container the servers listen on every interface; docker-compose.yml publishes them on
# the host's 127.0.0.1 only.
CMD ["python", "-m", "gateway.server", "--transport", "http", "--host", "0.0.0.0", "--port", "8765", \
     "--admin-port", "8766", "--client-id", "claude-code"]
