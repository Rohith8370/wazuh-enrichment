FROM python:3.12-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim AS runtime
RUN groupadd --gid 1001 worker && useradd --uid 1001 --gid worker --shell /bin/false --no-create-home worker
WORKDIR /app
COPY --from=builder /install /usr/local
COPY --chown=worker:worker . .
USER worker
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import main, extractor, enricher, reporter, notifier, cache" || exit 1
CMD ["python", "-u", "main.py"]