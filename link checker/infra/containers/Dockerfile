# Build from the repository root:  docker build -f infra/containers/Dockerfile -t unmask:1.0.0 .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src \
    UNMASK_ENVIRONMENT=production UNMASK_DATABASE_PATH=/data/unmask.db UNMASK_HOST=0.0.0.0

WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY src ./src
COPY config ./config
COPY migrations ./migrations
COPY assets ./assets

# Run as an unprivileged user; the only writable location is the data volume.
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin unmask \
 && mkdir /data && chown unmask /data
USER unmask
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/ready', timeout=4).status == 200 else 1)"

# Schema changes are applied by this explicit step, never silently by the running app.
CMD ["sh", "-c", "python -m interfaces.cli migrate && python -m interfaces.cli serve --host 0.0.0.0 --port 8000"]
