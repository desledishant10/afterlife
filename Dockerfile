# Afterlife: ghost-access auditor.
#
# Self-contained image for `afterlife scan/analyze/run/watch/serve`. The
# SQLite database lives at /data/afterlife.db; mount a volume at /data to
# persist it across runs. Credentials are passed as environment variables
# (see .env.example), never baked into the image.
#
#   docker build -t afterlife .
#   docker run --rm -v afterlife-data:/data --env-file .env \
#       afterlife watch --notify -s aws -s github
#
FROM python:3.12-slim

# Unprivileged user + a data dir it owns.
RUN useradd --create-home --uid 10001 afterlife \
    && mkdir -p /data && chown afterlife:afterlife /data

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

USER afterlife
WORKDIR /data
VOLUME ["/data"]

# The local dashboard (afterlife serve) listens here; bind 0.0.0.0 in-container:
#   docker run -p 8000:8000 afterlife serve --host 0.0.0.0
EXPOSE 8000

ENTRYPOINT ["afterlife"]
CMD ["--help"]
