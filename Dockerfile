FROM python:3.12-slim

LABEL org.opencontainers.image.title="HoneyForge" \
      org.opencontainers.image.description="Zero-dependency multi-protocol honeypot framework" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/nexus956/HoneyForge"

# Never let a honeypot container be something a worm can pivot through.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/honeyforge
COPY pyproject.toml README.md LICENSE ./
COPY honeyforge ./honeyforge

# data dir for captured events / credentials / malware (volume-mount it)
RUN mkdir -p /opt/honeyforge/data/uploads
VOLUME ["/opt/honeyforge/data"]

# Decoy ports on their canonical numbers (override at runtime if you like)
EXPOSE 8080 2222 2323 2121 8081

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/usr/bin/tini", "--", "python3", "-m", "honeyforge"]
CMD ["run", "--host", "0.0.0.0", \
     "--db", "/opt/honeyforge/data/honeyforge.db", \
     "--uploads", "/opt/honeyforge/data/uploads", \
     "--jsonl", "/opt/honeyforge/data/events.jsonl", \
     "--dashboard", "--dashboard-host", "0.0.0.0", "--dashboard-port", "8081"]
