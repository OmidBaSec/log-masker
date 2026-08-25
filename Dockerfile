# Log Masker container image.
#
#   docker build -t log-masker .
#   docker run -p 8888:8888 -v logmasker-data:/data \
#              -e LOGMASKER_MASTER_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
#              -e ANTHROPIC_API_KEY=sk-ant-... log-masker
#
# Read the security note at the bottom before exposing this to anything.

FROM python:3.13-slim AS build

WORKDIR /build
COPY requirements.lock .
# Wheels only where possible; the venv is copied wholesale into the final image
# so build tools never ship.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.lock


FROM python:3.13-slim

# A container has no OS keychain and no D-Bus, so keystore.py falls back to its
# encrypted-file tier. Supply LOGMASKER_MASTER_KEY from your secret manager and
# the key never touches the image or the volume.
ENV LOGMASKER_DATA_DIR=/data \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=build /opt/venv /opt/venv

WORKDIR /app
COPY --chown=root:root log_masker/ ./log_masker/

# Unprivileged, and owning only the data volume.
RUN useradd --system --uid 10001 --create-home --home-dir /home/logmasker logmasker \
    && mkdir -p /data \
    && chown logmasker:logmasker /data
USER logmasker
VOLUME ["/data"]

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8888/healthz', timeout=2).status == 200 else 1)"

# Inside the container 127.0.0.1 would be unreachable from outside, so the app
# must bind 0.0.0.0 — which it refuses to do unless told explicitly. That is the
# point: you are now responsible for what sits in front of it.
#
# LOGMASKER_ALLOWED_HOSTS must name the host clients use, or the request guard
# will refuse them (it only trusts loopback names by default).
ENV LOGMASKER_ALLOW_REMOTE=1 \
    LOGMASKER_ALLOWED_HOSTS=localhost
CMD ["uvicorn", "log_masker.app:app", "--host", "0.0.0.0", "--port", "8888"]

# SECURITY: this image has no authentication. Anything that can reach port 8888
# can read the entity vault and spend your API credit. Publish it only behind an
# authenticating reverse proxy (oauth2-proxy, Cloudflare Access, your identity
# provider), or bind it to localhost: -p 127.0.0.1:8888:8888
