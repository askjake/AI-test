# Phase 2 — computer-use environment. Phase 8 — least-privilege runtime.
# Debian base + Xvfb virtual display, a light WM, and the tools the vision loop drives:
# xdotool (input), scrot/imagemagick (capture), plus the target clients (xterm + ssh,
# xfreerdp, xtigervncviewer). Runs as a non-root user; the root FS is meant to be mounted READ-ONLY at run
# time (see scripts/run_container.sh / docker-run.md). The image carries no secrets and no
# AWS creds — those arrive at run time via env/role and the read-only secrets/ mount.
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    DISPLAY=:1 \
    HOME=/home/orchestrator \
    XDG_RUNTIME_DIR=/tmp/runtime \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src

# System packages for the virtual display, input/capture, and target clients.
RUN apt-get update && apt-get install -y --no-install-recommends \
        xvfb \
        fluxbox \
        xdotool \
        scrot \
        imagemagick \
        x11-utils \
        openssh-client \
        sshpass \
        xterm \
        xfonts-base \
        freerdp2-x11 \
        tigervnc-viewer \
        ca-certificates \
        # egress allowlist enforcement (P8-2; applied as root via docker/egress_firewall.sh)
        iptables \
        dnsutils \
        # sample GUI apps (xclock/xeyes) for the Phase 2 gate
        x11-apps \
    && rm -rf /var/lib/apt/lists/*

# Sublime Text: the .deb is vendored into the build context (downloaded on the host, where
# corporate-proxy TLS is trusted) rather than fetched over HTTPS from inside the build —
# the build VM does not carry the corporate root CA. Dependencies resolve from the plain-HTTP
# Debian mirror that the base packages above already used.
COPY docker/vendor/sublime-text_build-4200_amd64.deb /tmp/sublime-text.deb
RUN apt-get update \
    && apt-get install -y --no-install-recommends /tmp/sublime-text.deb \
    && rm -f /tmp/sublime-text.deb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for layer caching.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Application source.
COPY src/ /app/src/
COPY templates/ /app/templates/
COPY scripts/ /app/scripts/
COPY docker/entrypoint.sh /app/entrypoint.sh
COPY docker/egress_firewall.sh /app/docker/egress_firewall.sh
# Git preserves only the executable bit, while an owner umask can leave a
# reviewed working-tree patch at 0600/0700.  Normalize only non-secret packaged
# application content so uid 10001 can import and execute it. Runtime secrets,
# credentials, reports, and mounted project inputs are created later and are
# deliberately outside this permission change.
RUN chmod -R a+rX /app/src /app/templates /app/scripts \
    && chmod 0755 /app/entrypoint.sh /app/docker/egress_firewall.sh

# Non-root runtime user. Under rootless podman this uid is mapped into the host user's
# subuid range. Mount points are created and handed to the user so the read-only
# specs/secrets mounts and the writable reports mount all resolve.
RUN useradd --create-home --uid 10001 orchestrator \
    && mkdir -p \
        /app/tests_specs \
        /app/tests_manuals \
        /app/reports \
        /app/secrets \
        /app/secrets-source \
        /app/aws-credentials-source \
        /app/aws-config-source \
        /app/aws-runtime \
    && chown -R orchestrator:orchestrator /app

USER orchestrator

ENTRYPOINT ["/app/entrypoint.sh"]
# Default: scheduler in long-running mode. Override (e.g. `--once`) at run time.
CMD ["python", "-m", "orchestrator.scheduler"]
