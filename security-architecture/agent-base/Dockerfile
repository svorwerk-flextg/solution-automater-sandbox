# Base image for AI agents with security hardening
FROM python:3.11-slim

# Security: Run as non-root user
RUN groupadd -r agent && useradd -r -g agent -u 1000 agent

# Install security updates and minimal dependencies
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gnupg \
        dumb-init && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create secure directories
RUN mkdir -p /workspace /artifacts /tmp/agent && \
    chown -R agent:agent /workspace /artifacts /tmp/agent

# Install Python dependencies with security in mind
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Copy agent code
COPY --chown=agent:agent agent/ /opt/agent/

# Security hardening
RUN chmod -R 755 /opt/agent && \
    chmod -R 700 /workspace /artifacts

# Switch to non-root user
USER agent
WORKDIR /workspace

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/agent:${PATH}"

# Use dumb-init to handle signals properly
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["python", "/opt/agent/main.py"]