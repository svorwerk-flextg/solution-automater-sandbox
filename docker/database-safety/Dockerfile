# Database Safety Layer Dockerfile
# Multi-stage build for production-ready container

# ===== BUILD STAGE =====
FROM python:3.11-slim as builder

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    pkg-config \
    libssl-dev \
    libffi-dev \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install wheel
RUN pip install --upgrade pip wheel setuptools

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ===== RUNTIME STAGE =====
FROM python:3.11-slim as runtime

# Install runtime system dependencies
RUN apt-get update && apt-get install -y \
    # Database drivers
    unixodbc \
    unixodbc-dev \
    # Microsoft SQL Server ODBC Driver
    curl \
    gnupg \
    # SQLite
    sqlite3 \
    # Utilities
    procps \
    net-tools \
    netcat-traditional \
    # Cleanup
    && curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
    && curl https://packages.microsoft.com/config/debian/11/prod.list > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y msodbcsql17 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create application user
RUN groupadd -r dbsafety && useradd -r -g dbsafety -d /app -s /bin/bash dbsafety

# Create application directory structure
RUN mkdir -p /app /app/config /app/logs /app/data /app/backups \
    /var/log/database_safety /tmp/database_sandboxes \
    && chown -R dbsafety:dbsafety /app /var/log/database_safety /tmp/database_sandboxes

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=dbsafety:dbsafety src/database_safety/ /app/database_safety/
COPY --chown=dbsafety:dbsafety configs/ /app/config/
COPY --chown=dbsafety:dbsafety scripts/ /app/scripts/

# Copy entry scripts
COPY --chown=dbsafety:dbsafety docker/database-safety/entrypoint.sh /app/entrypoint.sh
COPY --chown=dbsafety:dbsafety docker/database-safety/healthcheck.sh /app/healthcheck.sh

# Make scripts executable
RUN chmod +x /app/entrypoint.sh /app/healthcheck.sh /app/scripts/*.sh

# Create CLI symlink
RUN ln -s /app/database_safety/cli/db_safety_cli.py /usr/local/bin/db-safety

# Set Python path
ENV PYTHONPATH="/app/database_safety:/app:$PYTHONPATH"

# Set default environment variables
ENV DB_SAFETY_PORT=8080 \
    DB_SAFETY_HOST=0.0.0.0 \
    DB_SAFETY_LOG_LEVEL=INFO \
    DB_SAFETY_CONFIG=/app/config/database_safety_config.yaml \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Expose port
EXPOSE 8080

# Switch to application user
USER dbsafety

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD /app/healthcheck.sh

# Entry point
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command
CMD ["api"]