# BLNCS - Bitcoin Lightning Network Control System
FROM python:3.10-slim

LABEL maintainer="BLNCS Development Team"
LABEL description="Bitcoin Lightning Network Control System"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
COPY pyproject.toml .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY blncs/ ./blncs/
COPY run_quick_tests.py .
COPY config/ ./config/

# Install BLNCS
RUN pip install -e .

# Create non-root user
RUN useradd --create-home --shell /bin/bash blncs && \
    chown -R blncs:blncs /app
USER blncs

# Create data directories
RUN mkdir -p /home/blncs/.blncs/data \
             /home/blncs/.blncs/logs \
             /home/blncs/.blncs/config

# Set environment variables
ENV PYTHONPATH=/app
ENV BLNCS_DATA_DIR=/home/blncs/.blncs/data
ENV BLNCS_LOG_DIR=/home/blncs/.blncs/logs
ENV BLNCS_CONFIG_DIR=/home/blncs/.blncs/config

# Expose ports (if needed for web interface)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -m blncs.cli.main status || exit 1

# Default command
CMD ["python", "-m", "blncs.cli.main", "status"]