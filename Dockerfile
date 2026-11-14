FROM python:3.12-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    libssl-dev \
    libffi-dev \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy platform source
COPY . .

# Create runtime directories
RUN mkdir -p \
    var/log/cowrie \
    var/log/ftp \
    var/log/web \
    var/log/database \
    var/log/credentials \
    var/log/collector \
    var/data \
    var/run \
    services/ftp/uploads

# Expose platform ports
# 2222: SSH Honeypot (Cowrie)
# 2121: FTP Honeypot (Isolated VFS)
# 8080: Web Admin Deception Portal (FastAPI)
# 5432: PostgreSQL Honeypot
# 3306: MySQL Honeypot
# 8000: Central Backend & REST API / WebSockets (FastAPI)
EXPOSE 2222 2121 8080 5432 3306 8000

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

CMD ["python", "--version"]
