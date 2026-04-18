FROM python:3.13-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends curl git && rm -rf /var/lib/apt/lists/*

# Install Stratus Red Team
RUN curl -sL "https://github.com/DataDog/stratus-red-team/releases/download/v2.31.0/stratus-red-team_Linux_x86_64.tar.gz" -o /tmp/stratus.tar.gz \
    && tar xzf /tmp/stratus.tar.gz -C /usr/local/bin/ stratus \
    && chmod +x /usr/local/bin/stratus \
    && rm /tmp/stratus.tar.gz

# Clone Atomic Red Team test definitions
RUN git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY main.py .
COPY static/ static/

# Config
ENV STRATUS_BIN=/usr/local/bin/stratus
ENV ATOMICS_PATH=/opt/atomic-red-team/atomics
ENV REDTEAM_LOG_DIR=/tmp/redteam-logs
ENV PORT=8080

EXPOSE 8080

CMD ["python3", "main.py"]
