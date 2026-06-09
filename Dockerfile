# ── JorginhoAgent ─────────────────────────────────────────────────────────────
# Imagem com Python 3.11, Trivy e Bandit pré-instalados.
# Build:  docker build -t jorginhoagent .
# Run:    docker run --rm --env-file .env jorginhoagent
# ──────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim AS base

# Evita prompts interativos e buffers no stdout
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ── Dependências de sistema ───────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    apt-transport-https \
    gnupg \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

# ── Instala Trivy ────────────────────────────────────────────────────────────
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# ── Diretório de trabalho ─────────────────────────────────────────────────────
WORKDIR /app

# ── Instala dependências Python ───────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Copia o código ────────────────────────────────────────────────────────────
COPY . .

# ── Entrypoint ────────────────────────────────────────────────────────────────
ENTRYPOINT ["python", "main.py"]
