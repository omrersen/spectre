FROM python:3.12-slim AS base

WORKDIR /app

# Install system dependencies for weasyprint (PDF reports)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY spectre/ ./spectre/

RUN pip install --no-cache-dir -e ".[ai]"

RUN useradd -m -u 1000 spectre && chown -R spectre:spectre /app
USER spectre

ENTRYPOINT ["spectre"]
CMD ["--help"]
