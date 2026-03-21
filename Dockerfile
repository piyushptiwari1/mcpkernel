FROM python:3.12-slim AS base

WORKDIR /app

# System deps for optional backends
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml LICENSE README.md ./
COPY src/ src/
COPY policies/ policies/

RUN pip install --no-cache-dir -e ".[docker]"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

ENTRYPOINT ["mcpguard"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
