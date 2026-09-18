FROM python:3.11-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

# Copy dependency files and README
COPY pyproject.toml uv.lock* README.md ./
# Also copy the voyd directory so hatchling can find voyd/themes
COPY voyd/ voyd/

# The container boots the Host (`python -m voyd`), so it needs the full costume:
# FastAPI, templates, embeddings, blob storage. Engine alone would be pymongo.
RUN uv sync --extra all --frozen --no-dev || uv sync --extra all --no-dev

# Copy the rest of the application
COPY . .

# Expose the port
EXPOSE 8000

# Run the application
CMD ["uv", "run", "python", "-m", "voyd"]
