FROM python:3.11-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

# Dependency metadata first, so a code change does not invalidate the layer
# that resolved and installed the environment. README.md is here because
# pyproject declares it as the package readme and the build reads it.
COPY pyproject.toml uv.lock* README.md ./

# The package itself, before `uv sync`, because this project is installed
# rather than merely depended on -- hatchling needs `voyd/` present to build
# the wheel it then installs.
COPY voyd/ voyd/

# The container boots the HTTP service (`python -m voyd`), which needs the
# `app` extra; `all` adds embeddings and the MCP server. `Engine` alone would
# be pymongo and nothing else -- that is the library install, not this one.
RUN uv sync --extra all --frozen --no-dev || uv sync --extra all --no-dev

# Examples, tests and the exhibit. Last, because they change most often and
# nothing above depends on them.
COPY . .

EXPOSE 8000

CMD ["uv", "run", "python", "-m", "voyd"]
