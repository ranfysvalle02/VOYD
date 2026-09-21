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

# The boundary needs the engine and a MongoDB driver. `all` adds embeddings
# and cryptographic erasure, which are library-only today -- see the README --
# and are here so a container can also be used as the in-process runtime.
RUN uv sync --extra all --frozen --no-dev || uv sync --extra all --no-dev

# The policy file, the proxy and the examples. Last, because they change most
# often and nothing above depends on them.
COPY . .

# The wire boundary, not an HTTP service: this container is a front door for
# a database, and what comes out of it is the MongoDB protocol. Mount your own
# `voydfile.py` over the example one and point `--target` at your cluster.
EXPOSE 27099

CMD ["uv", "run", "python", "tools/voyd_wire.py", \
     "--config", "voydfile.py", "--listen", "27099", \
     "--target", "host.docker.internal:27017"]
