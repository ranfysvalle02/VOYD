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

# Not root. The boundary opens one listening socket above 1024, reads a
# policy file and forwards bytes; nothing it does needs privilege, and a
# process that holds a database's front door is the last one that should
# have any. `--chown` because `uv sync` wrote the venv as root.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin voyd \
    && chown -R 10001:10001 /app
USER 10001

# Where `uv sync` put the interpreter, so the entry point is the console
# script rather than `uv run` -- which re-resolves the environment on every
# container start and needs a writable cache it no longer has.
ENV PATH="/app/.venv/bin:$PATH"

# The wire boundary, not an HTTP service: what comes out of 27099 is the
# MongoDB protocol. Mount your own `voydfile.py` over the example one and
# point `--target` at your cluster.
#
# **Run it as a sidecar**, sharing a network namespace with the
# application -- a Kubernetes pod, or `--network container:<app>`. That is
# not a workaround, it is the strongest shape available: the application
# reaches the boundary on `localhost`, nothing else on the network can
# reach it at all, and there is no route around it to bypass.
#
# It is also the only shape that works everywhere. Without `--tls-cert`
# the listener binds loopback, deliberately -- a plaintext boundary
# reachable from a network would carry in the clear every document it had
# just refused to serve. Publishing 27099 with `-p` happens to work on
# Docker Desktop, whose forwarder runs inside the namespace, and does not
# on Linux, whose DNAT targets the container's own address. Cross a
# network with `--tls-cert`, not with a port mapping.
#
# 27100 is different and is meant to be published: `/metrics` for a
# scrape and `/health` for a probe, both cross-pod by nature.
EXPOSE 27100

# Readiness, not liveness, and the distinction is the point: this asks
# whether the *upstream* is reachable, because a bound socket answers yes
# while the deployment behind it is gone. Orchestrators that read this
# label get it for free; Kubernetes wants it spelled out in the manifest,
# where the same URL is the readinessProbe.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["voyd-wire-health"]

ENTRYPOINT ["voyd-wire"]
CMD ["--config", "voydfile.py", "--listen", "27099", \
     "--metrics", "27100", "--metrics-bind", "0.0.0.0", \
     "--target", "host.docker.internal:27017"]
