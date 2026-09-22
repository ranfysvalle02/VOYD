"""Where the boundary forwards to, and how it stays right.

An address is a *lifecycle*, not a value, and that distinction is the whole
of this module. Resolved once at startup it cannot be re-resolved, so an
election means a restart -- which is an operability complaint, not a
subtlety. So the address is resolved lazily, cached, and invalidated by the
server's own error: `stepped_down` reads the reply the client was getting
anyway, and the next connection finds the new primary.

It is deliberately not a driver. It picks one node and forwards bytes; it
does not pool, load-balance, follow read preference, or retry a write the
client already saw fail. `LIMITS.md` section 8 says why ranking on a
replica is not this module's job either.

`upstream_ready` is here rather than with the listener because it answers
the same question from outside: readiness is about the hop past this
process, not about whether a socket is bound.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import threading
from typing import Callable, Mapping

from . import metrics


# What a replica set says when the node you are talking to is no longer the
# one that may write. The boundary learns from these rather than polling: a
# health check is a guess about the future, and this is the server telling
# you about the present.
STEPPED_DOWN = {
    10107,   # NotWritablePrimary
    13435,   # NotPrimaryNoSecondaryOk
    13436,   # NotPrimaryOrSecondary
    11602,   # InterruptedDueToReplStateChange
    189,     # PrimarySteppedDown
    91,      # ShutdownInProgress
}


class Upstream:
    """Where the boundary forwards to, and how it stays right.

    A connection is a *lifecycle*, not an address, and the difference is
    the whole class of operability complaint: an address resolved once at
    startup cannot be re-resolved, so a failover means a restart.

    - **resolved lazily**, so startup does not block on DNS and a cluster
      that is briefly unreachable does not prevent the boundary from
      listening;
    - **cached**, because resolving a `mongodb+srv` URI costs a DNS round
      trip and a topology scan, and doing that per connection would put the
      driver's startup cost on every client;
    - **invalidated by the server's own error**. When a reply carries
      `NotWritablePrimary` -- or any of the codes above -- the cached
      address is wrong *now*, and the next connection re-resolves. That is
      how a driver learns about an election, and it is strictly better than
      a timer: no window where the boundary knows and has not acted, and no
      polling a healthy cluster forever to find out about an event that may
      never happen.

    What it still is not: a driver. It picks one node and forwards bytes; it
    does not load-balance reads, follow read preference, or retry a write
    the client already saw fail. A client should reach it with
    ``directConnection=true`` so it does not chase the hosts the cluster
    advertises straight past the boundary.
    """

    def __init__(self, target: str, *, verbose: bool = True,
                 meter: "metrics.Meter | None" = None):
        self.target = target
        self.verbose = verbose
        self.meter = meter
        self._addr: tuple[str, int, bool] | None = None
        self._lock = threading.Lock()
        # Resolution is serialised so a burst of clients arriving after an
        # election causes one topology scan rather than one each. The
        # threading lock above still guards the cache itself, because
        # `_resolve` runs in an executor thread.
        self._resolving = asyncio.Lock()
        self.generation = 0

    def address(self) -> tuple[str, int, bool]:
        with self._lock:
            if self._addr is None:
                self._addr = self._resolve()
            return self._addr

    def invalidate(self, why: str) -> None:
        """Forget where the primary was. The next connection finds out."""
        with self._lock:
            if self._addr is None:
                return
            host, port, _ = self._addr
            self._addr = None
            self.generation += 1
            if self.meter is not None:
                self.meter.upstream_reresolve_total += 1
        print(f"voyd-wire: {host}:{port} is no longer writable ({why}); "
              f"re-resolving on the next connection", flush=True)

    def _resolve(self) -> tuple[str, int, bool]:
        """A bare `host:port`, or a URI resolved the way a driver would.

        Atlas is `mongodb+srv`, which means three things a raw TCP dial
        cannot do: the hosts live in DNS SRV records, the connection must be
        TLS, and the port is not in the string.
        """
        target = self.target
        if "://" not in target:
            host, _, port = target.partition(":")
            return host, int(port or 27017), False

        from pymongo.uri_parser import parse_uri
        parsed = parse_uri(target)
        tls = bool(parsed["options"].get("tls",
                                         target.startswith("mongodb+srv")))
        try:
            from pymongo import MongoClient
            probe: MongoClient = MongoClient(
                target, serverSelectionTimeoutMS=15000)
            with probe:
                # `ping` first: the driver connects lazily, and `.primary` on
                # an undiscovered topology is `None` -- which silently
                # selected the first DNS node and looked exactly like this
                # not working.
                probe.admin.command("ping")
                primary = probe.primary
            if primary:
                if self.verbose:
                    print(f"voyd-wire: primary is {primary[0]}:{primary[1]}",
                          flush=True)
                return primary[0], primary[1], tls
        except Exception as exc:
            print(f"voyd-wire: could not find the primary "
                  f"({type(exc).__name__}); using the first node DNS "
                  f"returned. Writes may come back `not primary`.", flush=True)

        host, port = parsed["nodelist"][0]
        return host, port, tls

    def connect(self) -> socket.socket:
        host, port, tls = self.address()
        sock = socket.create_connection((host, port), timeout=20)
        # No *read* timeout, deliberately. A MongoDB connection legitimately
        # idles for minutes -- an awaitData cursor, a change stream, a client
        # between requests -- so a read deadline would kill healthy
        # connections and look like the cluster flapping. TCP keepalive is
        # the right tool: it notices a peer that went away without
        # penalising one that is merely quiet.
        keepalive(sock)
        sock.settimeout(None)
        if not tls:
            return sock
        ctx = ssl.create_default_context()
        # `server_hostname` is what makes certificate validation mean
        # anything against a named cluster; without it this is an encrypted
        # channel to whoever answered.
        return ctx.wrap_socket(sock, server_hostname=host)

    async def open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """The same upstream connection, without holding a thread.

        `_resolve` stays blocking -- it is a DNS round trip and a pymongo
        topology scan -- so it goes to an executor. Doing it inline would
        stall every other connection on this loop for the length of a
        cluster handshake, which is exactly the failure an event loop is
        supposed to remove.
        """
        async with self._resolving:
            loop = asyncio.get_running_loop()
            host, port, tls = await loop.run_in_executor(None, self.address)

        ssl_ctx = None
        server_hostname = None
        if tls:
            ssl_ctx = ssl.create_default_context()
            server_hostname = host
        reader, writer = await asyncio.open_connection(
            host, port, ssl=ssl_ctx, server_hostname=server_hostname)

        # No *read* timeout, deliberately -- see `connect` above. Keepalive
        # is the tool that notices a peer that vanished without penalising
        # one that is merely idle, and it has to be set on the socket under
        # the stream rather than on the stream.
        raw_sock = writer.get_extra_info("socket")
        if raw_sock is not None:
            keepalive(raw_sock)
        return reader, writer








def stepped_down(reply: Mapping) -> str | None:
    """Did the server just say this node may not write?

    Read from the reply the client was going to get anyway. A write error
    inside a batch is nested under ``writeErrors``, which is where this
    hides on exactly the command -- a delete -- that matters most here.
    """
    if reply.get("code") in STEPPED_DOWN:
        return str(reply.get("codeName") or reply.get("code"))
    for err in reply.get("writeErrors") or ():
        if isinstance(err, dict) and err.get("code") in STEPPED_DOWN:
            return str(err.get("codeName") or err.get("code"))
    return None


def keepalive(sock: socket.socket) -> None:
    """Notice a peer that vanished, without punishing one that is idle."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for opt, value in (("TCP_KEEPIDLE", 60), ("TCP_KEEPINTVL", 15),
                           ("TCP_KEEPCNT", 4)):
            if hasattr(socket, opt):        # Linux; macOS spells one of them
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), value)
    except OSError:
        pass                                 # best effort, never fatal


def upstream_ready(target: str) -> "Callable[[], tuple[bool, str]]":
    """A readiness check that goes one hop past "am I listening".

    Bound-but-broken is the case worth catching. Measured: pointed at a
    dead port, this proxy starts, prints its banner, accepts connections
    and fails every read -- so a TCP probe on the listen port reports
    ready and a rolling deploy sends traffic to a pod that cannot serve.

    So the check resolves the upstream the way a connection would and
    opens a socket to it. `Upstream` caches the address, so the first
    probe pays the topology scan and the rest are one connect. A
    deployment that has gone away fails the *next* probe rather than
    being remembered as healthy, because `invalidate` clears that cache
    on the data path.

    Its own `Upstream`, not the one serving traffic: a probe must never
    contend with a connection for the resolution lock, and with
    `--workers` the process answering probes is the parent, which has no
    upstream of its own at all.
    """
    probe = Upstream(target, verbose=False)

    def ready() -> tuple[bool, str]:
        try:
            host, port, _tls = probe.address()
        except Exception as exc:                              # noqa: BLE001
            return False, f"cannot resolve upstream ({type(exc).__name__})"
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return True, ""
        except OSError as exc:
            probe.invalidate(type(exc).__name__)
            return False, f"cannot reach {host}:{port}"

    return ready


def vault_uri(target: str) -> str:
    """The connection string the vault dials, from `--target`.

    The same deployment the boundary forwards to, by construction rather
    than by a second flag somebody could point elsewhere. A key vault on a
    different cluster than the ciphertext is a failure that looks like
    "the keys are missing" rather than like a misconfiguration.
    """
    if "://" in target:
        return target
    return f"mongodb://{target}/?directConnection=true"
