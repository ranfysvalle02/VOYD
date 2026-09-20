"""A real KMIP server, started for the suite. Not a mock.

KMIP is *the* enterprise key-custody standard -- Thales, Fortanix, Entrust,
HSM appliances -- and a large class of deployments choose it precisely
because they will not put keys in a public cloud. It is also, unlike any
managed cloud KMS, **runnable**: PyKMIP is a conformant server that starts
in a subprocess with a self-signed chain.

That distinction is the whole reason this file exists. "Nothing has ever
run against a real KMS" was carried as a known gap for a long time on the
assumption that closing it needed a cloud account and CI secrets. It did
not. Enterprise custody is not a synonym for one vendor's managed service,
and the open standard for it can be stood up in eight seconds.

What this proves that a unit test cannot: the data key is wrapped by a key
this process does not hold, ``masterKey`` on the stored document names the
external provider, and ``rewrap_many_data_key`` works against a server that
can refuse.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import subprocess
import sys
import time
from pathlib import Path


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def write_chain(into: Path) -> None:
    """A CA, a server cert for localhost, and a client cert it will accept."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)

    def key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def named(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    ca_key = key()
    ca = (x509.CertificateBuilder()
          .subject_name(named("voyd-test-ca")).issuer_name(named("voyd-test-ca"))
          .public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now)
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                         critical=True)
          .sign(ca_key, hashes.SHA256()))

    def leaf(cn, san=False):
        k = key()
        b = (x509.CertificateBuilder().subject_name(named(cn))
             .issuer_name(ca.subject).public_key(k.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now)
             .not_valid_after(now + datetime.timedelta(days=1)))
        if san:
            b = b.add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False)
        return k, b.sign(ca_key, hashes.SHA256())

    def pem(obj, private=False):
        return (obj.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()) if private
            else obj.public_bytes(serialization.Encoding.PEM))

    (into / "ca.pem").write_bytes(pem(ca))
    sk, sc = leaf("localhost", san=True)
    (into / "server.key").write_bytes(pem(sk, True))
    (into / "server.pem").write_bytes(pem(sc))
    ck, cc = leaf("voyd-client")
    # The driver wants one file holding cert and key, which is also the
    # shape every KMIP appliance's documentation uses.
    (into / "client.pem").write_bytes(pem(cc) + pem(ck, True))


def start(into: Path) -> tuple[subprocess.Popen, str, dict]:
    """``(process, endpoint, kms_tls_options)``. Caller terminates."""
    write_chain(into)
    port = free_port()
    (into / "policies").mkdir(exist_ok=True)
    (into / "server.conf").write_text(f"""[server]
hostname=127.0.0.1
port={port}
certificate_path={into}/server.pem
key_path={into}/server.key
ca_path={into}/ca.pem
auth_suite=TLS1.2
policy_path={into}/policies
enable_tls_client_auth=False
logging_level=WARNING
database_path={into}/db.sqlite
""")
    # ``if __name__`` is load-bearing: the server opens a
    # multiprocessing.Manager, which re-imports the entry script, which
    # without the guard starts a second server and deadlocks the first.
    runner = into / "run.py"
    runner.write_text(
        "from kmip.services.server import KmipServer\n"
        "if __name__ == '__main__':\n"
        f"    s = KmipServer(config_path='{into}/server.conf',"
        f" log_path='{into}/server.log')\n"
        "    s.start()\n"
        "    s.serve()\n")

    proc = subprocess.Popen([sys.executable, str(runner)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    endpoint = f"127.0.0.1:{port}"
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError("the KMIP server exited while starting")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                break
        except OSError:
            time.sleep(0.2)
    else:
        proc.terminate()
        raise RuntimeError(f"the KMIP server never opened {endpoint}")

    tls = {"tlsCAFile": str(into / "ca.pem"),
           "tlsCertificateKeyFile": str(into / "client.pem")}
    return proc, endpoint, tls
