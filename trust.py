"""
trust.py -- make TLS "just work" on a customer machine.

Python is typically the only thing on a workstation that ignores the operating
system trust store: it ships its own CA bundle. So a corporate TLS-inspecting
proxy (Zscaler, Netskope, Palo Alto, an internal gateway) or a tenant behind a
private CA verifies fine in Chrome and fails in Python. Node solved this with
NODE_USE_SYSTEM_CA; this module is the equivalent.

Trust is resolved in this order, first hit wins:

  1. an explicit CA bundle the operator supplied (--ca-bundle / SSL_CERT_FILE)
  2. a certificate the operator explicitly pinned by SHA-256 fingerprint
  3. the `truststore` package, if it happens to be installed (best option)
  4. a bundle generated from the OS trust store  <-- handles most corporates
  5. Python's own default bundle
  6. verification disabled, only if explicitly requested

Standard library only. Steps 3 and 4 degrade quietly if unavailable.
"""

import hashlib
import os
import platform
import re
import ssl
import subprocess
import time

CACHE_NAME = "system-ca.pem"
CACHE_TTL = 24 * 3600  # regenerate daily; corporate roots do get rotated


# --------------------------------------------------------------- OS trust store

def _macos_pems():
    """Export roots from every keychain that can hold a corporate CA.

    System.keychain is where MDM/IT-installed roots land, which is the case
    that matters. The login keychain is included because some deployments put
    them there instead.
    """
    keychains = [
        "/System/Library/Keychains/SystemRootCertificates.keychain",
        "/Library/Keychains/System.keychain",
        os.path.expanduser("~/Library/Keychains/login.keychain-db"),
    ]
    out = []
    for kc in keychains:
        if not os.path.exists(kc):
            continue
        try:
            res = subprocess.run(
                ["security", "find-certificate", "-a", "-p", kc],
                capture_output=True, text=True, timeout=30, check=False)
            if res.returncode == 0 and "BEGIN CERTIFICATE" in res.stdout:
                out.append(res.stdout)
        except (OSError, subprocess.SubprocessError):
            continue
    return out


def _windows_pems():
    """Read the Windows certificate stores via the standard library."""
    out = []
    for store in ("ROOT", "CA"):
        try:
            for cert, enc, _trust in ssl.enum_certificates(store):
                if enc == "x509_asn":
                    try:
                        out.append(ssl.DER_cert_to_PEM_cert(cert))
                    except (ValueError, TypeError):
                        continue
        except (AttributeError, OSError):
            # enum_certificates is Windows-only and can fail on locked-down hosts.
            continue
    return out


def _linux_bundle():
    """Linux distros already expose a merged bundle; find it."""
    for path in ("/etc/ssl/certs/ca-certificates.crt",
                 "/etc/pki/tls/certs/ca-bundle.crt",
                 "/etc/ssl/ca-bundle.pem",
                 "/etc/ssl/cert.pem"):
        if os.path.exists(path):
            return path
    return None


def system_ca_bundle(data_dir, force=False):
    """Return a path to a PEM bundle built from the OS trust store, or None.

    The generated file is cached in data_dir and refreshed daily.
    """
    system = platform.system()

    if system == "Linux":
        # Nothing to generate; Python usually already uses this.
        return _linux_bundle()

    cache = os.path.join(data_dir, CACHE_NAME)
    if not force and os.path.exists(cache):
        age = time.time() - os.path.getmtime(cache)
        if age < CACHE_TTL and os.path.getsize(cache) > 0:
            return cache

    if system == "Darwin":
        chunks = _macos_pems()
    elif system == "Windows":
        chunks = _windows_pems()
    else:
        chunks = []

    if not chunks:
        return None

    blob = "\n".join(chunks)
    if "BEGIN CERTIFICATE" not in blob:
        return None
    try:
        os.makedirs(data_dir, exist_ok=True)
        tmp = cache + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(blob)
        os.replace(tmp, cache)
    except OSError:
        return None
    return cache


def count_certs(path):
    try:
        with open(path) as fh:
            return fh.read().count("BEGIN CERTIFICATE")
    except OSError:
        return 0


# ------------------------------------------------------------------- truststore

def truststore_context():
    """Use the `truststore` package if present. Best available option."""
    try:
        import truststore  # noqa: F401
    except Exception:
        return None
    try:
        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except Exception:
        return None


# ---------------------------------------------------------------- pinning (TOFU)

def leaf_fingerprint(host, port=443, timeout=15):
    """SHA-256 fingerprint of the leaf certificate, fetched WITHOUT verifying.

    Used to show the operator what they are being asked to trust so they can
    confirm it out of band -- the same model as accepting an SSH host key.
    """
    ctx = ssl._create_unverified_context()
    try:
        import socket
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                info = tls.getpeercert()
    except Exception as exc:
        return {"error": str(exc)}

    fp = hashlib.sha256(der).hexdigest().upper()
    pretty = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))

    def _flatten(seq):
        out = {}
        for item in (seq or ()):
            for pair in item:
                if len(pair) == 2:
                    out[pair[0]] = pair[1]
        return out

    subject = _flatten((info or {}).get("subject"))
    issuer = _flatten((info or {}).get("issuer"))
    not_after = (info or {}).get("notAfter", "")

    # On an unverified connection Python returns an empty dict, so the useful
    # fields are missing exactly when we need them most. Recover them by asking
    # openssl to parse the DER. Degrades to fingerprint-only if openssl is absent.
    if not issuer:
        parsed = _parse_with_openssl(der)
        issuer = parsed.get("issuer") or issuer
        subject = parsed.get("subject") or subject
        not_after = parsed.get("not_after") or not_after

    return {
        "sha256": fp,
        "sha256_pretty": pretty,
        "subject": subject,
        "issuer": issuer,
        "not_after": not_after,
        "issuer_line": _describe(issuer),
        "subject_line": _describe(subject),
    }


def _parse_dn(line):
    """Turn an openssl DN line into a dict keyed like getpeercert() does.

    Handles both output styles: OpenSSL 1.x emits `/O=Acme/CN=host` while
    OpenSSL 3.x emits `O = Acme, CN = host`. A CN can legitimately contain a
    comma, so split on ", " only where the next token looks like `KEY =`.
    """
    names = {"CN": "commonName", "O": "organizationName",
             "OU": "organizationalUnitName", "C": "countryName",
             "ST": "stateOrProvinceName", "L": "localityName",
             "emailAddress": "emailAddress"}
    line = line.strip()
    if line.startswith("/"):
        parts = [p for p in line.split("/") if p]
    else:
        parts = re.split(r",\s+(?=[A-Za-z][A-Za-z0-9.]*\s*=)", line)

    out = {}
    for part in parts:
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip()
        out[names.get(key, key)] = value.strip()
    return out


def _parse_with_openssl(der):
    try:
        pem = ssl.DER_cert_to_PEM_cert(der).encode()
        res = subprocess.run(
            ["openssl", "x509", "-noout", "-issuer", "-subject", "-enddate"],
            input=pem, capture_output=True, timeout=15, check=False)
        if res.returncode != 0:
            return {}
        out = {}
        for raw in res.stdout.decode("utf-8", "replace").splitlines():
            raw = raw.strip()
            if raw.startswith("issuer="):
                out["issuer"] = _parse_dn(raw[7:])
            elif raw.startswith("subject="):
                out["subject"] = _parse_dn(raw[8:])
            elif raw.startswith("notAfter="):
                out["not_after"] = raw[9:]
        return out
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}


def _describe(dn):
    """One-line human description of a DN, best field available."""
    if not dn:
        return ""
    org = dn.get("organizationName")
    cn = dn.get("commonName")
    if org and cn and org != cn:
        return "%s (%s)" % (cn, org)
    return cn or org or ""


def normalize_pin(value):
    return (value or "").replace(":", "").replace(" ", "").upper()


def pinned_https_handler(expected_sha256):
    """A urllib handler that trusts exactly one leaf certificate.

    For tenants behind a private CA the operator cannot export. Strictly
    stronger than disabling verification: the connection still fails closed if
    the certificate is not the one that was confirmed. Same trust model as
    accepting an SSH host key -- which is why the UI shows the fingerprint and
    makes the operator confirm it.
    """
    import http.client
    import urllib.request

    expected = normalize_pin(expected_sha256)

    class _PinnedConnection(http.client.HTTPSConnection):
        def __init__(self, *args, **kwargs):
            kwargs["context"] = ssl._create_unverified_context()
            super().__init__(*args, **kwargs)

        def connect(self):
            super().connect()
            der = self.sock.getpeercert(binary_form=True)
            actual = hashlib.sha256(der or b"").hexdigest().upper()
            if actual != expected:
                try:
                    self.sock.close()
                finally:
                    pass
                raise ssl.SSLCertVerificationError(
                    "Pinned certificate mismatch for %s. Expected %s…, got %s…. "
                    "The certificate changed: this may be a legitimate rotation or "
                    "an interception attempt. Re-pin only after confirming the new "
                    "fingerprint out of band."
                    % (self.host, expected[:16], actual[:16]))

    class _PinnedHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_PinnedConnection, req)

    return _PinnedHandler()


# ------------------------------------------------------------------ diagnostics

def diagnose(url, data_dir):
    """Work out which trust strategy would succeed, for the setup UI.

    Returns a dict with a machine-readable `state` plus what was tried, so the
    UI can offer a real remedy instead of printing an OpenSSL string.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return {"state": "bad_url", "detail": "Could not parse a hostname."}

    import socket

    def attempt(ctx):
        try:
            with socket.create_connection((host, port), timeout=15) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return None
        except ssl.SSLCertVerificationError as exc:
            return "verify:" + str(exc)
        except Exception as exc:
            return "conn:" + str(exc)

    result = {"host": host, "port": port, "tried": []}

    # Reachability first, so we do not report a trust problem for a dead host.
    probe = leaf_fingerprint(host, port)
    if "error" in probe:
        result.update(state="unreachable", detail=probe["error"])
        return result
    result["certificate"] = probe

    err = attempt(ssl.create_default_context())
    result["tried"].append({"strategy": "python_default", "ok": err is None})
    if err is None:
        result.update(state="ok", strategy="python_default")
        return result

    ts = truststore_context()
    if ts is not None:
        err = attempt(ts)
        result["tried"].append({"strategy": "truststore", "ok": err is None})
        if err is None:
            result.update(state="ok", strategy="truststore")
            return result

    bundle = system_ca_bundle(data_dir)
    if bundle:
        result["system_bundle"] = {"path": bundle, "certs": count_certs(bundle)}
        err = attempt(ssl.create_default_context(cafile=bundle))
        result["tried"].append({"strategy": "system_store", "ok": err is None})
        if err is None:
            result.update(state="ok", strategy="system_store")
            return result

    issuer = probe.get("issuer_line") or "an unknown authority"
    result.update(
        state="untrusted",
        issuer_hint=issuer,
        detail=("The certificate for %s is issued by %s, which is not in the OS "
                "trust store this machine exposes to Python. If your network "
                "inspects TLS, ask IT for the root certificate; otherwise you can "
                "pin the certificate shown here after verifying its fingerprint."
                % (host, issuer)))
    return result


# ------------------------------------------------------- context factory

def resolve(data_dir, ca_bundle=None, pinned=None, insecure=False):
    """Resolve the trust ladder.

    Returns (context, pin, label):
      context -- an ssl.SSLContext, or None meaning "Python default"
      pin     -- a fingerprint to enforce via pinned_https_handler, or None
      label   -- human-readable description for logs and the UI
    """
    if insecure:
        return ssl._create_unverified_context(), None, "verification disabled"

    explicit = ca_bundle or os.environ.get("SSL_CERT_FILE")
    if explicit:
        path = os.path.expanduser(explicit)
        return (ssl.create_default_context(cafile=path), None,
                "CA bundle %s (%d certs)" % (path, count_certs(path)))

    if pinned:
        return None, normalize_pin(pinned), "pinned certificate"

    ts = truststore_context()
    if ts is not None:
        return ts, None, "OS trust store via truststore"

    bundle = system_ca_bundle(data_dir)
    if bundle:
        return (ssl.create_default_context(cafile=bundle), None,
                "OS trust store (%d certs)" % count_certs(bundle))

    return None, None, "Python default CA bundle"
