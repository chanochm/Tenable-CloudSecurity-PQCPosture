#!/usr/bin/env python3
"""
PQC Posture Portal - Tenable Cloud Security

A zero-dependency local web portal showing post-quantum cryptography readiness
for every internet-reachable resource in your cloud estate.

    python3 app.py        then open http://127.0.0.1:8787

No pip install, no Node, no build step - standard library only.

Data comes live from Tenable Cloud Security's UDM NetworkEndpoint object via
the Tenable Hexa AI MCP server. You paste a service account token into the
setup screen on first run; it is stored encrypted at rest. A bundled demo
snapshot is served until you connect.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import datasource as ds
import trust

BASE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(BASE, "web")
QUERIES = os.path.join(BASE, "queries")
DEMO = os.path.join(BASE, "data", "snapshot.json")

DEFAULT_HOST, DEFAULT_PORT = "127.0.0.1", 8787
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1", ""}

_sync = {"running": False, "step": "", "error": "", "warning": "",
         "rows": 0, "resources": 0, "finished_at": 0}


def restrict_file(path):
    """Make a file readable only by the current user, on every platform.

    On POSIX the 0o600 passed to os.open does this. On Windows that mode is
    silently ignored -- NTFS uses ACLs -- so without this the credential file
    would inherit the profile directory's ACL. Best effort: if icacls is
    unavailable we leave the inherited ACL rather than fail the write.
    """
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return
    user = os.environ.get("USERNAME")
    if not user:
        return
    domain = os.environ.get("USERDOMAIN")
    principal = "%s\\%s" % (domain, user) if domain else user
    try:
        subprocess.run(
            ["icacls", path, "/inheritance:r", "/grant:r", "%s:F" % principal],
            capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        pass
_sync_lock = threading.Lock()


# ------------------------------------------------------------ credential vault

class Vault:
    """Encrypts credentials at rest with a per-install key file.

    HONEST SCOPE: this defeats casual disk inspection, stray backups and
    someone reading the SQLite file over your shoulder. It does NOT stop an
    attacker who can already read your home directory - the key file lives
    there too. On a shared machine treat the token as recoverable, and rotate
    it under Settings > Access Management if you suspect exposure.
    """

    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "instance.key")
        self._key = self._load_or_create()

    def _load_or_create(self):
        if os.path.exists(self.path):
            with open(self.path, "rb") as fh:
                return fh.read()
        material = os.urandom(32)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(material)
        restrict_file(self.path)
        return material

    def _stream(self, salt, length):
        key = hashlib.pbkdf2_hmac("sha256", self._key, salt, 200000, dklen=32)
        out, ctr = b"", 0
        while len(out) < length:
            out += hmac.new(key, ctr.to_bytes(4, "big"), hashlib.sha256).digest()
            ctr += 1
        return out[:length]

    def encrypt(self, text):
        if not text:
            return ""
        raw = text.encode("utf-8")
        salt = os.urandom(16)
        stream = self._stream(salt, len(raw))
        return base64.b64encode(salt + bytes(a ^ b for a, b in zip(raw, stream))).decode()

    def decrypt(self, blob):
        if not blob:
            return ""
        try:
            data = base64.b64decode(blob.encode())
        except Exception:
            return ""
        salt, ct = data[:16], data[16:]
        stream = self._stream(salt, len(ct))
        return bytes(a ^ b for a, b in zip(ct, stream)).decode("utf-8", "replace")


# ------------------------------------------------------------------ tiny store

class Store:
    """Flat JSON config + cached snapshot on disk. Nothing exotic needed."""

    def __init__(self, data_dir):
        os.makedirs(data_dir, exist_ok=True)
        self.cfg_path = os.path.join(data_dir, "config.json")
        self.cache_path = os.path.join(data_dir, "cache.json")
        self._lock = threading.Lock()

    def _read(self, path, default):
        try:
            with open(path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return default

    def _write(self, path, obj):
        with self._lock:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(obj, fh)
            restrict_file(path)

    def config(self):
        return self._read(self.cfg_path, {})

    def set_config(self, **kw):
        cfg = self.config()
        cfg.update(kw)
        self._write(self.cfg_path, cfg)

    def get(self, key, default=""):
        return self.config().get(key, default)

    def snapshot(self):
        return self._read(self.cache_path, None)

    def set_snapshot(self, doc):
        self._write(self.cache_path, doc)

    def reset(self):
        for path in (self.cfg_path, self.cache_path):
            try:
                os.remove(path)
            except OSError:
                pass


# ------------------------------------------------------------------- enrichment

def enrich(doc):
    """Recompute verdicts and counts so the UI never trusts stale fields."""
    if not doc:
        return doc
    native = bool(doc.get("native_pqc", True))
    counts = {"safe": 0, "review": 0, "not_safe": 0, "unknown": 0}
    for res in doc.get("resources", []):
        eps = res.get("endpoints") or []
        res["verdict"] = ds.score_verdict(
            [{"pqc_status": e.get("pqc"), "tls": e.get("tls"),
              "pqc_groups": [g for g in (e.get("kex") or []) if ds.is_pqc_group(g)]}
             for e in eps], native)
        counts[res["verdict"]] = counts.get(res["verdict"], 0) + 1
        for ep in eps:
            ep["pqc_groups"] = [g for g in (ep.get("kex") or []) if ds.is_pqc_group(g)]
            ep["tls_label"] = ds.PROTOCOL_LABELS.get(ep.get("tls") or "", "-")
        res["endpoint_count"] = len(eps)
    doc["verdict_counts"] = counts
    doc["resource_total"] = len(doc.get("resources", []))
    return doc


def load_query(name):
    with open(os.path.join(QUERIES, name)) as fh:
        return json.load(fh)


TLS_OPTS = {"ca_bundle": None, "verify_tls": True, "data_dir": None}


def make_source(store, vault):
    """Build a client. Trust settings saved from the UI take precedence over CLI."""
    return ds.McpDataSource(
        url=store.get("url") or ds.DEFAULT_MCP_URL,
        auth_mode=store.get("auth_mode", "bearer"),
        token=vault.decrypt(store.get("token")),
        access_key=vault.decrypt(store.get("access_key")),
        secret_key=vault.decrypt(store.get("secret_key")),
        ca_bundle=store.get("ca_bundle") or TLS_OPTS["ca_bundle"],
        pinned=store.get("pinned_sha256") or None,
        verify_tls=(not store.get("insecure")) and TLS_OPTS["verify_tls"],
        data_dir=TLS_OPTS["data_dir"],
    )


# ------------------------------------------------------------------------ sync

def run_sync(store, vault):
    def step(msg):
        _sync["step"] = msg

    try:
        step("Connecting to Hexa AI MCP")
        src = make_source(store, vault)
        src.connect()

        step("Checking PQC field availability")
        native = src.detect_pqc_support()

        step("Querying exposed resources")
        fleet_q = load_query("fleet.json" if native else "fleet_legacy.json")["query"]
        rows = src.execute_all(fleet_q)
        _sync["rows"] = len(rows)

        step("Running aggregates")
        aggregates, bundles = {}, load_query("aggregates.json")
        for key, spec in bundles.items():
            if key.startswith("_"):
                continue
            needs = spec.get("_requires_fields", [])
            if not native and any(f in ds.PQC_FIELDS for f in needs):
                continue  # field absent on this tenant - skip rather than show zeros
            try:
                aggregates[key] = {
                    "widget": spec.get("_widget", key),
                    "rows": ds.normalize_rows(src.execute(spec["query"], skip=0)),
                }
            except ds.McpError as exc:
                aggregates[key] = {"widget": spec.get("_widget", key),
                                   "rows": [], "error": str(exc)}

        step("Scoring")
        doc = ds.build_snapshot(rows, native, aggregates,
                               environment=store.get("environment", ""),
                               url=store.get("url", ""))
        _sync["resources"] = len(doc.get("resources", []))
        # A sync that returns nothing is a bug or a scope problem, never a
        # clean bill of health. Say so instead of rendering an empty dashboard.
        if not doc.get("resources"):
            _sync["warning"] = (
                "The sync completed but returned no resources (%d endpoint rows). "
                "Either this tenant has no scanned internet-facing endpoints, or the "
                "token's scope excludes them. Check Access Management, or run with "
                "--verbose and use /api/debug/query to inspect the raw response."
                % len(rows))
        store.set_snapshot(doc)
        _sync["error"] = ""
    except Exception as exc:
        _sync["error"] = str(exc)
    finally:
        _sync["running"] = False
        _sync["step"] = ""
        _sync["finished_at"] = time.time()


# ---------------------------------------------------------------------- server

class Handler(BaseHTTPRequestHandler):
    server_version = "PQCPosturePortal/1.0"
    store = None
    vault = None
    extra_host = None

    def log_message(self, fmt, *args):
        if "--verbose" in sys.argv:
            sys.stderr.write("  %s\n" % (fmt % args))

    def _host_ok(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        return host in LOCAL_HOSTS or host == self.extra_host

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj), "application/json; charset=utf-8")

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except ValueError:
            return {}

    def _configured(self):
        return bool(self.store.get("token") or self.store.get("access_key"))

    # -- GET ---------------------------------------------------------------

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, "Host not allowed.")
        path = self.path.split("?", 1)[0]

        if path in ("/", "/index.html"):
            page = os.path.join(WEB, "index.html")
            if not os.path.exists(page):
                return self._send(500, "web/index.html is missing from this install.")
            with open(page, encoding="utf-8") as fh:
                return self._send(200, fh.read(), "text/html; charset=utf-8")

        if path == "/api/snapshot.json":
            doc = self.store.snapshot()
            if doc is None:
                if not os.path.exists(DEMO):
                    return self._json({"error": "No data yet. Connect on the "
                                                "setup screen and run a sync."}, 404)
                with open(DEMO, encoding="utf-8") as fh:
                    doc = json.load(fh)
                doc["demo"] = True
            return self._json(enrich(doc))

        if path == "/api/status":
            doc = self.store.snapshot()
            return self._json({
                "configured": self._configured(),
                "auth_mode": self.store.get("auth_mode", "bearer"),
                "url": self.store.get("url") or ds.DEFAULT_MCP_URL,
                "has_data": doc is not None,
                "native_pqc": bool((doc or {}).get("native_pqc")),
                "generated_at": (doc or {}).get("generated_at", ""),
                "trust": {
                    "ca_bundle": self.store.get("ca_bundle", ""),
                    "pinned": bool(self.store.get("pinned_sha256")),
                    "insecure": bool(self.store.get("insecure")),
                },
                "sync": _sync,
            })

        if path == "/api/debug/query":
            """Raw first page of a saved query. For diagnosing shape mismatches."""
            if not self._configured():
                return self._json({"error": "Not connected."}, 400)
            from urllib.parse import parse_qs, urlparse as _up
            which = (parse_qs(_up(self.path).query).get("q") or ["fleet"])[0]
            fname = {"fleet": "fleet.json", "legacy": "fleet_legacy.json"}.get(which)
            try:
                src = make_source(self.store, self.vault)
                src.connect()
                if fname:
                    q = load_query(fname)["query"]
                else:
                    bundles = load_query("aggregates.json")
                    if which not in bundles:
                        return self._json({"error": "Unknown query name."}, 400)
                    q = bundles[which]["query"]
                raw = src.execute(q, skip=0)
                parsed = ds.normalize_rows(raw, primary_query_id=q.get("id"))
                return self._json({
                    "query": which,
                    "raw_top_level_keys": sorted(raw.keys()) if isinstance(raw, dict) else None,
                    "raw_row_count": len(raw.get("resultsList", [])) if isinstance(raw, dict) else None,
                    "parsed_row_count": len(parsed),
                    "first_parsed_row": parsed[0] if parsed else None,
                })
            except Exception as exc:
                return self._json({"error": str(exc)}, 400)

        if path == "/api/tls-probe":
            url = self.store.get("url") or ds.DEFAULT_MCP_URL
            try:
                return self._json(trust.diagnose(url, TLS_OPTS["data_dir"]))
            except Exception as exc:
                return self._json({"state": "error", "detail": str(exc)}, 200)

        if path == "/healthz":
            return self._send(200, "ok")

        self._send(404, "Not found.")

    # -- POST --------------------------------------------------------------

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, "Host not allowed.")
        path = self.path.split("?", 1)[0]

        if path == "/api/config":
            body = self._body()
            mode = "apikeys" if body.get("auth_mode") == "apikeys" else "bearer"
            url = (body.get("url") or "").strip() or ds.DEFAULT_MCP_URL
            if not url.startswith("https://"):
                return self._json({"error": "Server URL must use https."}, 400)
            fields = {"auth_mode": mode, "url": url,
                      "environment": (body.get("environment") or "").strip()}
            if mode == "bearer":
                token = (body.get("token") or "").strip()
                if not token:
                    return self._json({"error": "Service account token is required."}, 400)
                fields.update(token=self.vault.encrypt(token),
                              access_key="", secret_key="")
            else:
                ak = (body.get("access_key") or "").strip()
                sk = (body.get("secret_key") or "").strip()
                if not (ak and sk):
                    return self._json({"error": "Both access and secret keys "
                                                "are required."}, 400)
                fields.update(access_key=self.vault.encrypt(ak),
                              secret_key=self.vault.encrypt(sk), token="")
            self.store.set_config(**fields)
            return self._json({"ok": True})

        if path == "/api/test":
            if not self._configured():
                return self._json({"ok": False, "error": "No credentials saved."}, 400)
            try:
                src = make_source(self.store, self.vault)
                src.connect()
                return self._json({"ok": True, "native_pqc": src.detect_pqc_support()})
            except Exception as exc:
                return self._json({"ok": False, "error": str(exc)}, 400)

        if path == "/api/sync":
            if not self._configured():
                return self._json({"error": "Connect first on the setup screen."}, 400)
            with _sync_lock:
                if _sync["running"]:
                    return self._json({"error": "A sync is already running."}, 409)
                _sync.update(running=True, step="Starting", error="", warning="",
                             rows=0, resources=0)
            threading.Thread(target=run_sync, args=(self.store, self.vault),
                             daemon=True).start()
            return self._json({"ok": True})

        if path == "/api/trust":
            """Persist how this install should establish TLS trust."""
            body = self._body()
            mode = body.get("mode")
            if mode == "system":
                bundle = trust.system_ca_bundle(TLS_OPTS["data_dir"], force=True)
                if not bundle:
                    return self._json({"ok": False, "error":
                        "Could not read this machine's certificate store."}, 400)
                self.store.set_config(ca_bundle=bundle, pinned_sha256="", insecure=False)
                return self._json({"ok": True, "detail": "Using %d certificates from "
                                   "the OS trust store." % trust.count_certs(bundle)})
            if mode == "bundle":
                path_in = os.path.expanduser((body.get("path") or "").strip())
                if not path_in or not os.path.exists(path_in):
                    return self._json({"ok": False,
                                       "error": "No file at that path."}, 400)
                if trust.count_certs(path_in) == 0:
                    return self._json({"ok": False, "error":
                        "That file contains no PEM certificates."}, 400)
                self.store.set_config(ca_bundle=path_in, pinned_sha256="", insecure=False)
                return self._json({"ok": True, "detail": "Using %d certificates from %s."
                                   % (trust.count_certs(path_in), path_in)})
            if mode == "pin":
                fp = trust.normalize_pin(body.get("sha256"))
                if len(fp) != 64:
                    return self._json({"ok": False,
                                       "error": "Expected a SHA-256 fingerprint."}, 400)
                self.store.set_config(pinned_sha256=fp, ca_bundle="", insecure=False)
                return self._json({"ok": True, "detail":
                                   "Pinned. Connections now fail closed if the "
                                   "certificate changes."})
            if mode == "default":
                self.store.set_config(ca_bundle="", pinned_sha256="", insecure=False)
                return self._json({"ok": True, "detail": "Reverted to automatic trust."})
            return self._json({"ok": False, "error": "Unknown trust mode."}, 400)

        if path == "/api/reset":
            self.store.reset()
            return self._json({"ok": True})

        self._send(404, "Not found.")


def main():
    ap = argparse.ArgumentParser(description="PQC Posture Portal")
    ap.add_argument("--host", default=DEFAULT_HOST,
                    help="bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--data-dir",
                    default=os.path.join(os.path.expanduser("~"), ".pqc-portal"))
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--ca-bundle", metavar="PEM",
                    help="PEM file of trusted roots. Use this when your network "
                         "inspects TLS or your tenant sits behind an internal CA. "
                         "SSL_CERT_FILE is honoured if this is omitted.")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification entirely (last resort - your token "
                         "is sent over a connection you cannot verify)")
    args = ap.parse_args()

    TLS_OPTS["ca_bundle"] = args.ca_bundle
    TLS_OPTS["verify_tls"] = not args.insecure
    TLS_OPTS["data_dir"] = args.data_dir
    if args.insecure:
        print("WARNING: TLS verification is OFF. Your service account token will be\n"
              "         sent over a connection that cannot be authenticated. Use\n"
              "         --ca-bundle with your corporate root instead wherever possible.",
              file=sys.stderr)
    elif args.ca_bundle:
        print("TLS trust:              %s" % args.ca_bundle)

    Handler.store = Store(args.data_dir)
    Handler.vault = Vault(args.data_dir)

    if args.host not in LOCAL_HOSTS:
        Handler.extra_host = args.host
        print("WARNING: binding to %s exposes this portal beyond localhost.\n"
              "         It has no authentication of its own and will serve your\n"
              "         cloud posture to anyone who can reach it." % args.host,
              file=sys.stderr)

    url = "http://%s:%d" % (args.host, args.port)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("PQC Posture Portal  ->  %s" % url)
    print("Data directory:         %s" % args.data_dir)
    print("Ctrl-C to stop.")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
