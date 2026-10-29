"""
datasource.py -- the only file that talks to Tenable.

Swap the transport here and nothing else in the app changes. Three
implementations are provided:

  McpDataSource       speaks MCP JSON-RPC directly to the Hexa AI MCP server.
                      No Claude in the loop. This is the default.
  RestDataSource      stub for a direct UDM REST endpoint, if/when one is
                      available. Fill in _post() and delete the raise.
  SnapshotDataSource  reads a JSON file produced by the Claude Code skill.
                      Zero network. Useful for demos and air-gapped review.

Standard library only. No pip install.
"""

import json
import os
import time
import ssl
import urllib.error
import urllib.request

import trust

DEFAULT_MCP_URL = "https://app.tenable.com/api/mcp"
PAGE_SIZE = 20
TIMEOUT = 120

# ---------------------------------------------------------------- PQC taxonomy

# Key-exchange groups that provide post-quantum resistance (pure ML-KEM or
# classical+PQC hybrids). Everything else -- NIST curves, Brainpool, GOST,
# FFDHE -- is classical and Shor-vulnerable.
PQC_KEX_GROUPS = {
    "Mlkem512", "Mlkem768", "Mlkem1024",
    "Secp256R1Mlkem512", "Secp256R1Mlkem768", "Secp384R1Mlkem1024",
    "Mlkem512X25519", "X25519Mlkem768", "CurveSm2Mlkem768",
    "X25519Kyber768Draft00", "Secp256R1Kyber768Draft00",
}

WEAK_PROTOCOLS = {"Ssl20", "Ssl30", "Tls10", "Tls11"}

PROTOCOL_LABELS = {
    "Ssl20": "SSL 2.0", "Ssl30": "SSL 3.0", "Tls10": "TLS 1.0",
    "Tls11": "TLS 1.1", "Tls12": "TLS 1.2", "Tls13": "TLS 1.3",
    "Other": "Other",
}

# Native PQC fields. Their presence decides whether we can read verdicts
# directly or must fall back to inferring them from the negotiated cipher.
PQC_FIELDS = (
    "NetworkEndpointHttpResponseTlsPqcStatus",
    "NetworkEndpointHttpResponseTlsKeyExchangeGroups",
)


def is_pqc_group(group):
    return group in PQC_KEX_GROUPS


def score_verdict(endpoints, native):
    """Assign one of four verdicts to a resource from its endpoints.

    native=True  -> read TlsPqcStatus (authoritative)
    native=False -> infer from key exchange in the negotiated cipher (weaker)
    """
    if not endpoints:
        return "unknown"

    weak = any(e.get("tls") in WEAK_PROTOCOLS for e in endpoints)

    if native:
        statuses = {e.get("pqc_status") for e in endpoints if e.get("pqc_status")}
        if not statuses:
            return "unknown"
        if "Enforced" in statuses and not weak:
            return "safe"
        if "Ready" in statuses and "None" not in statuses and not weak:
            return "safe"
        if ("Ready" in statuses or "Enforced" in statuses) and "None" in statuses:
            return "review"
        if weak:
            return "review"
        if statuses == {"None"}:
            return "not_safe"
        return "unknown"

    # Inferred mode: no endpoint can be called safe without the native field,
    # so the best we can honestly say is "classical" or "needs review".
    any_pqc = any(e.get("pqc_groups") for e in endpoints)
    if any_pqc and not weak:
        return "safe"
    if weak:
        return "review"
    return "not_safe"


# ------------------------------------------------------------------ MCP client

class McpError(Exception):
    pass


class McpDataSource:
    """Minimal MCP client over streamable HTTP (JSON-RPC 2.0).

    Handshake: initialize -> notifications/initialized -> tools/call.
    Responses arrive as either application/json or text/event-stream.
    """

    def __init__(self, url=DEFAULT_MCP_URL, auth_mode="bearer", token=None,
                 access_key=None, secret_key=None, verify_tls=True, ca_bundle=None,
                 pinned=None, data_dir=None):
        self.url = (url or DEFAULT_MCP_URL).rstrip("/")
        self.auth_mode = auth_mode
        self.token = token
        self.access_key = access_key
        self.secret_key = secret_key
        self._session_id = None
        self._next_id = 0
        self._cached_opener = None
        # See trust.py for the full ladder. The important step is the OS trust
        # store: it is what makes this work on a corporate machine without the
        # customer having to export anything by hand.
        self._ctx, self._pin, self.trust_label = trust.resolve(
            data_dir or os.path.expanduser("~/.pqc-portal"),
            ca_bundle=ca_bundle, pinned=pinned, insecure=not verify_tls)

    # -- plumbing ----------------------------------------------------------

    def _auth_header(self):
        if self.auth_mode == "apikeys":
            if not (self.access_key and self.secret_key):
                raise McpError("Access key and secret key are required.")
            return ("X-ApiKeys",
                    "accessKey=%s;secretKey=%s" % (self.access_key, self.secret_key))
        if not self.token:
            raise McpError("Service account token is required.")
        return ("Authorization", "Bearer %s" % self.token)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        """Surface redirects as errors; an auth bounce must not look like data."""

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    def _opener(self):
        if getattr(self, "_cached_opener", None) is None:
            handlers = [self._NoRedirect()]
            if self._pin:
                handlers.append(trust.pinned_https_handler(self._pin))
            elif self._ctx is not None:
                handlers.append(urllib.request.HTTPSHandler(context=self._ctx))
            self._cached_opener = urllib.request.build_opener(*handlers)
        return self._cached_opener

    def _rpc(self, method, params=None, notify=False):
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        if not notify:
            self._next_id += 1
            payload["id"] = self._next_id

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        name, value = self._auth_header()
        req.add_header(name, value)
        if self._session_id:
            req.add_header("Mcp-Session-Id", self._session_id)

        try:
            with self._opener().open(req, timeout=TIMEOUT) as resp:
                sid = resp.headers.get("Mcp-Session-Id")
                if sid:
                    self._session_id = sid
                raw = resp.read().decode("utf-8", "replace")
                ctype = (resp.headers.get("Content-Type") or "").lower()
        except urllib.error.HTTPError as exc:
            # A 30x to the sign-in page means the credential was not accepted at
            # all. Report that plainly instead of trying to parse an HTML login
            # form as JSON-RPC.
            if exc.code in (301, 302, 303, 307, 308):
                target = exc.headers.get("Location") or ""
                if "login" in target.lower() or "signin" in target.lower():
                    raise McpError(
                        "The server redirected to a sign-in page, which means the "
                        "credential was rejected. Check the token is a Cloud "
                        "Security service account token and has not expired.")
                raise McpError("Unexpected redirect to %s" % target)
            if exc.code in (401, 403):
                raise McpError(
                    "Authentication failed (HTTP %s). Verify the token or API "
                    "keys, and that the account has Cloud Security access."
                    % exc.code)
            detail = exc.read().decode("utf-8", "replace")[:300]
            # Never echo credentials back to the caller.
            raise McpError("HTTP %s from MCP server: %s" % (exc.code, detail))
        except urllib.error.URLError as exc:
            reason = str(exc.reason)
            if "Pinned certificate mismatch" in reason:
                raise McpError(reason)
            if "CERTIFICATE_VERIFY_FAILED" in reason or "SSLCertVerification" in reason:
                raise McpError(
                    "TLS_UNTRUSTED: could not establish trust for %s (tried: %s). "
                    "Open Certificate trust in the connection dialog to resolve this."
                    % (self.url, self.trust_label))
            raise McpError("Cannot reach %s (%s)" % (self.url, reason))

        if notify:
            return None
        return self._parse(raw, ctype)

    @staticmethod
    def _parse(raw, ctype):
        """Handle both plain JSON and SSE-framed JSON-RPC responses."""
        obj = None
        if "text/event-stream" in ctype or raw.lstrip().startswith("event:") \
                or raw.lstrip().startswith("data:"):
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    chunk = line[5:].strip()
                    if not chunk or chunk == "[DONE]":
                        continue
                    try:
                        candidate = json.loads(chunk)
                    except ValueError:
                        continue
                    # Keep the frame that carries a result or error.
                    if "result" in candidate or "error" in candidate:
                        obj = candidate
        else:
            try:
                obj = json.loads(raw)
            except ValueError:
                raise McpError("Unparseable response from MCP server.")

        if obj is None:
            raise McpError("No JSON-RPC result in MCP response.")
        if "error" in obj:
            err = obj["error"]
            raise McpError(str(err.get("message") or err))
        return obj.get("result")

    def connect(self):
        self._rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "pqc-posture-portal", "version": "1.0"},
        })
        self._rpc("notifications/initialized", notify=True)
        return True

    def call_tool(self, name, arguments):
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        return self._tool_payload(result)

    @staticmethod
    def _tool_payload(result):
        """Unwrap MCP tool output into a Python object.

        Tool results arrive as content blocks; the useful one is the text
        block, which for UDM tools contains JSON.
        """
        if result is None:
            return None
        if isinstance(result, dict) and result.get("isError"):
            # A rejected query (unknown field, bad operator) comes back as a
            # tool error, not a JSON-RPC error. Surface it instead of letting
            # it parse as an empty result set.
            texts = [b.get("text", "") for b in result.get("content") or []
                     if isinstance(b, dict)]
            raise McpError("Tool error: " + ("; ".join(t for t in texts if t)
                                             or "query rejected by server"))
        if isinstance(result, dict) and "structuredContent" in result:
            return result["structuredContent"]
        blocks = (result or {}).get("content") if isinstance(result, dict) else None
        if not blocks:
            return result
        texts = [b.get("text", "") for b in blocks
                 if isinstance(b, dict) and b.get("type") == "text"]
        joined = "\n".join(t for t in texts if t)
        if not joined:
            return result
        try:
            return json.loads(joined)
        except ValueError:
            return {"text": joined}

    # -- capability detection ---------------------------------------------

    def detect_pqc_support(self):
        """True if this tenant's build exposes the native PQC fields.

        Prevents the silent-empty-dashboard failure: a saved view referencing
        TlsPqcStatus against a pre-PQC tenant would otherwise render zeros
        that look like a clean bill of health.
        """
        try:
            meta = self.call_tool("udm_get_object_type_metadata",
                                  {"objectTypeName": "NetworkEndpoint"})
            blob = json.dumps(meta) if not isinstance(meta, str) else meta
            if all(field in blob for field in PQC_FIELDS):
                return True
        except McpError:
            pass
        # The metadata tool can fail on some tenants even though the fields
        # exist. Probe directly: a count query that selects the PQC fields is
        # rejected by the server if any of them is unknown.
        return self._probe_fields(PQC_FIELDS)

    def _probe_fields(self, fields):
        qid = "0f0f0f0f-0000-0000-0000-000000000001"
        query = {
            "typeName": "UdmQuery", "objectTypeName": "NetworkEndpoint",
            "id": qid, "groupLevel": 0, "collapsed": False,
            "objectResultHidden": False, "timeZoneId": None, "joins": [],
            "properties": [{"identifier": f, "groupLevel": 0, "queryId": qid,
                            "aggregation": None, "sort": None,
                            "startOfWeek": None, "transform": None}
                           for f in fields],
            "ruleGroup": {"typeName": "UdmQueryRuleGroup",
                          "id": "0f0f0f0f-0000-0000-0000-000000000002",
                          "name": "", "operator": "And", "collapsed": False,
                          "ignored": False, "not": False, "rules": []},
        }
        try:
            self.count(query)
            return True
        except McpError:
            return False

    # -- queries -----------------------------------------------------------

    def count(self, query):
        res = self.call_tool("udm_get_query_results_count", {"query": json.dumps(query)})
        if isinstance(res, dict):
            for key in ("count", "total", "totalCount", "value"):
                if key in res:
                    return res[key]
        if isinstance(res, int):
            return res
        return None

    def execute(self, query, skip=0):
        return self.call_tool("udm_execute_query",
                              {"query": json.dumps(query), "skip": skip})

    def execute_all(self, query, page_size=PAGE_SIZE, max_pages=200):
        """Page through a query, accumulating normalized rows."""
        primary = query.get("id") if isinstance(query, dict) else None
        rows, skip, pages = [], 0, 0
        while pages < max_pages:
            payload = self.execute(query, skip=skip)
            page = normalize_rows(payload, primary_query_id=primary)
            rows.extend(page)
            has_more = bool(payload.get("hasMore")) if isinstance(payload, dict) else False
            if not page or not has_more:
                break
            skip += max(len(page), page_size)
            pages += 1
        return rows


class RestDataSource(McpDataSource):
    """Placeholder for a direct UDM REST endpoint.

    If Cloud Security exposes UDM over plain REST, subclass here: override
    execute()/count() to POST the same query bodies and return the same
    shape. Everything downstream is unchanged.
    """

    def connect(self):
        raise NotImplementedError(
            "No direct UDM REST endpoint is wired up. Use the MCP data source.")


class SnapshotDataSource:
    """Reads a snapshot JSON file instead of querying anything."""

    def __init__(self, path):
        self.path = path

    def connect(self):
        return True

    def detect_pqc_support(self):
        with open(self.path) as fh:
            return bool(json.load(fh).get("native_pqc"))

    def load(self):
        with open(self.path) as fh:
            return json.load(fh)


# ------------------------------------------------------------- normalization

ROW_CONTAINERS = ("resultsList", "rows", "items", "results", "data", "records")


def normalize_rows(payload, primary_query_id=None):
    """Flatten a UDM result payload into a list of {identifier: value} dicts.

    The real envelope looks like:

        {"hasMore": true,
         "resultsList": [
           {"groupLevel": 0,
            "queryIdToObjectMap": {
              "<primary-query-id>": {"propertyIdentifierToValueMap": {...}},
              "<join-query-id>":    {"propertyIdentifierToValueMap": {...}}}}]}

    Each result row therefore carries one object per query/join, and we merge
    them into a single flat dict. Both objects contain their own `Id`, so a
    naive merge silently clobbers the resource identifier with the endpoint's.
    We resolve that by mapping the primary object's `Id` to `EntityId` and
    merging the rest first-wins.
    """
    if payload is None:
        return []

    container = payload if isinstance(payload, list) else None
    if container is None:
        if not isinstance(payload, dict):
            return []
        for key in ROW_CONTAINERS:
            if isinstance(payload.get(key), list):
                container = payload[key]
                break
        if container is None:
            return []
    if not container:
        return []

    out = []
    for row in container:
        if not isinstance(row, dict):
            continue

        qmap = row.get("queryIdToObjectMap")
        if isinstance(qmap, dict):
            flat, primary_id = {}, None
            # Primary object first so its values win the merge.
            ordered = sorted(
                qmap.items(),
                key=lambda kv: 0 if (primary_query_id and kv[0] == primary_query_id) else 1)
            for qid, obj in ordered:
                if not isinstance(obj, dict):
                    continue
                props = obj.get("propertyIdentifierToValueMap")
                if not isinstance(props, dict):
                    continue
                is_primary = (primary_query_id and qid == primary_query_id) or \
                             (primary_query_id is None and primary_id is None)
                if is_primary and props.get("Id") is not None:
                    primary_id = props["Id"]
                for key, value in props.items():
                    flat.setdefault(key, value)
            if primary_id is not None:
                flat["EntityId"] = primary_id
            # Grouped queries put the aggregate at the ROW level, not inside
            # propertyIdentifierToValueMap. Lift it or every count reads zero.
            if isinstance(row.get("count"), int):
                flat["_count"] = row["count"]
            if "groupLevel" in row:
                flat.setdefault("_groupLevel", row["groupLevel"])
            if flat:
                out.append(flat)
            continue

        # Already-flat dict, or a properties list.
        if isinstance(row.get("properties"), list):
            flat = {}
            for prop in row["properties"]:
                if isinstance(prop, dict):
                    key = prop.get("identifier") or prop.get("name")
                    if key:
                        flat[key] = prop.get("value")
            out.append(flat)
        else:
            out.append(row)

    return out


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if v not in (None, "")]
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace("|", ",").split(",")]
        return [p for p in parts if p]
    return [value]


PROTOCOL_ORDER = ["Ssl20", "Ssl30", "Tls10", "Tls11", "Tls12", "Tls13"]


def _weakest_protocol(protocols):
    """Lowest TLS version an endpoint offers, so weak-protocol checks see it."""
    known = [p for p in protocols if p in PROTOCOL_ORDER]
    if known:
        return min(known, key=PROTOCOL_ORDER.index)
    return protocols[0] if protocols else ""


def build_snapshot(rows, native, aggregates, environment="", url=""):
    """Assemble the snapshot document the UI consumes.

    Live MCP mode and offline snapshot mode emit the SAME document, so the
    front end never needs to know which one produced it. This is the
    "saved query bundle" idea in practice: the queries are data, the render
    is deterministic, and no model sits in the view path.
    """
    by_resource, order = {}, []

    for row in rows:
        rid = (row.get("EntityId") or row.get("EntityName") or "").strip()
        if not rid:
            continue
        if rid not in by_resource:
            region = row.get("EntityRegion") or ""
            by_resource[rid] = {
                "id": rid,
                "name": row.get("EntityName") or rid,
                "type": row.get("EntityTypeName") or "",
                "provider": provider_from_region(region),
                "region": region,
                "console": row.get("EntityProviderConsoleUrl") or "",
                "endpoints": [],
            }
            order.append(rid)

        kex = _as_list(row.get("NetworkEndpointHttpResponseTlsKeyExchangeGroups"))
        # Current tenants expose TlsProtocols / TlsCipherSuites (lists); older
        # builds exposed singular TlsProtocol / TlsCipherSuite. Accept both.
        protocols = _as_list(row.get("NetworkEndpointHttpResponseTlsProtocols")
                             or row.get("NetworkEndpointHttpResponseTlsProtocol"))
        ciphers = _as_list(row.get("NetworkEndpointHttpResponseTlsCipherSuites")
                           or row.get("NetworkEndpointHttpResponseTlsCipherSuite"))
        endpoint = {
            "host": row.get("NetworkEndpointHost") or "",
            "port": row.get("NetworkEndpointPort"),
            "protocol": row.get("NetworkEndpointProtocolType") or "",
            "tls": _weakest_protocol(protocols),
            "protocols": protocols,
            "pqc": row.get("NetworkEndpointHttpResponseTlsPqcStatus") or None,
            "cipher": ciphers[0] if ciphers else "",
            "ciphers": ciphers,
            "kex": kex,
            "cert_expires": row.get(
                "NetworkEndpointHttpResponseTlsCertificateExpirationTime") or "",
        }
        seen = {(e["host"], e["port"], e["protocol"])
                for e in by_resource[rid]["endpoints"]}
        if (endpoint["host"], endpoint["port"], endpoint["protocol"]) not in seen:
            by_resource[rid]["endpoints"].append(endpoint)

    resources = []
    for rid in order:
        rec = by_resource[rid]
        eps = rec["endpoints"]
        rec["verdict"] = score_verdict(
            [{"pqc_status": e.get("pqc"), "tls": e.get("tls"),
              "pqc_groups": [g for g in e["kex"] if is_pqc_group(g)]} for e in eps],
            native)
        statuses = [e["pqc"] for e in eps if e.get("pqc")]
        rec["pqc_status"] = statuses[0] if statuses else None
        rec["endpoint_count"] = len(eps)
        resources.append(rec)

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "Tenable Cloud Security · Hexa AI MCP · UDM NetworkEndpoint",
        "environment": environment or _env_from_url(url),
        "native_pqc": native,
        "sample": False,
        "sample_note": (
            "" if native else
            "This tenant's Cloud Security build does not expose the native "
            "SSL/TLS PQC fields. Verdicts below are INFERRED from the negotiated "
            "cipher suite and are weaker evidence than a native PQC status."),
        "endpoint_totals": _endpoint_totals(aggregates, resources),
        "kex_profiles": _kex_profiles(aggregates),
        "cipher_suites": _cipher_suites(aggregates),
        "resources": resources,
    }


def _env_from_url(url):
    low = (url or "").lower()
    if "dev" in low or "staging" in low:
        return "dev"
    return "prod" if low else ""


def _agg_rows(aggregates, key):
    entry = (aggregates or {}).get(key) or {}
    return entry.get("rows") or []


def _first_str(row, skip_numeric=True):
    """Pull the grouping label out of an aggregate row."""
    for k, v in row.items():
        if k.startswith("_"):
            continue
        if isinstance(v, str) and v:
            return v
        if isinstance(v, list) and v:
            return ", ".join(str(x) for x in v)
    return ""


def _first_int(row):
    if isinstance(row.get("_count"), int):
        return row["_count"]
    for k, v in row.items():
        if k.startswith("_"):
            continue
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    return 0


def _endpoint_totals(aggregates, resources):
    totals = {"Ready": 0, "None": 0, "Enforced": 0, "total": 0}
    rows = _agg_rows(aggregates, "pqc_status")
    if rows:
        for row in rows:
            label, count = _first_str(row), _first_int(row)
            if label in totals:
                totals[label] = count
            totals["total"] += count
        return totals
    # No aggregate available: derive from the resource rows we do have.
    for res in resources:
        for ep in res.get("endpoints", []):
            status = ep.get("pqc") or "None"
            if status in totals:
                totals[status] += 1
            totals["total"] += 1
    return totals


def _kex_profiles(aggregates):
    out = []
    for row in _agg_rows(aggregates, "kex_profiles"):
        label = _first_str(row)
        groups = [g.strip() for g in label.split(",") if g.strip()]
        pqc = [g for g in groups if is_pqc_group(g)]
        out.append({
            "groups": groups,
            "endpoints": _first_int(row),
            "pqc": bool(pqc),
            "pqc_groups": pqc,
            "klass": "hybrid" if pqc else "classical",
        })
    return out


def _cipher_suites(aggregates):
    return [{"name": _first_str(row), "endpoints": _first_int(row)}
            for row in _agg_rows(aggregates, "cipher_suites")]


def provider_from_region(region):
    prefix = (region or "").split("-")[0].lower()
    return {"aws": "AWS", "gcp": "GCP", "azure": "Azure", "oci": "OCI"}.get(
        prefix, prefix.upper() or "Unknown")


def summarize(resources):
    counts = {"safe": 0, "not_safe": 0, "review": 0, "unknown": 0}
    for res in resources:
        counts[res["verdict"]] = counts.get(res["verdict"], 0) + 1
    counts["total"] = len(resources)
    return counts
