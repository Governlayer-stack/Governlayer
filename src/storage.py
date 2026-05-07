"""File storage abstraction for GovernLayer.

Supports two backends:
  - local: Filesystem storage under a configurable directory (default for dev).
  - s3: Any S3-compatible object store (AWS S3, MinIO, Cloudflare R2, etc.)
        Uses raw HTTP + AWS Signature V4 — no boto3 dependency.

Environment variables:
  STORAGE_BACKEND        "local" | "s3"  (default: "local")
  STORAGE_LOCAL_PATH     Directory for local storage (default: "./evidence_files")
  S3_BUCKET              Bucket name (required for s3)
  S3_REGION              AWS region (default: "us-east-1")
  S3_ACCESS_KEY          Access key ID
  S3_SECRET_KEY          Secret access key
  S3_ENDPOINT_URL        Custom endpoint for non-AWS S3 (e.g. MinIO, R2)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# ---------------------------------------------------------------------------
# Configuration (read once at import, overridable via env)
# ---------------------------------------------------------------------------

STORAGE_BACKEND: str = os.getenv("STORAGE_BACKEND", "local").lower()
STORAGE_LOCAL_PATH: str = os.getenv("STORAGE_LOCAL_PATH", "./evidence_files")

S3_BUCKET: str = os.getenv("S3_BUCKET", "")
S3_REGION: str = os.getenv("S3_REGION", "us-east-1")
S3_ACCESS_KEY: str = os.getenv("S3_ACCESS_KEY", "")
S3_SECRET_KEY: str = os.getenv("S3_SECRET_KEY", "")
S3_ENDPOINT_URL: str = os.getenv("S3_ENDPOINT_URL", "")

# Content-type fallback
_DEFAULT_CONTENT_TYPE = "application/octet-stream"

# Metadata header prefix for S3
_AMZN_META_PREFIX = "x-amz-meta-"


# ---------------------------------------------------------------------------
# AWS Signature V4 helpers (minimal, no external deps)
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k_date = _hmac_sha256(f"AWS4{secret}".encode("utf-8"), datestamp)
    k_region = _hmac_sha256(k_date, region)
    k_service = _hmac_sha256(k_region, service)
    k_signing = _hmac_sha256(k_service, "aws4_request")
    return k_signing


def _s3_host() -> str:
    """Return the S3 host (custom endpoint or default AWS)."""
    if S3_ENDPOINT_URL:
        # Strip scheme for the Host header
        host = S3_ENDPOINT_URL.replace("https://", "").replace("http://", "").rstrip("/")
        return host
    return f"{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com"


def _s3_base_url() -> str:
    """Return the base URL for S3 requests."""
    if S3_ENDPOINT_URL:
        return f"{S3_ENDPOINT_URL.rstrip('/')}/{S3_BUCKET}"
    return f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com"


def _sign_s3_request(
    method: str,
    key: str,
    headers: dict[str, str],
    payload: bytes = b"",
    query_params: dict[str, str] | None = None,
) -> dict[str, str]:
    """Sign an S3 request using AWS Signature V4. Returns updated headers dict."""

    now = datetime.now(timezone.utc)
    datestamp = now.strftime("%Y%m%d")
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")

    host = _s3_host()
    service = "s3"
    credential_scope = f"{datestamp}/{S3_REGION}/{service}/aws4_request"

    # Canonical URI — must be URL-encoded but preserve slashes
    canonical_uri = "/" + quote(key, safe="/")
    if S3_ENDPOINT_URL:
        canonical_uri = f"/{S3_BUCKET}" + canonical_uri

    # Canonical query string
    if query_params:
        canonical_querystring = "&".join(
            f"{quote(k, safe='')}={quote(v, safe='')}"
            for k, v in sorted(query_params.items())
        )
    else:
        canonical_querystring = ""

    # Mandatory headers
    headers["host"] = host
    headers["x-amz-date"] = amz_date
    headers["x-amz-content-sha256"] = _sha256(payload)

    # Canonical headers + signed headers (must be sorted)
    signed_header_keys = sorted(headers.keys())
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in signed_header_keys)
    signed_headers = ";".join(signed_header_keys)

    canonical_request = "\n".join([
        method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        _sha256(payload),
    ])

    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        _sha256(canonical_request.encode("utf-8")),
    ])

    signing_key = _signing_key(S3_SECRET_KEY, datestamp, S3_REGION, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={S3_ACCESS_KEY}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return headers


def _generate_presigned_url(key: str, expires: int = 3600) -> str:
    """Generate an S3 presigned GET URL using query-string authentication."""

    now = datetime.now(timezone.utc)
    datestamp = now.strftime("%Y%m%d")
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")

    host = _s3_host()
    service = "s3"
    credential_scope = f"{datestamp}/{S3_REGION}/{service}/aws4_request"
    credential = f"{S3_ACCESS_KEY}/{credential_scope}"

    canonical_uri = "/" + quote(key, safe="/")
    if S3_ENDPOINT_URL:
        canonical_uri = f"/{S3_BUCKET}" + canonical_uri

    query_params = {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": credential,
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(expires),
        "X-Amz-SignedHeaders": "host",
    }
    canonical_querystring = "&".join(
        f"{quote(k, safe='')}={quote(v, safe='')}"
        for k, v in sorted(query_params.items())
    )

    canonical_headers = f"host:{host}\n"
    canonical_request = "\n".join([
        "GET",
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        "host",
        "UNSIGNED-PAYLOAD",
    ])

    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        _sha256(canonical_request.encode("utf-8")),
    ])

    signing_key = _signing_key(S3_SECRET_KEY, datestamp, S3_REGION, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    base_url = _s3_base_url()
    signed_qs = canonical_querystring + f"&X-Amz-Signature={signature}"
    return f"{base_url}/{quote(key, safe='/')}?{signed_qs}"


# ---------------------------------------------------------------------------
# S3 backend operations
# ---------------------------------------------------------------------------

def _s3_put(key: str, data: bytes, content_type: str, metadata: dict[str, str] | None = None) -> str:
    """PUT an object to S3. Returns the object URL."""
    headers: dict[str, str] = {
        "content-type": content_type,
    }
    if metadata:
        for mk, mv in metadata.items():
            safe_key = mk.lower().replace(" ", "-")
            headers[f"{_AMZN_META_PREFIX}{safe_key}"] = str(mv)

    headers = _sign_s3_request("PUT", key, headers, payload=data)

    url = f"{_s3_base_url()}/{quote(key, safe='/')}"
    req = Request(url, data=data, headers=headers, method="PUT")

    try:
        with urlopen(req, timeout=30) as resp:
            resp.read()
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"S3 PUT failed ({exc.code}): {body}") from exc

    return url


def _s3_get(key: str) -> tuple[bytes, str]:
    """GET an object from S3. Returns (data, content_type)."""
    headers: dict[str, str] = {}
    headers = _sign_s3_request("GET", key, headers)

    url = f"{_s3_base_url()}/{quote(key, safe='/')}"
    req = Request(url, headers=headers, method="GET")

    try:
        with urlopen(req, timeout=60) as resp:
            data = resp.read()
            ct = resp.headers.get("Content-Type", _DEFAULT_CONTENT_TYPE)
            return data, ct
    except HTTPError as exc:
        if exc.code == 404:
            raise FileNotFoundError(f"S3 object not found: {key}") from exc
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"S3 GET failed ({exc.code}): {body}") from exc


def _s3_delete(key: str) -> bool:
    """DELETE an object from S3."""
    headers: dict[str, str] = {}
    headers = _sign_s3_request("DELETE", key, headers)

    url = f"{_s3_base_url()}/{quote(key, safe='/')}"
    req = Request(url, headers=headers, method="DELETE")

    try:
        with urlopen(req, timeout=30) as resp:
            resp.read()
            return True
    except HTTPError as exc:
        if exc.code == 404:
            return False
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"S3 DELETE failed ({exc.code}): {body}") from exc


def _s3_list(prefix: str = "") -> list[dict]:
    """List objects in S3 with a given prefix. Returns basic metadata list."""
    headers: dict[str, str] = {}
    query_params: dict[str, str] = {"list-type": "2"}
    if prefix:
        query_params["prefix"] = prefix

    headers = _sign_s3_request("GET", "", headers, query_params=query_params)

    qs = urlencode(query_params)
    url = f"{_s3_base_url()}/?{qs}"
    req = Request(url, headers=headers, method="GET")

    try:
        with urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
    except HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"S3 LIST failed ({exc.code}): {err_body}") from exc

    # Parse the XML response (minimal parsing, no lxml dependency)
    import xml.etree.ElementTree as ET

    root = ET.fromstring(body)
    # S3 namespaces can vary; strip namespace for robustness
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    results = []
    for contents in root.findall(f"{ns}Contents"):
        key_el = contents.find(f"{ns}Key")
        size_el = contents.find(f"{ns}Size")
        modified_el = contents.find(f"{ns}LastModified")
        if key_el is not None:
            results.append({
                "key": key_el.text,
                "size": int(size_el.text) if size_el is not None and size_el.text else 0,
                "last_modified": modified_el.text if modified_el is not None else None,
                "storage_backend": "s3",
            })

    return results


# ---------------------------------------------------------------------------
# Local filesystem backend operations
# ---------------------------------------------------------------------------

def _local_root() -> Path:
    """Return (and ensure exists) the local storage root directory."""
    root = Path(STORAGE_LOCAL_PATH)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _local_key_to_path(key: str) -> Path:
    """Resolve a storage key to an absolute local path."""
    return _local_root() / key


def _local_put(key: str, data: bytes, content_type: str, metadata: dict[str, str] | None = None) -> str:
    """Write a file to local storage. Returns a /files/{key} style path."""
    fpath = _local_key_to_path(key)
    fpath.parent.mkdir(parents=True, exist_ok=True)
    fpath.write_bytes(data)

    # Store content-type alongside the file as a sidecar
    meta_path = fpath.with_suffix(fpath.suffix + ".meta")
    import json
    meta = {"content_type": content_type, "size": len(data)}
    if metadata:
        meta["metadata"] = metadata
    meta_path.write_text(json.dumps(meta), encoding="utf-8")

    return f"/files/{key}"


def _local_get(key: str) -> tuple[bytes, str]:
    """Read a file from local storage. Returns (data, content_type)."""
    fpath = _local_key_to_path(key)
    if not fpath.is_file():
        raise FileNotFoundError(f"Local file not found: {key}")

    data = fpath.read_bytes()
    content_type = _DEFAULT_CONTENT_TYPE

    meta_path = fpath.with_suffix(fpath.suffix + ".meta")
    if meta_path.is_file():
        import json
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            content_type = meta.get("content_type", _DEFAULT_CONTENT_TYPE)
        except (json.JSONDecodeError, KeyError):
            pass

    return data, content_type


def _local_delete(key: str) -> bool:
    """Delete a file from local storage."""
    fpath = _local_key_to_path(key)
    if not fpath.is_file():
        return False

    fpath.unlink()
    meta_path = fpath.with_suffix(fpath.suffix + ".meta")
    if meta_path.is_file():
        meta_path.unlink()
    return True


def _local_list(prefix: str = "") -> list[dict]:
    """List files in local storage with an optional prefix filter."""
    root = _local_root()
    results = []

    for fpath in sorted(root.rglob("*")):
        if not fpath.is_file() or fpath.name.endswith(".meta"):
            continue
        rel = str(fpath.relative_to(root))
        if prefix and not rel.startswith(prefix):
            continue

        stat = fpath.stat()
        results.append({
            "key": rel,
            "size": stat.st_size,
            "last_modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "storage_backend": "local",
        })

    return results


# ---------------------------------------------------------------------------
# Generate a storage key for a new upload
# ---------------------------------------------------------------------------

def _make_key(filename: str) -> str:
    """Generate a date-partitioned, collision-free storage key.

    Format: {YYYY-MM-DD}/{uuid}_{sanitized_filename}
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in filename)
    uid = uuid.uuid4().hex[:12]
    return f"{today}/{uid}_{safe_name}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def upload_file(
    file_bytes: bytes,
    filename: str,
    content_type: str,
    metadata: Optional[dict] = None,
) -> dict:
    """Upload a file to the configured storage backend.

    Returns:
        dict with keys: key, url, size, content_type, storage_backend
    """
    if not filename:
        raise ValueError("filename is required")

    key = _make_key(filename)
    ct = content_type or _DEFAULT_CONTENT_TYPE
    str_metadata = {k: str(v) for k, v in metadata.items()} if metadata else None

    if STORAGE_BACKEND == "s3":
        _validate_s3_config()
        url = _s3_put(key, file_bytes, ct, str_metadata)
    else:
        url = _local_put(key, file_bytes, ct, str_metadata)

    return {
        "key": key,
        "url": url,
        "size": len(file_bytes),
        "content_type": ct,
        "storage_backend": STORAGE_BACKEND,
    }


async def get_file(key: str) -> tuple[bytes, str]:
    """Retrieve a file by its storage key.

    Returns:
        (file_bytes, content_type)

    Raises:
        FileNotFoundError: if the key does not exist.
    """
    if STORAGE_BACKEND == "s3":
        _validate_s3_config()
        return _s3_get(key)
    return _local_get(key)


async def delete_file(key: str) -> bool:
    """Delete a file by its storage key.

    Returns:
        True if the file was deleted, False if it did not exist.
    """
    if STORAGE_BACKEND == "s3":
        _validate_s3_config()
        return _s3_delete(key)
    return _local_delete(key)


async def get_presigned_url(key: str, expires: int = 3600) -> str:
    """Generate a time-limited URL for downloading the file.

    For S3: a properly signed presigned URL.
    For local: a relative /files/{key} path (your app must serve this route).
    """
    if expires < 1 or expires > 604800:
        raise ValueError("expires must be between 1 and 604800 seconds (7 days)")

    if STORAGE_BACKEND == "s3":
        _validate_s3_config()
        return _generate_presigned_url(key, expires)
    return f"/files/{key}"


def list_files(prefix: str = "") -> list[dict]:
    """List files with an optional key prefix filter.

    Returns:
        List of dicts with: key, size, last_modified, storage_backend
    """
    if STORAGE_BACKEND == "s3":
        _validate_s3_config()
        return _s3_list(prefix)
    return _local_list(prefix)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_s3_config() -> None:
    """Raise early if S3 configuration is incomplete."""
    missing = []
    if not S3_BUCKET:
        missing.append("S3_BUCKET")
    if not S3_ACCESS_KEY:
        missing.append("S3_ACCESS_KEY")
    if not S3_SECRET_KEY:
        missing.append("S3_SECRET_KEY")
    if missing:
        raise RuntimeError(
            f"S3 storage backend selected but missing environment variables: {', '.join(missing)}"
        )
