"""Signed, tamper-evident audit-evidence packs (Pro).

An evidence pack is a point-in-time attestation of an access review: which
findings were open and which were resolved (and when), the blast-radius picture,
mean-time-to-remediate, and the scan history behind it. The pack is signed with
a local Ed25519 key so anyone, an auditor included, can verify it was not
altered after generation.

The signing key is the CUSTOMER's own, generated locally next to the database
and never leaving the box. It is not the vendor license key, and the vendor is
never in the loop: generation and verification are entirely offline. Verifying a
pack proves internal integrity (the content matches the signature). To trust
*who* signed it, an auditor pins the customer's attestation public-key
fingerprint, which is stable across packs and printed on generation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from afterlife import __version__, db
from afterlife.scan_runs import list_runs

SCHEMA = "afterlife.evidence/v1"
ALGORITHM = "Ed25519"
KEY_FILENAME = ".afterlife-attestation-key.pem"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ---------------------------------------------------------------- signing key


def default_key_path(db_path: Path) -> Path:
    """The attestation key lives next to the database by default."""
    return Path(db_path).resolve().parent / KEY_FILENAME


def load_or_create_key(key_path: Path) -> Ed25519PrivateKey:
    """Load the local attestation key, generating it (mode 600) on first use."""
    if key_path.exists():
        key = ser.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{key_path} is not an Ed25519 private key")
        return key
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()
    )
    # Create the file atomically at mode 600 so the private key is never, even
    # briefly, group- or world-readable, and O_EXCL closes the exists()->write
    # race. This key is the customer's sole attestation identity; anyone who can
    # read it can forge packs that verify under their pinned fingerprint.
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return load_or_create_key(key_path)  # created concurrently; load it
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    return key


def _public_pem(key: Ed25519PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def fingerprint(public_key_pem: str) -> str:
    """Full SHA-256 fingerprint of an attestation public key, for pinning.

    Returned in full (256 bits, 64 hex): this is a long-lived trust anchor that
    an auditor compares out of band, so it is not truncated. A shortened id
    would invite a second-preimage collision (an attacker brute-forcing a key
    whose fingerprint matches a pinned value).
    """
    return hashlib.sha256(public_key_pem.strip().encode()).hexdigest()


# ---------------------------------------------------------------- payload


def _canonical(payload: dict) -> bytes:
    """Deterministic bytes to sign: sorted keys, no incidental whitespace."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _subject(row: dict) -> str:
    if row.get("identity_source") and row.get("identity_id"):
        return f"{row['identity_source']}:{row['identity_id']}"
    ev = row.get("evidence") or {}
    if isinstance(ev, dict):
        for k in ("credential_id", "role_name", "source_id"):
            if ev.get(k):
                return str(ev[k])
    return row.get("title", "")


def _blast_label(blast: dict | None) -> str | None:
    if not blast:
        return None
    score = blast.get("score") or 0.0
    if score >= 0.7:
        return "broad"
    if score >= 0.4:
        return "moderate"
    return "limited"


def _days_between(start: str | None, end: str | None) -> float | None:
    try:
        s = datetime.fromisoformat(start)  # type: ignore[arg-type]
        e = datetime.fromisoformat(end)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return round((e - s).total_seconds() / 86400, 2)


def _finding_record(row: dict) -> dict[str, Any]:
    ev = row.get("evidence")
    if isinstance(ev, str) and ev:
        try:
            ev = json.loads(ev)
        except json.JSONDecodeError:
            ev = None
    blast = row.get("blast_radius")
    if isinstance(blast, str) and blast:
        try:
            blast = json.loads(blast)
        except json.JSONDecodeError:
            blast = None
    rec = {
        "rule_id": row["rule_id"],
        "severity": row["severity"],
        "title": row["title"],
        "subject": _subject({**row, "evidence": ev}),
        "blast": _blast_label(blast if isinstance(blast, dict) else None),
        "status": row.get("status", "open"),
        "first_seen": row.get("first_seen") or row.get("detected_at"),
        "last_seen": row.get("last_seen"),
        "resolved_at": row.get("resolved_at"),
        "fingerprint": row.get("fingerprint"),
    }
    return rec


def build_payload(
    db_path: Path,
    *,
    licensed_to: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Assemble the (unsigned) attestation payload from the current database."""
    now = now or datetime.now(UTC)
    with db.connect(db_path) as conn:
        rows = [
            dict(r)
            for r in conn.execute(
                """
                SELECT rule_id, severity, title, identity_source, identity_id,
                       evidence, blast_radius, detected_at, status,
                       first_seen, last_seen, resolved_at, fingerprint
                FROM findings
                WHERE status IN ('open', 'resolved') AND suppressed = 0
                """
            ).fetchall()
        ]

    def _sort_key(r: dict) -> tuple:
        return (_SEVERITY_ORDER.get(r["severity"], 9), r.get("first_seen") or "")

    open_rows = sorted(
        (r for r in rows if r.get("status") == "open"), key=_sort_key
    )
    resolved_rows = sorted(
        (r for r in rows if r.get("status") == "resolved"),
        key=lambda r: r.get("resolved_at") or "",
    )

    open_findings = [_finding_record(r) for r in open_rows]
    resolved_findings = [_finding_record(r) for r in resolved_rows]

    by_severity: dict[str, int] = {}
    for r in open_findings:
        by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + 1

    ttrs = [
        d
        for r in resolved_rows
        if (d := _days_between(r.get("first_seen"), r.get("resolved_at")))
        is not None
    ]
    mttr = round(sum(ttrs) / len(ttrs), 2) if ttrs else None

    runs = list_runs(db_path, limit=100)
    scan_history = [
        {
            "source": run["source"],
            "started_at": run["started_at"],
            "finished_at": run.get("finished_at"),
            "records_collected": run.get("records_collected"),
            "error": run.get("error"),
        }
        for run in runs
    ]
    sources_scanned = sorted({run["source"] for run in runs})

    return {
        "schema": SCHEMA,
        "attestation_id": uuid.uuid4().hex,
        "generated_at": now.isoformat(),
        "tool": "afterlife",
        "tool_version": __version__,
        "licensed_to": licensed_to,
        "summary": {
            "open_total": len(open_findings),
            "open_by_severity": by_severity,
            "resolved_total": len(resolved_findings),
            "mean_time_to_remediate_days": mttr,
            "sources_scanned": sources_scanned,
            "scan_runs": len(scan_history),
        },
        "open_findings": open_findings,
        "resolved_findings": resolved_findings,
        "scan_history": scan_history,
    }


# ---------------------------------------------------------------- sign / verify


def sign_payload(payload: dict, key: Ed25519PrivateKey) -> dict[str, Any]:
    """Wrap a payload in a signed envelope."""
    canonical = _canonical(payload)
    return {
        "schema": SCHEMA,
        "payload": payload,
        "algorithm": ALGORITHM,
        "public_key": _public_pem(key),
        "content_sha256": hashlib.sha256(canonical).hexdigest(),
        "signature": base64.b64encode(key.sign(canonical)).decode("ascii"),
    }


def generate_evidence(
    db_path: Path,
    *,
    key_path: Path | None = None,
    licensed_to: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build and sign an evidence pack from the current database state."""
    key = load_or_create_key(key_path or default_key_path(db_path))
    payload = build_payload(db_path, licensed_to=licensed_to, now=now)
    return sign_payload(payload, key)


_REQUIRED_PAYLOAD_KEYS = frozenset({"attestation_id", "generated_at", "summary"})


def verify_evidence(pack: object) -> tuple[bool, dict | None, str]:
    """Verify a pack's signature. Free and offline: no license needed.

    Returns (ok, payload, reason). ok=True means the pack is a well-formed
    evidence payload, internally consistent, and unaltered since it was signed by
    the holder of the embedded public key. It does NOT establish *who* signed it:
    the pack carries its own public key, so trusting the origin requires pinning
    the key fingerprint out of band. Any malformed input yields (False, None,
    reason) rather than raising, since this is the untrusted, free verify path.
    """
    if not isinstance(pack, dict):
        return False, None, "pack is not a JSON object"
    payload = pack.get("payload")
    public_key_pem = pack.get("public_key")
    signature_b64 = pack.get("signature")
    if not (
        isinstance(payload, dict)
        and isinstance(public_key_pem, str)
        and isinstance(signature_b64, str)
    ):
        return False, None, "pack is malformed (missing or invalid fields)"

    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key = ser.load_pem_public_key(public_key_pem.encode())
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return False, None, "pack is malformed (bad signature or key encoding)"
    if not isinstance(public_key, Ed25519PublicKey):
        return False, None, "unsupported key type (not Ed25519)"

    canonical = _canonical(payload)
    expected_hash = pack.get("content_sha256")
    if expected_hash and expected_hash != hashlib.sha256(canonical).hexdigest():
        return False, None, "content hash does not match payload (tampered)"
    try:
        public_key.verify(signature, canonical)
    except InvalidSignature:
        return False, None, "signature does not verify (tampered or wrong key)"

    # A good signature proves integrity only; also require a well-formed evidence
    # payload so the caller never gets ok=True for a signed-but-malformed pack.
    if payload.get("schema") != SCHEMA:
        return False, None, "unrecognized evidence schema"
    if not _REQUIRED_PAYLOAD_KEYS.issubset(payload) or not isinstance(
        payload.get("summary"), dict
    ):
        return False, None, "payload is missing required fields"
    return True, payload, "ok"


# ---------------------------------------------------------------- io helpers


_EMBED_RE = re.compile(
    r'<script[^>]*id="afterlife-evidence"[^>]*>(.*?)</script>', re.DOTALL
)


def load_pack(path: Path) -> dict:
    """Load a pack from a .json file, or extract one embedded in an .html render."""
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return json.loads(text)
    match = _EMBED_RE.search(text)
    if match:
        return json.loads(match.group(1))
    raise ValueError(f"no evidence pack found in {path}")


_HTML_CSS = (
    "body{font:15px/1.5 system-ui,sans-serif;max-width:900px;"
    "margin:2rem auto;padding:0 1rem;color:#111}"
    "h1{font-size:1.4rem;margin-bottom:.2rem}"
    ".muted{color:#666}"
    ".mono{font-family:ui-monospace,Menlo,monospace;font-size:.85em}"
    "table{border-collapse:collapse;width:100%;margin:1rem 0}"
    "th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;font-size:.9em}"
    "th{background:#f5f5f5}"
    ".seal{background:#f5f7fa;border:1px solid #dde;border-radius:8px;"
    "padding:12px 16px;margin:1rem 0}"
    "code{background:#f0f0f0;padding:1px 5px;border-radius:4px}"
)


def render_html(pack: dict) -> str:
    """A readable, self-verifying HTML rendering: embeds the signed pack."""
    payload = pack["payload"]
    s = payload["summary"]
    fp = fingerprint(pack["public_key"])
    # Escape "</" so a stray "</script>" in the data cannot close the tag early;
    # JSON parsers read "<\/" back as "</", so the pack still round-trips.
    embedded = json.dumps(pack).replace("</", "<\\/")

    def _rows(findings: list[dict], when_key: str) -> str:
        if not findings:
            return '<tr><td colspan="5" class="muted">None</td></tr>'
        cells = []
        for f in findings:
            when = (
                f.get(when_key) or f.get("last_seen") or f.get("first_seen") or ""
            )
            cells.append(
                "<tr>"
                f"<td class=mono>{_esc(f['rule_id'])}</td>"
                f"<td>{_esc(f['severity'])}</td>"
                f"<td class=mono>{_esc(f['subject'])}</td>"
                f"<td>{_esc(f.get('blast') or '')}</td>"
                f"<td class=mono>{_esc(when)}</td>"
                "</tr>"
            )
        return "".join(cells)

    who = (
        f" for {_esc(payload['licensed_to'])} (claimed)"
        if payload.get("licensed_to")
        else ""
    )
    mttr = s["mean_time_to_remediate_days"]
    mttr_txt = str(mttr) if mttr is not None else "n/a"
    sources = _esc(", ".join(s["sources_scanned"]) or "none")
    sev = _esc(json.dumps(s["open_by_severity"]))

    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        "<title>Afterlife access-review attestation</title>",
        f"<style>{_HTML_CSS}</style></head><body>",
        "<h1>Access-review attestation</h1>",
        f'<p class="muted">Generated {_esc(payload["generated_at"])} by '
        f'afterlife {_esc(payload["tool_version"])}{who}.</p>',
        '<div class="seal"><strong>Cryptographically signed.</strong> '
        "A valid signature proves this document is unaltered since signing; trust "
        "its origin only if the fingerprint below matches one you obtained from "
        "the signer directly (the pack carries its own key).<br>"
        f'Attestation id <code class="mono">{_esc(payload["attestation_id"])}</code><br>'
        f'Signing-key fingerprint <code class="mono">{_esc(fp)}</code><br>'
        "Verify: <code>afterlife verify-evidence &lt;this file&gt;</code>.</div>",
        "<h2>Summary</h2><ul>",
        f"<li>Open findings: <strong>{s['open_total']}</strong> ({sev})</li>",
        f"<li>Resolved findings on record: <strong>{s['resolved_total']}</strong></li>",
        f"<li>Mean time to remediate: <strong>{mttr_txt}</strong> days</li>",
        f"<li>Sources scanned: {sources}</li></ul>",
        "<h2>Open findings</h2><table><tr><th>Rule</th><th>Severity</th>"
        "<th>Subject</th><th>Blast</th><th>Last seen</th></tr>"
        f"{_rows(payload['open_findings'], 'last_seen')}</table>",
        "<h2>Resolved (remediated) findings</h2><table><tr><th>Rule</th>"
        "<th>Severity</th><th>Subject</th><th>Blast</th><th>Resolved</th></tr>"
        f"{_rows(payload['resolved_findings'], 'resolved_at')}</table>",
        f'<script type="application/json" id="afterlife-evidence">{embedded}</script>',
        "</body></html>",
    ]
    return "\n".join(parts) + "\n"


def _esc(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
