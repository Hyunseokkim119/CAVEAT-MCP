"""
caveat.core
-----------
Reference implementation of the CAVEAT capability layer:

  * HMAC-SHA256 chained, attenuable capability tokens  (paper Eq. (1)-(2))
        m0 = HMAC_kS( id || H(D) || vD )
        mi = HMAC_{m_{i-1}}( cav_i )
  * Ed25519-signed tool manifests + runtime re-attestation (rug-pull detection)
  * Offline delegation by appending binding caveats (no issuer round-trip)

Design goal: a *thin* layer over a bearer-token MCP call. All authority checks
are deterministic and independent of any model context (structural isolation
of the authorisation decision from the manipulable context).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------
def H(data: bytes) -> bytes:
    """Manifest digest H(.) = SHA-256."""
    return hashlib.sha256(data).digest()


def _mac(key: bytes, msg: bytes) -> bytes:
    """Keyed MAC used for the caveat chain: HMAC-SHA256."""
    return hmac.new(key, msg, hashlib.sha256).digest()


def _canon(obj: Any) -> bytes:
    """Deterministic canonical serialisation for hashing/MAC input."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Tool manifest  (signed digest of the approved tool definition)
# ---------------------------------------------------------------------------
@dataclass
class ToolManifest:
    """The exact approved behaviour: digest H(D) + monotone version vD, signed."""
    tool_name: str
    digest: bytes            # H(D)
    version: int             # vD (monotone)
    signature: bytes         # Sign_skS( H(D) || vD )

    @staticmethod
    def create(definition: Dict[str, Any], version: int,
               sk: Ed25519PrivateKey) -> "ToolManifest":
        digest = H(_canon(definition))
        sig = sk.sign(digest + version.to_bytes(8, "big"))
        return ToolManifest(definition["name"], digest, version, sig)

    def verify(self, pk: Ed25519PublicKey) -> bool:
        try:
            pk.verify(self.signature, self.digest + self.version.to_bytes(8, "big"))
            return True
        except InvalidSignature:
            return False


# ---------------------------------------------------------------------------
# Caveats  (attenuation predicates over an invocation context)
# ---------------------------------------------------------------------------
# A caveat is a serialisable predicate label evaluated against a concrete
# invocation context (a dict). Each caveat can only *narrow* authority.
CaveatPredicate = Callable[[Dict[str, Any]], bool]


def _eval_caveat(cav: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
    """Deterministically evaluate a caveat against an invocation context."""
    kind = cav.get("k")
    if kind == "tool":                       # tool name must match
        return ctx.get("tool") == cav["v"]
    if kind == "prefix":                     # path argument must have prefix
        return str(ctx.get("path", "")).startswith(cav["v"])
    if kind == "argmax":                     # numeric argument upper bound
        return float(ctx.get(cav["arg"], float("inf"))) <= float(cav["v"])
    if kind == "expiry":                     # not expired
        return float(ctx.get("now", 0)) <= float(cav["v"])
    if kind == "bind":                       # bound principal + task (delegation)
        return (ctx.get("agent") == cav["agent"]
                and ctx.get("task") == cav["task"])
    return False                             # unknown caveat -> deny


# ---------------------------------------------------------------------------
# Capability token  (HMAC-chained, attenuable)
# ---------------------------------------------------------------------------
@dataclass
class Capability:
    cap_id: str
    manifest_digest: bytes
    manifest_version: int
    caveats: List[Dict[str, Any]] = field(default_factory=list)
    tag: bytes = b""                         # terminal MAC of the chain

    def attenuate(self, cav: Dict[str, Any]) -> "Capability":
        """Append a caveat, chaining the MAC:  m_i = HMAC_{m_{i-1}}(cav_i)."""
        new_tag = _mac(self.tag, _canon(cav))
        return Capability(self.cap_id, self.manifest_digest,
                          self.manifest_version, self.caveats + [cav], new_tag)

    def delegate(self, agent: str, task: str) -> "Capability":
        """Offline delegation: append a binding caveat (no issuer contact)."""
        return self.attenuate({"k": "bind", "agent": agent, "task": task})


class Issuer:
    """Per-server capability-issuing authority holding root key kS."""

    def __init__(self, server_id: str, root_key: bytes):
        self.server_id = server_id
        self.kS = root_key

    def mint_root(self, cap_id: str, manifest: ToolManifest) -> Capability:
        """Root capability:  m0 = HMAC_kS( id || H(D) || vD )."""
        seed_msg = _canon([cap_id, manifest.digest.hex(), manifest.version])
        m0 = _mac(self.kS, seed_msg)
        return Capability(cap_id, manifest.digest, manifest.version, [], m0)


# ---------------------------------------------------------------------------
# Verifier  (recomputes the chain, evaluates caveats, re-attests manifest)
# ---------------------------------------------------------------------------
class VerificationResult:
    def __init__(self, ok: bool, reason: str = ""):
        self.ok = ok
        self.reason = reason

    def __bool__(self) -> bool:
        return self.ok


class Verifier:
    """
    Runs at (or co-located with) the server. Deterministic, context-free
    authorisation decision -- never consults model context.
    """

    def __init__(self, server_id: str, root_key: bytes, pk: Ed25519PublicKey):
        self.server_id = server_id
        self.kS = root_key
        self.pk = pk

    def _recompute_chain(self, cap: Capability) -> bytes:
        seed_msg = _canon([cap.cap_id, cap.manifest_digest.hex(),
                           cap.manifest_version])
        m = _mac(self.kS, seed_msg)
        for cav in cap.caveats:
            m = _mac(m, _canon(cav))
        return m

    def verify(self, cap: Capability, ctx: Dict[str, Any],
               served_manifest: ToolManifest,
               reattest: bool = True) -> VerificationResult:
        # (1) MAC chain integrity  -> confinement / anti-forgery
        if not hmac.compare_digest(self._recompute_chain(cap), cap.tag):
            return VerificationResult(False, "mac_chain_mismatch")
        # (2) all caveats satisfied -> monotonic confinement at eval time
        for cav in cap.caveats:
            if not _eval_caveat(cav, ctx):
                return VerificationResult(False, f"caveat_unsatisfied:{cav.get('k')}")
        # (3) runtime re-attestation -> rug-pull detection
        if reattest:
            if not served_manifest.verify(self.pk):
                return VerificationResult(False, "manifest_bad_signature")
            if served_manifest.digest != cap.manifest_digest:
                return VerificationResult(False, "manifest_digest_mismatch")  # rug pull
            if served_manifest.version < cap.manifest_version:
                return VerificationResult(False, "version_regression")
        return VerificationResult(True, "ok")
