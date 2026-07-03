"""
caveat.stack
------------
A minimal in-process MCP-style host/client/server stack, used to measure the
end-to-end overhead of the CAVEAT capability layer against a bearer-token
baseline. The transport is a direct function call plus a fixed, configurable
network-emulation delay, so that the *relative* overhead of the crypto layer
is isolated from wire latency (both configurations pay the same wire cost).

Two acceptance paths:
  * BearerServer   -- accepts any presented opaque bearer token (baseline).
  * CaveatServer   -- runs the CAVEAT Verifier (chain + caveats + re-attest).
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .core import (Capability, Issuer, ToolManifest, Verifier, H, _canon)


# Emulated one-way transport delay (seconds). Both baseline and CAVEAT pay it,
# so it cancels in the delta; kept small to keep the crypto term visible.
NET_DELAY = float(os.environ.get("CAVEAT_NET_DELAY", "0.0002"))  # 200 us default


def _wire():
    if NET_DELAY > 0:
        time.sleep(NET_DELAY)


@dataclass
class ToolDef:
    name: str
    definition: Dict[str, Any]
    version: int


# ---------------------------------------------------------------------------
# Baseline bearer MCP
# ---------------------------------------------------------------------------
class BearerServer:
    def __init__(self, tool: ToolDef, valid_token: bytes):
        self.tool = tool
        self.valid_token = valid_token

    def call(self, token: bytes, ctx: Dict[str, Any]) -> Dict[str, Any]:
        _wire()
        if token != self.valid_token:          # opaque bearer check only
            return {"ok": False, "reason": "bad_token"}
        return {"ok": True, "result": f"ran {self.tool.name}"}


class BearerClient:
    def __init__(self, server: BearerServer, token: bytes):
        self.server = server
        self.token = token

    def invoke(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        _wire()                                 # request leg
        return self.server.call(self.token, ctx)


# ---------------------------------------------------------------------------
# CAVEAT-hardened MCP
# ---------------------------------------------------------------------------
class CaveatServer:
    def __init__(self, tool: ToolDef, sk: Ed25519PrivateKey, root_key: bytes,
                 server_id: str = "S1"):
        self.tool = tool
        self.sk = sk
        self.verifier = Verifier(server_id, root_key, sk.public_key())
        # current served manifest (mutated by a rug pull)
        self.manifest = ToolManifest.create(tool.definition, tool.version, sk)

    def current_manifest(self) -> ToolManifest:
        _wire()                                 # manifest fetch leg
        return self.manifest

    def call(self, cap: Capability, ctx: Dict[str, Any],
             served_manifest: ToolManifest, reattest: bool) -> Dict[str, Any]:
        _wire()
        vr = self.verifier.verify(cap, ctx, served_manifest, reattest=reattest)
        if not vr:
            return {"ok": False, "reason": vr.reason}
        return {"ok": True, "result": f"ran {self.tool.name}"}

    def rug_pull(self, new_definition: Dict[str, Any]):
        """Mutate the served tool AFTER approval; pinned manifest is unchanged."""
        # new manifest signs the *new* digest -> digest mismatch on re-attest
        self.manifest = ToolManifest.create(new_definition, self.tool.version, self.sk)


class CaveatClient:
    def __init__(self, server: CaveatServer, cap: Capability,
                 reattest_every: int = 1):
        self.server = server
        self.cap = cap
        self.reattest_every = reattest_every    # 1 = per-call; N = sampled
        self._n = 0

    def invoke(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        self._n += 1
        do_reattest = (self.reattest_every == 1) or (self._n % self.reattest_every == 0)
        served = self.server.current_manifest() if do_reattest else None
        _wire()                                 # request leg
        return self.server.call(self.cap, ctx, served, reattest=do_reattest)


# ---------------------------------------------------------------------------
# Wire-size accounting (bytes added by the capability envelope)
# ---------------------------------------------------------------------------
def capability_wire_bytes(cap: Capability, with_manifest: bool = True) -> int:
    """
    Bytes the CAVEAT envelope adds beyond an opaque bearer token.
    We serialise the capability (id, digest, version, caveats, tag) and,
    when re-attesting, the manifest (digest, version, signature).
    """
    cap_blob = _canon({
        "id": cap.cap_id,
        "d": cap.manifest_digest.hex(),
        "v": cap.manifest_version,
        "c": cap.caveats,
        "t": cap.tag.hex(),
    })
    n = len(cap_blob)
    if with_manifest:
        # manifest: 32-byte digest + 8-byte version + 64-byte Ed25519 sig (hex-encoded on wire)
        n += len((cap.manifest_digest.hex() + str(cap.manifest_version)).encode()) + 128
    return n
