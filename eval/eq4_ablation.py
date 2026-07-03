"""
EQ4 -- Ablation: contribution of each CAVEAT component.

We disable, in turn:
  (A) caveat confinement  (accept any caveat set / skip caveat evaluation)
  (B) manifest binding     (do not bind capability to H(D))
  (C) re-attestation       (never re-fetch/verify the served manifest)
and re-run the relevant attack classes, recording which guarantees collapse.
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from caveat import Issuer, ToolManifest, ToolDef, CaveatServer, CaveatClient
from caveat.core import Verifier, VerificationResult, _mac, _canon, hmac


def _env():
    sk = Ed25519PrivateKey.generate(); rk = os.urandom(32)
    tool = ToolDef("read_file", {"name": "read_file", "desc": "read"}, 1)
    cap = Issuer("S1", rk).mint_root("cap", ToolManifest.create(tool.definition, 1, sk))
    cap = cap.attenuate({"k": "tool", "v": "read_file"})
    cap = cap.attenuate({"k": "prefix", "v": "/proj/"})
    return sk, rk, tool, cap


def run_full():
    sk, rk, tool, cap = _env()
    srv = CaveatServer(tool, sk, rk); cli = CaveatClient(srv, cap, 1)
    # T3 rug pull detected? T6 overreach prevented?
    srv.rug_pull({"name": "read_file", "desc": "evil"})
    t3 = not cli.invoke({"tool": "read_file", "path": "/proj/a"})["ok"]
    sk, rk, tool, cap = _env()
    srv = CaveatServer(tool, sk, rk); cli = CaveatClient(srv, cap, 1)
    t6 = not cli.invoke({"tool": "write_file", "path": "/proj/a"})["ok"]
    return {"T3_rugpull_blocked": t3, "T6_overreach_blocked": t6}


def run_no_confinement():
    # Verifier that skips caveat evaluation (accepts regardless of caveats).
    sk, rk, tool, cap = _env()
    srv = CaveatServer(tool, sk, rk)

    def verify_no_conf(self, cap, ctx, served, reattest=True):
        if not hmac.compare_digest(self._recompute_chain(cap), cap.tag):
            return VerificationResult(False, "mac_chain_mismatch")
        # caveat evaluation DISABLED
        if reattest:
            if not served.verify(self.pk):
                return VerificationResult(False, "manifest_bad_signature")
            if served.digest != cap.manifest_digest:
                return VerificationResult(False, "manifest_digest_mismatch")
        return VerificationResult(True, "ok")

    srv.verifier.verify = verify_no_conf.__get__(srv.verifier, Verifier)
    cli = CaveatClient(srv, cap, 1)
    t6 = not cli.invoke({"tool": "write_file", "path": "/etc/x"})["ok"]  # should now PASS -> not blocked
    srv2 = CaveatServer(tool, sk, rk)
    srv2.verifier.verify = verify_no_conf.__get__(srv2.verifier, Verifier)
    srv2.rug_pull({"name": "read_file", "desc": "evil"})
    cli2 = CaveatClient(srv2, cap, 1)
    t3 = not cli2.invoke({"tool": "read_file", "path": "/proj/a"})["ok"]  # still detected
    return {"T3_rugpull_blocked": t3, "T6_overreach_blocked": t6}


def run_no_manifest_binding():
    # Capability not bound to H(D): verifier ignores digest comparison.
    sk, rk, tool, cap = _env()
    srv = CaveatServer(tool, sk, rk)

    def verify_no_mb(self, cap, ctx, served, reattest=True):
        if not hmac.compare_digest(self._recompute_chain(cap), cap.tag):
            return VerificationResult(False, "mac_chain_mismatch")
        for c in cap.caveats:
            from caveat.core import _eval_caveat
            if not _eval_caveat(c, ctx):
                return VerificationResult(False, "caveat_unsatisfied")
        # manifest DIGEST binding DISABLED (signature still checked)
        if reattest and not served.verify(self.pk):
            return VerificationResult(False, "manifest_bad_signature")
        return VerificationResult(True, "ok")

    srv.verifier.verify = verify_no_mb.__get__(srv.verifier, Verifier)
    srv.rug_pull({"name": "read_file", "desc": "evil"})  # signed by real sk, new digest
    cli = CaveatClient(srv, cap, 1)
    t3 = not cli.invoke({"tool": "read_file", "path": "/proj/a"})["ok"]  # NOT blocked now
    # T6 still enforced by caveats
    sk, rk, tool, cap = _env()
    srv2 = CaveatServer(tool, sk, rk)
    srv2.verifier.verify = verify_no_mb.__get__(srv2.verifier, Verifier)
    cli2 = CaveatClient(srv2, cap, 1)
    t6 = not cli2.invoke({"tool": "write_file", "path": "/proj/a"})["ok"]
    return {"T3_rugpull_blocked": t3, "T6_overreach_blocked": t6}


def run_no_reattest():
    sk, rk, tool, cap = _env()
    srv = CaveatServer(tool, sk, rk)
    cli = CaveatClient(srv, cap, reattest_every=10**9)  # effectively never
    srv.rug_pull({"name": "read_file", "desc": "evil"})
    t3 = not cli.invoke({"tool": "read_file", "path": "/proj/a"})["ok"]  # NOT detected
    # T6 still enforced (caveats independent of re-attestation)
    sk, rk, tool, cap = _env()
    srv2 = CaveatServer(tool, sk, rk)
    cli2 = CaveatClient(srv2, cap, reattest_every=10**9)
    t6 = not cli2.invoke({"tool": "write_file", "path": "/proj/a"})["ok"]
    return {"T3_rugpull_blocked": t3, "T6_overreach_blocked": t6}


def main():
    out = {
        "full":              run_full(),
        "no_confinement":    run_no_confinement(),
        "no_manifest_bind":  run_no_manifest_binding(),
        "no_reattestation":  run_no_reattest(),
    }
    print(json.dumps(out, indent=2))
    return out


if __name__ == "__main__":
    main()
