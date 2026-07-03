"""
EQ2 -- Latency & message overhead of CAVEAT vs bearer-token MCP.

Reports median / p99 end-to-end tool-invocation latency for:
  (a) baseline bearer MCP
  (b) CAVEAT, per-call re-attestation
  (c) CAVEAT, sampled re-attestation (1-in-K)
plus the additional wire bytes of the capability envelope.

To isolate the crypto-layer cost from wire latency, set CAVEAT_NET_DELAY=0.
The paper reports with a small emulated per-leg delay so the numbers reflect a
realistic in-datacentre call; the *delta* is dominated by the crypto term.
"""
import os, sys, statistics, time, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from caveat import (Issuer, ToolManifest, ToolDef, BearerServer, BearerClient,
                    CaveatServer, CaveatClient, capability_wire_bytes)

N = int(os.environ.get("CAVEAT_SAMPLES", "20000"))
SAMPLE_K = int(os.environ.get("CAVEAT_SAMPLE_K", "16"))


def _percentiles(xs):
    xs = sorted(xs)
    med = statistics.median(xs)
    p99 = xs[min(len(xs) - 1, int(0.99 * len(xs)))]
    return med * 1e3, p99 * 1e3   # ms


def build_common():
    sk = Ed25519PrivateKey.generate()
    root_key = os.urandom(32)
    tool = ToolDef("read_file",
                   {"name": "read_file", "args": ["path"], "desc": "read a file"},
                   version=1)
    issuer = Issuer("S1", root_key)
    manifest = ToolManifest.create(tool.definition, tool.version, sk)
    cap = issuer.mint_root("cap-001", manifest)
    # realistic attenuation: tool + path-prefix + expiry (3 caveats)
    cap = cap.attenuate({"k": "tool", "v": "read_file"})
    cap = cap.attenuate({"k": "prefix", "v": "/proj/"})
    cap = cap.attenuate({"k": "expiry", "v": 9.9e18})
    return sk, root_key, tool, cap


def bench_bearer(tool, n):
    token = os.urandom(32)
    srv = BearerServer(tool, token)
    cli = BearerClient(srv, token)
    ctx = {"tool": "read_file", "path": "/proj/a.txt", "now": 1.0}
    lat = []
    for _ in range(n):
        t0 = time.perf_counter()
        r = cli.invoke(ctx)
        lat.append(time.perf_counter() - t0)
        assert r["ok"]
    return lat


def bench_caveat(sk, root_key, tool, cap, n, reattest_every):
    srv = CaveatServer(tool, sk, root_key)
    cli = CaveatClient(srv, cap, reattest_every=reattest_every)
    ctx = {"tool": "read_file", "path": "/proj/a.txt", "now": 1.0}
    lat = []
    for _ in range(n):
        t0 = time.perf_counter()
        r = cli.invoke(ctx)
        lat.append(time.perf_counter() - t0)
        assert r["ok"], r
    return lat


def main():
    sk, root_key, tool, cap = build_common()

    base = bench_bearer(tool, N)
    perc = bench_caveat(sk, root_key, tool, cap, N, reattest_every=1)
    samp = bench_caveat(sk, root_key, tool, cap, N, reattest_every=SAMPLE_K)

    bm, bp = _percentiles(base)
    pm, pp = _percentiles(perc)
    sm, sp = _percentiles(samp)

    bytes_percall = capability_wire_bytes(cap, with_manifest=True)
    bytes_sampled = capability_wire_bytes(cap, with_manifest=False)  # amortised base

    out = {
        "samples": N,
        "sample_k": SAMPLE_K,
        "net_delay_s": float(os.environ.get("CAVEAT_NET_DELAY", "0.0002")),
        "baseline":   {"med_ms": bm, "p99_ms": bp},
        "per_call":   {"med_ms": pm, "p99_ms": pp,
                       "d_med_ms": pm - bm, "d_p99_ms": pp - bp,
                       "bytes_added": bytes_percall},
        "sampled":    {"med_ms": sm, "p99_ms": sp,
                       "d_med_ms": sm - bm, "d_p99_ms": sp - bp,
                       "bytes_added_amortised": round(
                           bytes_sampled + (bytes_percall - bytes_sampled) / SAMPLE_K)},
    }
    print(json.dumps(out, indent=2))
    return out


if __name__ == "__main__":
    main()
