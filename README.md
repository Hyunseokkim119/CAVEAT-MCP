# CAVEAT — Reference Implementation & Formal Models

Artefact for *"CAVEAT: Formal Analysis and Capability-Based Hardening of Model
Context Protocol Authorisation for LLM Agent Tool Ecosystems."*

## Layout
- `caveat/`            capability core (HMAC-SHA256 chain, Ed25519 manifests, re-attestation) + MCP-style stack
- `eval/`             EQ2 (overhead), EQ3 (coverage), EQ4 (ablation) harnesses + correctness tests + raw JSON results
- `tamarin/`          hardened Tamarin theories: `mcp_authz.spthy` (C1), `caveat_delegation.spthy` (C2)

## Requirements
- Python 3.12, `cryptography>=46`
- Tamarin-prover 1.10.x (for the formal models)

## Reproduce
```bash
# Formal verdicts (Table 3)
tamarin-prover tamarin/mcp_authz.spthy --prove
tamarin-prover tamarin/caveat_delegation.spthy --prove

# Empirical results (Tables 4–6)
python3 eval/test_correctness.py                       # correctness
CAVEAT_NET_DELAY=0.0002 CAVEAT_SAMPLES=20000 python3 eval/eq2_overhead.py   # Table 4
python3 eval/eq3_coverage.py                           # Table 5
python3 eval/eq4_ablation.py                           # Table 6
```

## Notes
The two `.spthy` theories are the *finalised* (hardened) models; file headers (H1–H6)
document each modelling decision relative to the initial skeletons, so that the
reported verdicts are faithful (non-vacuous) rather than trivially satisfied.
