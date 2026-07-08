[Uploading README.md…]()
# CAVEAT — Reference Implementation & Formal Models

Artefact for *"CAVEAT: Formal Analysis and Capability-Based Hardening of Model
Context Protocol Authorisation for LLM Agent Tool Ecosystems"* (submitted to
Computer Networks, 2026).

## Layout
- `caveat/`    capability core (HMAC-SHA256 chain, Ed25519 manifests, re-attestation) + MCP-style stack
- `eval/`      EQ2 (overhead), EQ3 (coverage), EQ4 (ablation) harnesses + correctness tests + raw JSON results
- `tamarin/`   Tamarin theories:
  - `mcp_authz.spthy` — C1 full model (secure `Server_Accept_full` active)
  - `mcp_authz_noaud.spthy` — auto-derived **-aud variant** (audience check omitted); reproduces the falsified confused-deputy row of Table 3 without manual editing
  - `caveat_delegation.spthy` — C2 delegation model
- `results/`   raw Tamarin `--prove` logs (incl. the -aud attack trace) and exact toolchain versions
- `run_all.sh` one-command reproduction of Tables 3–6 with log capture

## Requirements
- Tamarin-prover 1.10.x — the exact build used for the reported figures is
  recorded in `results/tamarin_version.txt`
- Python 3.12, `cryptography>=46`

## Reproduce everything
```bash
bash run_all.sh
```

## Reproduce individually
```bash
# Table 3, upper block (C1 full model; expected: all lemmas verified)
tamarin-prover tamarin/mcp_authz.spthy --prove

# Table 3, falsified row (C1 -aud variant; expected: confused_deputy_resistance
# FALSIFIED — Tamarin extracts the attack trace in which a malicious S_A leaks
# the client's audience-S_A token and it is replayed at honest S_B)
tamarin-prover tamarin/mcp_authz_noaud.spthy --prove=confused_deputy_resistance

# Table 3, lower block (C2; expected: all lemmas verified)
tamarin-prover tamarin/caveat_delegation.spthy --prove

# Tables 4–6 (empirical)
python3 eval/test_correctness.py
CAVEAT_NET_DELAY=0.0002 CAVEAT_SAMPLES=20000 python3 eval/eq2_overhead.py
python3 eval/eq3_coverage.py
python3 eval/eq4_ablation.py
```

The `-aud` variant file is derived from the full model by exactly one change
(the acceptance rule swap documented in both file headers); equivalently, the
same result is obtained by toggling the comment markers around
`Server_Accept_full` / `Server_Accept_noaud` inside `mcp_authz.spthy`.

## Measurement environment (paper §6, EQ1)
Virtual machine: 10 Intel Xeon vCPUs (2.10 GHz), 4 GiB RAM (3.9 GiB visible),
Ubuntu 24.04.4 LTS (Linux 6.18), Python 3.12.3. Tamarin-reported per-lemma
processing time is at most 0.04 s across both theories (see `results/`).

## Notes
The `.spthy` theories are the *finalised* (hardened) models; file headers
(H1–H6) document each modelling decision relative to the initial skeletons, so
that the reported verdicts are faithful (non-vacuous) rather than trivially
satisfied. Executability lemmas (`executable_honest`, `executable_delegation`)
are included as sanity checks against vacuous proofs.

## Licence
MIT — see `LICENSE`.
