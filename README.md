# CAVEAT — Tamarin theory files (contributions C1 & C2)

This directory contains the machine-checkable protocol models that back the
formal-analysis claims in the paper

> *CAVEAT: Formal Analysis and Capability-Based Hardening of Model Context
> Protocol Authorisation for LLM Agent Tool Ecosystems.*

Two theories:

| File | Paper section | What it models | Lemmas |
|------|---------------|----------------|--------|
| `mcp_authz.spthy` | §4 (C1) | MCP authorisation: OAuth 2.1 + PKCE (S256) + RFC 8707 resource indicators + RFC 9728 discovery, under a Dolev–Yao adversary **extended with an injection channel** | `executable_honest`, `token_secrecy` (P1), `injective_agreement` (P2), `audience_binding` (P3), `confused_deputy_resistance` (P4) |
| `caveat_delegation.spthy` | §5 (C2) | CAVEAT HMAC-chained attenuable capabilities (Eq. 1–2), offline delegation, runtime tool re-attestation (anti-rug-pull) | `executable_delegation`, `monotonic_confinement` (Thm 1), `capability_key_secrecy`, `reattestation_soundness` (Prop 1) |

> **Status.** These are *internally consistent skeletons*: they load and encode
> the intended rules, adversary, and properties, but the autoprover may need
> heuristics/oracles or minor refinement of the caveat-evaluation and honesty
> abstractions before every lemma discharges. Treat the verdicts you obtain
> locally as the source of truth for **Table 2** — do not report the paper's
> placeholders as results.

---

## 1. Install Tamarin

Tamarin is a Haskell tool; install via the official instructions
(<https://tamarin-prover.com>). On macOS with Homebrew:

```bash
brew install tamarin-prover/tap/tamarin-prover
tamarin-prover --version
```

You also need `maude` (installed automatically by the Homebrew formula) and,
for the interactive GUI, a browser.

## 2. Batch proving (fills Table 2)

```bash
# C1 — MCP authorisation (secure "full" model)
tamarin-prover mcp_authz.spthy --prove

# C2 — CAVEAT capability delegation
tamarin-prover caveat_delegation.spthy --prove
```

For each lemma Tamarin prints `verified` / `falsified` and the number of proof
steps. To capture wall-clock time and steps for the table:

```bash
/usr/bin/time -v tamarin-prover mcp_authz.spthy --prove 2>&1 | tee mcp_authz.out
```

Record, per lemma: **verdict**, **time (s)**, **#steps** → paper Table 2.

## 3. The confused-deputy NEGATIVE result (the "−aud" row)

The paper reports that confused-deputy resistance **fails** when the RFC 8707
audience check is omitted, yielding a concrete attack trace. To reproduce:

1. In `mcp_authz.spthy`, **comment out** `rule Server_Accept_full` and
   **uncomment** `rule Server_Accept_noaud` (both are provided; only the label
   `AcceptedFull` vs `AcceptedNoAud` differs, plus the missing `Eq` check).
2. Point the property at the no-aud acceptance (either rename the lemma's
   `AcceptedFull` to `AcceptedNoAud`, or add a second lemma variant).
3. Run interactively to extract the trace:

   ```bash
   tamarin-prover interactive mcp_authz.spthy
   # open http://127.0.0.1:3001 , select confused_deputy_resistance, Autoprove
   ```

4. Export the attack graph (PNG/JSON) for the paper's figure/appendix.

## 4. If the autoprover loops

- Try a different heuristic: `--heuristic=S` (smart), `--heuristic=C`, `--heuristic=I`.
- Add `reuse`/induction hints, or supply a proof **oracle** with
  `--heuristic=O --oracle=./mcp.oracle`.
- The caveat semantics in `caveat_delegation.spthy` are abstracted through a
  `Grant`/`CtxSatisfies` restriction; replace them with a concrete predicate
  theory (path-prefix, argument bounds, expiry) for a tighter model — this often
  *helps* termination by constraining the search.
- Bound sessions during development by adding a `restriction` limiting the number
  of `RootIssued`/`Attenuated` events, then remove it for the final run.

## 5. Mapping to the manuscript

- `mcp_authz.spthy` rules mirror Listings 1–2 (injection channel; token issuance
  with audience binding; audience-checked acceptance) in §4.
- `caveat_delegation.spthy` mirrors Eq. (1)–(2) and Figure 3 (root → attenuate →
  delegate) and the theorems in §5 (`monotonic_confinement` ↔ Theorem 1;
  `reattestation_soundness` ↔ Proposition 1).
- After proving, replace in `main.tex` (or `main_bib.tex`):
  - the red `\TODO{...}` verification notes,
  - the `\hypo{...}` expected verdicts in Table 2 and Table 4,
  - the `\XX` time/step cells,
  with the values you obtained, and (optionally) add the exported attack graph.

## 6. Reproducibility metadata to report

State in the paper's evaluation section: Tamarin version, Maude version, OS/CPU,
and total proof time. Deposit both `.spthy` files (and any `.oracle`) in the
artifact repository referenced under *Data availability*.
