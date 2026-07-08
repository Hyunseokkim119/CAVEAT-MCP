#!/usr/bin/env bash
# =============================================================================
# CAVEAT artefact -- one-command reproduction with log capture.
# Reproduces Table 3 (Tamarin verdicts, incl. the -aud falsified row) and
# Tables 4-6 (EQ2-EQ4). All logs land in results/.
# Usage:  bash run_all.sh
# =============================================================================
set -euo pipefail
mkdir -p results

echo "== [0/5] toolchain versions =="
tamarin-prover --version | tee results/tamarin_version.txt
python3 --version         | tee results/python_version.txt

echo "== [1/5] C1 full model (expected: 5/5 lemmas verified) =="
tamarin-prover tamarin/mcp_authz.spthy --prove 2>&1 | tee results/tamarin_mcp_authz.log

echo "== [2/5] C1 -aud variant (expected: confused_deputy_resistance FALSIFIED, trace found) =="
tamarin-prover tamarin/mcp_authz_noaud.spthy --prove=confused_deputy_resistance 2>&1 \
  | tee results/tamarin_mcp_authz_noaud.log

echo "== [3/5] C2 CAVEAT delegation model (expected: 5/5 lemmas verified) =="
tamarin-prover tamarin/caveat_delegation.spthy --prove 2>&1 | tee results/tamarin_caveat.log

echo "== [4/5] correctness tests =="
python3 eval/test_correctness.py 2>&1 | tee results/eq_correctness.log

echo "== [5/5] EQ2-EQ4 harnesses (Tables 4-6) =="
CAVEAT_NET_DELAY=0.0002 CAVEAT_SAMPLES=20000 python3 eval/eq2_overhead.py 2>&1 | tee results/eq2.log
python3 eval/eq3_coverage.py 2>&1 | tee results/eq3.log
python3 eval/eq4_ablation.py 2>&1 | tee results/eq4.log

echo "== done: verdict summary =="
grep -h -E "verified|falsified" results/tamarin_*.log | sed 's/^ *//' || true
