# Closed grammar 3 native core: reproduction commands

Run from the repository root on Linux aarch64 with the existing GNAT toolchain.
The observed toolchain was GNAT/GCC FSF 16.1.0, GPRbuild 26.0.0,
GNATprove FSF 16.1.0, Why3 1.8.2+git, Z3 4.15.4, CVC5 1.3.2
(commit 86cecd8), and Alt-Ergo 2.6.1. Full raw version output is retained in
`gnatprove-version.txt`, `gprbuild-version.txt`, and `gcc-version.stderr`.
No installation is performed by these commands.

```bash
source /home/sicarii/opt/gnat/env.sh
command -v gprbuild gnatprove
umask 077
SAT_CORE_WORK=$(mktemp -d /dev/shm/semantic-transport-core-repro.XXXXXX)
mkdir "$SAT_CORE_WORK/tmp" "$SAT_CORE_WORK/bin" "$SAT_CORE_WORK/obj" "$SAT_CORE_WORK/checks-obj"
export TMPDIR="$SAT_CORE_WORK/tmp"
ulimit -v 1048576

timeout 120 gprbuild -p -P evaluation/transport_core.gpr \
  -XTRANSPORT_CORE_OBJ="$SAT_CORE_WORK/obj" \
  -XTRANSPORT_CORE_BIN="$SAT_CORE_WORK/bin" \
  > "$SAT_CORE_WORK/build.stdout" 2> "$SAT_CORE_WORK/build.stderr"
SAT_BUILD_EXIT=$?
test "$SAT_BUILD_EXIT" -eq 0 || exit "$SAT_BUILD_EXIT"

timeout 300 gnatprove -P evaluation/transport_core.gpr -U \
  --level=2 --report=all --warnings=error -j1 \
  --prover=z3 --timeout=1 --counterexamples=off \
  -XTRANSPORT_CORE_OBJ="$SAT_CORE_WORK/obj" \
  -XTRANSPORT_CORE_BIN="$SAT_CORE_WORK/bin" \
  > "$SAT_CORE_WORK/proof.stdout" 2> "$SAT_CORE_WORK/proof.stderr"
SAT_PROOF_EXIT=$?
test "$SAT_PROOF_EXIT" -eq 0 || exit "$SAT_PROOF_EXIT"
test -f "$SAT_CORE_WORK/obj/gnatprove/gnatprove.out" || exit 1
rg '^Total|Success:|Unproved|Justified' \
  "$SAT_CORE_WORK/proof.stdout" "$SAT_CORE_WORK/obj/gnatprove/gnatprove.out"

timeout 120 gprbuild -p -P evaluation/transport_core_checks.gpr \
  -XTRANSPORT_CORE_OBJ="$SAT_CORE_WORK/checks-obj" \
  -XTRANSPORT_CORE_BIN="$SAT_CORE_WORK/bin" \
  > "$SAT_CORE_WORK/checks-build.stdout" 2> "$SAT_CORE_WORK/checks-build.stderr"
SAT_CHECKS_BUILD_EXIT=$?
test "$SAT_CHECKS_BUILD_EXIT" -eq 0 || exit "$SAT_CHECKS_BUILD_EXIT"
timeout 30 "$SAT_CORE_WORK/bin/core_checks" \
  > "$SAT_CORE_WORK/checks.stdout" 2> "$SAT_CORE_WORK/checks.stderr"
SAT_CHECKS_EXIT=$?
test "$SAT_CHECKS_EXIT" -eq 0 || exit "$SAT_CHECKS_EXIT"
cat "$SAT_CORE_WORK/checks.stdout"
```

A zero GNATprove process exit does **not** establish proof completion. Require
zero unproved and zero justified checks in its summary, no `pragma Assume`,
all intended units analyzed, and the source hashes recorded alongside the run.
The accepted run reported 1,368 checks, with 342 flow checks and 1,026 prover
checks; both final columns were zero. Earlier proof attempt 03 exited zero
while retaining five unproved obligations and was explicitly rejected.

The accepted proof command used incremental sessions from retained earlier
attempts. The commands above use a fresh directory; an independent clean
reproduction has not been claimed. If the stated time or memory bounds are
exceeded, retain that result. Do not delete contracts or hide unproved checks.
Independent builds are not promised byte-identical to the qualified binary.
The qualified native binary SHA-256 is
`aa04e9aca4afa2663202eac7085329ac5e1f331057b418d3339c2ed17309c23b`.

The core proof establishes the declared finite-model denotation, every-node
Step consistency, typing/safety and termination under the written preconditions.
The parser proof establishes valid output/reset behavior and runtime safety;
it does not establish a complete wire-to-JSON functional correspondence theorem.
File IO, CLI rendering, source interpretation, model-world truth, source
anchoring, package authentication and arbitrary-document completeness are
outside those SPARK postconditions.

The unchanged legacy suites were additionally built using a throwaway GPR
inside the private scratch directory. Its Source_Dirs pointed to the existing
`evaluation/tests`, `evaluation/src`, and `src`; its Main list was
`transport_eval_checks.adb` and `transport_bound_eval_checks.adb`; strict compiler
switches were `-gnat2022 -gnatwa -gnatwe -gnatVa -gnata -gnatf -O2 -g`.
The exact generated GPR, build command and both execution commands are retained
in `legacy_checks.gpr` and `legacy-receipt.json`. Both unchanged programs exited
zero with empty stderr. No original GPR or legacy test was edited.
