#!/usr/bin/env bash
# Asphallea: install, build, test, demo — end to end.
# Run this on the real Linux machine, not a container, so Landlock actually engages.

set -uo pipefail

REPO_URL="https://github.com/Asphallea/Asphallea.git"
REPO_DIR="${1:-Asphallea}"

echo "== 0. Sanity checks =="
uname -a
KVER=$(uname -r | cut -d. -f1,2)
echo "Kernel: $KVER (Landlock needs 5.13+, seccomp needs any modern kernel)"

command -v rustc >/dev/null 2>&1 || {
  echo "Rust not found. Installing via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
}
command -v python3 >/dev/null 2>&1 || { echo "python3 not found. Install it and re-run."; exit 1; }
command -v pip >/dev/null 2>&1 || command -v pip3 >/dev/null 2>&1 || { echo "pip not found. Install it and re-run."; exit 1; }

echo
echo "== 1. Clone or update repo =="
if [ -d "$REPO_DIR/.git" ]; then
  echo "Repo exists at $REPO_DIR, pulling latest..."
  git -C "$REPO_DIR" pull
else
  git clone "$REPO_URL" "$REPO_DIR"
fi
cd "$REPO_DIR"
echo "HEAD: $(git log -1 --oneline)"

echo
echo "== 2. Build the Rust containment core (release) =="
( cd core && cargo build --release ) || { echo "Rust build FAILED."; exit 1; }

echo
echo "== 3. Probe containment capabilities on this machine =="
PROBE=$(./core/target/release/asphallea-run --probe)
echo "$PROBE"
LANDLOCK_ABI=$(echo "$PROBE" | python3 -c \
  "import sys,json; print(json.load(sys.stdin).get('landlock_abi', 0))" 2>/dev/null || echo 0)

echo
echo "== 4. Install the Python package + test deps =="
pip install -e . --break-system-packages -q 2>/dev/null || pip install -e . -q
pip install pytest --break-system-packages -q 2>/dev/null || pip install pytest -q

echo
echo "== 5. Run the full test suite =="
set +e
pytest tests/ -v
TEST_EXIT=$?
set +e   # stay non-fatal: the SUMMARY below is the point of this script

echo
echo "== 6. Run the injection demo =="
python3 examples/demo.py

echo
echo "======================================================================"
echo "SUMMARY"
echo "======================================================================"
echo "Kernel:            $(uname -r)"
echo "Landlock ABI:      $LANDLOCK_ABI  (0 = unsupported, needs 5.13+ kernel)"
echo "Test suite exit:   $TEST_EXIT  (0 = all passed)"
echo "Install path:      editable + dev core build"
echo "NOTE: an editable install leaves asphallea/_core/ empty, so there is no"
echo "bundled checksums.json and verify_core() reports method=none. This run"
echo "therefore does NOT exercise the integrity-verification path a user on a"
echo "release wheel gets. Install the platform wheel and re-run the demo to"
echo "cover that."
if [ "$LANDLOCK_ABI" = "0" ]; then
  echo "NOTE: Landlock unavailable on this kernel. Any filesystem-containment"
  echo "test failures here are EXPECTED and are the fail-closed behavior"
  echo "working correctly, not a bug. Re-run on a 5.13+ kernel to get a"
  echo "clean pass on the containment tier."
fi
if [ "$TEST_EXIT" -eq 0 ]; then
  echo "RESULT: all tests passed. This machine backs the 'complete' claim."
else
  echo "RESULT: some tests failed. Read the pytest output above before"
  echo "claiming this platform's containment tier is done."
fi
echo "======================================================================"
