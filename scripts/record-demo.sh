#!/usr/bin/env bash
# Record the Asphallea demo.
#
# Two modes, and the split is the whole point: everything slow happens in
# `prepare`, off camera. `cast` is the only part you record, and it is three
# commands.
#
#   ./record-demo.sh prepare     # clone, venv, download wheel, pre-satisfy deps
#   asciinema rec --idle-time-limit 1 --cols 100 --rows 30 demo.cast
#     ./record-demo.sh cast
#     exit
#   ./record-demo.sh gif         # demo.cast -> media/demo.gif (needs agg)
#
# Do a full dry run first. Record the second take.

set -uo pipefail

VERSION="v0.0.1"
BASE="https://github.com/Asphallea/Asphallea"
WORK="${ASPHALLEA_DEMO_DIR:-$HOME/.asphallea-demo}"
REPO="$WORK/repo"
VENV="$WORK/venv"

wheel_name() {
  case "$(uname -s)" in
    Linux)  echo "asphallea-0.0.1-py3-none-linux_x86_64.whl" ;;
    Darwin) echo "asphallea-0.0.1-py3-none-macosx_10_9_universal2.whl" ;;
    *) echo "unsupported platform: $(uname -s). Record on Linux or macOS." >&2; exit 1 ;;
  esac
}

prepare() {
  local whl; whl="$(wheel_name)"
  echo "== preparing in $WORK =="
  mkdir -p "$WORK"

  if [ -d "$REPO/.git" ]; then
    echo "-- repo exists, pulling"
    git -C "$REPO" checkout -q main && git -C "$REPO" pull -q --ff-only
  else
    echo "-- cloning"
    git clone -q "$BASE.git" "$REPO"
  fi
  echo "   HEAD: $(git -C "$REPO" log -1 --oneline)"

  echo "-- creating venv"
  rm -rf "$VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip

  # Pre-satisfy the only runtime dep so the on-camera install needs no network
  # and finishes in about a second.
  echo "-- pre-satisfying dependencies (so the recorded install is instant)"
  "$VENV/bin/pip" install -q "pyyaml>=6.0"

  echo "-- downloading the release wheel: $whl"
  curl -fsSL -o "$WORK/$whl" "$BASE/releases/download/$VERSION/$whl" || {
    echo "   wheel download FAILED. Check $BASE/releases/tag/$VERSION" >&2; exit 1; }
  echo "   $(du -h "$WORK/$whl" | cut -f1)  $whl"

  # Sanity: make sure the recorded run will actually work, in a throwaway venv
  # so the real one still has nothing installed when the camera rolls.
  echo "-- dry-running the install in a throwaway venv"
  rm -rf "$WORK/_probe"
  python3 -m venv "$WORK/_probe" >/dev/null 2>&1
  "$WORK/_probe/bin/pip" install -q "$WORK/$whl" >/dev/null 2>&1 || {
    echo "   wheel does NOT install on this machine. Fix before recording." >&2; exit 1; }
  echo -n "   capabilities: "
  "$WORK/_probe/bin/python" -c "from asphallea import capabilities; print(capabilities().explain())"
  rm -rf "$WORK/_probe"

  cat <<EOF

== ready ==

Set your terminal to ~100x30 with a large, readable font, then:

  export PS1='\$ '
  clear
  asciinema rec --idle-time-limit 1 --cols 100 --rows 30 demo.cast
    $(cd "$(dirname "$0")" && pwd)/record-demo.sh cast
    exit

Then:  ./record-demo.sh gif

If the capabilities line above says the core was not found, or does not mention
Landlock, you are on a kernel below 5.13 or inside a container. The policy-tier
block still records fine, but the OS-containment flourish will be skipped. Record
on bare metal 5.13+ if you want the full run.
EOF
}

cast() {
  local whl; whl="$(wheel_name)"
  [ -f "$WORK/$whl" ] || { echo "run './record-demo.sh prepare' first" >&2; exit 1; }
  [ -d "$REPO" ]      || { echo "run './record-demo.sh prepare' first" >&2; exit 1; }

  # Run from $WORK, NOT from $REPO. The repo root contains an asphallea/ package
  # directory, and `python -c` puts CWD first on sys.path -- so running there
  # imports the source tree instead of the wheel we just installed, and the
  # capability check reports "core binary not found" while demo.py (whose
  # sys.path[0] is examples/) reports the real backend. That contradiction would
  # be baked into the recording. $WORK has no asphallea/ dir, so both agree.
  cd "$WORK"
  export PATH="$VENV/bin:$PATH"

  run() { printf '$ %s\n' "$*"; sleep 0.8; eval "$@"; echo; sleep 1.2; }

  clear
  # 1. One command. The wheel bundles the prebuilt, signed core binary.
  run "pip install -q $whl"

  # 2. Honest capability reporting, live, before any claim is made.
  run "python -c 'from asphallea import capabilities; print(capabilities().explain())'"

  # 3. The whole argument in one file.
  run "python repo/examples/demo.py"
}

gif() {
  command -v agg >/dev/null 2>&1 || {
    echo "agg not found. Install it:" >&2
    echo "  cargo install --locked agg     # or: brew install agg" >&2; exit 1; }
  [ -f demo.cast ] || { echo "demo.cast not found in $(pwd)" >&2; exit 1; }
  mkdir -p media
  agg --font-size 16 --theme asciinema demo.cast media/demo.gif
  echo "wrote media/demo.gif  ($(du -h media/demo.gif | cut -f1))"
  echo
  echo "Keep it under ~4MB or GitHub lazy-loads it and you lose autoplay."
  echo "Embed it directly under the logo in README.md:"
  echo
  echo '  <p align="center">'
  echo '    <img src="media/demo.gif" alt="A prompt-injected agent, contained" width="860">'
  echo '  </p>'
}

case "${1:-}" in
  prepare) prepare ;;
  cast)    cast ;;
  gif)     gif ;;
  *) echo "usage: $0 {prepare|cast|gif}" >&2; exit 2 ;;
esac
