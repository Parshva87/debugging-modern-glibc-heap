#!/usr/bin/env bash
# demo-hooks-setup.sh — Build BOTH Docker demo images for the BSides CT talk.
#
# Run ONCE on your laptop before the talk:
#   cd ~/debugging-modern-glibc-heap
#   bash demo-hooks-setup.sh
#
# During the talk (Act I):
#   docker run --rm -it heap-hooks        ← glibc 2.31, hooks ALIVE  → shell
#   docker run --rm -it heap-234          ← glibc 2.34, hooks DEAD   → fails
#   nm on both to prove the symbol exists in both

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Verify required files exist
for f in note.c classic_exploit.py Dockerfile.hooks Dockerfile.234 Dockerfile.227 Dockerfile.228; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: missing $f — run from the repo root"
        exit 1
    fi
done

# ── Image 1: glibc 2.31 (hooks alive) ──────────────────────
echo "=== [1/2] Building heap-hooks (Ubuntu 20.04 / glibc 2.31) ==="
echo "    Hooks alive. No safe-linking. Classic exploit works."
echo ""
docker build -f Dockerfile.hooks -t heap-hooks . 2>&1 | tail -5

echo ""
echo "Smoke test (2.31)..."
docker run --rm heap-hooks bash -c '
    echo "  glibc: $(ldd --version 2>&1 | head -1)"
    echo "  __free_hook: $(nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep __free_hook)"
    echo "  note binary: $(file /demo/note)"
'

# ── Image 2: glibc 2.34 (hooks dead) ───────────────────────
echo ""
echo "=== [2/2] Building heap-234 (Ubuntu 21.10 / glibc 2.34) ==="
echo "    Hooks COMPILED OUT. This is where the technique dies."
echo ""
docker build -f Dockerfile.234 -t heap-234 . 2>&1 | tail -5

echo ""
echo "Smoke test (2.34)..."
docker run --rm heap-234 bash -c '
    echo "  glibc: $(ldd --version 2>&1 | head -1)"
    echo "  __free_hook: $(nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep __free_hook)"
    echo "  note binary: $(file /demo/note)"
'

# ── Image 3: glibc 2.27 (unsorted-bin check ABSENT) ────────
echo ""
echo "=== [3/4] Building heap-227 (Ubuntu 18.04 / glibc 2.27) ==="
echo "    Slide 24 proof: unsorted-bin guard is ABSENT here."
echo ""
docker build -f Dockerfile.227 -t heap-227 . 2>&1 | tail -5

echo ""
echo "Smoke test (2.27)..."
docker run --rm heap-227 bash -c '
    echo "  glibc: $(ldd --version 2>&1 | head -1)"
    echo "  corrupted unsorted: $(strings /lib/x86_64-linux-gnu/libc.so.6 | grep -c "corrupted unsorted") matches"
'

# ── Image 4: glibc 2.28 (unsorted-bin check PRESENT) ──────
echo ""
echo "=== [4/4] Building heap-228 (Ubuntu 18.10 / glibc 2.28) ==="
echo "    Slide 24 proof: unsorted-bin guard IS PRESENT here."
echo ""
docker build -f Dockerfile.228 -t heap-228 . 2>&1 | tail -5

echo ""
echo "Smoke test (2.28)..."
docker run --rm heap-228 bash -c '
    echo "  glibc: $(ldd --version 2>&1 | head -1)"
    echo "  corrupted unsorted: $(strings /lib/x86_64-linux-gnu/libc.so.6 | grep -c "corrupted unsorted") matches"
'

echo ""
echo "=== All four images ready ==="
echo ""
echo "During Act I (same terminal tab):"
echo ""
echo "  # STEP 1 — show it working on 2.31"
echo "  docker run --rm -it heap-hooks"
echo "  python3 classic_exploit.py              ← shell pops"
echo "  nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep __free_hook"
echo "  exit"
echo ""
echo "  # STEP 2 — show it dying on 2.34"
echo "  docker run --rm -it heap-234"
echo "  python3 classic_exploit.py              ← fails"
echo "  nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep __free_hook"
echo "  exit"
echo ""
echo "During Slide 7 (tcache vis demo — plaintext deadbeef):"
echo ""
echo "  docker run --rm -it heap-hooks"
echo "  python3 vis_demo.py                     ← inline hex dumps, no GDB needed"
echo "  # Step through with Enter — STEP 3 shows ef be ad de (plaintext 0xdeadbeef)"
echo "  exit"
echo ""
echo "During Slide 24 (Correction 1: unsorted-bin check — 2.28 not 2.29):"
echo ""
echo "  # Show check is ABSENT on 2.27"
echo "  docker run --rm -it heap-227"
echo "  ldd --version | head -1"
echo "  strings /lib/x86_64-linux-gnu/libc.so.6 | grep 'corrupted unsorted'"
echo "  # → NO OUTPUT (check doesn't exist)"
echo "  exit"
echo ""
echo "  # Show check is PRESENT on 2.28"
echo "  docker run --rm -it heap-228"
echo "  ldd --version | head -1"
echo "  strings /lib/x86_64-linux-gnu/libc.so.6 | grep 'corrupted unsorted'"
echo "  # → shows 'corrupted unsorted chunks' strings (check exists)"
echo "  exit"
