# The Modern glibc Heap: What Still Works (and What's a Tombstone)

A version-by-version reference for heap exploitation on glibc. Every mitigation boundary
below was verified by grepping the actual `malloc/malloc.c` and `libio/libioP.h` at each
release tag (`github.com/bminor/glibc`, tags `glibc-2.23` … `glibc-2.41`) and cross-checked
against the shipped Ubuntu 24.04 libc (2.39). Not folklore — source.

---

## Matrix 1 — Mitigations by version (empirical: each cell = a check present in source)

Legend: `Y` = present · `-` = absent

| Mitigation / hardening                         | 2.23 | 2.24 | 2.26 | 2.27 | 2.28 | 2.29 | 2.31 | 2.32 | 2.33 | 2.34 | 2.39 | 2.41 |
|------------------------------------------------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| FILE vtable check (`_IO_vtable_check`)         |  -  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |
| tcache exists                                  |  -  |  -  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |
| unsorted-bin removal guard (`bck->fd!=victim`) |  -  |  -  |  -  |  -  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |
| tcache double-free key                         |  -  |  -  |  -  |  -  |  -  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |
| top-chunk size sanity (`corrupted top size`)   |  -  |  -  |  -  |  -  |  -  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |
| safe-linking (tcache/fastbin fd mangling)      |  -  |  -  |  -  |  -  |  -  |  -  |  -  |  Y  |  Y  |  Y  |  Y  |  Y  |
| tcache `aligned_OK` on get                     |  -  |  -  |  -  |  -  |  -  |  -  |  -  |  Y  |  Y  |  Y  |  Y  |  Y  |
| tcache free-side count/align guard             |  -  |  -  |  -  |  -  |  -  |  -  |  -  |  -  |  Y  |  Y  |  Y  |  Y  |
| malloc/free hooks still **called**             |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  Y  |  -  |  -  |  -  |

**Key boundaries (source-pinned):**
- **2.24** — `_IO_vtable_check` lands → naive FILE-vtable FSOP and classic House of Orange die.
- **2.26** — tcache introduced.
- **2.28** — unsorted-bin removal guard → **unsorted-bin attack dies here** (commonly mis-cited as 2.29).
- **2.29** — tcache double-free `key`; top-size sanity → **House of Force dies**.
- **2.32** — safe-linking + `aligned_OK` → tcache poisoning now needs a heap leak and a 16-aligned target.
- **2.33** — free-side tcache count/alignment hardening.
- **2.34** — malloc/free hooks are no longer called by the allocator.

---

## Matrix 2 — Technique viability (derived from Matrix 1 + exploitation requirements)

Legend: `●` works · `◐` works **with extra** (heap leak / adaptation / version-specific offsets) · `○` dead · `—` mechanism doesn't exist yet

| Technique                                   | 2.23 | 2.27 | 2.29 | 2.31 | 2.32 | 2.34 | 2.41 | Killed / gated by |
|---------------------------------------------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|-------------------|
| `__free_hook`/`__malloc_hook` → `system`    |  ●  |  ●  |  ●  |  ●  |  ●  |  ○  |  ○  | hooks not called (2.34) |
| tcache poisoning (arbitrary alloc)          |  —  |  ●  |  ●  |  ●  |  ◐  |  ◐  |  ◐  | safe-linking + `aligned_OK` (2.32) → needs heap leak |
| tcache double-free (naive)                  |  —  |  ●  |  ○  |  ○  |  ○  |  ○  |  ○  | tcache key (2.29) |
| fastbin dup                                 |  ●  |  ◐  |  ◐  |  ◐  |  ◐  |  ◐  |  ◐  | tcache intercepts frees (2.26); +mangling (2.32) |
| House of Force                              |  ●  |  ●  |  ○  |  ○  |  ○  |  ○  |  ○  | top-size sanity (2.29) |
| House of Spirit                             |  ●  |  ●  |  ●  |  ●  |  ●  |  ●  |  ●  | never fully killed (must pass size/align) |
| House of Einherjar (off-by-null)            |  ●  |  ●  |  ◐  |  ◐  |  ◐  |  ◐  |  ◐  | size/consolidate checks → needs heap leak |
| Classic House of Orange (FSOP half)         |  ●  |  ○  |  ○  |  ○  |  ○  |  ○  |  ○  | `_IO_vtable_check` (2.24) |
| Naive `_IO_2_1_stdout_` vtable overwrite    |  ●  |  ○  |  ○  |  ○  |  ○  |  ○  |  ○  | `_IO_vtable_check` (2.24) |
| House of Apple2 (modern FSOP)               |  —  |  ◐  |  ◐  |  ◐  |  ◐  |  ●  |  ●  | stays inside legal `_IO_wfile_jumps`; offsets version-specific |
| Unsorted-bin attack                         |  ●  |  ●  |  ○  |  ○  |  ○  |  ○  |  ○  | removal guard (**2.28**) |
| Large-bin attack                            |  ●  |  ●  |  ●  |  ●  |  ◐  |  ◐  |  ◐  | incremental checks (~2.30+); variants still viable with care |
| `environ` → stack ROP (payload delivery)    |  ●  |  ●  |  ●  |  ●  |  ●  |  ●  |  ●  | not an allocator technique — only needs leaks + a writable return addr |

Reading it: on **current** glibc (2.39/2.41) the only *primitive→control* paths still standing
are **tcache poisoning** (with a heap leak), **House of Apple2 / FSOP**, **House of Spirit**,
adapted **Einherjar/large-bin**, and hook-free **payload delivery via `environ`→ROP**. Everything
that made the 2016–2019 tutorials short — hooks, naive double-free, House of Force, unsorted-bin
attack, naive vtable FSOP — is gone.

---

## Two things the internet still gets wrong

1. **`__free_hook` is a tombstone, not a removal.** In 2.34 the allocator stopped *calling* the
   hooks (`malloc.c` references dropped from 5 → 0), but the **symbols still exist** for ABI
   compat. On the shipped 2.39 libc:
   ```
   $ nm -D libc.so.6 | grep _hook
   000000000020a148 V __free_hook@GLIBC_2.2.5
   000000000020a140 V __malloc_hook@GLIBC_2.2.5
   000000000020a138 V __realloc_hook@GLIBC_2.2.5
   ```
   pwntools will resolve `libc.sym['__free_hook']`, you can overwrite that 8-byte `.bss` slot,
   and your exploit still dies — because nothing reads it. That silent failure against a symbol
   that's *right there* is exactly why people get stuck.

2. **The unsorted-bin attack died in 2.28, not 2.29.** The `bck->fd != victim` guard at the
   "remove from unsorted list" site is absent in 2.27 and present in 2.28. Most writeups cite
   2.29 (bundling it with the tcache key); the source disagrees.

---

## How to reproduce this table (talk-proof)
```sh
for V in 2.23 2.24 2.26 2.27 2.28 2.29 2.31 2.32 2.33 2.34 2.39 2.41; do
  curl -s "https://raw.githubusercontent.com/bminor/glibc/glibc-$V/malloc/malloc.c" -o m-$V.c
done
grep -l "PROTECT_PTR" m-*.c            # safe-linking: 2.32+
grep -l "corrupted top size" m-*.c     # House of Force killer: 2.29+
grep -A3 "remove from unsorted list" m-2.27.c m-2.28.c   # unsorted-attack guard appears in 2.28
```
