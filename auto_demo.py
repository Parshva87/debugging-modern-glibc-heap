#!/usr/bin/env python3
"""
auto_demo.py -- hands-free run of the full chain, for recording a backup demo.

Runs exploit.py, waits for the shell, then issues a short sequence of commands
at a natural pace so a screen/asciinema recording looks live without you touching
the keyboard. Terminates the child after the last command so the post-shell
SIGSEGV never reaches the recording -- the video ends clean on your banner.

Usage (inside the repo, with ./note already built -- `make` or gcc):
    python3 auto_demo.py
Record it:
    asciinema rec -c "python3 auto_demo.py" demo.cast     # crisp terminal capture
"""
import pexpect, sys, time

TYPE_DELAY = 0.04    # per-char cadence when sending a command
SHOW_PAUSE = 1.1     # how long to display each command's output

CMDS = [
    "id",
    "uname -a",
    "whoami",
    "cat /etc/os-release | head -3",
    "echo '=== life after the hooks ==='",
]

def drain(child, secs):
    """Read (and thus mirror via logfile_read) for `secs` seconds."""
    end = time.time() + secs
    while time.time() < end:
        try:
            child.read_nonblocking(size=4096, timeout=0.2)
        except (pexpect.TIMEOUT, pexpect.EOF):
            pass

def typed(child, cmd):
    for ch in cmd:
        child.send(ch)
        time.sleep(TYPE_DELAY)
    child.send("\n")

def main():
    child = pexpect.spawn("python3 exploit.py", encoding="utf-8",
                          timeout=90, dimensions=(38, 120))
    child.logfile_read = sys.stdout
    child.expect(["Switching to interactive", "shell popped", pexpect.EOF])
    drain(child, 1.2)                     # let the prompt settle
    for cmd in CMDS:
        typed(child, cmd)
        drain(child, SHOW_PAUSE)          # mirror the command echo + its output
    drain(child, 1.0)
    child.close(force=True)               # kill before the shell-exit SIGSEGV
    print()

if __name__ == "__main__":
    main()
