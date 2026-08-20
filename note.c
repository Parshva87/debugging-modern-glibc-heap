// note.c  --  minimal "babyheap"-style tcache playground for a talk demo.
// Deliberately vulnerable: free() does NOT clear the pointer (use-after-free),
// which gives us both a read (show) and write (edit / alloc-time) primitive on
// freed chunks. This is the canonical shape of pwn.college's heap challenges,
// distilled to one file so the demo is fully reproducible against ANY libc.
//
// Build (matches the exploit assumptions):
//   gcc -no-pie -fno-stack-protector -o note note.c
//
// Protections: NX on (default), Full ASLR (system), no PIE, no canary.
// We defeat ASLR with leaks; -no-pie only fixes the *binary* base (handy for
// reading its GOT), the heap/libc/stack are still randomized.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX 16
static char  *notes[MAX];
static size_t sizes[MAX];

static long readint(void) {
    char buf[32];
    size_t i = 0;
    while (i < sizeof(buf) - 1) {               // read exactly one line
        char c;
        ssize_t n = read(0, &c, 1);
        if (n <= 0) exit(0);
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = 0;
    return strtol(buf, NULL, 0);
}

static void menu(void) {
    puts("\n1) alloc  2) free  3) edit  4) show  5) exit");
    printf("> ");
}

static void do_alloc(void) {
    printf("idx: ");   long i = readint();
    if (i < 0 || i >= MAX) return;
    printf("size: ");  long s = readint();
    if (s <= 0 || s > 0x500) return;
    notes[i] = malloc(s);
    if (!notes[i]) return;
    sizes[i] = s;
    printf("data: ");
    ssize_t n = read(0, notes[i], s);          // alloc-time write primitive
    if (n < 0) n = 0;
    if ((size_t)n < s) notes[i][n] = 0;
}

static void do_free(void) {
    printf("idx: ");  long i = readint();
    if (i < 0 || i >= MAX) return;
    free(notes[i]);                            // BUG: pointer left dangling (UAF)
}

static void do_edit(void) {
    printf("idx: ");  long i = readint();
    if (i < 0 || i >= MAX || !notes[i]) return;
    printf("data: ");
    read(0, notes[i], sizes[i]);               // UAF write
}

static void do_show(void) {
    printf("idx: ");  long i = readint();
    if (i < 0 || i >= MAX || !notes[i]) return;
    write(1, notes[i], sizes[i]);              // UAF read (raw bytes, leaks pointers)
}

int main(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    for (;;) {
        menu();
        switch (readint()) {
            case 1: do_alloc(); break;
            case 2: do_free();  break;
            case 3: do_edit();  break;
            case 4: do_show();  break;
            case 5: return 0;                  // clean return -> our ROP over main's
            default: break;                    // saved return address fires here
        }
    }
}
