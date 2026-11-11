// switch.c: jump tables, function pointer tables and value flow fixtures for @revlens/disasm.
// Written for this repo, public domain / CC0. Every case has a distinct side effect (a distinct
// string or callee) so a test can check that the resolved case target really is that case.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))

volatile int sink;

NOINLINE void hit(int v) { sink = v; }

// dense switch over 0..9: a jump table. Case bodies differ in shape so the compiler cannot turn
// the switch into a lookup table.
NOINLINE int dense_switch(int op) {
  int r = op;
  switch (op) {
    case 0: puts("op zero"); break;
    case 1: hit(0x11); hit(0x12); break;
    case 2: r = printf("op two %d\n", op); break;
    case 3: puts("op three"); hit(3); break;
    case 4: r = (int)strlen("op four") + op; hit(r); break;
    case 5: printf("op five %d %d\n", op, r); break;
    case 6: hit(6); puts("op six"); break;
    case 7: r = atoi("77"); break;
    case 8: puts("op eight"); r = 8 * op; hit(r); break;
    case 9: printf("op nine\n"); r = -9; break;
    default: puts("op default"); return -1;
  }
  return r * 3;
}

// switch on a biased range (cases 100..111) with holes: index = op - 100, holes go to default
NOINLINE int biased_switch(int op) {
  int r = 0;
  switch (op) {
    case 100: hit(0x100); break;
    case 101: puts("b101"); break;
    case 102: r = printf("b102 %d\n", op); break;
    case 104: hit(0x104); hit(op); break;
    case 105: puts("b105"); r = 5; break;
    case 106: r = atoi("106"); break;
    case 108: hit(0x108); puts("b108"); break;
    case 109: printf("b109 %d %d\n", op, r); break;
    case 110: r = (int)strlen("b110") * op; break;
    case 111: hit(0x111); r = 11; hit(r); break;
    default: hit(-1); return 0;
  }
  return r + 1;
}

// character dispatch, the kind of switch a lexer has
NOINLINE int char_class(const char *s) {
  int n = 0;
  for (; *s; s++) {
    switch (*s) {
      case 'a': puts("letter a"); n += 1; break;
      case 'b': hit(n); n *= 2; break;
      case 'c': n += printf("letter c %d\n", n); break;
      case 'd': n -= atoi("4"); break;
      case 'e': puts("letter e"); hit(5); break;
      case 'f': n = (int)strlen(s); break;
      case 'g': hit(7); hit(n); n++; break;
      default: n -= 1; break;
    }
  }
  return n;
}

// sparse switch: compilers use a compare tree, not a table
NOINLINE int sparse_switch(int v) {
  switch (v) {
    case 7: return hit(7), 1;
    case 1000: return hit(1000), 2;
    case 70000: return hit(70000), 3;
    case 9000000: return hit(9000000), 4;
    default: return 0;
  }
}

// function pointer table in .data.rel.ro / .rodata
NOINLINE int h_add(int a, int b) { puts("handler add"); return a + b; }
NOINLINE int h_sub(int a, int b) { puts("handler sub"); return a - b; }
NOINLINE int h_mul(int a, int b) { puts("handler mul"); return a * b; }
NOINLINE int h_div(int a, int b) { puts("handler div"); return b ? a / b : 0; }

typedef int (*binop)(int, int);
static binop const HANDLERS[4] = { h_add, h_sub, h_mul, h_div };

// variable index: the call goes through the table (targets: the 4 handlers)
NOINLINE int dispatch(unsigned k, int a, int b) {
  if (k >= 4) return 0;
  return HANDLERS[k](a, b);
}

// a pointer that is a known constant at the call: resolvable by constant propagation
binop volatile chosen = h_mul;
NOINLINE int call_through_global(int a) {
  binop f = chosen;
  return f(a, 7);
}

// value flow: constants and strings reaching call arguments
NOINLINE int open_config(const char *path, int flags, int mode) {
  printf("open %s %x %o\n", path, flags, mode);
  return flags ^ mode;
}

NOINLINE int load_settings(void) {
  const char *p = "/etc/revlens/settings.conf";
  int flags = 0x241;
  return open_config(p, flags, 0644);
}

NOINLINE int forward_secret(const char *key) {
  // the incoming argument flows to strcmp and to puts
  if (strcmp(key, "revlens-gap-key") == 0) { puts(key); return 1; }
  return 0;
}

NOINLINE int sum_array(const int *a, int n) {
  int total = 0;
  for (int i = 0; i < n; i++) {
    if (a[i] < 0) break;
    total += a[i];
  }
  return total;
}

NOINLINE int locals_demo(int x, int y) {
  int buf[8];
  for (int i = 0; i < 8; i++) buf[i] = x * i + y;
  int acc = 0;
  for (int i = 0; i < 8; i++) acc ^= buf[i];
  return acc;
}

int main(int argc, char **argv) {
  int r = 0;
  r += dense_switch(argc);
  r += biased_switch(argc + 99);
  r += char_class(argc > 1 ? argv[1] : "abcz");
  r += sparse_switch(argc * 7);
  r += dispatch((unsigned)argc, 6, 3);
  r += call_through_global(argc);
  r += load_settings();
  r += forward_secret(argc > 2 ? argv[2] : "none");
  int arr[4] = { 1, 2, argc, 4 };
  r += sum_array(arr, 4);
  r += locals_demo(argc, 5);
  printf("%d\n", r);
  return 0;
}
