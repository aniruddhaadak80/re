/* RevLens disasm test program. Public domain (CC0). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *greetings[] = { "alpha-greeting", "beta-greeting", "gamma-greeting" };

__attribute__((noinline)) int classify(int x) {
  if (x < 0) return -1;
  else if (x == 0) return 0;
  return 1;
}

__attribute__((noinline)) int sum_to(int n) {
  int s = 0;
  for (int i = 0; i < n; i++) {
    if (i % 3 == 0) s += i;
    else s -= 1;
  }
  return s;
}

__attribute__((noinline)) int check_password(const char *p) {
  if (strcmp(p, "revlens-secret-key") == 0) {
    puts("access granted");
    return 1;
  }
  puts("access denied");
  return 0;
}

__attribute__((noinline)) int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

__attribute__((noinline)) void deep3(void) { puts("deep path reached"); }
__attribute__((noinline)) void deep2(int v) { if (v > 1) deep3(); }
__attribute__((noinline)) void deep1(int v) { deep2(v + 1); }

int main(int argc, char **argv) {
  printf("hello from revlens %d\n", classify(argc));
  int r = sum_to(argc * 10);
  if (argc > 1) r += check_password(argv[1]);
  deep1(argc);
  printf("%s %d\n", greetings[argc % 3], fib(argc + 5));
  return r & 0xff;
}
