/* GameCube DOL fixture for RevLens (written for this repo, CC0). Built for big endian 32 bit
   PowerPC with zig cc, then packed into a DOL by make-dol.py. */
volatile unsigned int counter;
unsigned int table[4] = {3, 1, 4, 1};
static const char banner[] = "RevLens DOL";

__attribute__((noinline)) unsigned int mix(unsigned int a, unsigned int b) { return (a * 31u) ^ (b + table[a & 3]); }

__attribute__((noinline)) unsigned int spin(unsigned int n) {
  unsigned int acc = 0;
  for (unsigned int i = 0; i < n; i++) acc = mix(acc, i + (unsigned char)banner[i % 11]);
  return acc;
}

void __start(void) {
  counter = spin(16);
  for (;;) {}
}
