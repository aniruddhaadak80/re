#include <stdio.h>
int revlens_add(int a, int b) { return a + b; }
int main(void) { printf("hello from revlens extras\n"); return revlens_add(1, 2) == 3 ? 0 : 1; }
