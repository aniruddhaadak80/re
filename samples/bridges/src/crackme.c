/* RevLens bridges test fixture. Original code, MIT licensed, part of the RevLens repo. */
#include <stdio.h>
#include <string.h>

static const char *SECRET = "revlens-open-sesame";

int add_numbers(int a, int b) {
  return a + b;
}

int check_password(const char *input) {
  if (input == NULL) return 0;
  if (strlen(input) != strlen(SECRET)) return 0;
  return strcmp(input, SECRET) == 0;
}

unsigned int checksum(const unsigned char *data, unsigned int len) {
  unsigned int h = 2166136261u;
  for (unsigned int i = 0; i < len; i++) {
    h ^= data[i];
    h *= 16777619u;
  }
  return h;
}

int main(int argc, char **argv) {
  int total = add_numbers(argc, 41);
  printf("total=%d\n", total);
  if (argc > 1 && check_password(argv[1])) {
    puts("access granted");
    return 0;
  }
  printf("checksum=%u\n", checksum((const unsigned char *)"RevLens", 7));
  puts("access denied");
  return 1;
}
