/* DWARF type fixture for RevLens (written for this repo, CC0). */
#include <stddef.h>
#include <stdint.h>

typedef unsigned int u32_t;
typedef struct point { int x; int y; } point_t;
enum color { RED = 0, GREEN = 5, BLUE = -3 };
typedef enum color color_t;

union value { int i; float f; double d; char bytes[8]; };

struct flags { unsigned a : 3; unsigned b : 5; unsigned c : 1; };

typedef int (*cmp_fn)(const void *a, const void *b);

struct node {
  struct node *next;
  const char *name;
  point_t pos;
  color_t color;
  union value val;
  struct flags fl;
  u32_t ids[4];
  cmp_fn compare;
  volatile long counter;
};

struct node g_root;
point_t g_points[3] = {{1, 2}, {3, 4}, {5, 6}};

__attribute__((noinline)) int point_sum(point_t *p) { return p->x + p->y; }

__attribute__((noinline)) int node_weight(struct node *n, int scale, color_t c) {
  int w = 0;
  for (struct node *it = n; it; it = it->next) w += point_sum(&it->pos) * scale + (int)it->fl.b;
  if (c == GREEN) w += n->ids[2];
  return w;
}

__attribute__((noinline)) double value_mix(union value v, float k) { return v.d * k + v.i; }

static int cmp_int(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }

int main(int argc, char **argv) {
  (void)argv;
  g_root.compare = cmp_int;
  g_root.pos = g_points[argc % 3];
  g_root.fl.b = (unsigned)argc;
  union value v; v.d = argc;
  return node_weight(&g_root, argc, (color_t)argc) + (int)value_mix(v, 1.5f) + g_root.compare(&argc, &argc);
}
