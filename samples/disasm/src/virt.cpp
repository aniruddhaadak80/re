// virt.cpp: C++ virtual calls for @revlens/disasm indirect call resolution tests.
// Written for this repo, public domain / CC0. No C++ standard library is used, so the binary
// stays small; operator new and delete are defined on top of malloc and free.
#include <stdio.h>
#include <stdlib.h>

#define NOINLINE __attribute__((noinline))

void *operator new(unsigned long n) { return malloc(n); }
void operator delete(void *p) noexcept { free(p); }
void operator delete(void *p, unsigned long) noexcept { free(p); }

struct Animal {
  virtual ~Animal() {}
  virtual const char *name() const = 0;
  virtual int legs() const { return 4; }
  virtual void speak() const = 0;
};

struct Dog : Animal {
  const char *name() const override { return "dog"; }
  void speak() const override { puts("woof"); }
};

struct Bird : Animal {
  const char *name() const override { return "bird"; }
  int legs() const override { return 2; }
  void speak() const override { puts("tweet"); }
};

struct Snake : Animal {
  const char *name() const override { return "snake"; }
  int legs() const override { return 0; }
  void speak() const override { puts("hiss"); }
};

// a call through an unknown object: candidates are the speak slot of every vtable
NOINLINE void make_noise(const Animal *a) { a->speak(); }

NOINLINE int count_legs(Animal **zoo, int n) {
  int t = 0;
  for (int i = 0; i < n; i++) t += zoo[i]->legs();
  return t;
}

Animal *volatile g_pet;

int main(int argc, char **) {
  Animal *zoo[3];
  zoo[0] = new Dog();
  zoo[1] = new Bird();
  zoo[2] = new Snake();
  for (int i = 0; i < 3; i++) make_noise(zoo[i]);
  int legs = count_legs(zoo, 3);
  g_pet = zoo[argc % 3];
  printf("%s %d\n", g_pet->name(), legs);
  for (int i = 0; i < 3; i++) delete zoo[i];
  return 0;
}
