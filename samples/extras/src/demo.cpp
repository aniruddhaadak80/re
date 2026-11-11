#include <vector>
#include <map>
#include <string>
#include <cstdio>
namespace revlens { namespace demo {
template <typename T> struct Box { T v; T get() const { return v; } };
struct Widget { virtual ~Widget() {} virtual int area(int w, int h) const { return w * h; } };
static std::map<std::string, std::vector<int>> table;
int sum(const std::vector<int>& xs) { int s = 0; for (int x : xs) s += x; return s; }
}}
__attribute__((constructor)) static void early_init() { std::puts("init"); }
int main(int argc, char** argv) {
  revlens::demo::Box<long> b{argc};
  revlens::demo::Widget w;
  revlens::demo::table["a"].push_back(argc);
  std::printf("%ld %d %d\n", b.get(), w.area(argc, 3), revlens::demo::sum(revlens::demo::table["a"]));
  return 0;
}
