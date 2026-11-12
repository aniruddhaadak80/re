// C++ class fixture for PDB and DWARF type tests (written for this repo, CC0).
namespace geo {
struct Vec { float x, y; };
class Shape {
 public:
  virtual int area() const { return 0; }
  virtual int sides() const { return 0; }
  int id;
  static int count;
 protected:
  Vec origin;
};
class Rect : public Shape {
 public:
  Rect(int w, int h) : w_(w), h_(h) {}
  int area() const override { return w_ * h_; }
  int sides() const override { return 4; }
  int scaled(int k) const { return area() * k; }
 private:
  int w_, h_;
};
enum class Mode : unsigned char { Off = 0, On = 1, Auto = 200 };
int Shape::count = 3;
}
extern "C" int revlens_entry(int argc) {
  geo::Rect r(argc, 3);
  geo::Shape *s = &r;
  geo::Mode m = argc > 2 ? geo::Mode::Auto : geo::Mode::On;
  return s->area() + r.scaled(2) + (int)m + geo::Shape::count;
}
