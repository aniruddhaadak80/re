namespace revlens { namespace demo {
template <typename T> struct Box { T v; T get() const { return v; } };
class Widget { public: virtual ~Widget() {} virtual int area(int w, int h) const { return w * h; } static int count; };
int Widget::count = 0;
int sum(const int* xs, unsigned n) { int s = 0; for (unsigned i = 0; i < n; i++) s += xs[i]; return s; }
double scale(double x, float f, long long k) { return x * f + k; }
}}
int use() { revlens::demo::Box<long> b{3}; revlens::demo::Widget w; int a[2] = {1, 2}; return (int)b.get() + w.area(2, 3) + revlens::demo::sum(a, 2) + (int)revlens::demo::scale(1.0, 2.0f, 3); }
