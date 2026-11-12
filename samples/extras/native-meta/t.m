#include <objc/objc.h>
#include <objc/runtime.h>
@protocol Greeter
- (int)greet:(int)times name:(const char *)who;
@optional
+ (id)shared;
@property (readonly) int level;
@end
__attribute__((objc_root_class))
@interface RLRoot { Class isa; }
+ (id)alloc;
@end
@implementation RLRoot
+ (id)alloc { return 0; }
@end
@interface RLWidget : RLRoot <Greeter> {
  int _count;
  double _ratio;
  const char *_label;
}
@property (nonatomic) int count;
@property (atomic, copy) id title;
@property (readonly) int level;
- (int)greet:(int)times name:(const char *)who;
- (double)scale:(double)f;
+ (id)shared;
@end
@implementation RLWidget
@synthesize count = _count;
@dynamic title;
- (int)level { return 3; }
- (int)greet:(int)times name:(const char *)who { return times + _count; }
- (double)scale:(double)f { return f * _ratio; }
+ (id)shared { return 0; }
@end
@interface RLWidget (Extra)
- (void)extraThing:(long)x;
+ (int)classExtra;
@property (readonly) long extraProp;
@end
@implementation RLWidget (Extra)
- (void)extraThing:(long)x { }
+ (int)classExtra { return 7; }
- (long)extraProp { return 9; }
@end
int main(void) { return [RLWidget shared] != 0; }
