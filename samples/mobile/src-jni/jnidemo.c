/* RevLens JNI fixture library. A tiny hand written subset of jni.h: only what is called. */
#include <stdint.h>
#include <stddef.h>

typedef void *jobject; typedef jobject jclass; typedef jobject jstring; typedef jobject jbyteArray;
typedef int32_t jint; typedef int64_t jlong; typedef uint8_t jboolean;
typedef struct { const char *name; const char *signature; void *fnPtr; } JNINativeMethod;
typedef const void *const *JNIEnv;   /* pointer to the function table */
typedef const void *const *JavaVM;

#define JNI_VERSION_1_6 0x00010006
typedef jint (*GetEnvFn)(JavaVM *, void **, jint);
typedef jclass (*FindClassFn)(JNIEnv *, const char *);
typedef jint (*RegisterNativesFn)(JNIEnv *, jclass, const JNINativeMethod *, jint);
typedef jstring (*NewStringUTFFn)(JNIEnv *, const char *);

__attribute__((visibility("default"))) jint Java_org_revlens_jnidemo_NativeBridge_add(JNIEnv *env, jclass c, jint a, jint b) { return a + b; }
__attribute__((visibility("default"))) jstring Java_org_revlens_jnidemo_NativeBridge_greet(JNIEnv *env, jobject self, jstring name) { return ((NewStringUTFFn)(*env)[167])(env, "hello"); }
__attribute__((visibility("default"))) jint Java_org_revlens_jnidemo_NativeBridge_overloaded__I(JNIEnv *env, jobject self, jint x) { return x * 3; }

static jlong native_hash(JNIEnv *env, jobject self, jbyteArray data, jint seed) { return (jlong)seed * 1099511628211LL; }
static void native_reset(JNIEnv *env, jclass c) {}

static const JNINativeMethod kMethods[] = {
    { "hash", "([BI)J", (void *)native_hash },
    { "reset", "()V", (void *)native_reset },
};

__attribute__((visibility("default"))) jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    if (((GetEnvFn)(*vm)[6])(vm, (void **)&env, JNI_VERSION_1_6) != 0) return -1;
    jclass c = ((FindClassFn)(*env)[6])(env, "org/revlens/jnidemo/NativeBridge");
    if (!c) return -1;
    if (((RegisterNativesFn)(*env)[215])(env, c, kMethods, sizeof kMethods / sizeof kMethods[0]) != 0) return -1;
    return JNI_VERSION_1_6;
}
