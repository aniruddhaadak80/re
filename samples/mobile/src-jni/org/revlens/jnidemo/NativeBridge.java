package org.revlens.jnidemo;

/** RevLens JNI fixture: static exports, RegisterNatives and an unbound native method. */
public class NativeBridge {
    static { System.loadLibrary("jnidemo"); }

    public static native int add(int a, int b);
    public native String greet(String name);
    public native long hash(byte[] data, int seed);
    public static native void reset();
    public native boolean missing();
    public native int overloaded(int x);
    public native int overloaded(String s);

    public int twice(int x) { return add(x, x); }
}
