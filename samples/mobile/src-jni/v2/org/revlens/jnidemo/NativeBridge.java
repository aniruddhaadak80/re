package org.revlens.jnidemo;

/** Version 2 of the JNI fixture, for member diff tests: one method removed, one added, one signature changed, a field added. */
public class NativeBridge {
    static { System.loadLibrary("jnidemo"); }

    public static final String VERSION = "2";
    private int calls;

    public static native int add(int a, int b);
    public native String greet(String name, String locale);
    public native long hash(byte[] data, int seed);
    public static native void reset();
    public native int overloaded(int x);
    public native int overloaded(String s);
    public native void shutdown();

    public int twice(int x) { calls++; return add(x, x); }
    protected long thrice(long x) { return x * 3; }
}
