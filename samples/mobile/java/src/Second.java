package com.revlens.demo2;

import dalvik.system.DexClassLoader;

public final class Second {
    private static final String ENDPOINT = "http://tracker.example.net/collect";
    public static String pick(String k) {
        switch (k) {
            case "alpha": return "a";
            case "beta": return "b";
            default: return ENDPOINT;
        }
    }
    public static Object load(String path, ClassLoader parent) throws Exception {
        DexClassLoader cl = new DexClassLoader(path, "/data/local/tmp", null, parent);
        return cl.loadClass("com.payload.Entry").newInstance();
    }
    public static long[] wide() { return new long[] { 1L, 0x123456789L, -5L }; }
}
