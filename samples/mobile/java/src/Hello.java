package com.revlens.demo;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public class Hello implements Runnable {
    public static final String API = "https://api.example.com/v1/login";
    private static final String KEY = "AKIAIOSFODNN7EXAMPLE";
    private int counter;
    protected long total = 5L;
    static double ratio = 1.5;
    private final List<String> items = new ArrayList<>();

    public Hello(int start) { this.counter = start; }

    public int add(int a, int b) {
        int r = a + b;
        if (r > 100) { r = r - 100; }
        counter += r;
        return r;
    }

    public static String grade(int score) {
        switch (score / 10) {
            case 10: case 9: return "A";
            case 8: return "B";
            case 7: return "C";
            default: return "F";
        }
    }

    public static int sparse(int v) {
        switch (v) {
            case 1: return 10;
            case 1000: return 20;
            case 100000: return 30;
            default: return -1;
        }
    }

    public int[] table() { return new int[] { 3, 1, 4, 1, 5, 9, 2, 6 }; }

    public Object reflect(String cls) {
        try {
            Class<?> c = Class.forName(cls);
            Method m = c.getMethod("toString");
            return m.invoke(c.getDeclaredConstructor().newInstance());
        } catch (Exception e) {
            return null;
        }
    }

    public native int nativeSum(int a, int b);

    static { System.loadLibrary("hello"); }

    @Override
    public void run() {
        for (int i = 0; i < 3; i++) { items.add(API + i); }
        System.out.println("items=" + items.size() + " key=" + KEY.length());
    }

    public synchronized double mix(long a, float b, double c, char d, byte e, short f, boolean g) {
        return g ? a * b + c + d + e + f : ratio;
    }

    interface Callback { void done(String s); }

    public void later(Callback cb) { cb.done("ok"); new Thread(this).start(); }

    public static void main(String[] args) {
        Hello h = new Hello(1);
        System.out.println(h.add(2, 3) + grade(85) + sparse(1000));
        h.later(s -> System.out.println(s));
    }
}
