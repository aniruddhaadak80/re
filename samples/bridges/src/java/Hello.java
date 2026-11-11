// RevLens bridges test fixture. Original code, MIT licensed, part of the RevLens repo.
package dev.revlens.fixture;

public class Hello {
    private static final String API_HOST = "https://api.example.invalid/v1";

    public static int addNumbers(int a, int b) {
        return a + b;
    }

    public static boolean checkLicense(String key) {
        if (key == null || key.length() != 16) {
            return false;
        }
        int sum = 0;
        for (char c : key.toCharArray()) {
            sum += c;
        }
        return sum % 7 == 3;
    }

    public static void main(String[] args) {
        System.out.println("total=" + addNumbers(args.length, 41));
        System.out.println("host=" + API_HOST);
        System.out.println(checkLicense(args.length > 0 ? args[0] : null) ? "licensed" : "unlicensed");
    }
}
