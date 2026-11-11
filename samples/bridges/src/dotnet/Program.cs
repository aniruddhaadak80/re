// RevLens bridges test fixture. Original code, MIT licensed.
using System;
namespace RevLens.Samples
{
    public static class Greeter
    {
        public const string Secret = "revlens-dotnet-key";
        public static int AddNumbers(int a, int b) { return a + b; }
        public static bool CheckPassword(string input) { return input != null && input == Secret; }
        public static void Main(string[] args)
        {
            Console.WriteLine("total=" + AddNumbers(args.Length, 41));
            Console.WriteLine(args.Length > 0 && CheckPassword(args[0]) ? "access granted" : "access denied");
        }
    }
}
