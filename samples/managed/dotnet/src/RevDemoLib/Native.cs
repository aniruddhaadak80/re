// RevLens fixture: P/Invoke declarations against the .NET Brotli native library and Windows APIs.
using System;
using System.Runtime.InteropServices;

namespace RevDemo
{
    public static class Native
    {
        [DllImport("libSystem.IO.Compression.Native")]
        public static extern IntPtr BrotliEncoderCreateInstance(IntPtr alloc, IntPtr free, IntPtr opaque);

        [DllImport("libSystem.IO.Compression.Native", EntryPoint = "BrotliDecoderVersion")]
        public static extern uint DecoderVersion();

        [DllImport("libSystem.IO.Compression.Native", EntryPoint = "RevDemoDoesNotExist", SetLastError = true)]
        public static extern int Missing();

        [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = false)]
        public static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);

        [DllImport("libc", CallingConvention = CallingConvention.Cdecl)]
        public static extern int getpid();
    }
}
