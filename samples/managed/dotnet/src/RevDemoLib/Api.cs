// RevLens fixture: a public API that changes between version 1.0.0 and 2.0.0.
using System;
using System.Collections.Generic;

namespace RevDemo
{
    public interface IStore { int Count { get; } }

    public class Store : IStore
#if V2
        , IDisposable
#endif
    {
        private readonly List<string> items = new List<string>();
#if V2
        public const int Capacity = 64;
        public event EventHandler Changed;
#endif
        public int Count => items.Count;

        public void Add(string item) { items.Add(item); }
#if V2
        public void Add(string item, int copies) { for (int i = 0; i < copies; i++) items.Add(item); Changed?.Invoke(this, EventArgs.Empty); }
        public bool Remove(string item) => items.Remove(item);
        public T Find<T>(Func<string, T> map) => items.Count > 0 ? map(items[0]) : default;
        public void Dispose() { items.Clear(); }
        public string Describe() => "store v2 with " + items.Count;
#else
        public void Clear() { items.Clear(); }
        public string Describe() => "store with " + items.Count;
#endif
        protected virtual long Size() => items.Count;
    }

#if V2
    public sealed class Index { public string Key { get; set; } }
#else
    public class Legacy { public static int Version = 1; }
#endif
}
