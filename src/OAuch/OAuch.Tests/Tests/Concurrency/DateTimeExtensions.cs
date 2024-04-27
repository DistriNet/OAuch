using System;
using System.Runtime.InteropServices;

namespace OAuch.Compliance.Tests.Concurrency {
    public static partial class PreciseTime {
        [LibraryImport("Kernel32.dll")]
        private static partial void GetSystemTimePreciseAsFileTime(out long filetime);
        public static DateTimeOffset Now {
            get {
                GetSystemTimePreciseAsFileTime(out long fileTime);
                return DateTimeOffset.FromFileTime(fileTime);
            }
        }
    }
}