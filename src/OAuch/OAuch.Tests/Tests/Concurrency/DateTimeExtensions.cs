using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

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