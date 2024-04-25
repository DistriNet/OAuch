using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Concurrency {
    public static class PreciseTime {
        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern void GetSystemTimePreciseAsFileTime(out long filetime);
        public static DateTimeOffset Now {
            get {
                long fileTime;
                GetSystemTimePreciseAsFileTime(out fileTime);
                return DateTimeOffset.FromFileTime(fileTime);
            }
        }
    }
}