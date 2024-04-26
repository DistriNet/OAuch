using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace OAuch.Helpers {
    public static class SiteInfo {
        public static string BuildVersion {
            get {
                if (_buildVersion == null) {
                    var v = Assembly.GetExecutingAssembly().GetName().Version ?? new Version("1.0");
                    var bd = new DateTime(Builtin.CompileTime, DateTimeKind.Utc);
                    _buildVersion = bd.ToString("yyyy.MM.dd"); // $"{ v.Major }.{ v.Minor }.{ bd.ToString("yyyy.MM.dd") }";
#if DEBUG
                    _buildVersion += "d";
#endif
                    _buildVersion += $" (.NET {Environment.Version.ToString(3)} / {GetOS()} / {RuntimeInformation.OSArchitecture})";
                }
                return _buildVersion;
            }
        }
        private static string? _buildVersion;

        private static string GetOS() {
            return Environment.OSVersion.Platform switch {
                PlatformID.Win32NT => "Win",
                PlatformID.Unix => "Unix",
                _ => "Unk.",
            };
        }

        private static string? _copyright;
        public static string Copyright {
            get {
                _copyright ??= $"Copyright © {DateTime.Now.Year}";
                return _copyright;
            }
        }
    }
}
