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
                    var v = Assembly.GetExecutingAssembly().GetName().Version;
                    if (v == null)
                        v = new Version("1.0");
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
            switch (Environment.OSVersion.Platform) {
                case PlatformID.Win32NT:
                    return "Win";
                case PlatformID.Unix:
                    return "Unix";
                default:
                    return "Unk.";
            }            
        }

        private static string? _copyright;
        public static string Copyright {
            get {
                if (_copyright == null)
                    _copyright = $"Copyright © { DateTime.Now.Year.ToString() }";
                return _copyright;
            }
        }
    }
}
