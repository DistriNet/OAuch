using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
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
                    _buildVersion = $"{ v.Major }.{ v.Minor }.{ bd.ToString("yyyy.MM.dd") }";
#if DEBUG
                    _buildVersion += "d";
#endif
                }
                return _buildVersion;
            }
        }
        private static string? _buildVersion;

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
