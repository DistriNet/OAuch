using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Text;

namespace OAuch.Protocols.Http {
    public class SecurityReport : ISecurityReport {
        [JsonConstructor]
        public SecurityReport() { }
        private SecurityReport(ISecurityReport connectionSecurity, bool hasFrameOptions, bool hasCsp, CacheSettings cached) {
            this.Url = connectionSecurity.Url;
            this.HasFrameOptions = hasFrameOptions;
            this.HasContentSecurityPolicy = hasCsp;
            this.NegotiatedTlsVersion = connectionSecurity.NegotiatedTlsVersion;
            this.ServerCertificate = connectionSecurity.ServerCertificate;
            this.IsHttpsUsed = connectionSecurity.IsHttpsUsed;
            this.Cached = cached;
        }

        public bool HasFrameOptions { get; set; }
        public bool HasContentSecurityPolicy { get; set; }
        public SslProtocols? NegotiatedTlsVersion { get; set; }
        public CertificateReport? ServerCertificate { get; set; }
        public bool IsHttpsUsed { get; set; }
        public CacheSettings Cached { get; set; }
        public string? Url { get; set; }

        public bool Check(SecurityChecks checks) {
            if (checks.HasFlag(SecurityChecks.HttpsUsed)) {
                if (!IsHttpsUsed)
                    return false;
            }
            if (checks.HasFlag(SecurityChecks.TlsMin12)) {
                if (this.NegotiatedTlsVersion == null || (this.NegotiatedTlsVersion != SslProtocols.Tls12 && this.NegotiatedTlsVersion != SslProtocols.Tls13))
                    return false;
            }
            if (checks.HasFlag(SecurityChecks.TlsMin13)) {
                if (this.NegotiatedTlsVersion == null || this.NegotiatedTlsVersion != SslProtocols.Tls13)
                    return false;
            }
            if (checks.HasFlag(SecurityChecks.ServerCertificateValid)) {
                if (ServerCertificate == null || !ServerCertificate.IsValid)
                    return false;
            }
            return true;
        }


        public static SecurityReport CreateReportFromResponse(HttpResponse response) {
            var validCert = response.SecurityReport.IsHttpsUsed && response.SecurityReport.ServerCertificate != null && response.SecurityReport.ServerCertificate.IsValid;
            var hasFrameOptions = response.Headers.HasFrameOptions();
            var hasCsp = response.Headers.HasCsp();
            var cache = CacheSettings.None;
            if (response.Headers.HasCacheControlNoStore()) cache = cache | CacheSettings.CacheControlNoStore;
            if (response.Headers.HasPragmaNoCache()) cache = cache | CacheSettings.PragmaNoCache;
            if (!hasCsp) {
                // see if it is embedded in the HTML
                // <meta http-equiv="Content-Security-Policy" content="...">
                try {
                    var html = response.ToString(true);
                    hasCsp = html.IndexOf("Content-Security-Policy") >= 0; // not the best test to see if it is correctly embedded, but good enough for us
                } catch { 
                    // ok, guess it's not a UTF-8 string
                }
            }
            return new SecurityReport(response.SecurityReport, hasFrameOptions, hasCsp, cache);
        }
    }
}
