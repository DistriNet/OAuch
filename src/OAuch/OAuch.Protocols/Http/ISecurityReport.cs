using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace OAuch.Protocols.Http {
    public interface ISecurityReport {
        bool IsHttpsUsed { get; }
        SslProtocols? NegotiatedTlsVersion { get; }
        CertificateReport? ServerCertificate { get; }
        CacheSettings Cached { get; }
        string? Url { get; }
    }
    [Flags]
    public enum SecurityChecks : int { 
        HttpsUsed = 1,
        ServerCertificateValid = 2,
        TlsMin12 = 4,
        TlsMin13 = 8
    }
    [Flags]
    public enum CacheSettings : int { 
        None = 0,
        CacheControlNoStore = 1,
        PragmaNoCache = 2,
        NotCached = CacheControlNoStore | PragmaNoCache
    }
    public class CertificateReport {
        public CertificateReport() { }
        public CertificateReport(X509Certificate certificate, bool isValid) {
            this.IsValid = isValid;
            var c2 = certificate as X509Certificate2;
            if (c2 != null) {
                this.IssuedTo = c2.Subject;
                this.IssuedBy = c2.Issuer;
                this.ValidFrom = c2.NotBefore;
                this.ValidTo = c2.NotAfter;
                this.Thumbprint = c2.Thumbprint;
            } else {
                this.IssuedTo = certificate.Subject;
                this.IssuedBy = certificate.Issuer;
                this.ValidFrom = DateTime.Parse(certificate.GetEffectiveDateString());
                this.ValidTo = DateTime.Parse(certificate.GetExpirationDateString());
                this.Thumbprint = certificate.GetCertHashString();
            }
        }
        public bool IsValid { get; set; }
        public string IssuedTo { get; set; }
        public string IssuedBy { get; set; }
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public string Thumbprint { get; set; }

        public override string ToString() {
            return $"Issued to: { IssuedTo }\r\nIssued by: { IssuedBy }\r\nThumbprint: { Thumbprint }\r\nValid from { ValidFrom.ToString("d MMM yyyy") } to { ValidTo.ToString("d MMM yyyy") }\r\n\r\nTrusted certificate: { (IsValid ? "YES" : "NO") }";
        }
    }
}
