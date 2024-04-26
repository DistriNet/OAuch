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
        public CertificateReport() {
            this.IssuedBy = string.Empty;
            this.IssuedTo = string.Empty;
            this.Thumbprint = string.Empty;
        }
        public CertificateReport(X509Certificate certificate, bool isValid) {
            this.IsValid = isValid;
            if (certificate is X509Certificate2 c2) {
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
            return $"Issued to: { IssuedTo }\r\nIssued by: { IssuedBy }\r\nThumbprint: { Thumbprint }\r\nValid from {ValidFrom:d MMM yyyy} to {ValidTo:d MMM yyyy}\r\n\r\nTrusted certificate: { (IsValid ? "YES" : "NO") }";
        }
    }
}
