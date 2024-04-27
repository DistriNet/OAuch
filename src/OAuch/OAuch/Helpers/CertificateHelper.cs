using OAuch.Database.Entities;
using System.Security.Cryptography.X509Certificates;

namespace OAuch.Helpers {
    public static class CertificateHelper {
        public static X509Certificate2? GetCertificate(byte[] blob, string? password) {
            /* 
                SslStream doesn't work with Ephemeral key sets :-/ 
                https://github.com/dotnet/runtime/issues/23749 
             */
            try {
                var col = new X509Certificate2Collection();
                if (string.IsNullOrEmpty(password))
                    col.Import(blob);
                else
                    col.Import(blob, password, X509KeyStorageFlags.DefaultKeySet);

                foreach (var c in col) {
                    if (c.HasPrivateKey) {
                        return c;
                    }
                }
                return null;
            } catch {
                return null;
            }
        }
        public static X509Certificate2Collection ToCollection(this SavedCertificate cert) {
            /* 
                SslStream doesn't work with Ephemeral key sets :-/ 
                https://github.com/dotnet/runtime/issues/23749 
             */
            var col = new X509Certificate2Collection();
            if (string.IsNullOrEmpty(cert.Password))
                col.Import(cert.Blob);
            else
                col.Import(cert.Blob, cert.Password, X509KeyStorageFlags.DefaultKeySet);
            return col;
        }
    }
}