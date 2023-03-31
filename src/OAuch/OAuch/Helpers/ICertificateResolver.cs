using OAuch.Database;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OAuch.Helpers {
    public class CertificateResolver : ICertificateResolver {
        public X509CertificateCollection? FindCertificate(Guid id) {
            using (var db = new OAuchDbContext()) {
                var cert = db.Certificates.Where(c => c.SavedCertificateId == id).SingleOrDefault();
                if (cert == null) {
                    return null;
                }
                return cert.ToCollection();
            }
        }
    }
}