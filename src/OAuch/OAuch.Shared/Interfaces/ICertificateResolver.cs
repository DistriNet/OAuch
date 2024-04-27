using System;
using System.Security.Cryptography.X509Certificates;

namespace OAuch.Shared.Interfaces {
    public interface ICertificateResolver {
        X509CertificateCollection? FindCertificate(Guid id);
    }
}
