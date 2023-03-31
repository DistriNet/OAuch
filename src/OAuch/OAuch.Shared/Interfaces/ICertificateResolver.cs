using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Interfaces {
    public interface ICertificateResolver {
        X509CertificateCollection? FindCertificate(Guid id);
    }
}
