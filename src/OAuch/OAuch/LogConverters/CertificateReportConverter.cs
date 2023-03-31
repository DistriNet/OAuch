using OAuch.Protocols.Http;
using OAuch.Shared.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.LogConverters {
    public class CertificateReportConverter : ILogConverter<CertificateReport> {
        public LoggedItem Convert(CertificateReport item) {
            return new LoggedCertificateReport() {
                Content = item.ToString()
            };
        }
    }
}
