using OAuch.Protocols.Http;
using OAuch.Shared.Logging;

namespace OAuch.LogConverters {
    public class CertificateReportConverter : ILogConverter<CertificateReport> {
        public LoggedItem Convert(CertificateReport item) {
            return new LoggedCertificateReport() {
                Content = item.ToString()
            };
        }
    }
}
