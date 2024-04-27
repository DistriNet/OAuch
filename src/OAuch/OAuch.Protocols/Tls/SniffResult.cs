using System.Collections.Generic;
using System.Security.Authentication;

namespace OAuch.Protocols.Tls {
    public class SniffResult {
        public SniffResult(List<SslProtocols> protocols, List<CipherSuite> ciphers) {
            _acceptedCipherSuites = ciphers;
            _acceptedProtocols = protocols;
        }
        public IReadOnlyList<SslProtocols> AcceptedProtocols => _acceptedProtocols;
        public IReadOnlyList<CipherSuite> AcceptedCipherSuites => _acceptedCipherSuites;
        private readonly List<SslProtocols> _acceptedProtocols;
        private readonly List<CipherSuite> _acceptedCipherSuites;
    }
}
