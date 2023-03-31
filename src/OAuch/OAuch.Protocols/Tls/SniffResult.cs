using System;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Text;

namespace OAuch.Protocols.Tls {
    public class SniffResult {
        public SniffResult(List<SslProtocols> protocols, List<CipherSuite> ciphers) {
            _acceptedCipherSuites = ciphers;
            _acceptedProtocols = protocols;
        }
        public IReadOnlyList<SslProtocols> AcceptedProtocols => _acceptedProtocols;
        public IReadOnlyList<CipherSuite> AcceptedCipherSuites => _acceptedCipherSuites;
        private List<SslProtocols> _acceptedProtocols;
        private List<CipherSuite> _acceptedCipherSuites;
    }
}
