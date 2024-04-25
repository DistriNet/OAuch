using System;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Text;

namespace OAuch.Protocols.Tls {
    public class SniffOptions {
#pragma warning disable SYSLIB0039
#pragma warning disable CS0618
        public SniffOptions() {
            this.SniffAlgorithms = false;
            this.SniffProtocols = false;
            this.Protocols = new SslProtocols[] { SslProtocols.Ssl3, SslProtocols.Tls, SslProtocols.Tls11, SslProtocols.Tls12, SslProtocols.Tls13 };
            this.CipherSuites = CipherSuite.All;
        }
#pragma warning restore SYSLIB0039
#pragma warning restore CS0618
        /// <summary>
        /// Set to true to sniff support for individual cipher suites
        /// </summary>
        public bool SniffAlgorithms { get; set; }
        /// <summary>
        /// Set to true to sniff support for individual protocols
        /// </summary>
        public bool SniffProtocols { get; set; }
        /// <summary>
        /// The list of cipher suites to offer to the server. If SniffAlgorithms is true, a connection
        /// will be set up for each of these suites to see if the server supports it.
        /// </summary>
        public IEnumerable<CipherSuite> CipherSuites { get; set; }

        /// <summary>
        /// The list of protocols to allow. If SniffProtocols is true, a connection
        /// will be set up for each of these suites to see if the server supports it.
        /// </summary>
        public IEnumerable<SslProtocols> Protocols { get; set; }

        public static SniffOptions Default => new SniffOptions();
    }
}
