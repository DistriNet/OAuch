using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Tls;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Shared {
    public abstract class AreStrongCiphersEnabledTestImplementationBase : TestImplementation {
        public AreStrongCiphersEnabledTestImplementationBase(TestRunContext context, TestResult result, string? url, bool strictCheck, HasSupportedFlowsTestResult supportedFlows, TestResult<IsModernTlsSupportedExtraInfo> modernTls, IsDeprecatedTlsSupportedTestResult deprecatedTls) : base(context, result, supportedFlows, modernTls, deprecatedTls) {
            _url = url;
            _strictCheck = strictCheck;
        }
        public override async Task Run() {
            if (string.IsNullOrWhiteSpace(_url) || HasFailed<HasSupportedFlowsTestResult>() || HasFailed<TestResult<IsModernTlsSupportedExtraInfo>>() || HasSucceeded<IsDeprecatedTlsSupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if (!Uri.TryCreate(_url, UriKind.Absolute, out var uri)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var sniffer = new TlsSniffer();
            var options = new SniffOptions() {
                SniffProtocols = true,
                SniffAlgorithms = true
            };
            var result = await sniffer.Sniff(uri, options);

            if (result.AcceptedCipherSuites.Count == 0) {
                LogInfo("Handshake failure; could not determine supported TLS versions and cipher suites...");
                Result.Outcome = TestOutcomes.Failed;
                return;
            }

            Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            // only check the TLS v1.2 ciphers; all v1.3 ciphers are OK
            var oldProtocolCiphers = result.AcceptedCipherSuites.Where(c => !c.IsTls13Cipher).ToList();
            if (oldProtocolCiphers.Count > 0) {
                int orgCount = oldProtocolCiphers.Count;
                oldProtocolCiphers.Remove(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
                oldProtocolCiphers.Remove(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
                oldProtocolCiphers.Remove(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
                oldProtocolCiphers.Remove(CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
                if (orgCount == oldProtocolCiphers.Count) {
                    LogInfo("The server does not implement any of these four required cipher suites for TLS 1.2: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                }
                if (oldProtocolCiphers.Count > 0 && _strictCheck) {
                    LogInfo("The server supports the following disallowed cipher suites for TLS 1.2: " + string.Join(", ", oldProtocolCiphers.Select(c => c.Name)));
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                }
            } else {
                LogInfo("Only TLS 1.3 is supported.");
            }
        }
        private readonly string? _url;
        private readonly bool _strictCheck;
    }
}
