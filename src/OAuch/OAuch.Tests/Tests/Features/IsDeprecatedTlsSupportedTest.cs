using OAuch.Protocols.Http;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public class IsDeprecatedTlsSupportedTest : Test {
        public override string Title => "Are deprecated TLS versions supported on the OAuth endpoints";

        public override string Description => "This test determines whether the OAuth endpoints supports older versions of the TLS protocol (v1.0 and 1.1) or any version of the SSL protocol.";

        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;

        public override Type ResultType => typeof(IsDeprecatedTlsSupportedTestResult);
    }
    public class IsDeprecatedTlsSupportedTestResult : TestResult<IsDeprecatedTlsSupportedExtraInfo> {
        public IsDeprecatedTlsSupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsDeprecatedTlsSupportedTestImplementation);
    }
    public class IsDeprecatedTlsSupportedExtraInfo {
        public IEnumerable<SslProtocols>? SupportedDeprecatedProtocols { get; set; }
    }
    public class IsDeprecatedTlsSupportedTestImplementation : TestImplementation<IsDeprecatedTlsSupportedExtraInfo> {
        public IsDeprecatedTlsSupportedTestImplementation(TestRunContext context, IsDeprecatedTlsSupportedTestResult result, HasSupportedFlowsTestResult supportedFlows) : base(context, result, supportedFlows) { }
        public override async Task Run() {
            if (HasFailed<HasSupportedFlowsTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var hosts = new string?[] {
                Context.SiteSettings.AuthorizationUri,
                Context.SiteSettings.TokenUri,
                Context.SiteSettings.DeviceAuthorizationUri,
                Context.SiteSettings.MetadataUri,
                Context.SiteSettings.JwksUri,
                Context.SiteSettings.RevocationUri,
                Context.SiteSettings.TestUri
            };
            var testedHosts = new List<string>();
            var supportedProtocols = new List<SslProtocols>();
            bool hasDeprecatedTls = false;
            foreach (var host in hosts) {
                var result = await HasDeprecatedTls(host, testedHosts, supportedProtocols);
                if (result == true)
                    hasDeprecatedTls = true;
            }
            this.ExtraInfo.SupportedDeprecatedProtocols = supportedProtocols;
            this.Result.Outcome = hasDeprecatedTls ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
        }

        private async Task<bool?> HasDeprecatedTls(string? url, List<string> testedHosts, List<SslProtocols> supportedProtocols) {
            if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri)) {
                return null;
            }

            var host = $"{uri.Host}:{uri.Port}";
            if (testedHosts.Contains(host))
                return null;
            testedHosts.Add(host);

            var result = await HttpHelper.TryDowngradeConnection(url);
            if (result.Any()) {
                foreach (var sslProt in result) {
                    if (!supportedProtocols.Contains(sslProt))
                        supportedProtocols.Add(sslProt);
                }
                LogInfo($"The host '{host}' supports the following deprecated protocols: " + string.Join(", ", result.Select(c => c.ToName())));
                return true;
            }
            LogInfo($"The host '{host}' does not support deprecated protocols");
            return false;
        }
    }
}
