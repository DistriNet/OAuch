using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Shared {
    public abstract class IsModernTlsSupportedTestImplementationBase : TestImplementation<IsModernTlsSupportedExtraInfo> {
        public IsModernTlsSupportedTestImplementationBase(TestRunContext context, TestResult<IsModernTlsSupportedExtraInfo> result, string? url, HasSupportedFlowsTestResult supportedFlows) : base(context, result, supportedFlows) {
            _url = url;
        }
        public override async Task Run() {
            if (string.IsNullOrWhiteSpace(_url) || HasFailed<HasSupportedFlowsTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if (!Uri.TryCreate(_url, UriKind.Absolute, out var uri)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var result = await Http.TryModernConnection(_url);
            if (result.Any()) {
                LogInfo("The server supports the following modern protocols: " + string.Join(", ", result.Select(c => c.ToName())));
            }
            this.ExtraInfo.SupportedModernProtocols = result;
            this.Result.Outcome = (result == null || !result.Any()) ? TestOutcomes.SpecificationNotImplemented : TestOutcomes.SpecificationFullyImplemented;
        }
        private readonly string? _url;
    }
    public class IsModernTlsSupportedExtraInfo {
        public IEnumerable<SslProtocols>? SupportedModernProtocols { get; set; }
    }
}

