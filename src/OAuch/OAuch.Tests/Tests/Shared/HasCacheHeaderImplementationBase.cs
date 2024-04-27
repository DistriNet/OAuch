using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Shared {
    public abstract class HasCacheHeaderImplementationBase : TestImplementation {
        public HasCacheHeaderImplementationBase(TestRunContext context, TestResult result, string? url, CacheSettings checkFor, HasSupportedFlowsTestResult supportedFlows) : base(context, result, supportedFlows) {
            _url = url;
            _checkFor = checkFor;
        }
        protected abstract string FailedInfoMessage { get; }
        public override async Task Run() {
            if (HasFailed<HasSupportedFlowsTestResult>() || string.IsNullOrWhiteSpace(_url)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var report = await Http.GetSecurityReport(_url);
            if (report.Cached.HasFlag(_checkFor)) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                LogInfo(FailedInfoMessage);
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
        }

        private readonly string? _url;
        private readonly CacheSettings _checkFor;
    }
}
