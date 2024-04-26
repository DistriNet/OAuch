using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class RefreshTokenPresentTest : Test {
        public override string Title => "Does the implicit flow grant refresh tokens";
        public override string Description => "This test checks whether the implicit flow grants refresh tokens.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(RefreshTokenPresentTestResult);
    }
    public class RefreshTokenPresentTestResult : TestResult {
        public RefreshTokenPresentTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RefreshTokenPresentTestImplementation);
    }
    public class RefreshTokenPresentTestImplementation : TestImplementation {
        public RefreshTokenPresentTestImplementation(TestRunContext context, RefreshTokenPresentTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || string.IsNullOrEmpty(this.Context.SiteSettings.CallbackUri)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProviderWithStage<AddScope, Dictionary<string, string?>, Dictionary<string, string?>>(Context, (f, p) => p is ImplicitTokenProvider);
            if (provider == null) {
                LogInfo("Could not find a working implicit flow");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }
            var processor = new ChangeScope();
            provider.Pipeline.AddAfter<AddScope, Dictionary<string, string?>, Dictionary<string, string?>>(processor);

            var token = await provider.GetToken();
            if (token.RefreshToken != null) {
                LogInfo("The implicit flow issues refresh tokens");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                return;
            }

            if (processor.Scope == null || !processor.Scope.Contains("offline_access")) {
                processor.AddOfflineAccess = true;
                token = await provider.GetToken();
                if (token.RefreshToken != null) {
                    LogInfo("The implicit flow issues refresh tokens");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    return;
                }
            }
            LogInfo("The implicit flow does not issue refresh tokens");
            Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
        }

        private class ChangeScope : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public string? Scope { get; set; }
            public bool AddOfflineAccess { get; set; }
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
                this.Scope = value["scope"];
                if (AddOfflineAccess) {
                    var scope = this.Scope;
                    if (scope != null && scope.Length > 0)
                        scope += " ";

                    value["scope"] = scope + "offline_access";
                }
                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}
