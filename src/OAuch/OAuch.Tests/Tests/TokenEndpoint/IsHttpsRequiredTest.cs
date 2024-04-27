using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class IsHttpsRequiredTest : Test {
        public override string Title => "Is HTTPS required at the token endpoint";
        public override string Description => "This test checks whether the token endpoint enforces HTTPS connections.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsHttpsRequiredTestResult);
    }
    public class IsHttpsRequiredTestResult : TestResult {
        public IsHttpsRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsHttpsRequiredTestImplementation);
    }
    public class IsHttpsRequiredTestImplementation : TestImplementation {
        public IsHttpsRequiredTestImplementation(TestRunContext context, IsHttpsRequiredTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var httpContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with {
                    TokenUri = this.Context.SiteSettings.TokenUri?.ToHttp() // use regular http
                }
            };
            var provider = flows.CreateProviderWithStage<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(httpContext);
            if (provider == null) { // no provider that has the CreateTokenRequest stage
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that accesses the token endpoint");
                return;
            }
            // we have found a working provider

            if (!this.Context.SiteSettings.TokenUri!.IsSecure()) {
                // we have a working provider that uses an insecure token uri
                LogInfo("The token endpoint does not use HTTPS");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                var result = await provider.GetToken();
                if (result.AccessToken != null) {
                    LogInfo("The token endpoint can be used over an insecure HTTP connection");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                } else {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                }
            }
        }
    }
}
