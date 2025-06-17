using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ParEndpoint {
    public class IsHttpsRequiredTest : Test {
        public override string Title => "Is HTTPS required at the authorization PAR endpoint";
        public override string Description => "This test checks whether the authorization PAR endpoint enforces HTTPS connections.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsHttpsRequiredTestResult);
    }
    public class IsHttpsRequiredTestResult : TestResult {
        public IsHttpsRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsHttpsRequiredTestImplementation);
    }
    public class IsHttpsRequiredTestImplementation : TestImplementation {
        public IsHttpsRequiredTestImplementation(TestRunContext context, IsHttpsRequiredTestResult result, HasSupportedFlowsTestResult flows, IsParSupportedTestResult par) : base(context, result, flows, par) { }

        public async override Task Run() {
            if (HasFailed<IsParSupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            string par = Context.SiteSettings.ParUri;
            if (!par.IsSecure()) {
                LogInfo("The PAR endpoint does not use HTTPS.");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented; // no HTTPS PAR URI
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var httpContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with {
                    ParUri = par.ToHttp() // use regular http
                }
            };

            var provider = flows.CreateProviderWithStage<PushAuthorizationRequest, Dictionary<string, string?>, Dictionary<string, string?>>(httpContext);
            if (provider == null) { // no provider that has the PushAuthorizationRequest stage
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that accesses the PAR endpoint");
                return;
            }
            // we have found a working provider
            var result = await provider.GetToken();
            if (result.AccessToken != null || result.IdentityToken != null) {
                LogInfo("The authorization PAR endpoint can be used over an insecure HTTP connection");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}
