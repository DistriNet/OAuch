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

namespace OAuch.Compliance.Tests.ParEndpoint {
    public class IsParAuthenticationRequiredTest : Test {
        public override string Title => "Is PAR authentication required at the authorization endpoint";
        public override string Description => "This test checks whether Pushed Authorization Requests (PAR) are required to authenticate on the authorization endpoint.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsParAuthenticationRequiredTestResult);
    }
    public class IsParAuthenticationRequiredTestResult : TestResult {
        public IsParAuthenticationRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsParAuthenticationRequiredTestImplementation);
    }
    public class IsParAuthenticationRequiredTestImplementation : TestImplementation {
        public IsParAuthenticationRequiredTestImplementation(TestRunContext context, IsParAuthenticationRequiredTestResult result, HasSupportedFlowsTestResult flows, IsParSupportedTestResult par) : base(context, result, flows, par) { }

        public async override Task Run() {
            if (HasFailed<IsParSupportedTestResult>()) { // no PAR support
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var context = Context with {
                SiteSettings = Context.SiteSettings with {
                    DefaultClient = Context.SiteSettings.DefaultClient with {
                        ClientSecret = null
                    },
                    ClientAuthenticationMechanism = ClientAuthenticationMechanisms.ClientSecretBasic
                }
            };
            var prov = flows.CreateProviderWithStage<PushAuthorizationRequest, Dictionary<string, string?>, Dictionary<string, string?>>(context);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped; // no providers that support the PAR standard (weird, should not happen here, because we know PAR is supported)
                return;
            }

            var result = await prov.GetToken();
            if (result.AccessToken == null && result.IdentityToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The request failed without PAR authentication");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The request succeeded without PAR authentication");
            }
        }
    }
}
