using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class IsJarSupportedTest : Test {
        public override string Title => "Is JAR supported at the authorization endpoint";
        public override string Description => "This test checks whether JWT-Secured Authorization Requests (JAR) are supported on the authorization endpoint.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsJarSupportedTestResult);
    }
    public class IsJarSupportedTestResult : TestResult {
        public IsJarSupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsJarSupportedTestImplementation);
    }
    public class IsJarSupportedTestImplementation : TestImplementation {
        public IsJarSupportedTestImplementation(TestRunContext context, IsJarSupportedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var context = Context with {
                SiteSettings = Context.SiteSettings with {
                    UseRequestParameter = true
                }
            };
            var prov = flows.CreateProviderWithStage<RewriteAsJarJwt, Dictionary<string, string?>, Dictionary<string, string?>>(context);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped; // no providers that intrinsically support the JAR standard
                return;
            }

            if (Context.SiteSettings.UseRequestParameter) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                // force JAR, see if it works
                var token = await prov.GetToken();
                if (token.AccessToken != null || token.IdentityToken != null) {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                } else {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                }
            }
        }
    }
}
