using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.ParEndpoint;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class IsJarRequiredTest : Test {
        public override string Title => "Is JAR required at the authorization endpoint";
        public override string Description => "This test checks whether JWT-Secured Authorization Requests (JAR) are required on the authorization endpoint.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsJarRequiredTestResult);
    }
    public class IsJarRequiredTestResult : TestResult {
        public IsJarRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsJarRequiredTestImplementation);
    }
    public class IsJarRequiredTestImplementation : TestImplementation {
        public IsJarRequiredTestImplementation(TestRunContext context, IsJarRequiredTestResult result, HasSupportedFlowsTestResult flows, IsJarSupportedTestResult jar) : base(context, result, flows, jar) { }

        public async override Task Run() {
            if (HasFailed<IsJarSupportedTestResult>()) { // no JAR support
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var httpContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with {
                    UseRequestParameter = false // do not use JAR
                }
            };
            var prov = flows.CreateProviderWithStage<RewriteAsJwt, Dictionary<string, string?>, Dictionary<string, string?>>(httpContext);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped; // no providers that support the JAR standard, weird
                return;
            }

            if (!Context.SiteSettings.UseRequestParameter) {
                // it isn't used by default (and that works)
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                // if it's used by default, try to disable it
                var result = await prov.GetToken();
                if (result.AccessToken == null && result.IdentityToken == null) {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    LogInfo("The request failed without JAR");
                } else {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    LogInfo("The request succeeded without JAR");
                }
            }
        }
    }
}