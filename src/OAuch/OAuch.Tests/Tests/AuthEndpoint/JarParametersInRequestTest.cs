using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.ParEndpoint;
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
    public class JarParametersInRequestTest : Test {
        public override string Title => "Server requires all parameters to be in request object";
        public override string Description => "This test checks whether the server requires all parameters related to the authorization to be included in the request object.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(JarParametersInRequestTestResult);
    }
    public class JarParametersInRequestTestResult : TestResult {
        public JarParametersInRequestTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(JarParametersInRequestTestImplementation);
    }
    public class JarParametersInRequestTestImplementation : TestImplementation {
        public JarParametersInRequestTestImplementation(TestRunContext context, JarParametersInRequestTestResult result, HasSupportedFlowsTestResult flows, IsParSupportedTestResult par) : base(context, result, flows, par) { }

        public async override Task Run() {
            if (HasFailed<IsParSupportedTestResult>()) { // no PAR support
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if (Context.SiteSettings.AlternativeClient == null) {
                Result.Outcome = TestOutcomes.Skipped; // no alternative client to test with
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var prov = flows.CreateProviderWithStage<PushAuthorizationRequest, Dictionary<string, string?>, Dictionary<string, string?>>(Context);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped; // no providers that support the PAR standard (weird, should not happen here, because we know PAR is supported)
                return;
            }
            prov.Pipeline.Replace<RewriteAsJwt, Dictionary<string, string?>, Dictionary<string, string?>>(new MoveResponseType());

            var result = await prov.GetToken();
            if (result.AccessToken == null && result.IdentityToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The server detected the missing response_type from the request object.");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server did not detect the missing response_type from the request object.");
            }
        }
    }

    public class MoveResponseType : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
        public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider provider, TokenResult tokenResult) {
            var responseType = value["response_type"];
            value.Remove("response_type");
            OAuthHelper.RewriteAsJwt(provider.SiteSettings, value);
            value["response_type"] = responseType;
            return Task.FromResult(value);
        }
    }
}
