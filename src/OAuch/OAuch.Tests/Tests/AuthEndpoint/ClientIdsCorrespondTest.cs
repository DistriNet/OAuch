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
    public class ClientIdsCorrespondTest : Test {
        public override string Title => "Check mismatched client_id parameters";
        public override string Description => "This test checks that the authenticated client id corresponds to the client id in the request object.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(ClientIdsCorrespondTestResult);
    }
    public class ClientIdsCorrespondTestResult : TestResult {
        public ClientIdsCorrespondTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(ClientIdsCorrespondTestImplementation);
    }
    public class ClientIdsCorrespondTestImplementation : TestImplementation {
        public ClientIdsCorrespondTestImplementation(TestRunContext context, ClientIdsCorrespondTestResult result, HasSupportedFlowsTestResult flows, IsJarSupportedTestResult jar) : base(context, result, flows, jar) { }

        public async override Task Run() {
            if (HasFailed<IsJarSupportedTestResult>()) { // no JAR support
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

            var prov = flows.CreateProviderWithStage<RewriteAsJarJwt, Dictionary<string, string?>, Dictionary<string, string?>>(Context);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped; // no providers that support the PAR standard (weird, should not happen here, because we know PAR is supported)
                return;
            }
            prov.Pipeline.Replace<RewriteAsJarJwt, Dictionary<string, string?>, Dictionary<string, string?>>(new ChangeClientInRequest());

            var result = await prov.GetToken();
            if (result.AccessToken == null && result.IdentityToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The server detected the invalid client id.");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server issued a valid token to the wrong client.");
            }
        }
    }

    public class ChangeClientInRequest : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
        public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider provider, TokenResult tokenResult) {
            value["client_id"] = provider.Context.SiteSettings.AlternativeClient.ClientId;
            OAuthHelper.RewriteAsJarJwt(provider.SiteSettings, value);
            value["client_id"] = provider.Context.SiteSettings.DefaultClient.ClientId;
            return Task.FromResult(value);
        }
    }
}
