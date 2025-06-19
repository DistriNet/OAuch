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
    public class IsClientBoundToUriTest : Test {
        public override string Title => "Is the client bound to the request_uri";
        public override string Description => "This test checks whether the request_uri is bound to the client that posted the authorization request.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsClientBoundToUriTestResult);
    }
    public class IsClientBoundToUriTestResult : TestResult {
        public IsClientBoundToUriTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsClientBoundToUriTestImplementation);
    }
    public class IsClientBoundToUriTestImplementation : TestImplementation {
        public IsClientBoundToUriTestImplementation(TestRunContext context, IsClientBoundToUriTestResult result, HasSupportedFlowsTestResult flows, IsParSupportedTestResult par) : base(context, result, flows, par) { }

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
            prov.Pipeline.AddAfter<PushAuthorizationRequest, Dictionary<string, string?>, Dictionary<string, string?>>(new ChangeClientToAlternative());

            var result = await prov.GetToken();
            if (result.AccessToken == null && result.IdentityToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The server detected the invalid client id.");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server issued a valid token to the wrong client.");
            }
        }
        class ChangeClientToAlternative : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider provider, TokenResult tokenResult) {
                value["client_id"] = provider.Context.SiteSettings.AlternativeClient.ClientId;
                value["client_secret"] = provider.Context.SiteSettings.AlternativeClient.ClientSecret;
                return Task.FromResult(value);
            }
        }
    }
}
