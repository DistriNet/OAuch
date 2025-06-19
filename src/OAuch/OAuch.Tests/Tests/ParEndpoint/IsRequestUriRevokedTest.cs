using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
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
    public class IsRequestUriRevokedTest : Test {
        public override string Title => "Is the request_uri revoked";
        public override string Description => "This test checks whether the generated request_uri is revoked after use.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsRequestUriRevokedTestResult);
    }
    public class IsRequestUriRevokedTestResult : TestResult {
        public IsRequestUriRevokedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsRequestUriRevokedTestImplementation);
    }
    public class IsRequestUriRevokedTestImplementation : TestImplementation {
        public IsRequestUriRevokedTestImplementation(TestRunContext context, IsRequestUriRevokedTestResult result, HasSupportedFlowsTestResult flows, IsParSupportedTestResult par) : base(context, result, flows, par) { }

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

            var prov = flows.CreateProviderWithStage<PushAuthorizationRequest, Dictionary<string, string?>, Dictionary<string, string?>>(Context);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped; // no providers that support the PAR standard (weird, should not happen here, because we know PAR is supported)
                return;
            }

            var firstToken = await prov.GetToken();
            if (firstToken.AccessToken == null && firstToken.IdentityToken == null || firstToken.ParRequestUri == null) {
                Result.Outcome = TestOutcomes.Skipped; // weird
                return;
            }

            await Task.Delay(3000);

            // try to get a second token with the same request uri
            prov.Pipeline.Replace<PushAuthorizationRequest, Dictionary<string, string?>, Dictionary<string, string?>>(new OverrideRequestUri(firstToken.ParRequestUri));

            var token = await prov.GetToken();
            if (token.AccessToken == null && token.IdentityToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The request_uri was revoked after use");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The request_uri was still valid after use");
            }
        }
        class OverrideRequestUri : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public OverrideRequestUri(string uri) {
                this.Uri = uri;
            }
            public string Uri { get; }
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider provider, TokenResult tokenResult) {
                value.Clear();
                value["client_id"] = provider.SiteSettings.DefaultClient.ClientId;
                value["request_uri"] = this.Uri;
                return Task.FromResult(value);
            }
        }
    }
}
