using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class RedirectUriRequiredTest : Test {
        public override string Title => "Does the authorization server require the redirect uri";
        public override string Description => "This test checks whether the authorization server requires the presence of the redirect uri parameter.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RedirectUriRequiredTestResult);
    }
    public class RedirectUriRequiredTestResult : TestResult {
        public RedirectUriRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RedirectUriRequiredTestImplementation);
    }
    public class RedirectUriRequiredTestImplementation : TestImplementation {
        public RedirectUriRequiredTestImplementation(TestRunContext context, RedirectUriRequiredTestResult result, HasSupportedFlowsTestResult flows, OpenIdSupportedTestResult oidc) : base(context, result, flows, oidc) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (HasFailed<OpenIdSupportedTestResult>() || flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProviderWithStage<GetAuthParameters, bool, Dictionary<string, string?>>(Context, (fact, prov) => fact.HasIdentityTokens);
            if (provider == null) {
                LogInfo("Could not find a provider that uses the authorization server");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var redirectResultProcessor = new RemoveRedirectProcessor();
            provider.Pipeline.AddAfter<GetAuthParameters, bool, Dictionary<string, string?>>(redirectResultProcessor);

            var result = await provider.GetToken();
            if (result.IsValid && !string.IsNullOrEmpty(result.IdentityToken)) {
                LogInfo("The server returned a valid token despite the missing redirect uri parameter");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
        public class RemoveRedirectProcessor : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
                value.Remove("redirect_uri");
                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}