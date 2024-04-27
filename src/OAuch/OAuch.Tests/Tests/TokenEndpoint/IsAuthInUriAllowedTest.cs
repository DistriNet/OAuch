using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class IsAuthInUriAllowedTest : Test {
        public override string Title => "Are authentication parameters in the URI allowed";
        public override string Description => "This test checks if the authentication parameters can be passed via the URI (instead of the request body or the Authorization header).";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(IsAuthInUriAllowedTestResult);
    }
    public class IsAuthInUriAllowedTestResult : TestResult {
        public IsAuthInUriAllowedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsAuthInUriAllowedTestImplementation);
    }
    public class IsAuthInUriAllowedTestImplementation : TestImplementation {
        public IsAuthInUriAllowedTestImplementation(TestRunContext context, IsAuthInUriAllowedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var basicContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with {
                    ClientAuthenticationMechanism = ClientAuthenticationMechanisms.ClientSecretBasic // force basic authentication, so that we know where to remove the credentials
                }
            };
            var provider = flows.CreateProviderWithStage<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(basicContext,
                (f, p) => !string.IsNullOrEmpty(p.SiteSettings.DefaultClient.ClientSecret)); // we need providers with a secret
            if (provider == null) { // no provider that has the CreateTokenRequest stage and has a password
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that requires client authentication via a client secret");
                return; // no flows that use client authentication
            }
            // we have found a working provider with a password

            provider.Pipeline.AddAfter<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(new UriAuthentication());

            var result = await provider.GetToken();
            if (result.AccessToken != null) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
        public class UriAuthentication : Processor<HttpRequest, HttpRequest> {
            public override Task<HttpRequest?> Process(HttpRequest value, IProvider tokenProvider, TokenResult tokenResult) {
                value.Headers.Remove(HttpRequestHeaders.Authorization);
                value.Url = value.Url.AddQueryParameter("client_id", tokenProvider.SiteSettings.DefaultClient.ClientId).AddQueryParameter("client_secret", tokenProvider.SiteSettings.DefaultClient.ClientSecret);
                return Task.FromResult<HttpRequest?>(value);
            }
        }
    }
}