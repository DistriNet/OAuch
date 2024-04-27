using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class IsCodeBoundToClientTest : Test {
        public override string Title => "Is the authorization code bound to the client";
        public override string Description => "This test checks if the authorization code is bound to the client.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsCodeBoundToClientTestResult);
    }
    public class IsCodeBoundToClientTestResult : TestResult {
        public IsCodeBoundToClientTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsCodeBoundToClientTestImplementation);
    }
    public class IsCodeBoundToClientTestImplementation : TestImplementation {
        public IsCodeBoundToClientTestImplementation(TestRunContext context, IsCodeBoundToClientTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            if (string.IsNullOrEmpty(Context.SiteSettings.AlternativeClient.ClientId)) {
                LogInfo("This test requires that an alternative client id is set up");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }
            if (Context.SiteSettings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.PrivateKeyJwt) {
                LogInfo("This test requires that a client secret is used");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProviderWithStage<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(this.Context,
                (f, p) => f.HasAuthorizationCodes);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow with authorization codes");
                return;
            }

            provider.Pipeline.Replace<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(new CreateAlternativeTokenRequest());
            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The authorization code is bound to the client id");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The authorization code can be exchanged with the wrong client id");
            }
        }

        private class CreateAlternativeTokenRequest : Processor<Dictionary<string, string?>, HttpRequest> {
            public override Task<HttpRequest?> Process(Dictionary<string, string?> parameters, IProvider tokenProvider, TokenResult tokenResult) {
                var tokenUri = tokenProvider.SiteSettings.TokenUri!;
                var request = HttpRequest.CreatePost(tokenUri);
                request.Headers[HttpRequestHeaders.ContentType] = "application/x-www-form-urlencoded";
                if (tokenUri.IsSecure())
                    request.ClientCertificates = []; // do not use mTLS authentication
                OAuthHelper.AddClientAuthentication(tokenProvider.SiteSettings, request.Headers, parameters, tokenProvider.SiteSettings.AlternativeClient);
                request.Content = EncodingHelper.FormUrlEncode(parameters);
                return Task.FromResult<HttpRequest?>(request);
            }
        }
    }
}
