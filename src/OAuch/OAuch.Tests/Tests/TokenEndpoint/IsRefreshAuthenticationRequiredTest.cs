using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class IsRefreshAuthenticationRequiredTest : Test {
        public override string Title => "Is refresh authentication required";
        public override string Description => "This test checks if the token endpoint requires client authentication when refreshing a token.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsRefreshAuthenticationRequiredTestResult);
    }
    public class IsRefreshAuthenticationRequiredTestResult : TestResult {
        public IsRefreshAuthenticationRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsRefreshAuthenticationRequiredTestImplementation);
    }
    public class IsRefreshAuthenticationRequiredTestImplementation : TestImplementation {
        public IsRefreshAuthenticationRequiredTestImplementation(TestRunContext context, IsRefreshAuthenticationRequiredTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProvider(Context, (f, p) => p.Context.SiteSettings.IsConfidentialClient && f.HasRefreshTokens);
            if (provider == null) { // no confidential provider with refresh tokens found
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that requires client authentication and returns refresh tokens");
                return; // no flows that use client authentication
            }

            var result = await provider.GetToken();
            if (result.RefreshToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Provider did not return refresh token");
                return; // should not happen
            }

            var postSettings = this.Context.SiteSettings with
            {
                ClientAuthenticationMechanism = ClientAuthenticationMechanisms.ClientSecretPost, // force post authentication
                Certificates = new X509CertificateCollection()
            };
            var refreshProvider = provider.CreateRefreshProvider(postSettings);
            var processor = new NoAuthentication();
            refreshProvider.Pipeline.AddAfter<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(processor);

            var refreshedResult = await refreshProvider.RefreshToken(result.RefreshToken);
            if (refreshedResult.AccessToken == null) {
                processor.RemoveClientId = true;
                refreshedResult = await refreshProvider.RefreshToken(result.RefreshToken);
                if (refreshedResult.AccessToken == null) {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                } else {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    LogInfo("Valid token received without client secret");
                }
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("Valid token received without client authentication");
            }
        }
        public class NoAuthentication : Processor<HttpRequest, HttpRequest> {
            public bool RemoveClientId { get; set; }
            public override Task<HttpRequest?> Process(HttpRequest value, IProvider tokenProvider, TokenResult tokenResult) {
                var dictionary = EncodingHelper.EncodedFormToDictionary(Encoding.UTF8.GetString(value.Content));
                dictionary.Remove("client_secret");
                if (RemoveClientId)
                    dictionary.Remove("client_id");
                value.Content = EncodingHelper.FormUrlEncode(dictionary!);
                return Task.FromResult<HttpRequest?>(value);
            }
        }

    }
}
