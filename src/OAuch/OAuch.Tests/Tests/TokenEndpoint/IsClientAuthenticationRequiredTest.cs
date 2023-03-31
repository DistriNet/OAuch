using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
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
    public class IsClientAuthenticationRequiredTest : Test {
        public override string Title => "Is client authentication required";
        public override string Description => "This test checks if the token endpoint requires client authentication when requesting a token.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsClientAuthenticationRequiredTestResult);
    }
    public class IsClientAuthenticationRequiredTestResult : TestResult {
        public IsClientAuthenticationRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsClientAuthenticationRequiredTestImplementation);
    }
    public class IsClientAuthenticationRequiredTestImplementation : TestImplementation {
        public IsClientAuthenticationRequiredTestImplementation(TestRunContext context, IsClientAuthenticationRequiredTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var basicContext = this.Context with
            {
                SiteSettings = this.Context.SiteSettings with
                {
                    ClientAuthenticationMechanism = ClientAuthenticationMechanisms.ClientSecretPost, // force post authentication
                    Certificates = new X509CertificateCollection(),
                    PKCEDefault = Context.MostSecureSupportedPKCEType()
                }
            };
            var provider = flows.CreateProviderWithStage<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(basicContext,
                (f, p) => p.Context.SiteSettings.IsConfidentialClient);
            if (provider == null) { // no confidential provider found
                // check if a flow that supports client authentication is working (without client authentication)
                string[] aflows = new string[] { OAuthHelper.CODE_FLOW_TYPE, OAuthHelper.CODE_IDTOKEN_FLOW_TYPE, OAuthHelper.CODE_IDTOKEN_TOKEN_FLOW_TYPE, OAuthHelper.CODE_TOKEN_FLOW_TYPE, OAuthHelper.DEVICE_FLOW_TYPE, OAuthHelper.CLIENT_CREDENTIALS_FLOW_TYPE, OAuthHelper.PASSWORD_FLOW_TYPE };
                if (aflows.Any(f => flows.HasFlow(f))) {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    LogInfo("The token server does not require a password");
                } else { // no flows that use client authentication
                    Result.Outcome = TestOutcomes.Skipped;
                    LogInfo("Could not find a working flow that requires a client authentication password");
                }
                return;
            }

            var processor = new NoAuthentication();
            provider.Pipeline.AddAfter<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(processor);

            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                processor.RemoveClientId = true;
                result = await provider.GetToken();
            }

            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
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
