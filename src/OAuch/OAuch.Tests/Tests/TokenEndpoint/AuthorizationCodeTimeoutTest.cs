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
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class AuthorizationCodeTimeoutTest : Test {
        public override string Title => "Do authorization codes have a short timeout";
        public override string Description => "This test checks if authorization codes time out after at most 10 minutes.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(AuthorizationCodeTimeoutTestResult);
    }
    public class AuthorizationCodeTimeoutTestResult : TestResult<AuthorizationCodeTimeoutInfo> {
        public AuthorizationCodeTimeoutTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(AuthorizationCodeTimeoutTestImplementation);
    }
    public class AuthorizationCodeTimeoutInfo : ITimeDelayedTest { 
        public string? AuthorizationCode { get; set; }
        public string? CodeVerifier { get; set; }
        public DateTime? ResumeWhen { get; set; }
    }
    public class AuthorizationCodeTimeoutTestImplementation : TestImplementation<AuthorizationCodeTimeoutInfo> {
        public AuthorizationCodeTimeoutTestImplementation(TestRunContext context, AuthorizationCodeTimeoutTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProvider(Context, (f, p) => f.HasAuthorizationCodes) as AuthorizationCodeTokenProvider;
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if (ExtraInfo.AuthorizationCode == null) {
                // we don't have an authorization code; let's get it
                var requestCodePipeline = ProviderPipeline.Start()
                    .Then(new CheckAuthorizationUri())
                    .Then(new CheckTokenUri())
                    .Then(new GetAuthParameters())
                    .Then(new AddScope())
                    .Then(new AddPKCEChallenge(provider.SiteSettings.PKCEDefault))
                    .Then(new AddResponseMode(provider.DefaultResponseMode))
                    .Then(new AddNonce())
                    .Then(new RewriteAsJwt())
                    .Then(new BuildAuthorizationUrl())
                    .Then(new SendAuthorizationRedirect())
                    .Then(new GetServerResponseFromCallback(provider.DefaultResponseMode))
                    .FinishAuthorizationResponse();

                var codeResult = new TokenResult();
                var success = await requestCodePipeline.Run(provider, codeResult);
                if (!success || codeResult.AuthorizationCode == null) {
                    Result.Outcome = TestOutcomes.Skipped;
                    LogInfo("Authorization code request failed.");
                    return;
                }
                ExtraInfo.AuthorizationCode = codeResult.AuthorizationCode;
                ExtraInfo.ResumeWhen = DateTime.Now.AddMinutes(12);
                ExtraInfo.CodeVerifier = provider.CodeVerifier;
                LogInfo($"Authorization code request succeeded. Please resume this test run after { ExtraInfo.ResumeWhen.Value:HH:mm:ss} to complete the test.");
            } else if (ExtraInfo.ResumeWhen.HasValue && DateTime.Now >= ExtraInfo.ResumeWhen.Value) {
                // code should have expired
                provider.CodeVerifier = ExtraInfo.CodeVerifier ?? "";
                var exchangeCodePipeline = ProviderPipeline.Start()
                    .Then(new GetClaimParameters())
                    .Then(new AddRedirectUri())
                    .Then(new AddPKCEVerifier(provider.SiteSettings.PKCEDefault))
                    .Then(new CreateTokenRequest())
                    .Then(new SendRequest(UriTypes.TokenUri))
                    .Then(new GetServerResponseFromHttpResponse())
                    .FinishTokenResponse();

                var tokenResult = new TokenResult();
                tokenResult.AuthorizationResponse = ServerResponse.FromAuthorizationCode(ExtraInfo.AuthorizationCode);
                var success = await exchangeCodePipeline.Run(provider, tokenResult);
                if (tokenResult.AccessToken != null) {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    LogInfo("The expired authorization code was successfully exchanged.");
                } else {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    LogInfo("The exchange of the authorization code was not allowed.");
                }

            } // else: do nothing and keep the Result.Outcome == null
        }
    }
}
