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

namespace OAuch.Compliance.Tests.Tokens {
    public class TokenTimeoutTest : Test {
        public override string Title => "Do access tokens have a short timeout";
        public override string Description => "This test checks if access tokens time out after at most one hour.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(TokenTimeoutTestResult);
    }
    public class TokenTimeoutTestResult : TestResult<TokenTimeoutInfo> {
        public TokenTimeoutTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(TokenTimeoutTestImplementation);
    }
    public class TokenTimeoutInfo : ITimeDelayedTest {
        public string? AccessToken { get; set; }
        public DateTime? ResumeWhen { get; set; }
    }
    public class TokenTimeoutTestImplementation : TestImplementation<TokenTimeoutInfo> {
        public TokenTimeoutTestImplementation(TestRunContext context, TokenTimeoutTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if (ExtraInfo.AccessToken == null) {
                var provider = flows.CreateAccessTokenProvider(Context);
                if (provider == null) {
                    Result.Outcome = TestOutcomes.Skipped;
                    return;
                }

                var tokenResult = await provider.GetToken();
                var expiresIn = tokenResult.ExpiresIn;
                ExtraInfo.AccessToken = tokenResult.AccessToken;
                ExtraInfo.ResumeWhen = DateTime.Now.AddSeconds(3600); // an expiry time of one hour is the default
                if (expiresIn != null) {
                    LogInfo($"The token has a reported lifetime of { expiresIn.Value } seconds.");
                    if (expiresIn.Value > 3600) {
                        LogInfo("The access token lives longer than one hour.");
                        Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                        return;
                    }
                    ExtraInfo.ResumeWhen = DateTime.Now.AddSeconds(expiresIn.Value); // if the server reports an expiry shorter than one hour, use that
                }
                LogInfo($"Access token request succeeded. Please resume this test run after { ExtraInfo.ResumeWhen.Value:HH:mm:ss} to complete the test.");
            } else if (DateTime.Now > ExtraInfo.ResumeWhen!.Value) {
                var request = new ApiRequest(Context);
                var response = await request.Send(new TokenResult { AuthorizationResponse = ServerResponse.FromAccessToken(ExtraInfo.AccessToken) });
                if (response.StatusCode.IsOk()) {
                    // the call to the API worked; the token has not timed out
                    LogInfo("The access token can still be used after it should have expired.");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                } else {
                    LogInfo("The access token has expired.");
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                }
            } // else: do nothing and keep the Outcome == null
        }
    }
}
