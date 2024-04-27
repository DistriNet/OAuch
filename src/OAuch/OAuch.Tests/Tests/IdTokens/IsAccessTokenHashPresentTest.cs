using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.IdTokens {
    public class IsAccessTokenHashPresentTest : Test {
        public override string Title => "Is the at_hash claim present";
        public override string Description => "This test determines whether the value of the at_hash claim is present in the implicit flow.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsAccessTokenHashPresentTestResult);
    }
    public class IsAccessTokenHashPresentTestResult : TestResult {
        public IsAccessTokenHashPresentTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsAccessTokenHashPresentTestImplementation);
    }
    public class IsAccessTokenHashPresentTestImplementation : TestImplementation {
        public IsAccessTokenHashPresentTestImplementation(TestRunContext context, IsAccessTokenHashPresentTestResult result, OpenIdSupportedTestResult oidc)
            : base(context, result, oidc) { }

        public override Task Run() {
            if (HasFailed<OpenIdSupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            int count = 0;
            var idTokens = TokenHelper.GetAllTokenResults(Context).Where(vt => vt.FlowType == OAuthHelper.IDTOKEN_TOKEN_FLOW_TYPE);
            foreach (var idToken in idTokens) {
                var jwtIdToken = JsonWebToken.CreateFromString(idToken?.IdentityToken, Context.Log);
                string? hashInIdToken = jwtIdToken?.Claims.AccessTokenHash;
                if (jwtIdToken != null && hashInIdToken == null) {
                    LogInfo("An identity token was issued over the implicit flow, but did not contain an 'at_hash' claim");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    break;
                }
                count++;
            }
            if (count == 0) {
                LogInfo("No identity tokens were issued over the implicit flow with 'id_token token' response type");
                Result.Outcome = TestOutcomes.Skipped;
            }
            return Task.CompletedTask;
        }
    }
}