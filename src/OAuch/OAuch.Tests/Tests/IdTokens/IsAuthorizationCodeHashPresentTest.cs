using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.IdTokens {
    public class IsAuthorizationCodeHashPresentTest : Test {
        public override string Title => "Is the c_hash claim present";
        public override string Description => "This test determines whether the value of the c_hash claim is present if the ID Token is issued from the Authorization Endpoint.";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsAuthorizationCodeHashPresentTestResult);
    }
    public class IsAuthorizationCodeHashPresentTestResult : TestResult {
        public IsAuthorizationCodeHashPresentTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsAuthorizationCodeHashPresentTestImplementation);
    }
    public class IsAuthorizationCodeHashPresentTestImplementation : TestImplementation {
        public IsAuthorizationCodeHashPresentTestImplementation(TestRunContext context, IsAuthorizationCodeHashPresentTestResult result, OpenIdSupportedTestResult oidc)
            : base(context, result, oidc) { }

        public override Task Run() {
            if (HasFailed<OpenIdSupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            int count = 0;
            var idTokens = TokenHelper.GetAllTokenResults(Context).Where(vt => vt.FlowType == OAuthHelper.CODE_IDTOKEN_FLOW_TYPE || vt.FlowType == OAuthHelper.CODE_IDTOKEN_TOKEN_FLOW_TYPE);
            foreach (var idToken in idTokens) {
                var jwtIdToken = JsonWebToken.CreateFromString(idToken?.IdentityToken, Context.Log);
                string? hashInIdToken = jwtIdToken?.Claims.CodeHash;
                if (jwtIdToken != null && hashInIdToken == null) {
                    LogInfo("An identity token was issued from the authorization endpoint, but did not contain a 'c_hash' claim");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    break;
                }
                count++;
            }
            if (count == 0) {
                LogInfo("No identity tokens were issued over the authorization endpoint with 'code id_token token' or 'code id_token' response type");
                Result.Outcome = TestOutcomes.Skipped;
            }
            return Task.CompletedTask;
        }
    }
}
