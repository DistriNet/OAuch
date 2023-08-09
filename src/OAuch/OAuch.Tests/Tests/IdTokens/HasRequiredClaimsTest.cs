using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Compliance.Tests.Shared;
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
    public class HasRequiredClaimsTest : Test {
        public override string Title => "Are all required required claims present";
        public override string Description => "This test determines whether the identity token contains all the required claims.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasRequiredClaimsTestResult);
    }
    public class HasRequiredClaimsTestResult : TestResult {
        public HasRequiredClaimsTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasRequiredClaimsTestImplementation);
    }
    public class HasRequiredClaimsTestImplementation : IdTokenInspectionTestImplementationBase {
        public HasRequiredClaimsTestImplementation(TestRunContext context, HasRequiredClaimsTestResult result, OpenIdSupportedTestResult oidc) : base(context, result, oidc) { }
        protected override void ProcessToken(string flowType, ValidToken fullTokenResult, JsonWebToken idToken) {
            Result.Outcome = TestOutcomes.SpecificationFullyImplemented;

            var keys = new string[] { "iss", "sub", "aud", "exp", "iat" };
            var names = new string[] { "issuer", "subject", "audience", "expiration time", "issued at" };
            for (int i = 0; i < keys.Length; i++) {
                if (!idToken.Claims.ContainsKey(keys[i])) {
                    LogInfo($"The { names[i] } claim ({ keys[i] }) is missing from the ID token");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                }
            }
        }
    }
}
