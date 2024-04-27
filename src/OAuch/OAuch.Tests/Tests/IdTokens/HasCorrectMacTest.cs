using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Text;

namespace OAuch.Compliance.Tests.IdTokens {
    public class HasCorrectMacTest : Test {
        public override string Title => "Is the token mac correct";
        public override string Description => "This test determines whether the mac signature of the identity token is correct.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasCorrectMacTestResult);
    }
    public class HasCorrectMacTestResult : TestResult {
        public HasCorrectMacTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasCorrectMacTestImplementation);
    }
    public class HasCorrectMacTestImplementation : IdTokenInspectionTestImplementationBase {
        public HasCorrectMacTestImplementation(TestRunContext context, HasCorrectMacTestResult result, OpenIdSupportedTestResult oidc) : base(context, result, oidc) { }
        protected override void ProcessToken(string flowType, ValidToken fullTokenResult, JsonWebToken idToken) {
            var alg = idToken.Header.Algorithm;
            var client = Context.SiteSettings.GetClient(flowType);
            if (alg == null || alg == JwtAlgorithm.None || alg.IsAsymmetric || string.IsNullOrEmpty(client.ClientSecret)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var key = Encoding.UTF8.GetBytes(client.ClientSecret);
            if (idToken.Verify(TokenKey.FromBytes(key))) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The signature of the identity token is valid");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The signature of the identity token is invalid");
            }
        }
    }
}
