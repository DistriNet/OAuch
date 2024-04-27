using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;

namespace OAuch.Compliance.Tests.IdTokens {
    public class HasCorrectIssuerTest : Test {
        public override string Title => "Is the token issuer set";
        public override string Description => "This test determines whether the identity token contains the correct value in the issuer claim.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasCorrectIssuerTestResult);
    }
    public class HasCorrectIssuerTestResult : TestResult {
        public HasCorrectIssuerTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasCorrectIssuerTestImplementation);
    }
    public class HasCorrectIssuerTestImplementation : IdTokenInspectionTestImplementationBase {
        public HasCorrectIssuerTestImplementation(TestRunContext context, HasCorrectIssuerTestResult result, OpenIdSupportedTestResult oidc) : base(context, result, oidc) { }
        protected override void ProcessToken(string flowType, ValidToken fullTokenResult, JsonWebToken idToken) {
            var issuer = idToken.Claims.Issuer;
            if (issuer == null) {
                LogInfo("The token is missing the issuer (iss) claim");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else if (!string.Equals(Context.SiteSettings.OpenIdIssuer, issuer)) {
                LogInfo("The token's issuer is invalid", Context.SiteSettings.OpenIdIssuer, issuer);
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                Result.Outcome = string.IsNullOrWhiteSpace(Context.SiteSettings.OpenIdIssuer) ? TestOutcomes.Skipped : TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}
