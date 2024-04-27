using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;

namespace OAuch.Compliance.Tests.IdTokens {
    public class HasAzpForMultiAudienceTest : Test {
        public override string Title => "Is the 'azp' claim present for multiple audiences";
        public override string Description => "This test determines whether the authorized party claim in the identity token is present if multiple audiences are presented.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasAzpForMultiAudienceTestResult);
    }
    public class HasAzpForMultiAudienceTestResult : TestResult {
        public HasAzpForMultiAudienceTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasAzpForMultiAudienceTestImplementation);
    }
    public class HasAzpForMultiAudienceTestImplementation : IdTokenInspectionTestImplementationBase {
        public HasAzpForMultiAudienceTestImplementation(TestRunContext context, HasAzpForMultiAudienceTestResult result, OpenIdSupportedTestResult oidc) : base(context, result, oidc) { }
        protected override void ProcessToken(string flowType, ValidToken fullTokenResult, JsonWebToken idToken) {
            Result.Outcome = TestOutcomes.Skipped;

            var audience = idToken.Claims.Audience;
            if (audience != null && audience.Count > 1 && string.IsNullOrWhiteSpace(idToken.Claims.AuthorizedParty)) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("No authorized party claim was present in the identity token, even though multiple audiences were presented.");
            }
        }
    }
}
