using OAuch.Compliance.Tests.DocumentSupport;
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
    public class HasCorrectAudienceTest : Test {
        public override string Title => "Is the token audience set";
        public override string Description => "This test determines whether the audience claim in the identity token is correct.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasCorrectAudienceTestResult);
    }
    public class HasCorrectAudienceTestResult : TestResult {
        public HasCorrectAudienceTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasCorrectAudienceTestImplementation);
    }
    public class HasCorrectAudienceTestImplementation : IdTokenInspectionTestImplementationBase {
        public HasCorrectAudienceTestImplementation(TestRunContext context, HasCorrectAudienceTestResult result, OpenIdSupportedTestResult oidc) : base(context, result, oidc) { }
        protected override void ProcessToken(string flowType, ValidToken fullTokenResult, JsonWebToken idToken) {
            var client = Context.SiteSettings.GetClient(flowType);
            if (string.IsNullOrEmpty(client.ClientId)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }
            var audience = idToken.Claims.Audience;
            if (audience == null || audience.Count == 0) {
                LogInfo("The token is missing the audience (aud) claim");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else if (!audience.Contains(client.ClientId)) {
                LogInfo("The token's audience is invalid", client.ClientId, string.Join(',', audience));
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}
