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
    public class HasAuthorizedPartyTest : Test {
        public override string Title => "Is the token authorized party set correctly";
        public override string Description => "This test determines whether the identity token contains the correct value for the authorized party.";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasAuthorizedPartyTestResult);
    }
    public class HasAuthorizedPartyTestResult : TestResult {
        public HasAuthorizedPartyTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasAuthorizedPartyTestImplementation);
    }
    public class HasAuthorizedPartyTestImplementation : IdTokenInspectionTestImplementationBase {
        public HasAuthorizedPartyTestImplementation(TestRunContext context, HasAuthorizedPartyTestResult result, OpenIdSupportedTestResult oidc) : base(context, result, oidc) { }
        protected override void ProcessToken(string flowType, ValidToken fullTokenResult, JsonWebToken idToken) {
            var azp = idToken.Claims.AuthorizedParty;
            if (string.IsNullOrEmpty(Context.SiteSettings.DefaultClient.ClientId) || azp == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }
            var client = Context.SiteSettings.GetClient(flowType);
            Result.Outcome = azp == client.ClientId ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
        }
    }
}
