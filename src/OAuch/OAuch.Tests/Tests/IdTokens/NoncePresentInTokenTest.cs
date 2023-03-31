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
    public class NoncePresentInTokenTest : Test {
        public override string Title => "Is the nonce present in the ID token";
        public override string Description => "This test determines whether the identity token contains the 'nonce' claim and that it has the correct value.";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(NoncePresentInTokenTestResult);
    }
    public class NoncePresentInTokenTestResult : TestResult {
        public NoncePresentInTokenTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(NoncePresentInTokenTestImplementation);
    }
    public class NoncePresentInTokenTestImplementation : IdTokenInspectionTestImplementationBase {
        public NoncePresentInTokenTestImplementation(TestRunContext context, NoncePresentInTokenTestResult result, OpenIdSupportedTestResult oidc) : base(context, result, oidc) { }
        protected override void ProcessToken(string flowType, ValidToken fullTokenResult, JsonWebToken idToken) {
            var tokenNonce = idToken.Claims.Nonce;
            if (tokenNonce == null || tokenNonce != "oauch_openid_nonce") {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                if (tokenNonce == null)
                    LogInfo("The identity token did not contains a nonce claim");
                else
                    LogInfo("The identity token contains a nonce claim, but it has the wrong value");
            } else {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}
