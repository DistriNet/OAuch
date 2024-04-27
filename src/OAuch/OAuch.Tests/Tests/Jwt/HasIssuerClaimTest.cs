using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWT;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.Jwt {
    public class HasIssuerClaimTest : Test {
        public override string Title => "Is JWT issuer checked";
        public override string Description => "This test checks if the authorization server checks for the presence of the issuer (iss) claim in the client authentication JWT.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasIssuerClaimTestResult);
    }
    public class HasIssuerClaimTestResult : TestResult {
        public HasIssuerClaimTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasIssuerClaimTestImplementation);
    }
    public class HasIssuerClaimTestImplementation : ModifyAuthenticationJwtTestImplementationBase {
        public HasIssuerClaimTestImplementation(TestRunContext context, HasIssuerClaimTestResult result, HasSupportedFlowsTestResult flows, SupportsJwtClientAuthenticationTestResult jwt) : base(context, result, flows, jwt) { }
        protected override void ModifyToken(JwtTokenBuilder builder) {
            LogInfo("Sending a client authentication token without an issuer claim");
            builder.Claims.Remove("iss");
        }
    }
}
