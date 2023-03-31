using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWT;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Jwt {
    public class HasAudienceClaimTest : Test {
        public override string Title => "Is JWT audience checked";
        public override string Description => "This test checks if the authorization server checks for the presence of the audience (aud) claim in the client authentication JWT.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasAudienceClaimTestResult);
    }
    public class HasAudienceClaimTestResult : TestResult {
        public HasAudienceClaimTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasAudienceClaimTestImplementation);
    }
    public class HasAudienceClaimTestImplementation : ModifyAuthenticationJwtTestImplementationBase {
        public HasAudienceClaimTestImplementation(TestRunContext context, HasAudienceClaimTestResult result, HasSupportedFlowsTestResult flows, SupportsJwtClientAuthenticationTestResult jwt) : base(context, result, flows, jwt) { }
        protected override void ModifyToken(JwtTokenBuilder builder) {
            LogInfo("Sending a client authentication token without an audience claim");
            builder.Claims.Remove("aud");
        }
    }
}
