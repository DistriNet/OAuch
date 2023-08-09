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
    public class HasSubjectClaimTest : Test {
        public override string Title => "Is JWT subject checked";
        public override string Description => "This test checks if the authorization server checks for the presence of the subject (sub) claim in the client authentication JWT.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasSubjectClaimTestResult);
    }
    public class HasSubjectClaimTestResult : TestResult {
        public HasSubjectClaimTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasSubjectClaimTestImplementation);
    }
    public class HasSubjectClaimTestImplementation : ModifyAuthenticationJwtTestImplementationBase {
        public HasSubjectClaimTestImplementation(TestRunContext context, HasSubjectClaimTestResult result, HasSupportedFlowsTestResult flows, SupportsJwtClientAuthenticationTestResult jwt) : base(context, result, flows, jwt) { }
        protected override void ModifyToken(JwtTokenBuilder builder) {
            LogInfo("Sending a client authentication token without a subject claim");
            builder.Claims.Remove("sub");
        }
    }
}
