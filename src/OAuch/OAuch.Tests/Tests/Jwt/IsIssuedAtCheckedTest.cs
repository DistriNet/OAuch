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
    public class IsIssuedAtCheckedTest : Test {
        public override string Title => "Is JWT 'issued at' checked";
        public override string Description => "This test checks if the authorization server rejects a client authentication JWT with an 'issued at' timestamp long in the past.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsIssuedAtCheckedTestResult);
    }
    public class IsIssuedAtCheckedTestResult : TestResult {
        public IsIssuedAtCheckedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsIssuedAtCheckedTestImplementation);
    }
    public class IsIssuedAtCheckedTestImplementation : ModifyAuthenticationJwtTestImplementationBase {
        public IsIssuedAtCheckedTestImplementation(TestRunContext context, IsIssuedAtCheckedTestResult result, HasSupportedFlowsTestResult flows, SupportsJwtClientAuthenticationTestResult jwt) : base(context, result, flows, jwt) { }
        protected override void ModifyToken(JwtTokenBuilder builder) {
            LogInfo("Sending a client authentication token with a very early issued at time");
            builder.Claims["iat"] = DateTimeOffset.Now.AddYears(-1).ToUnixTimeSeconds();
        }
    }
}
