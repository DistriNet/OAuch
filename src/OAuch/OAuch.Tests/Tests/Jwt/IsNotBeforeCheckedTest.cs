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
    public class IsNotBeforeCheckedTest : Test {
        public override string Title => "Is JWT 'not before' checked";
        public override string Description => "This test checks if the authorization server rejects a client authentication JWT if it is used before its 'not before' time.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsNotBeforeCheckedTestResult);
    }
    public class IsNotBeforeCheckedTestResult : TestResult {
        public IsNotBeforeCheckedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsNotBeforeCheckedTestImplementation);
    }
    public class IsNotBeforeCheckedTestImplementation : ModifyAuthenticationJwtTestImplementationBase {
        public IsNotBeforeCheckedTestImplementation(TestRunContext context, IsNotBeforeCheckedTestResult result, HasSupportedFlowsTestResult flows, SupportsJwtClientAuthenticationTestResult jwt) : base(context, result, flows, jwt) { }
        protected override void ModifyToken(JwtTokenBuilder builder) {
            LogInfo("Sending a client authentication token with a future 'not before' time");
            builder.Claims["nbf"] = DateTimeOffset.Now.AddDays(1).ToUnixTimeSeconds();
            builder.Claims["exp"] = DateTimeOffset.Now.AddDays(2).ToUnixTimeSeconds();
        }
    }
}
