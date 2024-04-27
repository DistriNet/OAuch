using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWT;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.Jwt {
    public class IsExpirationCheckedTest : Test {
        public override string Title => "Is JWT expiration checked";
        public override string Description => "This test checks if the authorization server checks accepts an expired client authentication JWT.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsExpirationCheckedTestResult);
    }
    public class IsExpirationCheckedTestResult : TestResult {
        public IsExpirationCheckedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsExpirationCheckedTestImplementation);
    }
    public class IsExpirationCheckedTestImplementation : ModifyAuthenticationJwtTestImplementationBase {
        public IsExpirationCheckedTestImplementation(TestRunContext context, IsExpirationCheckedTestResult result, HasSupportedFlowsTestResult flows, SupportsJwtClientAuthenticationTestResult jwt) : base(context, result, flows, jwt) { }
        protected override void ModifyToken(JwtTokenBuilder builder) {
            LogInfo("Sending a client authentication token that has expired");
            builder.Claims["exp"] = DateTimeOffset.Now.AddDays(-1).ToUnixTimeSeconds(); ;
        }
    }
}