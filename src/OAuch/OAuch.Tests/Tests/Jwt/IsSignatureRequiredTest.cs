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
    public class IsSignatureRequiredTest : Test {
        public override string Title => "Is a JWT signature required";
        public override string Description => "This test checks if the authorization server rejects unsigned JWTs.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsSignatureRequiredTestResult);
    }
    public class IsSignatureRequiredTestResult : TestResult {
        public IsSignatureRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsSignatureRequiredTestImplementation);
    }
    public class IsSignatureRequiredTestImplementation : ModifyAuthenticationJwtTestImplementationBase {
        public IsSignatureRequiredTestImplementation(TestRunContext context, IsSignatureRequiredTestResult result, HasSupportedFlowsTestResult flows, SupportsJwtClientAuthenticationTestResult jwt) : base(context, result, flows, jwt) { }
        protected override string BuildToken(JwtTokenBuilder builder) {
            return builder.Build(JwtAlgorithm.None, TokenKey.Empty);
        }
    }
}
