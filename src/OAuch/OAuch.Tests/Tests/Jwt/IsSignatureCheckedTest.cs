using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWT;
using OAuch.Shared;
using System;
using System.Security.Cryptography;

namespace OAuch.Compliance.Tests.Jwt {
    public class IsSignatureCheckedTest : Test {
        public override string Title => "Is the JWT signature checked";
        public override string Description => "This test checks if the authorization server rejects JWTs with an invalid signature.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsSignatureCheckedTestResult);
    }
    public class IsSignatureCheckedTestResult : TestResult {
        public IsSignatureCheckedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsSignatureCheckedTestImplementation);
    }
    public class IsSignatureCheckedTestImplementation : ModifyAuthenticationJwtTestImplementationBase {
        public IsSignatureCheckedTestImplementation(TestRunContext context, IsSignatureCheckedTestResult result, HasSupportedFlowsTestResult flows, SupportsJwtClientAuthenticationTestResult jwt) : base(context, result, flows, jwt) { }
        protected override TokenKey Key {
            get {
                var original = base.Key;
                // return a random key
                return original switch {
                    BytesTokenKey => TokenKey.FromBytes(new byte[20]),
                    RsaTokenKey => TokenKey.FromRsa(RSA.Create()),
                    ECDsaTokenKey => TokenKey.FromECDsa(ECDsa.Create()),
                    _ => TokenKey.Empty,
                };
            }
        }
    }
}
