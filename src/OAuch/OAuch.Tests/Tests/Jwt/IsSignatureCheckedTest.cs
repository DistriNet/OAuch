using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWT;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Jwt {
    public class IsSignatureCheckedTest : Test {
        public override string Title => "Is the JWT signature checked";
        public override string Description => "This test checks if the authorization server rejects JWTs with an invalid signature.";
        public override string? TestingStrategy => "";
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
                switch (original) {
                    case BytesTokenKey btk:
                        return TokenKey.FromBytes(new byte[20]);
                    case RsaTokenKey btk:
                        return TokenKey.FromRsa(RSA.Create());
                    case ECDsaTokenKey btk:
                        return TokenKey.FromECDsa(ECDsa.Create());
                    default:
                        return TokenKey.Empty;
                }
            }
        }
    }
}
