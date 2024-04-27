using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWK;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;

namespace OAuch.Compliance.Tests.IdTokens {
    public class SigningKeySecureTest : Test {
        public override string Title => "Is the signing key secure";
        public override string Description => "This test determines whether the (asymmetric) signing key of the ID tokens is secure. The key must be at least 2048 bits for RSA or 160 bits for elliptic curve algorithms.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(SigningKeySecureTestResult);
    }
    public class SigningKeySecureTestResult : TestResult {
        public SigningKeySecureTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(SigningKeySecureTestImplementation);
    }
    public class SigningKeySecureTestImplementation : IdTokenInspectionTestImplementationBase {
        public SigningKeySecureTestImplementation(TestRunContext context, SigningKeySecureTestResult result, OpenIdSupportedTestResult oidc, CanSignatureBeVerifiedTestResult canVerify) : base(context, result, oidc) {
            this.AddDependency(canVerify);
        }
        protected override void ProcessToken(string flowType, ValidToken fullTokenResult, JsonWebToken idToken) {
            Result.Outcome = TestOutcomes.Skipped;

            var client = Context.SiteSettings.GetClient(flowType);
            if (idToken.Header.Algorithm?.IsAsymmetric == false) {
                return; // AS uses symmetric key to sign ID tokens
            }

            var keyset = Context.State.Find<JwkSet>(StateKeys.JsonWebKeySet);
            if (keyset == null)
                return;

            var key = idToken.Header.GetAsymmetricSigningKey(keyset, LogInfo);
            if (key == null)
                return;

            bool ok;
            switch (key.TokenKey) {
                case RsaTokenKey rsa:
                    ok = rsa.Value.KeySize >= 2048;
                    LogInfo($"The identity token is signed with an RSA key size of {rsa.Value.KeySize} bits.");
                    break;
                case ECDsaTokenKey ecdsa:
                    ok = ecdsa.Value.KeySize >= 160;
                    LogInfo($"The identity token is signed with an ECDSA key size of {ecdsa.Value.KeySize} bits.");
                    break;
                default:
                    return;
            }

            Result.Outcome = ok ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
        }
    }
}
