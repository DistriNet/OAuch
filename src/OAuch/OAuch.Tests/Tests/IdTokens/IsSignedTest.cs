using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWK;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Text;

namespace OAuch.Compliance.Tests.IdTokens {
    public class IsSignedTest : Test {
        public override string Title => "Is the ID token signed";
        public override string Description => "This test determines whether the identity token contains a valid signature.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsSignedTestResult);
    }
    public class IsSignedTestResult : TestResult {
        public IsSignedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsSignedTestImplementation);
    }
    public class IsSignedTestImplementation : IdTokenInspectionTestImplementationBase {
        public IsSignedTestImplementation(TestRunContext context, IsSignedTestResult result, OpenIdSupportedTestResult oidc, CanSignatureBeVerifiedTestResult sign) : base(context, result, oidc) {
            AddDependency(sign);
        }
        protected override void ProcessToken(string flowType, ValidToken fullTokenResult, JsonWebToken idToken) {
            var alg = idToken.Header.Algorithm;
            if (alg == null || alg == JwtAlgorithm.None) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The identity token is unsigned");
                return;
            }

            Result.Outcome = TestOutcomes.Skipped;
            if (alg.IsAsymmetric && HasSucceeded<CanSignatureBeVerifiedTestResult>()) { // RSA or ECDSA
                var keyset = Context.State.Find<JwkSet>(StateKeys.JsonWebKeySet);
                if (keyset == null)
                    return;

                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                var key = idToken.Header.GetAsymmetricSigningKey(keyset, LogInfo);
                if (key == null)
                    return;

                if (idToken.Verify(key.TokenKey)) {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    LogInfo("The signature is valid.");
                } else {
                    LogInfo("The signature is invalid.");
                }
            } else if (!alg.IsAsymmetric) { // MAC
                var client = Context.SiteSettings.GetClient(flowType);
                if (!string.IsNullOrEmpty(client.ClientSecret)) {
                    var key = Encoding.UTF8.GetBytes(client.ClientSecret);
                    if (idToken.Verify(TokenKey.FromBytes(key))) {
                        Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                        LogInfo("The signature is valid.");
                    } else {
                        Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                        LogInfo("The signature is invalid.");
                    }
                }
            }
        }
    }
}