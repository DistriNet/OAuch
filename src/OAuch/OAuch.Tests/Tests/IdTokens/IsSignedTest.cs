using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWK;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.IdTokens {
    public class IsSignedTest : Test {
        public override string Title => "Is the ID token signed";
        public override string Description => "This test determines whether the identity token contains a valid signature.";
        public override string? TestingStrategy => null;
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
                var kid = idToken.Header.KeyId;
                JsonWebKey? key;
                if (kid == null) {
                    // 'kid' is required if there are multiple keys in the key set
                    if (keyset.Count == 1) {
                        key = keyset.First();
                    } else {
                        LogInfo("The ID token does not have a key identifier ('kid') claim in its header.");
                        return;
                    }
                } else {
                    key = keyset[kid];
                    if (key == null) {
                        LogInfo($"The key with identifier '{ kid }' could not be found in the key set downloaded from the JWKS URI.");
                        return;
                    }
                }
                if (key.Algorithm != null && key.Algorithm != alg) {
                    LogInfo($"The key from the JWKS key store only allows for a specific algorithm to be used, but the ID token uses another algorithm.", key.Algorithm.Name, alg.Name);
                    return;
                }
                if (key.Usage != null && key.Usage != JwkKeyUsage.Sign) {
                    LogInfo($"The key from the JWKS key store does not allow it to be used for signing.");
                    return;
                }
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