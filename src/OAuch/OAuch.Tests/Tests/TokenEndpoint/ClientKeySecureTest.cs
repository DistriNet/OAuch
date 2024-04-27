using OAuch.Protocols.JWK;
using OAuch.Protocols.JWT;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class ClientKeySecureTest : Test {
        public override string Title => "Is the asymmetric client authentication key secure";
        public override string Description => "This test checks if the asymmetric client authentication key secure. A key must be 2048 bits or larger for RSA or 160 bits or larger for ECDSA.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(ClientKeySecureTestResult);
    }
    public class ClientKeySecureTestResult : TestResult {
        public ClientKeySecureTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(ClientKeySecureTestImplementation);
    }
    public class ClientKeySecureTestImplementation : TestImplementation {
        public ClientKeySecureTestImplementation(TestRunContext context, ClientKeySecureTestResult result, IsAsymmetricClientAuthenticationUsedTestResult usesAsym) : base(context, result, usesAsym) { }

#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        public async override Task Run() {
            if (HasFailed<IsAsymmetricClientAuthenticationUsedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if (this.Context.SiteSettings.CertificateId == null && this.Context.SiteSettings.RequestSigningKey == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            Result.Outcome = TestOutcomes.SpecificationFullyImplemented;

            // if we're using mTLS...
            if (this.Context.SiteSettings.CertificateId != null) {
                // ... check every certificate in the client authentication chain
                var certs = this.Context.SiteSettings.Certificates;
                foreach (var cert in certs) {
                    if (cert is X509Certificate2 x509) {
                        var rsa = x509.PublicKey.GetRSAPublicKey();
                        if (rsa != null) {
                            if (rsa.KeySize < 2048) {
                                LogInfo($"The certificate with subject '{x509.Subject}' in the certificate chain uses an RSA key that is too weak ({rsa.KeySize} bits, 2048 bits required).");
                                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                            }
                        } else {
                            var ecdsa = x509.PublicKey.GetECDsaPublicKey();
                            if (ecdsa != null) {
                                if (ecdsa.KeySize < 160) {
                                    LogInfo($"The certificate with subject '{x509.Subject}' in the certificate chain uses an RSA key that is too weak ({ecdsa.KeySize} bits, 160 bits required).");
                                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                                }
                            } else {
                                LogInfo($"Cannot verify the public key size of the certificate with subject '{x509.Subject}'. It does not appear to contain an RSA or ECDSA key...");
                            }
                        }
                    }
                }
            }

            // if we're using the request parameter or private_key_jwt
            if (this.Context.SiteSettings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.PrivateKeyJwt) {
                var jwk = JsonWebKey.Create(this.Context.SiteSettings.RequestSigningKey);
                if (jwk == null) {
                    LogInfo("Invalid JWK specified as the Request Signing Key");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                } else {
                    switch (jwk.TokenKey) {
                        case RsaTokenKey rsa:
                            if (rsa.Value.KeySize < 2048) {
                                LogInfo($"The Request Signing Key is an RSA key that is too weak ({rsa.Value.KeySize} bits, 2048 bits required).");
                                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                            }
                            break;
                        case ECDsaTokenKey ecdsa:
                            if (ecdsa.Value.KeySize < 160) {
                                LogInfo($"The Request Signing Key is an ECDSA key that is too weak ({ecdsa.Value.KeySize} bits, 160 bits required).");
                                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                            }
                            break;
                        default:
                            LogInfo("No asymmetric Request Signing Key specified");
                            Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                            break;
                    }
                }
            }
        }
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
    }
}
