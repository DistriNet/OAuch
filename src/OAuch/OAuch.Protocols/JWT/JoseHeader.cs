using System;

namespace OAuch.Protocols.JWT {
    public class JoseHeader : JsonCollection {
        public JoseHeader(string json) : base(json) {
            //
        }

        public string? Type => ReadObject<string>("typ");
        public string? ContentType => ReadObject<string>("cty");
        public JwtAlgorithm? Algorithm {
            get {
                if (_jwtAlgorithm == null) {
                    var alg = ReadObject<string>("alg");
                    if (alg == null)
                        return null;
                    _jwtAlgorithm = JwtAlgorithm.CreateFromString(alg);
                }
                return _jwtAlgorithm;
            }
        }
        private JwtAlgorithm? _jwtAlgorithm;

        public string? Issuer => ReadObject<string>("iss"); // unencrypted replicas of these claims in encrypted JWTs
        public string? Subject => ReadObject<string>("sub"); // unencrypted replicas of these claims in encrypted JWTs
        public string? Audience => ReadObject<string>("aud"); // unencrypted replicas of these claims in encrypted JWTs

        public string? JwkSetUrl => ReadObject<string>("jku");
        public string? JsonWebKey => ReadObject<string>("jwk");
        public string? KeyId => ReadObject<string>("kid");
        public string? X509Url => ReadObject<string>("x5u");
        public string? X509CertificateChain => ReadObject<string>("x5c");
        public string? X509CertificateSha1Thumbprint => ReadObject<string>("x5t");
        public string? X509CertificateSha256Thumbprint => ReadObject<string>("x5t#S256");
        //public string? X509CertificateThumbprint => ReadObject<string>("crit");



        public bool IsValid {
            get {
                // at+JWT: https://tools.ietf.org/id/draft-bertocci-oauth-access-token-jwt-00.html

                return (this.Type == null 
                            || string.Equals(this.Type, "JWT", StringComparison.OrdinalIgnoreCase) 
                            || string.Equals(this.Type, "at+JWT", StringComparison.OrdinalIgnoreCase)
                            || string.Equals(this.Type, "dpop+JWT", StringComparison.OrdinalIgnoreCase)) // it must be a JWT
                    && (this.Algorithm?.Id ?? -1) > 0; // we must understand the algorithm used
                /*
                    Verify that the resulting JOSE Header includes only parameters
                    and values whose syntax and semantics are both understood and
                    supported or that are specified as being ignored when not
                    understood.                 
                 */
            }
        }
    }
}
