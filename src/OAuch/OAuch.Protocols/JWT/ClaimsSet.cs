using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace OAuch.Protocols.JWT {
    public class ClaimsSet : JsonCollection {
        public ClaimsSet(string json) : base(json) { }

        public string? Issuer => ReadObject<string>("iss");
        public string? Subject => ReadObject<string>("sub");
        public long? ExpirationTime => ReadValue<long>("exp");
        public IList<string>? Audience { // must contain the OAuth 2.0 client ID
            get {
                if (Root["aud"] is JArray) {
                    return ReadObject<List<string>>("aud");
                }
                var s = ReadObject<string>("aud");
                if (s == null)
                    return null;
                return [s];
            }
        }

        public long? NotBefore => ReadValue<long>("nbf");
        public long? IssuedAt => ReadValue<long>("iat");
        public long? AuthenticationTime => ReadValue<long>("auth_time");
        public string? JwtId => ReadObject<string>("jti");
        public string? Nonce => ReadObject<string>("nonce");
        public string? AuthenticationContextClassReference => ReadObject<string>("acr");
        public List<string>? AuthenticationMethodsReferences => ReadObject<List<string>>("amr");
        public string? AuthorizedParty => ReadObject<string>("azp");
#pragma warning disable IDE1006 // Naming Styles
        public string? mTLSCertificateHash => ReadObject<string>("cnf", "x5t#S256");
#pragma warning restore IDE1006 // Naming Styles
        public string? AccessTokenHash => ReadObject<string>("at_hash");
        public string? CodeHash => ReadObject<string>("c_hash");
        public string? StateHash => ReadObject<string>("s_hash");
    }
}
