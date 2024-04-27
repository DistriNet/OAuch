using Newtonsoft.Json;
using OAuch.Shared;
using OAuch.Shared.Logging;
using System;
using System.Text;

namespace OAuch.Protocols.JWT {
    public class JsonWebToken {
        public JsonWebToken(string[] tokenParts, JoseHeader header, ClaimsSet claims) {
            this._tokenParts = tokenParts;
            this.Header = header;
            this.Claims = claims;
        }

        public JoseHeader Header { get; }
        public ClaimsSet Claims { get; }
        public byte[] SignatureData => Encoding.ASCII.GetBytes(this[JWTComponents.Header] + "." + this[JWTComponents.Payload]);
        public string this[JWTComponents component] {
            get {
                if (!Enum.IsDefined(typeof(JWTComponents), component))
                    throw new NotSupportedException();
                return _tokenParts[(int)component];
            }
        }

        public override string ToString() => ToString(true);

        public string ToString(bool base64Encoded, Formatting formatting = Formatting.None) {
            if (base64Encoded)
                return _tokenParts[0] + "." + _tokenParts[1] + "." + _tokenParts[2];
            if (formatting == Formatting.None)
                return Header.ToString(false, Formatting.None) + "." + Claims.ToString(false, Formatting.None) + "." + (_tokenParts[2].Length > 0 ? "{ …signature data… }" : "");
            return Header.ToString(false, Formatting.Indented) + Environment.NewLine + Claims.ToString(false, Formatting.Indented) + (_tokenParts[2].Length > 0 ? Environment.NewLine + "{ …signature data… }" : "");
        }

        public bool Verify(TokenKey key) {
            if (Header.Algorithm == null)
                throw new NotSupportedException();
            return Header.Algorithm.Verify(this, key);
        }

        private readonly string[] _tokenParts;

        public static JsonWebToken? CreateFromString(string? token, LogContext logger) {
            if (token == null)
                return null;
            try {
                var parts = token.Split('.');
                if (parts.Length != 3)
                    return null; // not a valid JWS (we do not support JWE)
                string encodedJoseHeader = parts[0];
                string encodedPayload = parts[1];
                string encodedSignature = parts[2];
                var header = new JoseHeader(EncodingHelper.Base64UrlDecodeAsString(encodedJoseHeader));
                if (!header.IsValid)
                    return null;
                if (string.Equals(header.ContentType, "JWT", StringComparison.OrdinalIgnoreCase) || string.Equals(header.ContentType, "at+JWT", StringComparison.OrdinalIgnoreCase)) {
                    // normally, we should first verify whether the signature is valid before decoding
                    // the JWT; but we assume we don't have the signature key anyway, so don't do that
                    return CreateFromString(encodedPayload, logger); // the payload is an embedded JWT
                }
                var claims = new ClaimsSet(EncodingHelper.Base64UrlDecodeAsString(encodedPayload));
                var jwt = new JsonWebToken(parts, header, claims);
                logger.Log(jwt);
                return jwt;
            } catch { }
            return null;
        }
    }
    public enum JWTComponents : int {
        Header = 0,
        Payload = 1,
        Signature = 2
    }
}
