using Newtonsoft.Json;
using OAuch.Shared;
using System;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using static System.Security.Cryptography.ECCurve;

namespace OAuch.Protocols.JWT {
    public abstract class TokenKey {
        public static TokenKey FromBytes(byte[] value) => new BytesTokenKey(value);
        public static TokenKey FromRsa(RSA value) => new RsaTokenKey(value);
        public static TokenKey FromECDsa(ECDsa value) => new ECDsaTokenKey(value);
        public static TokenKey Empty => new EmptyTokenKey();
        public virtual TokenKeyDescription ExportPublicKey() => throw new NotSupportedException();
    }
    public class BytesTokenKey : TokenKey {
        public BytesTokenKey(byte[] value) {
            this.Value = value;
        }
        public byte[] Value { get; }
    }
    public class EmptyTokenKey : TokenKey {
        //
    }
    public class TokenKeyDescription {
        public byte[] GetThumbprint() {
            // implemented according to RFC7638
            var json = JsonConvert.SerializeObject(this, Formatting.None);
            return SHA256.HashData(Encoding.UTF8.GetBytes(json));
        }
    }
    public class RsaTokenKey : TokenKey {
        public RsaTokenKey(RSA value) {
            this.Value = value;
        }
        public RSA Value { get; }
        public override TokenKeyDescription ExportPublicKey() => new RsaPublicKey(this.Value);
        private class RsaPublicKey : TokenKeyDescription { 
            public RsaPublicKey(RSA rsa) {
                var p = rsa.ExportParameters(false);
                this.Modulus = EncodingHelper.Base64UrlEncode(p.Modulus!);
                this.Exponent = EncodingHelper.Base64UrlEncode(p.Exponent!);
                this.KeyType = "RSA";
            }

            [JsonProperty("e", Order = 0)]
            public string Exponent { get; set; }

            [JsonProperty("kty", Order = 1)]
            public string KeyType { get; set; }

            [JsonProperty("n", Order = 2)]
            public string Modulus { get; set; }
        }
    }
    public class ECDsaTokenKey : TokenKey {
        public ECDsaTokenKey(ECDsa value) {
            this.Value = value;
        }
        public ECDsa Value { get; }
        public override TokenKeyDescription ExportPublicKey() => new EcPublicKey(this.Value);
        private class EcPublicKey : TokenKeyDescription {
            public EcPublicKey(ECDsa ec) {
                var p = ec.ExportParameters(false);
                this.Curve = CurveName();
                this.X = EncodingHelper.Base64UrlEncode(p.Q.X!);
                this.Y = EncodingHelper.Base64UrlEncode(p.Q.Y!);
                this.KeyType = "EC";
                string CurveName() {
                    switch (p.Curve.Oid.Value) {
                        case "1.2.840.10045.3.1.7": // nistP256
                            return "P-256";
                        case "1.3.132.0.34": // nistP384
                            return "P-384";
                        case "1.3.132.0.35": // nistP521
                            return "P-521";
                        default:
                            throw new NotSupportedException($"Unsupported curve OID: {p.Curve.Oid.Value}");
                    }
                }
            }

            [JsonProperty("crv", Order = 0)]
            public string Curve { get; set; }

            [JsonProperty("kty", Order = 1)]
            public string KeyType { get; set; }

            [JsonProperty("x", Order = 2)]
            public string X { get; set; }

            [JsonProperty("y", Order = 3)]
            public string Y { get; set; }

        }
    }
}