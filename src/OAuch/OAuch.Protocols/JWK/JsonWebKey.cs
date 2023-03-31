using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using OAuch.Protocols.JWT;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace OAuch.Protocols.JWK {
    public class JsonWebKey {
        [JsonConstructor]
        private JsonWebKey(string? id, JwkKeyTypes type, TokenKey tokenKey, JwkKeyUsage? usage, JwtAlgorithm? algorithm, string? certificateThumbprint) {
            this.Id = id;
            this.CertificateThumbprint = certificateThumbprint;
            this.Type = type;
            this.TokenKey = tokenKey;
            this.Usage = usage;
            this.Algorithm = algorithm;
        }
        [JsonProperty("kid")]
        public string? Id { get; }

        [JsonProperty("x5t")]
        public string? CertificateThumbprint { get; }

        [JsonProperty("kty")]
        [JsonConverter(typeof(StringEnumConverter))]
        public JwkKeyTypes Type { get; }

        [JsonIgnore]
        public TokenKey TokenKey { get; }

        [JsonProperty("use")]
        [JsonConverter(typeof(StringEnumConverter))]
        public JwkKeyUsage? Usage {get; }

        [JsonProperty("alg")]
        [JsonConverter(typeof(JwtAlgorithmConverter))]
        public JwtAlgorithm? Algorithm { get; }

        public override string ToString() {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }

        public static JsonWebKey? Create(string? json) => string.IsNullOrEmpty(json) ? null : Create(JObject.Parse(json));
        public static JsonWebKey? Create(JToken key) {
            try {
                JwkKeyTypes keyType;
                TokenKey? tokenKey = null;
                var kts = key["kty"]?.ToObject<string>();
                switch (kts) {
                    case "RSA":
                        keyType = JwkKeyTypes.RSA;
                        tokenKey = ParseRSA();
                        break;
                    case "EC":
                        keyType = JwkKeyTypes.EC;
                        tokenKey = ParseEC();
                        break;
                    case "oct":
                        keyType = JwkKeyTypes.Oct;
                        tokenKey = ParseOct();
                        break;
                    default:
                        return null;
                }
                if (tokenKey == null)
                    return null;
                var kid = key["kid"]?.ToObject<string>();
                JwkKeyUsage? usage = null;
                var us = key["use"]?.ToObject<string>();
                if (us == "enc") {
                    usage = JwkKeyUsage.Encrypt;
                } else if (us == "sig") {
                    usage = JwkKeyUsage.Sign;
                }
                JwtAlgorithm? alg = null;
                var algs = key["alg"]?.ToObject<string>();
                if (algs != null) {
                    alg = JwtAlgorithm.CreateFromString(algs);
                    if (alg.Id < 0)
                        alg = null;
                }
                var certThumbprint = key["x5t"]?.ToObject<string>();
                return new JsonWebKey(kid, keyType, tokenKey, usage, alg, certThumbprint);
            } catch (Exception e) {
                Debug.WriteLine(e.ToString());
            }
            return null;

            TokenKey ParseOct() {
                var key = GetValue("k");
                if (key == null)
                    throw new NotSupportedException();
                return TokenKey.FromBytes(key);
            }
            TokenKey ParseRSA() {
                var rsap = new RSAParameters();
                rsap.Modulus = GetValue("n");
                int size = rsap.Modulus?.Length ?? 0;
                if (size == 0)
                    return TokenKey.Empty;
                if (size % 2 != 0) {
                    size = size + 1;
                    rsap.Modulus = FixSize(rsap.Modulus, size);
                }
                rsap.Exponent = GetValue("e");
                rsap.D = FixSize(GetValue("d"), size);
                rsap.P = FixSize(GetValue("p"), size / 2);
                rsap.Q = FixSize(GetValue("q"), size / 2);
                rsap.DP = FixSize(GetValue("dp"), size / 2);
                rsap.DQ = FixSize(GetValue("dq"), size / 2);
                rsap.InverseQ = FixSize(GetValue("qi"), size / 2);
                var rsa = RSA.Create(rsap);
                return TokenKey.FromRsa(rsa);
            }
            TokenKey ParseEC() {
                var ecp = new ECParameters();
                var rc = key["crv"]?.ToObject<string>();
                int expectedSize;
                switch (rc) {
                    case "P-256":
                        ecp.Curve = ECCurve.NamedCurves.nistP256;
                        expectedSize = 32; // bytes
                        break;
                    case "P-384":
                        ecp.Curve = ECCurve.NamedCurves.nistP384;
                        expectedSize = 48; // bytes
                        break;
                    case "P-521":
                        ecp.Curve = ECCurve.NamedCurves.nistP521;
                        expectedSize = 66; // bytes
                        break;
                    default:
                        return null;
                }
                ecp.D = FixSize(GetValue("d"), expectedSize);
                ecp.Q = new ECPoint() {
                    X = FixSize(GetValue("x"), expectedSize),
                    Y = FixSize(GetValue("y"), expectedSize)
                };
                var rsa = ECDsa.Create(ecp);
                return TokenKey.FromECDsa(rsa);
            }
            byte[]? GetValue(string id) {
                var token = key[id];
                var tokenString = token?.ToObject<string>();
                if (tokenString == null)
                    return null;
                return EncodingHelper.Base64UrlDecode(tokenString);
            }
            byte[]? FixSize(byte[]? input, int expectedSize) {
                if (input == null)
                    return null;
                if (input.Length == expectedSize) {
                    return input;
                }

                byte[] tmp;

                if (input.Length < expectedSize) {
                    tmp = new byte[expectedSize];
                    Buffer.BlockCopy(input, 0, tmp, expectedSize - input.Length, input.Length);
                    return tmp;
                }

                if (input.Length > expectedSize + 1 || input[0] != 0) {
                    throw new InvalidOperationException();
                }

                tmp = new byte[expectedSize];
                Buffer.BlockCopy(input, 1, tmp, 0, expectedSize);
                return tmp;
            }
        }
    }
    public class JwtAlgorithmConverter : JsonConverter<JwtAlgorithm> {
        public override void WriteJson(JsonWriter writer, JwtAlgorithm value, JsonSerializer serializer) {
            writer.WriteValue(value.Name);
        }
        public override JwtAlgorithm ReadJson(JsonReader reader, Type objectType, JwtAlgorithm existingValue, bool hasExistingValue, JsonSerializer serializer) {
            return JwtAlgorithm.CreateFromString((reader.Value as string) ?? "unknown");
        }
    }
}