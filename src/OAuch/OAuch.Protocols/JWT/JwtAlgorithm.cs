using OAuch.Shared;
using System;
using System.Security.Cryptography;
using System.Text;

namespace OAuch.Protocols.JWT {
    // zie ook https://tools.ietf.org/html/rfc7518
    public class JwtAlgorithm : Enumeration {
        public static readonly JwtAlgorithm None = new NoneAlgorithm();
        public static readonly JwtAlgorithm HmacSha256 = new HmacAlgorithm(2, "HS256", key => new HMACSHA256(key), HashAlgorithmName.SHA256);
        public static readonly JwtAlgorithm HmacSha384 = new HmacAlgorithm(3, "HS384", key => new HMACSHA384(key), HashAlgorithmName.SHA384);
        public static readonly JwtAlgorithm HmacSha512 = new HmacAlgorithm(4, "HS512", key => new HMACSHA512(key), HashAlgorithmName.SHA512);
        public static readonly JwtAlgorithm RsaSha256 = new RsaAlgorithm(5, "RS256", HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        public static readonly JwtAlgorithm RsaSha384 = new RsaAlgorithm(6, "RS384", HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        public static readonly JwtAlgorithm RsaSha512 = new RsaAlgorithm(7, "RS512", HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        public static readonly JwtAlgorithm ECDsaSha256 = new ECDsaAlgorithm(8, "ES256", HashAlgorithmName.SHA256); // always uses curve P-256
        public static readonly JwtAlgorithm ECDsaSha384 = new ECDsaAlgorithm(9, "ES384", HashAlgorithmName.SHA384); // always uses curve P-384
        public static readonly JwtAlgorithm ECDsaSha512 = new ECDsaAlgorithm(10, "ES512", HashAlgorithmName.SHA512); // always uses curve P-521
        public static readonly JwtAlgorithm RsaPssSha256 = new RsaAlgorithm(11, "PS256", HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        public static readonly JwtAlgorithm RsaPssSha384 = new RsaAlgorithm(11, "PS384", HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        public static readonly JwtAlgorithm RsaPssSha512 = new RsaAlgorithm(11, "PS512", HashAlgorithmName.SHA512, RSASignaturePadding.Pss);

        protected JwtAlgorithm(int id, string name) : base(id, name) { }

        public virtual bool Verify(JsonWebToken token, TokenKey key) => throw new NotSupportedException();
        public virtual string Sign(byte[] tokenData, TokenKey key) => throw new NotSupportedException();
        public virtual HashAlgorithm? Hash => null;
        public virtual bool IsAsymmetric => false;

        public static JwtAlgorithm CreateFromString(string alg) {
            var algs = new JwtAlgorithm[] { None, HmacSha256, HmacSha384, HmacSha512, RsaSha256, RsaSha384, RsaSha512, ECDsaSha256, ECDsaSha384, ECDsaSha512, RsaPssSha256, RsaPssSha384, RsaPssSha512 };
            foreach (var a in algs) {
                if (string.Equals(a.Name, alg, StringComparison.OrdinalIgnoreCase))
                    return a;
            }
            return new JwtAlgorithm(-1, alg);
        }
        protected static HashAlgorithm? GetHashFromName(HashAlgorithmName hashName) {
            if (hashName == HashAlgorithmName.SHA256) {
                return SHA256.Create();
            } else if (hashName == HashAlgorithmName.SHA384) {
                return SHA384.Create();
            } else if (hashName == HashAlgorithmName.SHA512) {
                return SHA512.Create();
            }
            return null;
        }
    }

    public class NoneAlgorithm : JwtAlgorithm {
        public NoneAlgorithm() : base(1, "none") { }
        public override string Sign(byte[] tokenData, TokenKey key) {
            return string.Empty;
        }
        public override bool Verify(JsonWebToken token, TokenKey key) {
            return (key as EmptyTokenKey) != null;
        }
    }
    public class HmacAlgorithm : JwtAlgorithm {
        public HmacAlgorithm(int id, string name, Func<byte[], HMAC> hashCreator, HashAlgorithmName hashName) : base(id, name) {
            _hashCreator = hashCreator;
            _hashName = hashName;
        }
        public override string Sign(byte[] tokenData, TokenKey key) {
            if (key is not BytesTokenKey bytesKey)
                throw new NotSupportedException();
            var hmac = _hashCreator(bytesKey.Value);
            var hash = hmac.ComputeHash(tokenData);
            return EncodingHelper.Base64UrlEncode(hash);
        }
        public override bool Verify(JsonWebToken token, TokenKey key) {
            var signature = Sign(token.SignatureData, key);
            return signature == token[JWTComponents.Signature];
        }
        public override HashAlgorithm? Hash => GetHashFromName(_hashName);
        private readonly HashAlgorithmName _hashName;
        private readonly Func<byte[], HashAlgorithm> _hashCreator;
    }
    public class RsaAlgorithm : JwtAlgorithm {
        public RsaAlgorithm(int id, string name, HashAlgorithmName hashName, RSASignaturePadding padding) : base(id, name) {
            _hashName = hashName;
            _padding = padding;
        }
        public override string Sign(byte[] tokenData, TokenKey key) {
            var rsaKey = key as RsaTokenKey ?? throw new NotSupportedException();
            var signature = rsaKey.Value.SignData(tokenData, _hashName, _padding);
            return EncodingHelper.Base64UrlEncode(signature);
        }
        public override bool Verify(JsonWebToken token, TokenKey key) {
            var rsaKey = key as RsaTokenKey ?? throw new NotSupportedException();
            var data = Encoding.ASCII.GetBytes(token[JWTComponents.Header] + "." + token[JWTComponents.Payload]);
            var signature = EncodingHelper.Base64UrlDecode(token[JWTComponents.Signature]);
            return rsaKey.Value.VerifyData(data, signature, _hashName, _padding);
        }
        public override HashAlgorithm? Hash => GetHashFromName(_hashName);
        public override bool IsAsymmetric => true;
        private readonly HashAlgorithmName _hashName;
        private readonly RSASignaturePadding _padding;
    }
    public class ECDsaAlgorithm : JwtAlgorithm {
        public ECDsaAlgorithm(int id, string name, HashAlgorithmName hashName) : base(id, name) {
            _hashName = hashName;
        }
        public override string Sign(byte[] tokenData, TokenKey key) {
            var ecdsaKey = key as ECDsaTokenKey ?? throw new NotSupportedException();
            var signature = ecdsaKey.Value.SignData(tokenData, _hashName);
            return EncodingHelper.Base64UrlEncode(signature);
        }
        public override bool Verify(JsonWebToken token, TokenKey key) {
            if (key is not ECDsaTokenKey ecdsaKey)
                throw new NotSupportedException();
            var signature = EncodingHelper.Base64UrlDecode(token[JWTComponents.Signature]);
            return ecdsaKey.Value.VerifyData(token.SignatureData, signature, _hashName);
        }
        public override HashAlgorithm? Hash => GetHashFromName(_hashName);
        public override bool IsAsymmetric => true;
        private readonly HashAlgorithmName _hashName;
    }
}
