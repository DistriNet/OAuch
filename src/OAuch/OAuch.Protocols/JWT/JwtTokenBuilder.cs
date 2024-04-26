using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using OAuch.Shared;
using OAuch.Shared.Logging;

namespace OAuch.Protocols.JWT {
    public class JwtTokenBuilder {
        public JwtTokenBuilder() {
            this.Header = [];
            this.Claims = [];
        }

        public JsonDictionary Header { get; }
        public JsonDictionary Claims { get; }


        public string Build(TokenKey key) {
            string? algName = Header.Read<string>("alg") ?? throw new NotSupportedException();
            var alg = JwtAlgorithm.CreateFromString(algName);
            if (alg.Id < 0)
                throw new NotSupportedException();
            return Build(alg, key);
        }
        public string Build(JwtAlgorithm algorithm, TokenKey key) {
            Header["alg"] = algorithm.Name;
            var encodedHeader = EncodingHelper.Base64UrlEncode(JsonConvert.SerializeObject(Header, Formatting.None));
            var encodedClaims = EncodingHelper.Base64UrlEncode(JsonConvert.SerializeObject(Claims, Formatting.None));
            var tokenData = Encoding.ASCII.GetBytes(encodedHeader + "." + encodedClaims);
            var encodedSignature = algorithm.Sign(tokenData, key);
            return encodedHeader + "." + encodedClaims + "." + encodedSignature;
        }

        public static JwtTokenBuilder CreateFromToken(JsonWebToken token) {
            var builder = new JwtTokenBuilder();
            foreach (var node in token.Header.Root) {
                builder.Header[node.Key] = node.Value?.DeepClone();
            }
            foreach (var node in token.Claims.Root) {
                builder.Claims[node.Key] = node.Value?.DeepClone();
            }
            return builder;
        }
        public static JwtTokenBuilder? CreateFromToken(string? token, LogContext? logger = null) {
            logger ??= LogContext.NullLogger;
            var t = JsonWebToken.CreateFromString(token, logger);
            if (t == null)
                return null;
            return CreateFromToken(t);
        }
    }
}
