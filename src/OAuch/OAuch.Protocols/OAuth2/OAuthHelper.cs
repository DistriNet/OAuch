using OAuch.Protocols.Http;
using OAuch.Protocols.JWK;
using OAuch.Protocols.JWT;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Settings;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace OAuch.Protocols.OAuth2 {
    public static class OAuthHelper {
        public static string GenerateCodeVerifier() => EncodingHelper.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        public static string S256(string? input) {
            byte[] bytes;
            if (input == null)
                bytes = [];
            else
                bytes = Encoding.ASCII.GetBytes(input);
            var hash = SHA256.HashData(bytes);
            return EncodingHelper.Base64UrlEncode(hash);
        }
        public static string BuildUrl(string baseUrl, Dictionary<string, string?> properties) {
            var uriBuilder = new UriBuilder(baseUrl);
            var query = HttpUtility.ParseQueryString(uriBuilder.Query);
            foreach (var key in properties.Keys) {
                var s = properties[key];
                if (!string.IsNullOrEmpty(s))
                    query[key] = s;
            }
            uriBuilder.Query = query.ToString();
            return uriBuilder.ToString();
        }
        public static string CallbackUri {
            get {
                return "https://oauch.io/Callback";
            }
        }
        public static void AddResponseMode(Dictionary<string, string?> pars, ResponseModes requested, ResponseModes def) {
            if (requested == ResponseModes.Default || requested == ResponseModes.AutoDetect || requested == def)
                return;
            switch (requested) {
                case ResponseModes.FormPost:
                    pars["response_mode"] = "form_post";
                    break;
                case ResponseModes.Fragment:
                    pars["response_mode"] = "fragment";
                    break;
                case ResponseModes.Query:
                    pars["response_mode"] = "query";
                    break;
                case ResponseModes.Jwt:
                    pars["response_mode"] = "jwt";
                    break;
                case ResponseModes.FormPostJwt:
                    pars["response_mode"] = "form_post.jwt";
                    break;
                case ResponseModes.FragmentJwt:
                    pars["response_mode"] = "fragment.jwt";
                    break;
                case ResponseModes.QueryJwt:
                    pars["response_mode"] = "query.jwt";
                    break;
            }
        }

        public static bool IsOpenIdFlow(string flowType) {
            return flowType switch {
                // these flows are defined by OpenId
                IDTOKEN_FLOW_TYPE or IDTOKEN_TOKEN_FLOW_TYPE or CODE_IDTOKEN_FLOW_TYPE or CODE_IDTOKEN_TOKEN_FLOW_TYPE or CODE_TOKEN_FLOW_TYPE => true,
                _ => false,
            };
        }
        public static bool HasOpenIdScope(string? scope) {
            var hasOpenIdScope = false;
            if (!string.IsNullOrWhiteSpace(scope)) {
                var scopes = scope.Split(' ');
                foreach (var s in scopes) {
                    if (s == "openid") { // case sensitive
                        hasOpenIdScope = true;
                        break;
                    }
                }
            }
            return hasOpenIdScope;
        }
        public static bool IsOpenId(string flowType, string? scope) {
            if (IsOpenIdFlow(flowType))
                return true;
            else if (flowType == CODE_FLOW_TYPE) // auth code can be openid or not
                return HasOpenIdScope(scope);
            else // token, password, client credentials, device
                return false;
        }

        public static void RewriteAsJwt(SiteSettings settings, Dictionary<string, string?> keys) {
            if (!settings.UseRequestParameter) // use JAR?
                return;

            var builder = new JwtTokenBuilder();
            Copy("client_id"); // only required parameter (depending on client authentication method), in addition to the 'request' parameter
            Move("response_type");
            Move("scope");
            Move("code_challenge");
            Move("code_challenge_method");
            Move("redirect_uri");
            Move("state");
            Move("nonce");
            Move("response_mode");
            builder.Claims["iss"] = settings.DefaultClient.ClientId; // we signed this token
            builder.Claims["aud"] = settings.OpenIdIssuer; // we signed it for the OP
            builder.Claims["iat"] = DateTimeOffset.Now.AddSeconds(-5).ToUnixTimeSeconds();
            builder.Claims["exp"] = DateTimeOffset.Now.AddDays(1).ToUnixTimeSeconds();
            builder.Claims["nbf"] = builder.Claims["iat"];
            string token;
            JsonWebKey? key = null;
            if (!string.IsNullOrEmpty(settings.RequestSigningKey)) {
                key = JsonWebKey.Create(settings.RequestSigningKey);
            }
            if (key == null || key.Algorithm == null) {
                token = builder.Build(JwtAlgorithm.None, TokenKey.Empty);
            } else {
                token = builder.Build(key.Algorithm, key.TokenKey);
            }
            keys["request"] = token;

            void Copy(string key) {
                if (keys.TryGetValue(key, out string? value) && value != null) {
                    builder.Claims.Add(key, value);
                }
            }
            void Move(string key) {
                if (keys.TryGetValue(key, out string? value) && value != null) {
                    builder.Claims.Add(key, value);
                    keys.Remove(key);
                }
            }
        }

        public static void AddClientAuthentication(SiteSettings settings, Dictionary<HttpRequestHeaders, string> headers, Dictionary<string, string?> body, ClientSettings? client = null) {
            if (client == null)
                client = settings.DefaultClient;

            if (string.IsNullOrEmpty(client.ClientId))
                return;
            if (settings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.ClientSecretBasic && !string.IsNullOrEmpty(client.ClientSecret)) { // without a secret, we must use POST parameters
                headers[HttpRequestHeaders.Authorization] = $"Basic {EncodingHelper.Base64Encode(client.ClientId + ":" + client.ClientSecret)}";
            } else if (settings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.ClientSecretPost || settings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.ClientSecretBasic /* we don't have a secret */) {
                body["client_id"] = client.ClientId;
                body["client_secret"] = client.ClientSecret;
            } else {
                //body["client_id"] = client.ClientId;
                body["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

                var builder = new JwtTokenBuilder();
                builder.Claims["iss"] = client.ClientId;
                builder.Claims["sub"] = client.ClientId;
                builder.Claims["aud"] = string.IsNullOrWhiteSpace(settings.RequestAudience) ? settings.TokenUri : settings.RequestAudience;
                builder.Claims["jti"] = Guid.NewGuid().ToString("N");
                builder.Claims["exp"] = DateTimeOffset.Now.AddDays(1).ToUnixTimeSeconds();
                builder.Claims["iat"] = DateTimeOffset.Now.AddSeconds(-5).ToUnixTimeSeconds();
                builder.Claims["nbf"] = builder.Claims["iat"];
                JwtAlgorithm? alg = null;
                TokenKey? key = null;
                if (settings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.ClientSecretJwt && !string.IsNullOrEmpty(client.ClientSecret)) {
                    // client_secret_jwt
                    alg = JwtAlgorithm.HmacSha256;
                    key = TokenKey.FromBytes(Encoding.UTF8.GetBytes(client.ClientSecret));
                } else if (settings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.PrivateKeyJwt) {
                    // private_key_jwt
                    var jwk = JsonWebKey.Create(settings.RequestSigningKey);
                    if (jwk != null) {
                        alg = jwk.Algorithm;
                        key = jwk.TokenKey;

                        if (jwk.CertificateThumbprint != null)
                            builder.Header["x5t"] = jwk.CertificateThumbprint;
                        else if (jwk.Id != null)
                            builder.Header["kid"] = jwk.Id;
                    }
                }
                if (alg != null && key != null)
                    body["client_assertion"] = builder.Build(alg, key);
            }
        }

        public const string TOKEN_FLOW_TYPE = "token";
        public const string IDTOKEN_TOKEN_FLOW_TYPE = "id_token token";
        public const string IDTOKEN_FLOW_TYPE = "id_token";
        public const string CODE_FLOW_TYPE = "code";
        public const string CODE_IDTOKEN_FLOW_TYPE = "code id_token";
        public const string CODE_TOKEN_FLOW_TYPE = "code token";
        public const string CODE_IDTOKEN_TOKEN_FLOW_TYPE = "code id_token token";
        public const string DEVICE_FLOW_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
        public const string CLIENT_CREDENTIALS_FLOW_TYPE = "client_credentials";
        public const string PASSWORD_FLOW_TYPE = "password";

        public static string[] AllFlows => [CODE_FLOW_TYPE, CLIENT_CREDENTIALS_FLOW_TYPE, TOKEN_FLOW_TYPE, PASSWORD_FLOW_TYPE, DEVICE_FLOW_TYPE, IDTOKEN_FLOW_TYPE, IDTOKEN_TOKEN_FLOW_TYPE, CODE_IDTOKEN_FLOW_TYPE, CODE_TOKEN_FLOW_TYPE, CODE_IDTOKEN_TOKEN_FLOW_TYPE];
        public static string GetFlowName(string? flow) {
            return flow switch {
                CODE_FLOW_TYPE => "Authorization Code grant",
                CLIENT_CREDENTIALS_FLOW_TYPE => "Client Credentials grant",
                TOKEN_FLOW_TYPE => "Implicit grant",
                PASSWORD_FLOW_TYPE => "Password grant",
                DEVICE_FLOW_TYPE => "Device Code grant",
                IDTOKEN_FLOW_TYPE => "Implicit grant (id_token)",
                IDTOKEN_TOKEN_FLOW_TYPE => "Implicit grant (id_token token)",
                CODE_IDTOKEN_FLOW_TYPE => "Hybrid grant (code id_token)",
                CODE_TOKEN_FLOW_TYPE => "Hybrid grant (code token)",
                CODE_IDTOKEN_TOKEN_FLOW_TYPE => "Hybrid grant (code id_token token)",
                _ => "Unknown flow",
            };
        }
    }
}
