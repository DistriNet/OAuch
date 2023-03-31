using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Newtonsoft.Json;
using OAuch.Protocols.Http;
using OAuch.Shared;

namespace OAuch.Protocols.OAuth2 {
    public class OAuthMetaData {
        [JsonConstructor]
        private OAuthMetaData() {
            _grantTypesSupported = new List<string>();
        }

        [JsonProperty("issuer")]
        public string? Issuer { get; set; }

        [JsonProperty("authorization_endpoint")]
        public string? AuthorizationEndpoint { get; set; }

        [JsonProperty("device_authorization_endpoint")]
        public string? DeviceAuthorizationEndpoint { get; set; }

        [JsonProperty("token_endpoint")]
        public string? TokenEndpoint { get; set; }

        [JsonProperty("userinfo_endpoint")]
        public string? UserinfoEndpoint { get; set; }

        [JsonProperty("jwks_uri")]
        public string? JwksUri { get; set; }

        [JsonProperty("registration_endpoint")]
        public string? RegistrationEndpoint { get; set; }

        [JsonProperty("scopes_supported")]
        public List<string>? ScopesSupported { get; set; }

        [JsonProperty("response_types_supported")]
        public List<string>? ResponseTypesSupported { get; set; }

        [JsonProperty("subject_types_supported")]
        public List<string>? SubjectTypesSupported { get; set; }

        [JsonProperty("response_modes_supported")]
        public List<string>? ResponseModesSupported { get; set; }

        [JsonProperty("grant_types_supported")]
        public List<string> GrantTypesSupported {
            get {
                return _grantTypesSupported;
            }
            set {
                if (value == null)
                    _grantTypesSupported = new List<string>();
                else
                    _grantTypesSupported = value;
            }
        }
        private List<string> _grantTypesSupported;

        [JsonProperty("token_endpoint_auth_methods_supported")]
        public List<string>? TokenEndpointAuthMethodsSupported { get; set; } // e.g. "token_endpoint_auth_methods_supported": ["client_secret_post","client_secret_basic","private_key_jwt","windows_client_authentication"],

        [JsonProperty("token_endpoint_auth_signing_alg_values_supported")]
        public List<string>? TokenEndpointAuthSigningAlgValuesSupported { get; set; } // e.g. "id_token_signing_alg_values_supported":["RS256"],

        [JsonProperty("service_documentation")]
        public string? ServiceDocumentation { get; set; }

        [JsonProperty("ui_locales_supported")]
        public List<string>? UiLocalesSupported { get; set; }

        [JsonProperty("op_policy_uri")]
        public string? OpPolicyUri { get; set; }

        [JsonProperty("op_tos_uri")]
        public string? OpTosUri { get; set; }

        [JsonProperty("revocation_endpoint")]
        public string? RevocationEndpoint { get; set; }

        [JsonProperty("revocation_endpoint_auth_methods_supported")]
        public List<string>? RevocationEndpointAuthMethodsSupported { get; set; }

        [JsonProperty("revocation_endpoint_auth_signing_alg_values_supported")]
        public List<string>? RevocationEndpointAuthSigningAlgValuesSupported { get; set; }

        [JsonProperty("introspection_endpoint")]
        public string? IntrospectionEndpoint { get; set; }

        [JsonProperty("introspection_endpoint_auth_methods_supported")]
        public List<string>? IntrospectionEndpointAuthMethodsSupported { get; set; }

        [JsonProperty("introspection_endpoint_auth_signing_alg_values_supported")]
        public List<string>? IntrospectionEndpointAuthSigningAlgValuesSupported { get; set; }

        [JsonProperty("code_challenge_methods_supported")]
        public List<string>? CodeChallengeMethodsSupported { get; set; } // containing the supported PKCE challenge methods

        [JsonProperty("id_token_signing_alg_values_supported")]
        public List<string>? IdTokenSigningAlgValuesSupported { get; set; }

        [JsonProperty("claims_supported")]
        public List<string>? ClaimsSupported { get; set; }
        [JsonProperty("request_parameter_supported")]
        public bool? RequestParameterSupported { get; set; }

        public string MetadataUri { get; set; }

        public bool IsValid() {
            return !string.IsNullOrWhiteSpace(this.Issuer) && this.ResponseTypesSupported != null && this.GrantTypesSupported != null;
        }

        public static OAuthMetaData? CreateFromUrl(Uri issuerUrl) {
            var urls = GetMetadataUrls(issuerUrl);
            // try each url, until a valid url is found
            var http = HttpHelper.CreateTransient();
            foreach (var url in urls) {
                var metadata = CreateFromUrl(http, url);
                if (metadata != null)
                    return metadata;
            }
            return null;
        }
        private static List<string> GetMetadataUrls(Uri issuerUrl) {
            // create a number of urls that may contain the metadata
            var urls = new List<string>();
            var schemeAndServer = issuerUrl.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped).TrimEnd('/');
            var path = issuerUrl.GetComponents(UriComponents.Path, UriFormat.Unescaped).TrimStart('/');
            if (path.Length > 0) {
                urls.Add($"{ schemeAndServer }/.well-known/openid-configuration/{ path }");
                urls.Add($"{ schemeAndServer }/.well-known/oauth-authorization-server/{ path }");
            }
            urls.Add($"{ schemeAndServer }/.well-known/openid-configuration");
            urls.Add($"{ schemeAndServer }/.well-known/oauth-authorization-server");
            if (path.Length > 0) {
                urls.Add($"{ schemeAndServer }/{ path }");
            }
            return urls;
        }
        private static OAuthMetaData? CreateFromUrl(HttpHelper http, string url) {
            try {
                var request = HttpRequest.CreateGet(url);
                request.AllowAutoRedirect = true;
                var response = http.SendRequest(request).Result;
                if (!response.StatusCode.IsOk() || response.Content.Length == 0)
                    return null;
                var json = response.ToString(true);
                var result = JsonConvert.DeserializeObject<OAuthMetaData>(json);
                if (result?.IsValid() == true) {
                    result.MetadataUri = url;
                    return result;
                }
            } catch (Exception e) {
                //Debug.WriteLine(e.ToString());
            }
            return null;
        }
    }
}