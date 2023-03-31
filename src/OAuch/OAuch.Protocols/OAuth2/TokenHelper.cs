using Newtonsoft.Json;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2 {
    public static class TokenHelper {
        public static void RegisterTokenResult(TokenProvider provider, TokenResult result) {
            var dictionary = provider.Context.State.Get<Dictionary<string, List<ValidToken>>>(StateKeys.TokenCache);
            if (!dictionary.TryGetValue(provider.FlowType, out var list)) {
                list = new List<ValidToken>();
                dictionary[provider.FlowType] = list;
            }
            if (result.UnexpectedError == null && (result.IdentityToken != null || result.AccessToken != null)) {
                var dict = new Dictionary<string, string>();
                CopyDictionary(result.AuthorizationResponse?.Items, dict);
                CopyDictionary(result.TokenResponse?.Items, dict);
                list.Add(new ValidToken(provider.FlowType, DateTime.Now, dict));
            }

            static void CopyDictionary(IDictionary<string, string>? src, IDictionary<string, string> dest) {
                if (src == null)
                    return;
                foreach (var item in src) {
                    dest[item.Key] = item.Value;
                }
            }
        }
        public static IEnumerable<ValidToken> GetAllTokenResults(TestRunContext context) {
            var dictionary = context.State.Get<Dictionary<string, List<ValidToken>>>(StateKeys.TokenCache);
            foreach(var list in dictionary.Values) {
                if (list != null) {
                    foreach (var token in list) {
                        if (token != null)
                            yield return token;
                    }
                }
            }
        }
    }
    public class ValidToken {
        [JsonConstructor]
        public ValidToken(string flowType, DateTime issuedAt, Dictionary<string, string> items) {
            this.FlowType = flowType;
            this.IssuedAt = issuedAt;
            this.Items = items;
        }

        [JsonProperty]
        public DateTime IssuedAt { get; }
        [JsonProperty]
        public Dictionary<string, string> Items { get; }
        [JsonProperty]
        public string FlowType { get; }


        public string? GetItem(string key) {
            if (Items != null && Items.TryGetValue(key, out var value)) {
                return value;
            }
            return null;
        }

        [JsonIgnore]
        public string? AuthorizationCode => GetItem("code");
        [JsonIgnore]
        public string? AccessToken => GetItem("access_token");
        [JsonIgnore]
        public string? IdentityToken => GetItem("id_token");
        [JsonIgnore]
        public string? RefreshToken => GetItem("refresh_token");
    }
}
