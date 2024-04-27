using OAuch.Protocols.OAuth2.Pipeline;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class GetRevocationParameters : Processor<bool, Dictionary<string, string?>> {
        public string? Token { get; set; }
        public bool? IsRefresh { get; set; }
        public override Task<Dictionary<string, string?>?> Process(bool value, IProvider tokenProvider, TokenResult tokenResult) {
            if (string.IsNullOrEmpty(Token)) {
                this.Succeeded = false;
                return Task.FromResult<Dictionary<string, string?>?>(null);
            }
            var ret = new Dictionary<string, string?> {
                ["token"] = Token
            };
            if (IsRefresh != null) {
                ret["token_type_hint"] = IsRefresh.Value ? "refresh_token" : "access_token";
            }
            return Task.FromResult<Dictionary<string, string?>?>(ret);
        }
    }
}
