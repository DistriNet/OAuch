using OAuch.Protocols.OAuth2.Pipeline;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class AddNonce : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
        public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
            if (OAuthHelper.IsOpenId(tokenProvider.FlowType, tokenProvider.SiteSettings.DefaultClient.Scope)) {
                value["nonce"] = "oauch_openid_nonce";
            }
            return Task.FromResult<Dictionary<string, string?>?>(value);
        }
    }
}
