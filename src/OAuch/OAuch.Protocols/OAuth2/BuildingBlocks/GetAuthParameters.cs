using OAuch.Protocols.OAuth2.Pipeline;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class GetAuthParameters : Processor<bool, Dictionary<string, string?>> {
        public override Task<Dictionary<string, string?>?> Process(bool value, IProvider tokenProvider, TokenResult tokenResult) {
            return Task.FromResult<Dictionary<string, string?>?>(new Dictionary<string, string?> {
                ["response_type"] = tokenProvider.FlowType,
                ["client_id"] = tokenProvider.SiteSettings.DefaultClient.ClientId,
                ["redirect_uri"] = tokenProvider.SiteSettings.CallbackUri,
                ["state"] = "oauch_state_var"
            });
        }
    }
}
