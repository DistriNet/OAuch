using OAuch.Protocols.OAuth2.Pipeline;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    /// <summary>
    /// Creates the initial parameter set for a device authorization request.
    /// </summary>
    public class GetDeviceCodeParameters : Processor<bool, Dictionary<string, string?>> {
        public override Task<Dictionary<string, string?>?> Process(bool value, IProvider tokenProvider, TokenResult tokenResult) {
            return Task.FromResult<Dictionary<string, string?>?>(new Dictionary<string, string?> {
                ["client_id"] = tokenProvider.SiteSettings.DefaultClient.ClientId
            });
        }
    }
}
