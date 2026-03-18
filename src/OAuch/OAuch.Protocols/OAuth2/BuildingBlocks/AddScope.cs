using OAuch.Protocols.OAuth2.Pipeline;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    /// <summary>
    /// Adds the configured client scope to the current request parameter set.
    /// </summary>
    public class AddScope : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
        public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
            value["scope"] = tokenProvider.SiteSettings.DefaultClient.Scope;
            return Task.FromResult<Dictionary<string, string?>?>(value);
        }
    }
}
