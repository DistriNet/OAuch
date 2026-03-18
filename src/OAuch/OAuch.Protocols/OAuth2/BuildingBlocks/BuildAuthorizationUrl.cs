using OAuch.Protocols.OAuth2.Pipeline;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    /// <summary>
    /// Converts the assembled authorization parameters into the final authorization request URL.
    /// </summary>
    public class BuildAuthorizationUrl : Processor<Dictionary<string, string?>, string> {
        public override Task<string?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
            return Task.FromResult<string?>(OAuthHelper.BuildUrl(tokenProvider.SiteSettings.AuthorizationUri!, value));
        }
    }
}
