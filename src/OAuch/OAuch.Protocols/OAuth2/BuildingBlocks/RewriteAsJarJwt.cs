using OAuch.Protocols.OAuth2.Pipeline;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class RewriteAsJarJwt : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
        public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
            // JAR specification
            OAuthHelper.RewriteAsJarJwt(tokenProvider.SiteSettings, value);
            return Task.FromResult<Dictionary<string, string?>?>(value);
        }
    }
}
