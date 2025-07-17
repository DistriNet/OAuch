using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class AddDPoPThumbprint : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
        public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
            var t = OAuthHelper.GetDPoPThumbprint(tokenProvider.SiteSettings);
            if (t != null) {
                value["dpop_jkt"] = t;
            }
            return Task.FromResult<Dictionary<string, string?>?>(value);
        }
    }
}
