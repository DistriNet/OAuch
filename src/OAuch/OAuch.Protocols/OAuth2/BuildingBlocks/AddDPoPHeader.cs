using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    internal class AddDPoPHeader : Processor<HttpRequest, HttpRequest> {
        public override Task<HttpRequest?> Process(HttpRequest value, IProvider tokenProvider, TokenResult tokenResult) {
            var dpop = OAuthHelper.CreateDPoPToken(tokenProvider.SiteSettings, value, null, null);
            if (dpop != null) {
                value.Headers[HttpRequestHeaders.DPoP] = dpop;
            }
            return Task.FromResult<HttpRequest?>(value);
        }
    }
}
