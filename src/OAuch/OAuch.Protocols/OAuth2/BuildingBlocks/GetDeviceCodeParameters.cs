using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class GetDeviceCodeParameters : Processor<bool, Dictionary<string, string?>> {
        public override Task<Dictionary<string, string?>?> Process(bool value, IProvider tokenProvider, TokenResult tokenResult) {
            return Task.FromResult<Dictionary<string, string?>?>(new Dictionary<string, string?> {
                ["client_id"] = tokenProvider.SiteSettings.DefaultClient.ClientId
            });
        }
    }
}
