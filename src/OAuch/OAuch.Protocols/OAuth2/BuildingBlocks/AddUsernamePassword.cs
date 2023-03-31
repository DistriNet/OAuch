using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class AddUsernamePassword : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
        public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
            value["username"] = tokenProvider.SiteSettings.Username;
            value["password"] = tokenProvider.SiteSettings.Password;
            return Task.FromResult<Dictionary<string, string?>?>(value);
        }
    }
}
