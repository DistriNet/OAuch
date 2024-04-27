using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared.Enumerations;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class AddResponseMode : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
        public AddResponseMode(ResponseModes defaultMode) {
            this.DefaultMode = defaultMode;
        }
        public ResponseModes DefaultMode { get; }
        public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
            OAuthHelper.AddResponseMode(value, tokenProvider.SiteSettings.ResponseMode, this.DefaultMode);
            return Task.FromResult<Dictionary<string, string?>?>(value);
        }
    }
}
