using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class CheckTokenUri : Processor<bool, bool> {
        public override Task<bool> Process(bool value, IProvider tokenProvider, TokenResult tokenResult) {
            if (string.IsNullOrWhiteSpace(tokenProvider.SiteSettings.TokenUri)) {
                tokenResult.UnexpectedError = new ArgumentException("The token URI cannot be empty.");
                this.Succeeded = false;
            } else {
                this.Succeeded = true;
            }
            return Task.FromResult(this.Succeeded);
        }
    }
}
