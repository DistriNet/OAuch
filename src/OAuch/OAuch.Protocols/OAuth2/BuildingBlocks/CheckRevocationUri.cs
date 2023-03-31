using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class CheckRevocationUri : Processor<bool, bool> {
        public override Task<bool> Process(bool value, IProvider tokenProvider, TokenResult tokenResult) {
            if (string.IsNullOrWhiteSpace(tokenProvider.SiteSettings.RevocationUri)) {
                tokenResult.UnexpectedError = new ArgumentException("The revocation URI cannot be empty.");
                this.Succeeded = false;
            } else {
                this.Succeeded = true;
            }
            return Task.FromResult(this.Succeeded);
        }
    }

}
