using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    /// <summary>
    /// Verifies that the authorization response produced an authorization code before the token exchange continues.
    /// </summary>
    public class CheckAuthorizationCode : Processor<bool, bool> {
        public override Task<bool> Process(bool value, IProvider tokenProvider, TokenResult tokenResult) {
            if (tokenResult.AuthorizationCode == null) {
                tokenResult.UnexpectedError = new ArgumentException("The authorization response did not contain a code.");
                this.Succeeded = false;
            } else {
                this.Succeeded = true;
            }
            return Task.FromResult(this.Succeeded);
        }
    }
}
