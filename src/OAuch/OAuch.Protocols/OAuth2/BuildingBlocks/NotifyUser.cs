using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class NotifyUser : Processor<bool, bool> {
        public async override Task<bool> Process(bool value, IProvider provider, TokenResult tokenResult) {
            var tokenProvider = (TokenProvider)provider;
            var verificationUri = tokenResult.AuthorizationResponse!.VerificationUri;
            var userCode = tokenResult.AuthorizationResponse!.UserCode;
            if (string.IsNullOrWhiteSpace(verificationUri) || string.IsNullOrWhiteSpace(userCode)) {
                tokenResult.UnexpectedError = new ArgumentException("The authorization response did not include a verification URI and/or user code.");
                this.Succeeded = false;
            } else {
                tokenProvider.RaiseOnSendingRedirect(UriTypes.VerificationUri, verificationUri);
                await tokenProvider.Context.Browser.RedirectPopup(verificationUri, true);
                await tokenProvider.Context.Browser.SendMessage($"Please enter the following code in the popup window: <strong class=\"text-success\">{userCode}</strong>");
                this.Succeeded = true;
            }
            return this.Succeeded;
        }
    }
}
