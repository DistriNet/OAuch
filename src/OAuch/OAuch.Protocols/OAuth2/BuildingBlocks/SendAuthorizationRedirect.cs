using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class SendAuthorizationRedirect : Processor<string, ICallbackResult?> {
        public async override Task<ICallbackResult?> Process(string authUrl, IProvider provider, TokenResult tokenResult) {
            var tokenProvider = (TokenProvider)provider;
            tokenProvider.RaiseOnSendingRedirect(UriTypes.AuthorizationUri, authUrl);
            var callbackResult = await tokenProvider.Context.Browser.RequestCallback(authUrl);
            if (callbackResult != null)
                tokenProvider.RaiseOnCallbackReceived(UriTypes.AuthorizationUri, callbackResult);
            return callbackResult;
        }
    }
}
