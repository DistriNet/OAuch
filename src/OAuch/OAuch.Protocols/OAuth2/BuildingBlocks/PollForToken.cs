using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class PollForToken : Processor<HttpRequest, HttpServerResponse> {
        public async override Task<HttpServerResponse?> Process(HttpRequest request, IProvider provider, TokenResult tokenResult) {
            var completionSource = provider.Context.Browser.RegisterCompletionSource();
            
            int interval = tokenResult.AuthorizationResponse?.Interval ?? 5;
            var tokenProvider = (TokenProvider)provider;
            var claimResponse = await TryClaim(request, tokenProvider);
            while (!claimResponse.IsValid) {
                if (claimResponse.Error == "slow_down") {
                    interval += 5;
                } else if (claimResponse.Error != "authorization_pending" // some error occurred (user denied access, or token expired)
                    || completionSource.Task.IsCompleted /* the user canceled */) {
                    break; 
                }
                await Task.Delay(interval * 1000);
                claimResponse = await TryClaim(request, tokenProvider);
            }

            provider.Context.Browser.RemoveCompletionSource(completionSource);
            return claimResponse;
        }
        private async Task<HttpServerResponse> TryClaim(HttpRequest claimRequest, TokenProvider tokenProvider) {
            tokenProvider.RaiseOnSendingRequest(UriTypes.TokenUri, claimRequest);
            var claimResult = await tokenProvider.Http.SendRequest(claimRequest);
            tokenProvider.RaiseOnResponseReceived(UriTypes.TokenUri, claimResult);
            return ServerResponse.FromResponseBody(claimResult);
        }

    }
}
