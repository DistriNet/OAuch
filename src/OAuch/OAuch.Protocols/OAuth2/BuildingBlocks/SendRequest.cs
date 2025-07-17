using Newtonsoft.Json.Linq;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Data;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class SendRequest : Processor<HttpRequest, HttpResponse> {
        public SendRequest(UriTypes uriType) {
            this.UriType = uriType;
        }
        public UriTypes UriType { get; }
        public async override Task<HttpResponse?> Process(HttpRequest request, IProvider provider, TokenResult tokenResult) {
            var tokenProvider = provider as TokenProvider;
            tokenProvider?.RaiseOnSendingRequest(this.UriType, request);
            var response = await provider.Http.SendRequest(request);
            
            // check if there is a DPoP-related follow-up
            var dpopNonce = response.Headers.Get("DPoP-Nonce");
            if (dpopNonce != null) {
                if (response.StatusCode == System.Net.HttpStatusCode.BadRequest) {
                    // update the request to include the new nonce
                    var dpop = OAuthHelper.CreateDPoPToken(provider.SiteSettings, request, null, dpopNonce);
                    if (dpop != null) {
                        // retry if the original request failed; maybe it was rejected because of an invalid DPoP nonce
                        request.Headers[OAuch.Protocols.Http.HttpRequestHeaders.DPoP] = dpop;
                        response = await provider.Http.SendRequest(request);
                        dpopNonce = response.Headers.Get("DPoP-Nonce") ?? dpopNonce; // update the DPoP nonce if we receive a new one
                    }
                }
                tokenResult.AuthorizationDPoPNonce = dpopNonce;
            }

            tokenProvider?.RaiseOnResponseReceived(this.UriType, response);
            return response;
        }
    }
}
