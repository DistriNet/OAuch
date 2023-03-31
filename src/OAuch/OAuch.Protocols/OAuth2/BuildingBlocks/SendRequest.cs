using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
            tokenProvider?.RaiseOnResponseReceived(this.UriType, response);
            return response;
        }
    }
}
