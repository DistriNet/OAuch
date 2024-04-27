using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.Pipeline;
using System.Net;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class GetServerResponseFromHttpResponse : Processor<HttpResponse, HttpServerResponse> {
        public override Task<HttpServerResponse?> Process(HttpResponse httpResponse, IProvider tokenProvider, TokenResult tokenResult) {
            var sr = ServerResponse.FromResponseBody(httpResponse);
            this.StatusCode = httpResponse.StatusCode;
            this.Error = sr.Error;
            this.ErrorDescription = sr.ErrorDescription;
            return Task.FromResult<HttpServerResponse?>(sr);
        }
        public HttpStatusCode? StatusCode { get; private set; }
        public string? Error { get; set; }
        public string? ErrorDescription { get; set; }
    }
}
