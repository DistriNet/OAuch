using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Settings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class CreateRequestBase : Processor<Dictionary<string, string?>, HttpRequest> {
        public CreateRequestBase(Func<SiteSettings, string> uriSelector, Action<IProvider, HttpRequest, Dictionary<string, string?>>? addClientAuthentication = null) {
            if (addClientAuthentication == null) {
                AddClientAuthenticationMethod = (tokenProvider, request, parameters) => OAuthHelper.AddClientAuthentication(tokenProvider.SiteSettings, request.Headers, parameters);
            } else {
                AddClientAuthenticationMethod = addClientAuthentication;
            }
            _uriSelector = uriSelector;
        }
        public override Task<HttpRequest?> Process(Dictionary<string, string?> parameters, IProvider tokenProvider, TokenResult tokenResult) {
            var uri = _uriSelector(tokenProvider.SiteSettings);
            var request = HttpRequest.CreatePost(uri);
            request.Headers[HttpRequestHeaders.UserAgent] = "OAuch";
            request.Headers[HttpRequestHeaders.ContentType] = "application/x-www-form-urlencoded";
            if (uri.IsSecure())
                request.ClientCertificates = tokenProvider.SiteSettings.Certificates;
            AddClientAuthenticationMethod(tokenProvider, request, parameters);
            request.Content = EncodingHelper.FormUrlEncode(parameters);
            return Task.FromResult<HttpRequest?>(request);
        }
        public Action<IProvider, HttpRequest, Dictionary<string, string?>> AddClientAuthenticationMethod { get; set; }
        private Func<SiteSettings, string> _uriSelector;
    }
}
