using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Logging;
using OAuch.Shared.Settings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Markup;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    // PAR implementation
    public class PushAuthorizationRequest : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
        public async override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider provider, TokenResult tokenResult) {
            var settings = provider.SiteSettings;
            var parUri = settings.ParUri;
            
            // check if we are using PAR
            if (string.IsNullOrWhiteSpace(parUri))
                return value; // we are not using PAR

            // create the PAR request
            var request = HttpRequest.CreatePost(parUri);
            request.Headers[HttpRequestHeaders.UserAgent] = "OAuch";
            request.Headers[HttpRequestHeaders.ContentType] = "application/x-www-form-urlencoded";
            if (parUri.IsSecure())
                request.ClientCertificates = settings.Certificates;
            OAuthHelper.AddClientAuthentication(settings, request.Headers, value);

            if (value.ContainsKey("request_uri"))
                value.Remove("request_uri"); // this is explicitly forbidden in the RFC9126

            request.Content = EncodingHelper.FormUrlEncode(value);

            // send the PAR request
            var tokenProvider = provider as TokenProvider;
            tokenProvider?.RaiseOnSendingRequest(UriTypes.ParUri, request);
            var response = await provider.Http.SendRequest(request);
            tokenProvider?.RaiseOnResponseReceived(UriTypes.ParUri, response);

            // process result
            var newParameters = new Dictionary<string, string?>();
            var sr = ServerResponse.FromResponseBody(response);
            if (!sr.IsValid) {
                provider.Context.Log.Log("The authorization server returned an invalid response when pushing the authorization parameters. Verify that PAR is supported and that the correct PAR endpoint is configured.", LoggedStringTypes.Warning);
                this.Succeeded = false;
                return newParameters;
            }

            if (!sr.Items.TryGetValue("request_uri", out var uri) || string.IsNullOrWhiteSpace(uri)) {
                provider.Context.Log.Log("The authorization server returned did not return a valid value for the required 'request_uri' parameter.", LoggedStringTypes.Warning);
                this.Succeeded = false;
                return newParameters;
            }
            tokenResult.ParRequestUri = uri; // register it

            string? expiry = null;
            sr.Items.TryGetValue("expires_in", out expiry);
            provider.Context.Log.Log($"The authorization parameters were pushed to the uri '{uri}' (expiry time (s): {expiry ?? "unknown"})", LoggedStringTypes.Info);

            newParameters["client_id"] = value["client_id"];
            newParameters["request_uri"] = uri;
            return newParameters;
        }
    }
}