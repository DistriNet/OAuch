using OAuch.Protocols.Http;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Settings;
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2 {
    public class ApiRequest {
        public ApiRequest(TestRunContext context) {
            this.Context = context;
            this.Http = new HttpHelper(context);
        }

        public TestRunContext Context { get; }
        protected SiteSettings Settings => Context.SiteSettings;
        protected virtual HttpHelper Http { get; }

        public event Action<bool>? ServerCertificateReceived;

        protected virtual bool RemoteCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors) {
            ServerCertificateReceived?.Invoke(sslPolicyErrors == SslPolicyErrors.None);
            return true;
        }

        protected virtual HttpRequest GetRequest(string uri, TokenResult token) {
            string accessToken = token.AccessToken ?? "";
            string url = uri;
            bool hasAddedTokenToUrl = FixString(ref url, accessToken);
            bool hasAddedTokenToBody = false, hasAddedTokenToHeaders = false;

            HttpRequest req;
            if (Settings.TestMethod == HttpMethodsEnum.Post) {
                req = HttpRequest.CreatePost(url);
                if (!string.IsNullOrEmpty(Settings.TestPostData)) {
                    var postData = Settings.TestPostData;
                    hasAddedTokenToBody = FixString(ref postData, accessToken);
                    req.Content = Encoding.UTF8.GetBytes(postData);
                    req.Headers[HttpRequestHeaders.ContentLength] = req.Content.Length.ToString();
                    req.Headers[HttpRequestHeaders.ContentType] = "application/x-www-form-urlencoded; charset=utf-8";
                }
            } else {
                req = HttpRequest.CreateGet(url);
            }
            // add any additional headers that the user requested to be added
            if (!string.IsNullOrWhiteSpace(Settings.TestHeaders)) {
                using var sr = new StringReader(Settings.TestHeaders);
                var line = sr.ReadLine();
                while (line != null) {
                    int index = line.IndexOf(':');
                    if (index > 0) {
                        string name = line[..index].Trim();
                        string value = line[(index + 1)..].Trim();
                        if (name.Length > 0 && value.Length > 0)
                            hasAddedTokenToHeaders = hasAddedTokenToHeaders || FixString(ref value, accessToken);
                        req.Headers[HttpRequestHeaders.Create(name)] = value;
                    }
                    line = sr.ReadLine();
                }
            }
            if (uri.IsSecure())
                req.ClientCertificates = Settings.ApiCertificates;
            if (!hasAddedTokenToUrl && !hasAddedTokenToBody && !hasAddedTokenToHeaders && accessToken.Length > 0)
                req.Headers[HttpRequestHeaders.Authorization] = $"Bearer {accessToken}";
            req.ServerCertificateValidationCallback = RemoteCertificateValidationCallback;
            this.ManualAccessTokenInUrl = hasAddedTokenToUrl;
            this.ManualAccessTokenInBody = hasAddedTokenToBody;
            this.ManualAccessTokenInHeader = hasAddedTokenToHeaders;
            return req;

            bool FixString(ref string value, string accessToken) {
                return FixDelim(ref value, ACCESS_TOKEN_DELIM_RAW, accessToken)
                    || FixDelim(ref value, ACCESS_TOKEN_DELIM_URL, EncodingHelper.UrlEncode(accessToken))
                    || FixDelim(ref value, ACCESS_TOKEN_DELIM_BASE64, EncodingHelper.Base64Encode(accessToken));
            }
            bool FixDelim(ref string value, string delim, string replaceWith) {
                if (value.Contains(delim, StringComparison.CurrentCulture)) {
                    value = value.Replace(delim, replaceWith);
                    return true;
                }
                return false;
            }
        }

        public bool ManualAccessTokenInUrl { get; private set; }
        public bool ManualAccessTokenInBody { get; private set; }
        public bool ManualAccessTokenInHeader { get; private set; }

        public virtual async Task<HttpResponse> Send(TokenResult token) {
            try {
                if (string.IsNullOrWhiteSpace(Settings.TestUri))
                    return HttpResponse.Invalid;

                var request = GetRequest(Settings.TestUri, token);
                var response = await Http.SendRequest(request);

                // check if there is a failure indicator
                if (!string.IsNullOrWhiteSpace(Context.SiteSettings.TestFailureIndicator)) {
                    var contents = response.ToString(true);
                    if (contents.Contains(Context.SiteSettings.TestFailureIndicator, StringComparison.InvariantCultureIgnoreCase)) {
                        response = new HttpResponse(response.Request, HttpStatusCode.Unauthorized, response.Headers, response.Content, response.SecurityReport);
                    }
                }

                return response;
            } catch (Exception e) {
                Context.Log.Log(e);
                return HttpResponse.Invalid;
            }
        }

        public const string ACCESS_TOKEN_DELIM_RAW = "$OAUCH_ACCESSTOKEN_RAW$";
        public const string ACCESS_TOKEN_DELIM_URL = "$OAUCH_ACCESSTOKEN_URL$";
        public const string ACCESS_TOKEN_DELIM_BASE64 = "$OAUCH_ACCESSTOKEN_BASE64$";
    }
}
