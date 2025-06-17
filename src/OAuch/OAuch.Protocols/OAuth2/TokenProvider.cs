using OAuch.Protocols.Http;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using OAuch.Shared.Logging;
using OAuch.Shared.Settings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;

namespace OAuch.Protocols.OAuth2 {
    public abstract class TokenProvider : IProvider {
        public TokenProvider(TokenProviderSettings settings, TestRunContext context) {
            this.ProviderSettings = settings;
            this.Http = new HttpHelper(context);

            var defClient = context.SiteSettings.GetClient(settings.FlowType);
            if (defClient == context.SiteSettings.DefaultClient) {
                this.Context = context;
            } else {
                this.Context = context with {
                    SiteSettings = context.SiteSettings with {
                        DefaultClient = defClient
                    }
                };
            }

            this.Pipeline = CreateTokenPipeline();
            this.OnNewTokenResult += TokenHelper.RegisterTokenResult;
        }


        public virtual TestRunContext Context { get; }
        public virtual LogContext Log => this.Context.Log;
        public virtual SiteSettings SiteSettings => this.Context.SiteSettings;
        public virtual TokenProviderSettings ProviderSettings { get; }
        public virtual HttpHelper Http { get; }
        public PipelineStage<bool> Pipeline { get; }

        public string Name => ProviderSettings.Name;
        public string FlowType => ProviderSettings.FlowType; // token, code, ...

        protected abstract PipelineStage<bool> CreateTokenPipeline();

        public async Task<TokenResult> GetToken() {
            if (Context.SiteSettings.TokenDelay > 0 && Context.SiteSettings.TokenDelay <= 15) {
                Log.Log($"Waiting {Context.SiteSettings.TokenDelay} second(s)");
                await Task.Delay(Context.SiteSettings.TokenDelay * 1000);
            }
            Log.Log($"Requesting a token via the {Name}");
            OnNewTokenRequested?.Invoke(this);
            var result = new TokenResult();
            try {
                await Pipeline.Run(this, result);
                OnNewTokenResult?.Invoke(this, result);
            } catch (Exception e) {
                Log.Log(e);
                result = new TokenResult {
                    UnexpectedError = e
                };
            }
            Log.Log(result);
            return result;
        }

        //public event ConnectionInfoDelegate? OnNewConnectionInfo;
        public event Action<TokenProvider>? OnNewTokenRequested;
        public event Action<TokenProvider, TokenResult>? OnNewTokenResult;
        public event Action<TokenProvider, UriTypes, string>? OnSendingRedirect;
        public event Action<TokenProvider, UriTypes, ICallbackResult>? OnCallbackReceived;
        public event Action<TokenProvider, UriTypes, HttpRequest>? OnSendingRequest;
        public event Action<TokenProvider, UriTypes, HttpResponse>? OnResponseReceived;

        //protected void RaiseOnNewConnectionInfo(IConnectionSecurityReport securityReport)  => OnNewConnectionInfo?.Invoke(this, securityReport);
        public void RaiseOnSendingRedirect(UriTypes redirectType, string redirectUri) => OnSendingRedirect?.Invoke(this, redirectType, redirectUri);
        public void RaiseOnCallbackReceived(UriTypes callbackType, ICallbackResult callbackResult) => OnCallbackReceived?.Invoke(this, callbackType, callbackResult);
        public void RaiseOnSendingRequest(UriTypes requestType, HttpRequest request) => OnSendingRequest?.Invoke(this, requestType, request);
        public void RaiseOnResponseReceived(UriTypes responseType, HttpResponse response) => OnResponseReceived?.Invoke(this, responseType, response);
    }
    public enum UriTypes {
        AuthorizationUri,
        DeviceAuthorizationUri,
        TokenUri,
        VerificationUri,
        RevocationUri,
        ParUri
    }

    public class TokenResult {
        public TokenResult() {
            //
        }
        public string? ParRequestUri { get; set; }
        public ServerResponse? AuthorizationResponse { get; set; }
        public HttpServerResponse? TokenResponse { get; set; }
        public IList<string> AllAccessTokens {
            get {
                var ret = new List<string>();
                if (AuthorizationResponse?.AccessToken != null) ret.Add(AuthorizationResponse.AccessToken);
                if (TokenResponse?.AccessToken != null) ret.Add(TokenResponse.AccessToken);
                return ret;
            }
        }
        public IList<string> AllIdentityTokens {
            get {
                var ret = new List<string>();
                if (AuthorizationResponse?.IdentityToken != null) ret.Add(AuthorizationResponse.IdentityToken);
                if (TokenResponse?.IdentityToken != null) ret.Add(TokenResponse.IdentityToken);
                return ret;
            }
        }
        public string? AccessToken => IsValid ? (TokenResponse?.AccessToken ?? AuthorizationResponse?.AccessToken) : null;
        public string? IdentityToken => IsValid ? (TokenResponse?.IdentityToken ?? AuthorizationResponse?.IdentityToken) : null;
        public string? AuthorizationCode => IsValid ? (AuthorizationResponse?.Code) : null;
        public string? RefreshToken => IsValid ? (TokenResponse?.RefreshToken ?? AuthorizationResponse?.RefreshToken) : null;
        public int? ExpiresIn => TokenResponse?.ExpiresIn ?? AuthorizationResponse?.ExpiresIn;
        public bool IsValid => (AuthorizationResponse == null || AuthorizationResponse.IsValid) && (TokenResponse == null || TokenResponse.IsValid);
        public Exception? UnexpectedError {
            get {
                if (_unexpected != null)
                    return _unexpected;
                return TokenResponse?.UnexpectedError ?? AuthorizationResponse?.UnexpectedError;
            }
            set {
                _unexpected = value;
            }
        }
        private Exception? _unexpected;
    }

    public class HttpServerResponse : ServerResponse {
        public HttpServerResponse(HttpStatusCode code) {
            this.ResponseCode = code;
        }
        public HttpStatusCode ResponseCode { get; set; }
        public override bool IsValid => base.IsValid && ResponseCode.IsOk();
    }
    public class ServerResponse {
        public ServerResponse() {
            this.Items = new Dictionary<string, string>();
        }

        public IDictionary<string, string> Items { get; set; }
        public string? OriginalContents { get; set; }
        public Exception? UnexpectedError { get; set; }
        public bool WasCallbackStalled { get; set; } // did the user click on the 'Stalled test' button?


        private string? GetString(string name) {
            if (this.Items != null && Items.TryGetValue(name, out var ret)) {
                return ret;
            }
            return null;
        }
        private int? GetInt(string name) {
            if (this.Items != null && Items.TryGetValue(name, out var ret)) {
                if (int.TryParse(ret, out var retNum)) {
                    return retNum;
                }
            }
            return null;
        }

        public virtual bool IsValid {
            get {
                if (this.UnexpectedError != null || this.Items == null || this.Items.Count == 0 || !string.IsNullOrWhiteSpace(this.Error))
                    return false;
                return true;
            }
        }

        public string? Code => GetString("code");
        public string? State => GetString("state");
        public string? AccessToken => GetString("access_token");
        public string? IdentityToken => GetString("id_token");
        public string? TokenType => GetString("token_type");
        public int? ExpiresIn => GetInt("expires_in");
        public string? RefreshToken => GetString("refresh_token");
        public string? Error => GetString("error");
        public string? ErrorDescription => GetString("error_description");
        public string? ErrorUri => GetString("error_uri");
        public string? DeviceCode => GetString("device_code");
        public string? UserCode => GetString("user_code");
        public string? VerificationUri {
            get {
                var vUri = GetString("verification_uri");
                if (string.IsNullOrEmpty(vUri))
                    return GetString("verification_url"); // fix for a Google bug
                return vUri;
            }
        }
        public int? Interval => GetInt("interval");

        public static ServerResponse FromAuthorizationCode(string code) {
            var ret = new ServerResponse();
            ret.Items["code"] = code;
            return ret;
        }
        public static ServerResponse FromAccessToken(string accessToken) {
            var ret = new ServerResponse();
            ret.Items["access_token"] = accessToken;
            return ret;
        }
        public static ServerResponse FromRefreshToken(string refreshToken) {
            var ret = new ServerResponse();
            ret.Items["refresh_token"] = refreshToken;
            return ret;
        }
        public static ServerResponse FromRefreshToken(TokenResult token) {
            return FromRefreshToken(token.RefreshToken ?? "");
        }
        public static ServerResponse FromCallbackResult(ICallbackResult callbackResult, ResponseModes requestedMode, ResponseModes defaultMode, LogContext log) {
            if (requestedMode == ResponseModes.Default)
                requestedMode = defaultMode;
            if (requestedMode == ResponseModes.Jwt) {
                switch (defaultMode) {
                    case ResponseModes.FormPost:
                        requestedMode = ResponseModes.FormPostJwt;
                        break;
                    case ResponseModes.Fragment:
                        requestedMode = ResponseModes.FragmentJwt;
                        break;
                    case ResponseModes.Query:
                        requestedMode = ResponseModes.QueryJwt;
                        break;
                }
            }

            try {
                switch (requestedMode) {
                    case ResponseModes.FormPost:
                    case ResponseModes.FormPostJwt:
                        if (string.IsNullOrWhiteSpace(callbackResult.FormData))
                            return new ServerResponse { OriginalContents = callbackResult.ToString(), UnexpectedError = new ArgumentException("Expected form POST data, but no data was found.") };
                        return FromRawDictionary(EncodingHelper.EncodedFormToDictionary(callbackResult.FormData), callbackResult.FormData, log);
                    case ResponseModes.Fragment:
                    case ResponseModes.FragmentJwt:
                        if (Uri.TryCreate(callbackResult.Url, UriKind.Absolute, out var urlf)) {
                            if (string.IsNullOrWhiteSpace(urlf.Fragment))
                                return new ServerResponse { OriginalContents = callbackResult.ToString(), UnexpectedError = new ArgumentException("Expected URL fragment data, but no data was found.") };
                            var itemsf = HttpUtility.ParseQueryString(urlf.Fragment.TrimStart('#'));
                            return FromRawDictionary(itemsf.ToDictionary(), urlf.Fragment, log);
                        }
                        return new ServerResponse { OriginalContents = callbackResult.ToString(), UnexpectedError = new ArgumentException("Could not parse callback URI.") };
                    case ResponseModes.Query:
                    case ResponseModes.QueryJwt:
                        if (Uri.TryCreate(callbackResult.Url, UriKind.Absolute, out var urlq)) {
                            if (string.IsNullOrWhiteSpace(urlq.Query))
                                return new ServerResponse { OriginalContents = callbackResult.ToString(), UnexpectedError = new ArgumentException("Expected URL query data, but no data was found.") };
                            var itemsq = HttpUtility.ParseQueryString(urlq.Query.TrimStart('?'));
                            return FromRawDictionary(itemsq.ToDictionary(), urlq.Query, log);
                        }
                        return new ServerResponse { OriginalContents = callbackResult.ToString(), UnexpectedError = new ArgumentException("Could not parse callback URI.") };
                }
                // auto-detect
                var tokens = new ServerResponse[] {
                    FromCallbackResult(callbackResult, ResponseModes.Fragment, ResponseModes.Fragment, log),
                    FromCallbackResult(callbackResult, ResponseModes.Query, ResponseModes.Query, log),
                    FromCallbackResult(callbackResult, ResponseModes.FormPost, ResponseModes.FormPost, log),
                    FromCallbackResult(callbackResult, ResponseModes.FragmentJwt, ResponseModes.FragmentJwt, log),
                    FromCallbackResult(callbackResult, ResponseModes.QueryJwt, ResponseModes.QueryJwt, log),
                    FromCallbackResult(callbackResult, ResponseModes.FormPostJwt, ResponseModes.FormPostJwt, log)
                };
                var ret = tokens.FirstOrDefault(t => t.IsValid && (t.Code != null || t.AccessToken != null || t.IdentityToken != null));
                if (ret != null) return ret;
                ret = tokens.FirstOrDefault(t => t.IsValid);
                if (ret != null) return ret;
                return new ServerResponse { OriginalContents = callbackResult.ToString(), UnexpectedError = new ArgumentException("Could not automatically detect the server's response mode") };
            } catch (Exception e) {
                return new ServerResponse { OriginalContents = callbackResult.ToString(), UnexpectedError = e };
            }

            ServerResponse FromRawDictionary(Dictionary<string, string> items, string original, LogContext log) {
                if (requestedMode == ResponseModes.FormPostJwt || requestedMode == ResponseModes.QueryJwt || requestedMode == ResponseModes.FragmentJwt) {
                    if (!items.TryGetValue("response", out string? value))
                        return new ServerResponse { OriginalContents = original, UnexpectedError = new ArgumentException("The 'response' parameter was expected but not present.") };
                    var formJwt = JsonWebToken.CreateFromString(value, log);
                    if (formJwt == null)
                        return new ServerResponse { OriginalContents = original, UnexpectedError = new ArgumentException("The encoded JWT in the 'response' parameter could not be decoded.") };
                    items = DecodeJwt(formJwt);
                }
                return new ServerResponse { Items = items, OriginalContents = original };
            }
            Dictionary<string, string> DecodeJwt(JsonWebToken token) {
                var ret = new Dictionary<string, string>();
                foreach (var key in token.Claims.Keys) {
                    var val = token.Claims.ReadObject<string>(key);
                    if (val != null)
                        ret[key] = val;
                }
                return ret;
            }
        }
        public static HttpServerResponse FromResponseBody(HttpResponse response) {
            HttpServerResponse sr;
            try {
                string c = response.ToString(true);
                var contentType = response.Headers.Get("Content-Type");
                contentType ??= "application/json";
                int si = contentType.IndexOf(';');
                if (si >= 0)
                    contentType = contentType[..si];
                contentType = contentType.Trim().ToLower();

                IDictionary<string, string> dictionary;
                if (string.IsNullOrWhiteSpace(c)) {
                    dictionary = new Dictionary<string, string>();
                } else {
                    if (contentType == "application/x-www-form-urlencoded" || contentType == "text/plain") { // result is form encoded
                        dictionary = EncodingHelper.EncodedFormToDictionary(c);
                    } else { // result is sent as JSON
                        dictionary = EncodingHelper.JsonToDictionary(c);
                    }
                }
                sr = new HttpServerResponse(response.StatusCode) { Items = dictionary, OriginalContents = c };
            } catch (Exception e) {
                sr = new HttpServerResponse((HttpStatusCode)418 /* I'm a teapot - this mean OAuch had an unexpected error */) { UnexpectedError = e };
            }
            return sr;
        }
    }

    public class TokenProviderSettings {
        public TokenProviderSettings(string name, string flowType) {
            this.Name = name;
            this.FlowType = flowType;
        }
        public string Name { get; }
        public string FlowType { get; }
    }
    public class TokenProviderInfo {
        public TokenProviderSettings? Settings { get; set; }
        public bool HasAccessTokens { get; set; }
        public bool HasJwtAccessTokens { get; set; }
        public bool HasIdentityTokens { get; set; }
        public bool HasAuthorizationCodes { get; set; }
        public bool HasRefreshTokens { get; set; }
    }

    public class TokenProviderFactory {
        public TokenProviderFactory(TokenProviderInfo providerInfo) {
            if (providerInfo.Settings == null)
                throw new ArgumentNullException("providerInfo.Settings cannot be null.");
            this.Info = providerInfo;
        }
        public TokenProviderInfo Info { get; }
        public string Name => Info.Settings?.Name ?? string.Empty;
        public string FlowType => Info.Settings?.FlowType ?? string.Empty;

        public bool HasAccessTokens => Info.HasAccessTokens;
        public bool HasJwtAccessTokens => Info.HasJwtAccessTokens;
        public bool HasIdentityTokens => Info.HasIdentityTokens;
        public bool HasAuthorizationCodes => Info.HasAuthorizationCodes;
        public bool HasRefreshTokens => Info.HasRefreshTokens;

        public TokenProvider CreateProvider(TestRunContext context) {
            if (Info.Settings == null)
                throw new ArgumentNullException(nameof(context), "Settings cannot be null.");
            return FlowType switch {
                OAuthHelper.TOKEN_FLOW_TYPE or OAuthHelper.IDTOKEN_TOKEN_FLOW_TYPE or OAuthHelper.IDTOKEN_FLOW_TYPE => new ImplicitTokenProvider(Info.Settings, context),
                OAuthHelper.CLIENT_CREDENTIALS_FLOW_TYPE => new ClientCredentialsTokenProvider(Info.Settings, context),
                OAuthHelper.CODE_FLOW_TYPE or OAuthHelper.CODE_IDTOKEN_FLOW_TYPE or OAuthHelper.CODE_IDTOKEN_TOKEN_FLOW_TYPE or OAuthHelper.CODE_TOKEN_FLOW_TYPE => new AuthorizationCodeTokenProvider(Info.Settings, context),
                OAuthHelper.DEVICE_FLOW_TYPE => new DeviceTokenProvider(Info.Settings, context),
                OAuthHelper.PASSWORD_FLOW_TYPE => new PasswordTokenProvider(Info.Settings, context),
                _ => throw new NotSupportedException("The requested response type is not supported."),
            };
        }
    }
}