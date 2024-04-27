using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Logging;
using OAuch.Shared.Settings;
using System;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2 {
    public class RefreshTokenProvider : IProvider {
        public RefreshTokenProvider(TokenProvider provider, TestRunContext context) {
            this.Context = context;
            this.Provider = provider;
            this.Pipeline = CreatePipeline();
            this.Http = new HttpHelper(context);
        }
        public TokenProvider Provider { get; }
        public TestRunContext Context { get; }
        public SiteSettings SiteSettings => Context.SiteSettings;
        public LogContext Log => Context.Log;
        public HttpHelper Http { get; }
        public string FlowType => "refresh_token";

        public PipelineStage<bool> Pipeline { get; }
        protected virtual PipelineStage<bool> CreatePipeline() {
            return ProviderPipeline.Start()
                .Then(new CheckTokenUri())
                .Then(new GetClaimParameters(true))
                .Then(new CreateTokenRequest())
                .Then(new SendRequest(UriTypes.TokenUri))
                .Then(new GetServerResponseFromHttpResponse())
                .FinishTokenResponse();
        }

        public async Task<TokenResult> RefreshToken(string refreshToken) {
            if (Context.SiteSettings.TokenDelay > 0 && Context.SiteSettings.TokenDelay <= 15) {
                Log.Log($"Waiting {Context.SiteSettings.TokenDelay} second(s)");
                await Task.Delay(Context.SiteSettings.TokenDelay * 1000);
            }
            Log.Log("Refreshing a token");
            var result = new TokenResult { AuthorizationResponse = ServerResponse.FromRefreshToken(refreshToken) };
            try {
                await Pipeline.Run(this, result);
            } catch (Exception e) {
                Log.Log(e);
                result = new TokenResult {
                    UnexpectedError = e
                };
            }
            Log.Log(result);
            return result;
        }
    }
    public static class RefreshTokenProviderExtensions {
        public static RefreshTokenProvider CreateRefreshProvider(this TokenProvider provider, SiteSettings? overrideSettings = null) {
            var ctx = provider.Context;
            if (overrideSettings != null) {
                ctx = ctx with { SiteSettings = overrideSettings };
            }
            return new RefreshTokenProvider(provider, ctx);
        }
    }
}
