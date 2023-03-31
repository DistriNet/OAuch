using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Logging;
using OAuch.Shared.Settings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2 {
    public class RevocationProvider : IProvider {
        public RevocationProvider(TokenProvider provider, TestRunContext context) {
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
        public string FlowType => "revocation";

        public PipelineStage<bool> Pipeline { get; }
        protected virtual PipelineStage<bool> CreatePipeline() {
            return ProviderPipeline.Start()
                .Then(new CheckRevocationUri())
                .Then(new GetRevocationParameters())
                .Then(new CreateRevocationRequest())
                .Then(new SendRequest(UriTypes.RevocationUri))
                .Then(new GetServerResponseFromHttpResponse())
                .FinishTokenResponse();
        }

        public async Task<bool> RevokeToken(string token, bool isRefresh) {
            Log.Log($"Revoking { (isRefresh ? "a refresh" : "an access") } token");

            var rp = this.Pipeline.FindProcessor<GetRevocationParameters>();
            if (rp == null)
                return false;
            rp.Token = token;
            rp.IsRefresh = isRefresh;

            try {
                var result = new TokenResult();
                await Pipeline.Run(this, result);
                if (result.TokenResponse?.ResponseCode == HttpStatusCode.OK)
                    return true;
            } catch (Exception e) {
                Log.Log(e);
            }
            return false;
        }
    }
    public static class RevocationProviderExtensions {
        public static RevocationProvider? CreateRevocationProvider(this TokenProvider provider, SiteSettings? overrideSettings = null) {
            var ctx = provider.Context;
            if (overrideSettings != null) {
                ctx = ctx with { SiteSettings = overrideSettings };
            }
            if (string.IsNullOrWhiteSpace(ctx.SiteSettings.RevocationUri))
                return null;
            return new RevocationProvider(provider, ctx);
        }
    }
}