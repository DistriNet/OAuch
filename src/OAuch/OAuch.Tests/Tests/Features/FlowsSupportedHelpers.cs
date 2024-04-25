using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Settings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public abstract class FlowSupportedTest : Test {
        public FlowSupportedTest(string flowType, Type resultType) {
            this.FlowType = flowType;
            _resultType = resultType;
        }
        private Type _resultType;
        protected string FlowType { get; }
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => _resultType;
    }
    public abstract class FlowSupportedTestResult : TestResult<TokenProviderInfo> {
        public FlowSupportedTestResult(string testId, Type implementationType) : base(testId) {
            this.ImplementationType = implementationType;
        }
        public override Type ImplementationType { get; }
    }
    public abstract class FlowSupportedTestImplementation : TestImplementation<TokenProviderInfo> {
        public FlowSupportedTestImplementation(string name, string flowType, TestRunContext context, FlowSupportedTestResult result) : base(context, result) {
            this.Name = name;
            this.FlowType = flowType;
        }
        protected string FlowType { get; }
        protected string Name { get; }
        protected abstract TokenProvider CreateProvider(TokenProviderSettings s, TestRunContext c);
        public async override Task Run() {
            try {
                if (this.Context.SiteSettings.ExcludedFlows?.Any(ef => ef == this.FlowType) ?? false) {
                    LogInfo("This flow has been excluded from the test run. If you wish to include it, please change the site settings.");
                    Result.Outcome = TestOutcomes.Skipped;
                    return;
                }

                if (OAuthHelper.IsOpenIdFlow(this.FlowType) && !OAuthHelper.HasOpenIdScope(this.Context.SiteSettings.DefaultClient.Scope)) {
                    LogInfo("This flow is an OpenId-specific flow, but the scope does not include 'openid'");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    return;
                }

                var settings = new TokenProviderSettings(this.Name, this.FlowType);
                var provider = CreateProvider(settings, this.Context);
                provider.OnSendingRedirect += Provider_OnSendingRedirect;
                var response = await provider.GetToken();
                if (response.AccessToken != null || response.IdentityToken != null) {
                    bool isJwt = JsonWebToken.CreateFromString(response.AccessToken, Context.Log) != null;
                    ExtraInfo.Settings = settings;
                    ExtraInfo.HasAccessTokens = response.AccessToken != null;
                    ExtraInfo.HasJwtAccessTokens = isJwt;
                    ExtraInfo.HasIdentityTokens = response.IdentityToken != null;
                    ExtraInfo.HasAuthorizationCodes = provider is AuthorizationCodeTokenProvider;
                    ExtraInfo.HasRefreshTokens = response.RefreshToken != null;
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;

                    if (_authUrl != null)
                        Http.RegisterUrl(_authUrl);
                } else {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                }
            } finally {
                await Context.Browser.SendFeatureDetected(this.FlowType.Replace(' ', '_').Replace(':', '_'), Result.Outcome == TestOutcomes.SpecificationFullyImplemented);
            }
        }

        private void Provider_OnSendingRedirect(TokenProvider source, UriTypes uriType, string redirectUri) {
            _authUrl = redirectUri;
        }
        private string? _authUrl;
    }
}