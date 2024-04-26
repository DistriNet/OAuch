using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2 {
    public class AuthorizationCodeTokenProvider : TokenProvider {
        public AuthorizationCodeTokenProvider(TokenProviderSettings settings, TestRunContext context) : base(settings, context) {            
            //
        }
        public string CodeVerifier {
            get {
                _codeVerifier ??= OAuthHelper.GenerateCodeVerifier();
                return _codeVerifier;
            }
            set {
                _codeVerifier = value;
            }
        }
        private string? _codeVerifier;

        public virtual ResponseModes DefaultResponseMode {
            get {
                if (this.FlowType == OAuthHelper.CODE_FLOW_TYPE)
                    return ResponseModes.Query;
                return ResponseModes.Fragment;
            }
        }

        protected override PipelineStage<bool> CreateTokenPipeline() {
            return ProviderPipeline.Start()
                .Then(new CheckAuthorizationUri())
                .Then(new CheckTokenUri())
                .Then(new GetAuthParameters())
                .Then(new AddScope())
                .Then(new AddPKCEChallenge(SiteSettings.PKCEDefault))
                .Then(new AddResponseMode(DefaultResponseMode))
                .Then(new AddNonce())
                .Then(new RewriteAsJwt())
                .Then(new BuildAuthorizationUrl())
                .Then(new SendAuthorizationRedirect())
                .Then(new GetServerResponseFromCallback(DefaultResponseMode))
                .FinishAuthorizationResponse()
                .Then(new GetClaimParameters())
                .Then(new AddRedirectUri())
                .Then(new AddPKCEVerifier(SiteSettings.PKCEDefault))
                .Then(new CreateTokenRequest())
                .Then(new SendRequest(UriTypes.TokenUri))
                .Then(new GetServerResponseFromHttpResponse())
                .FinishTokenResponse();
        }
    }
}