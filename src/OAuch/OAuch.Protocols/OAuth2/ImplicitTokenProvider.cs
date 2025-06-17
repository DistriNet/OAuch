using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;

namespace OAuch.Protocols.OAuth2 {
    public class ImplicitTokenProvider : TokenProvider {
        public ImplicitTokenProvider(TokenProviderSettings settings, TestRunContext context) : base(settings, context) {
            //
        }

        protected override PipelineStage<bool> CreateTokenPipeline() {
            return ProviderPipeline.Start()
                .Then(new CheckAuthorizationUri())
                .Then(new GetAuthParameters())
                .Then(new AddScope())
                .Then(new AddResponseMode(ResponseModes.Fragment))
                .Then(new AddNonce())
                .Then(new RewriteAsJwt())
                .Then(new PushAuthorizationRequest())
                .Then(new BuildAuthorizationUrl())
                .Then(new SendAuthorizationRedirect())
                .Then(new GetServerResponseFromCallback(ResponseModes.Fragment))
                .FinishAuthorizationResponse();
        }
    }
}